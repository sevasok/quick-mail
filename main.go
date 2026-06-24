package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	configFile    = "quick-mail.cfg"
	mailboxesFile = "mailboxes.txt"
	cfAPI         = "https://api.cloudflare.com/client/v4"
	githubRepo    = "sevasok/quick-mail"
)

// apiClient is used for short-lived server API calls (poll, push, clear,
// version). The timeout prevents a single hung request from stalling a client
// while others poll the same shared inbox concurrently.
var apiClient = &http.Client{Timeout: 30 * time.Second}

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

type Config struct {
	VPSIP    string
	VPSPort  string
	Token    string
	CFToken  string
	Domain   string
	SSHUser  string
	SSHKey   string
	CatchAll bool
	Guest    bool
}

type Email struct {
	ID      int64    `json:"id"`
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	Time    int64    `json:"time"`
}

func loadConfig() Config {
	home, _ := os.UserHomeDir()
	cfg := Config{VPSPort: "8080", CatchAll: true, SSHUser: "admin", SSHKey: filepath.Join(home, ".ssh", "id_ed25519")}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "vps_ip":
			cfg.VPSIP = parts[1]
		case "vps_port":
			cfg.VPSPort = parts[1]
		case "token":
			cfg.Token = parts[1]
		case "cf_token":
			cfg.CFToken = parts[1]
		case "domain":
			cfg.Domain = parts[1]
		case "ssh_user":
			cfg.SSHUser = parts[1]
		case "ssh_key":
			cfg.SSHKey = parts[1]
		case "catch_all":
			cfg.CatchAll = parts[1] == "true"
		case "guest":
			cfg.Guest = parts[1] == "true"
		}
	}
	return cfg
}

func saveConfig(cfg Config) {
	catchAllVal := "false"
	if cfg.CatchAll {
		catchAllVal = "true"
	}
	guestVal := "false"
	if cfg.Guest {
		guestVal = "true"
	}
	os.WriteFile(configFile, []byte(
		"vps_ip="+cfg.VPSIP+"\n"+
			"vps_port="+cfg.VPSPort+"\n"+
			"token="+cfg.Token+"\n"+
			"cf_token="+cfg.CFToken+"\n"+
			"domain="+cfg.Domain+"\n"+
			"ssh_user="+cfg.SSHUser+"\n"+
			"ssh_key="+cfg.SSHKey+"\n"+
			"catch_all="+catchAllVal+"\n"+
			"guest="+guestVal+"\n",
	), 0600)
}

func fetchZone(token string) (zid, zoneName string, err error) {
	res, err := cfReq(token, "GET", "/zones?status=active&per_page=50", nil)
	if err != nil {
		return
	}
	results, _ := res["result"].([]interface{})
	if len(results) == 0 {
		err = fmt.Errorf("no zones found for this token")
		return
	}
	if len(results) == 1 {
		z, _ := results[0].(map[string]interface{})
		zid, _ = z["id"].(string)
		zoneName, _ = z["name"].(string)
		return
	}
	// multiple zones: list and ask user
	fmt.Println("Multiple zones found:")
	for i, item := range results {
		z, _ := item.(map[string]interface{})
		n, _ := z["name"].(string)
		fmt.Printf("  [%d] %s\n", i+1, n)
	}
	fmt.Print("Select zone number: ")
	var sel int
	fmt.Scan(&sel)
	if sel < 1 || sel > len(results) {
		err = fmt.Errorf("invalid selection")
		return
	}
	z, _ := results[sel-1].(map[string]interface{})
	zid, _ = z["id"].(string)
	zoneName, _ = z["name"].(string)
	return
}

// loadMailboxHistory returns the local history of addresses this client has
// used before. It is not authoritative; the server owns the real list.
func loadMailboxHistory() []string {
	data, err := os.ReadFile(mailboxesFile)
	if err != nil {
		return nil
	}
	var list []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" && !strings.HasPrefix(line, "#") {
			list = append(list, line)
		}
	}
	return list
}

// appendMailboxHistory adds addr to the local history file if not already present.
func appendMailboxHistory(addr string) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return
	}
	for _, h := range loadMailboxHistory() {
		if h == addr {
			return
		}
	}
	f, err := os.OpenFile(mailboxesFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, addr)
}

func pushMailboxes(baseURL, token string, list []string) error {
	if list == nil {
		list = []string{}
	}
	body, _ := json.Marshal(list)
	req, _ := http.NewRequest(http.MethodPut, baseURL+"/mailboxes?token="+token, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// syncMailboxes pulls the authoritative shared mailbox list from the server.
func syncMailboxes(baseURL, token string) ([]string, error) {
	resp, err := apiClient.Get(baseURL + "/mailboxes?token=" + token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("wrong token")
	}
	var list []string
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// changeMailbox applies a single add or del on the server and returns the
// updated shared list. Merge-based, so it never overwrites other clients.
func changeMailbox(baseURL, token, op, addr string) ([]string, error) {
	u := fmt.Sprintf("%s/mailboxes?op=%s&addr=%s&token=%s",
		baseURL, op, url.QueryEscape(addr), token)
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("wrong token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var list []string
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// clearMailboxes removes all addresses from the server in a single request.
// Admin token required.
func clearMailboxes(baseURL, token string) error {
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/mailboxes?token="+token, nil)
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("admin token required")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func containsStr(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// guestInfo describes a guest token issued by the server owner.
type guestInfo struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// createGuest asks the server to mint a new (short, non-admin) guest token.
// Admin token required.
func createGuest(baseURL, token, name string) (guestInfo, error) {
	u := fmt.Sprintf("%s/guests?name=%s&token=%s", baseURL, url.QueryEscape(name), token)
	req, _ := http.NewRequest(http.MethodPost, u, nil)
	resp, err := apiClient.Do(req)
	if err != nil {
		return guestInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return guestInfo{}, fmt.Errorf("admin token required")
	}
	if resp.StatusCode != http.StatusOK {
		return guestInfo{}, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var gi guestInfo
	if err := json.NewDecoder(resp.Body).Decode(&gi); err != nil {
		return guestInfo{}, err
	}
	return gi, nil
}

// listGuests returns the current guest tokens. Admin token required.
func listGuests(baseURL, token string) ([]guestInfo, error) {
	resp, err := apiClient.Get(baseURL + "/guests?token=" + token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("admin token required")
	}
	var list []guestInfo
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// revokeGuest revokes a single guest token by name or token. Admin token required.
func revokeGuest(baseURL, token, which string) error {
	u := fmt.Sprintf("%s/guests?revoke=%s&token=%s", baseURL, url.QueryEscape(which), token)
	req, _ := http.NewRequest(http.MethodDelete, u, nil)
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("admin token required")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// revokeAllGuests revokes every guest token. Admin token required.
func revokeAllGuests(baseURL, token string) error {
	u := fmt.Sprintf("%s/guests?all=1&token=%s", baseURL, token)
	req, _ := http.NewRequest(http.MethodDelete, u, nil)
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("admin token required")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "changeme"
	}
	return hex.EncodeToString(b)
}

func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func promptLine(r *bufio.Reader, label, saved string) string {
	if saved != "" {
		fmt.Printf("%s [%s]: ", label, saved)
	} else {
		fmt.Printf("%s: ", label)
	}
	val, _ := r.ReadString('\n')
	val = strings.TrimSpace(val)
	if val == "" {
		return saved
	}
	return val
}

func isFirstRun(cfg Config) bool {
	return cfg.VPSIP == "" || cfg.Token == ""
}

// ensureToken guarantees cfg.Token holds a real secret. Empty values and known
// placeholders are replaced with a freshly generated random token.
func ensureToken(cfg *Config) bool {
	switch cfg.Token {
	case "", "auto-generated", "changeme", "mysecrettoken":
		cfg.Token = randomToken()
		return true
	}
	return false
}

// guestWizard configures the client to connect to an existing server.
func guestWizard(r *bufio.Reader, cfg *Config) {
	wasGuest := cfg.Guest
	cfg.Guest = true
	cfg.CatchAll = false
	cfg.CFToken = ""
	cfg.VPSIP = promptLine(r, "  Server IP", cfg.VPSIP)
	cfg.VPSPort = promptLine(r, "  Port", cfg.VPSPort)
	tokenDefault := ""
	if wasGuest {
		tokenDefault = cfg.Token
	}
	cfg.Token = strings.TrimSpace(promptLine(r, "  Token", tokenDefault))
	fmt.Println()
}

func setupWizard(r *bufio.Reader, cfg *Config) {
	fmt.Println("=== Setup ===")
	fmt.Println()

	// Role: admin (own server) or guest (joining someone else's).
	fmt.Println("  admin  - you own the server")
	fmt.Println("  guest  - you have a token from an admin")
	roleDefault := "admin"
	if cfg.Guest {
		roleDefault = "guest"
	}
	role := strings.ToLower(promptLine(r, "Role (admin / guest)", roleDefault))
	fmt.Println()
	if role == "guest" {
		guestWizard(r, cfg)
		return
	}
	cfg.Guest = false

	// Step 1: VPS server
	fmt.Println("Step 1: VPS")
	cfg.VPSIP = promptLine(r, "  IP address", cfg.VPSIP)
	ensureToken(cfg)
	fmt.Println()

	// Provision the VPS automatically (downloads the server binary if needed,
	// runs one-time setup, then deploys). Always run so the VPS is fully
	// configured regardless of later optional steps.
	if cfg.VPSIP != "" {
		provisionVPS(r, cfg)
		fmt.Println()
	}

	// Step 2: Cloudflare DNS
	fmt.Println("Step 2: Cloudflare DNS (optional)")
	fmt.Println("  Auto-configures MX, SPF, DMARC. Token needs Zone:DNS:Edit + Zone:Zone:Read.")
	fmt.Println()
	openTok := promptLine(r, "  Open Cloudflare token page? (y/n)", "y")
	if strings.ToLower(openTok) == "y" {
		openURL("https://dash.cloudflare.com/profile/api-tokens")
	}
	cfg.CFToken = promptLine(r, "  Cloudflare token (Enter to skip)", cfg.CFToken)
	if cfg.CFToken != "" {
		fmt.Print("  Detecting domain from Cloudflare... ")
		_, zoneName, err := fetchZone(cfg.CFToken)
		if err != nil {
			fmt.Println("Warning:", err)
		} else {
			cfg.Domain = zoneName
			fmt.Println(zoneName)
		}
	}
	if cfg.Domain == "" {
		cfg.Domain = promptLine(r, "  Domain (e.g. example.com)", "")
	}
	fmt.Println()

	// Step 3: Mail mode
	fmt.Println("Step 3: Mail mode")
	fmt.Println("  catch-all  - accept all addresses")
	fmt.Println("  list       - only accept addresses you allow (recommended)")
	modeDefault := "list"
	if cfg.CatchAll {
		modeDefault = "catch-all"
	}
	modeVal := promptLine(r, "  Mode (catch-all / list)", modeDefault)
	cfg.CatchAll = strings.ToLower(modeVal) == "catch-all"
	fmt.Println()
}

func main() {
	r := bufio.NewReader(os.Stdin)
	cfg := loadConfig()
	if ensureToken(&cfg) {
		saveConfig(cfg)
	}
	// Clean up the previous executable left by a self-update.
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe + ".old")
	}

	fmt.Println("Quick Mail " + version)
	fmt.Println()

	firstRun := isFirstRun(cfg)
	if firstRun {
		setupWizard(r, &cfg)
	} else {
		// Quick re-confirm with ability to change
		if cfg.Guest {
			fmt.Printf("Server: %s  Token: %s\n", cfg.VPSIP, cfg.Token)
		} else {
			mode := "list"
			if cfg.CatchAll {
				mode = "catch-all"
			}
			fmt.Printf("VPS: %s  Token: %s  Mode: %s\n", cfg.VPSIP, cfg.Token, mode)
		}
		fmt.Println("Enter to continue, or 'setup' to reconfigure.")
		input, _ := r.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(input)) == "setup" {
			setupWizard(r, &cfg)
		}
	}

	if cfg.VPSIP == "" || cfg.Token == "" {
		fmt.Println("VPS IP and token are required.")
		pause(r)
		return
	}

	saveConfig(cfg)

	// Update DNS if CF token provided (owner only; guests don't manage DNS).
	if cfg.Guest {
		// nothing to do
	} else if cfg.CFToken != "" {
		fmt.Print("Updating Cloudflare DNS (MX, SPF, DMARC)... ")
		if err := updateDNS(cfg.CFToken, cfg.VPSIP, cfg.Domain); err != nil {
			fmt.Println("Warning:", err)
		} else {
			fmt.Println("ok")
		}
	} else if firstRun {
		d := cfg.Domain
		fmt.Println("Skipping DNS update (no Cloudflare token). Configure DNS manually:")
		fmt.Println("  MX  @ -> mail." + d + " (priority 10)")
		fmt.Println("  A   mail." + d + " -> " + cfg.VPSIP)
		fmt.Println("  TXT @  -> v=spf1 ip4:" + cfg.VPSIP + " -all")
		fmt.Println("  TXT _dmarc -> v=DMARC1; p=reject; rua=mailto:you@" + d)
		fmt.Println()
	}

	baseURL := "http://" + cfg.VPSIP + ":" + cfg.VPSPort

	// Check connectivity; if unreachable, provision the VPS automatically.
	// The first-run wizard already provisioned, so don't provision twice.
	// Guests have no SSH access, so they can't provision: just report the issue.
	fmt.Print("Connecting to VPS... ")
	if err := ping(baseURL, cfg.Token); err != nil {
		fmt.Println("not reachable")
		if cfg.Guest {
			fmt.Println("Cannot reach " + baseURL + ". Check the address and token, then try again.")
			pause(r)
			return
		}
		if !firstRun {
			provisionVPS(r, &cfg)
			time.Sleep(2 * time.Second)
		}
		if err := ping(baseURL, cfg.Token); err != nil {
			fmt.Println()
			fmt.Println("Server port is not reachable. Open these ports in your VPS firewall:")
			fmt.Println("  TCP " + cfg.VPSPort + "  (API)")
			fmt.Println("  TCP 25    (SMTP)")
			fmt.Println("Then run quick-mail again.")
			pause(r)
			return
		}
	}
	fmt.Println("ok")

	// Version check: compare server version against client version.
	// Admin: redeploy the server if versions differ.
	// Guest: self-update the client to match the server.
	if sv, err := checkServerVersion(baseURL); err == nil && sv != "" && sv != "dev" && sv != version {
		if cfg.Guest {
			fmt.Printf("Server is v%s, client is v%s - updating...\n", sv, version)
			tag := "v" + sv
			_, assets, rerr := releaseByTag(tag)
			if rerr != nil {
				fmt.Println("Could not fetch release", tag+":", rerr)
			} else if url, ok := assets["quick-mail.exe"]; !ok {
				fmt.Println("No client binary in release", tag)
			} else if err := selfUpdate(url); err != nil {
				fmt.Println("Update error:", err)
			} else {
				fmt.Printf("Updated to %s. Restart quick-mail.\n", tag)
			}
		} else {
			fmt.Printf("Updating server (%s -> %s)...\n", sv, version)
			if err := deployServer(cfg); err != nil {
				fmt.Println("Deploy error:", err)
			} else {
				time.Sleep(2 * time.Second)
			}
		}
	}

	// Push mailbox list to server. Guests always work against the shared list.
	if !cfg.Guest && cfg.CatchAll {
		fmt.Print("Pushing catch-all mode to server... ")
		if err := pushMailboxes(baseURL, cfg.Token, []string{}); err != nil {
			fmt.Println("Warning:", err)
		} else {
			fmt.Println("ok")
		}
	} else {
		// Server is the sole authority. Just show what's there; no local merging.
		fmt.Print("Syncing mailboxes from server... ")
		serverList, err := syncMailboxes(baseURL, cfg.Token)
		if err != nil {
			fmt.Println("Warning:", err)
		} else {
			fmt.Printf("ok (%d)\n", len(serverList))
		}

		// First run with an empty shared list: let the user seed it.
		if firstRun && len(serverList) == 0 {
			fmt.Println()
			fmt.Println("No mailboxes configured yet.")
			fmt.Println("Add addresses now (one per line, blank to finish):")
			for {
				addr := promptLine(r, "  Address", "")
				if addr == "" {
					break
				}
				addr = strings.ToLower(addr)
				if _, aerr := changeMailbox(baseURL, cfg.Token, "add", addr); aerr == nil {
					appendMailboxHistory(addr)
				}
			}
		}
	}

	fmt.Println()
	printHelp := func() {
		if cfg.Guest {
			fmt.Println("Commands: add <email>  |  del <email>  |  list  |  sync  |  clear (delete received mail)  |  setup  |  help")
		} else if cfg.CatchAll {
			fmt.Println("Mode: catch-all (accepting all addresses)")
			fmt.Println("Commands: clear (delete received mail)  |  deploy  |  setup  |  update  |  guest <name>  |  guests  |  revoke <name|token>  |  revoke all  |  help")
		} else {
			fmt.Println("Mode: verified list")
			fmt.Println("Commands: add <email>  |  del <email>  |  del all (remove all addresses)  |  list  |  sync  |  clear (delete received mail)  |  deploy  |  setup  |  update  |  guest <name>  |  guests  |  revoke <name|token>  |  revoke all  |  help")
		}
	}
	printHelp()
	fmt.Println("Listening for mail on *@" + cfg.Domain + " (Ctrl+C to stop)")
	fmt.Println()

	go func() {
		for {
			line, _ := r.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, " ", 2)
			cmd := strings.ToLower(parts[0])
			arg := ""
			if len(parts) == 2 {
				arg = strings.TrimSpace(parts[1])
			}
			switch cmd {
			case "add":
				if cfg.CatchAll {
					fmt.Println("Not in list mode.")
					continue
				}
				if arg == "" {
					fmt.Println("Usage: add user@" + cfg.Domain)
					continue
				}
				arg = strings.ToLower(arg)
				_, err := changeMailbox(baseURL, cfg.Token, "add", arg)
				if err != nil {
					fmt.Println("Warning adding on server:", err)
				} else {
					appendMailboxHistory(arg)
					fmt.Println("Added:", arg)
				}
			case "del":
				if arg != "" && strings.ToLower(arg) == "all" {
					if cfg.Guest {
						fmt.Println("Admin only.")
						continue
					}
					if err := clearMailboxes(baseURL, cfg.Token); err != nil {
						fmt.Println("Error:", err)
					} else {
						fmt.Println("All addresses removed.")
					}
					continue
				}
				if cfg.CatchAll {
					fmt.Println("Not in list mode.")
					continue
				}
				if arg == "" {
					if cfg.Guest {
						fmt.Println("Usage: del user@" + cfg.Domain)
					} else {
						fmt.Println("Usage: del user@" + cfg.Domain + "  |  del all (remove all mailbox addresses)")
					}
					continue
				}
				arg = strings.ToLower(arg)
				_, err := changeMailbox(baseURL, cfg.Token, "del", arg)
				if err != nil {
					fmt.Println("Warning removing on server:", err)
				} else {
					fmt.Println("Removed:", arg)
				}
			case "list":
				if cfg.CatchAll {
					fmt.Println("Catch-all mode: no allowlist.")
					continue
				}
				list, err := syncMailboxes(baseURL, cfg.Token)
				if err != nil {
					fmt.Println("Warning syncing from server:", err)
					continue
				}
				if len(list) == 0 {
					fmt.Println("No mailboxes yet. Use: add user@" + cfg.Domain)
				} else {
					for _, e := range list {
						fmt.Println(" ", e)
					}
				}
			case "sync":
				list, err := syncMailboxes(baseURL, cfg.Token)
				if err != nil {
					fmt.Println("Sync error:", err)
				} else {
					fmt.Printf("%d mailboxes on server.\n", len(list))
				}
			case "clear":
				if err := clearInbox(baseURL, cfg.Token); err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("Inbox cleared.")
				}
			case "help":
				printHelp()
			case "guest":
				if cfg.Guest {
					fmt.Println("Admin only.")
					continue
				}
				if arg == "" {
					fmt.Println("Usage: guest <name>")
					continue
				}
				gi, err := createGuest(baseURL, cfg.Token, arg)
				if err != nil {
					fmt.Println("Error creating guest token:", err)
				} else {
					fmt.Printf("Guest token for %q: %s\n", gi.Name, gi.Token)
					fmt.Println("Share this with the guest. They choose 'join' in setup and paste it as the access token.")
				}
			case "guests":
				if cfg.Guest {
					fmt.Println("Admin only.")
					continue
				}
				list, err := listGuests(baseURL, cfg.Token)
				if err != nil {
					fmt.Println("Error listing guests:", err)
				} else if len(list) == 0 {
					fmt.Println("No guest tokens.")
				} else {
					for _, g := range list {
						fmt.Printf("  %s\t%s\n", g.Token, g.Name)
					}
				}
			case "revoke":
				if cfg.Guest {
					fmt.Println("Admin only.")
					continue
				}
				if arg == "" {
					fmt.Println("Usage: revoke <name|token>  |  revoke all")
					continue
				}
				if strings.ToLower(arg) == "all" {
					if err := revokeAllGuests(baseURL, cfg.Token); err != nil {
						fmt.Println("Error:", err)
					} else {
						fmt.Println("All guest tokens revoked.")
					}
				} else {
					if err := revokeGuest(baseURL, cfg.Token, arg); err != nil {
						fmt.Println("Error:", err)
					} else {
						fmt.Println("Revoked:", arg)
					}
				}
			case "deploy":
				if cfg.Guest {
					fmt.Println("Admin only.")
					continue
				}
				if err := deployServer(cfg); err != nil {
					fmt.Println("Deploy error:", err)
				}
			case "update":
				if cfg.Guest {
					fmt.Println("Admin only. Client auto-updates on version mismatch.")
					continue
				}
				updateAll(cfg)
			case "init", "setup":
				if cfg.Guest {
					setupWizard(r, &cfg)
					saveConfig(cfg)
					fmt.Println("Saved. Restart quick-mail to apply changes.")
					continue
				}
				provisionVPS(r, &cfg)
			}
		}
	}()

	var lastID int64
	for {
		emails, err := fetchMail(baseURL, cfg.Token, lastID)
		if err != nil {
			fmt.Println("Poll error:", err)
		} else {
			for _, e := range emails {
				printEmail(e)
				if e.ID > lastID {
					lastID = e.ID
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func ping(baseURL, token string) error {
	_, err := fetchMail(baseURL, token, 0)
	return err
}

func fetchMail(baseURL, token string, after int64) ([]Email, error) {
	url := fmt.Sprintf("%s/mail?after=%d&token=%s", baseURL, after, token)
	resp, err := apiClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("wrong token")
	}
	body, _ := io.ReadAll(resp.Body)
	var emails []Email
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func printEmail(e Email) {
	t := time.Unix(e.Time, 0).Format("2006-01-02 15:04:05")
	fmt.Println("--- NEW MAIL ---")
	fmt.Println("Time:   ", t)
	fmt.Println("From:   ", e.From)
	fmt.Println("To:     ", strings.Join(e.To, ", "))
	fmt.Println("Subject:", e.Subject)
	if e.Body != "" {
		fmt.Println()
		fmt.Println(e.Body)
	}
	fmt.Println("----------------")
	fmt.Println()
}

func cfReq(token, method, path string, body interface{}) (map[string]interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, cfAPI+path, reqBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func upsertTXT(token, zid, name, content string) error {
	res, _ := cfReq(token, "GET", "/zones/"+zid+"/dns_records?type=TXT&name="+name, nil)
	items, _ := res["result"].([]interface{})
	if len(items) > 0 {
		rec, _ := items[0].(map[string]interface{})
		id, _ := rec["id"].(string)
		r, err := cfReq(token, "PUT", "/zones/"+zid+"/dns_records/"+id, map[string]interface{}{
			"type": "TXT", "name": name, "content": content, "ttl": 1,
		})
		if err != nil {
			return err
		}
		if ok, _ := r["success"].(bool); !ok {
			return fmt.Errorf("update failed: %v", r["errors"])
		}
	} else {
		r, err := cfReq(token, "POST", "/zones/"+zid+"/dns_records", map[string]interface{}{
			"type": "TXT", "name": name, "content": content, "ttl": 1,
		})
		if err != nil {
			return err
		}
		if ok, _ := r["success"].(bool); !ok {
			return fmt.Errorf("create failed: %v", r["errors"])
		}
	}
	return nil
}

// --- SSH helpers ---

var sshPassCache string

// errKeyNotAuthorized means the server accepted the connection but rejected our
// public key, i.e. the key is not in the server's authorized_keys.
var errKeyNotAuthorized = fmt.Errorf("ssh key not authorized on server")

func readPassword(prompt string) string {
	fmt.Print(prompt + ": ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		r := bufio.NewReader(os.Stdin)
		s, _ := r.ReadString('\n')
		return strings.TrimSpace(s)
	}
	return string(b)
}

func sshDial(host, user string, auths []gossh.AuthMethod) (*gossh.Client, error) {
	cfg := &gossh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	return gossh.Dial("tcp", host, cfg)
}

func sshRun(client *gossh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return strings.TrimSpace(string(out)), err
}

// sshRunIn runs cmd with content piped to stdin.
func sshRunIn(client *gossh.Client, cmd, stdin string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(stdin)
	return sess.Run(cmd)
}

// sshSudoRun runs cmd via sudo. It tries passwordless sudo first, then falls
// back to "sudo -S" using sudoPass for authentication.
func sshSudoRun(client *gossh.Client, cmd, sudoPass string) (string, error) {
	if out, err := sshRun(client, "sudo -n "+cmd); err == nil {
		return out, nil
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(sudoPass + "\n")
	out, err := sess.CombinedOutput("sudo -S -p '' " + cmd)
	return strings.TrimSpace(string(out)), err
}

// sshUpload uploads a local file to remotePath using cat over stdin.
func sshUpload(client *gossh.Client, localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = f
	return sess.Run("cat > " + remotePath)
}

func sshConnectCfg(cfg Config) (*gossh.Client, error) {
	keyData, err := os.ReadFile(cfg.SSHKey)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", cfg.SSHKey, err)
	}
	signer, err := gossh.ParsePrivateKey(keyData)
	if err != nil {
		// key has a passphrase; try the cached one, then prompt (up to 3 tries)
		for attempt := 0; attempt < 3; attempt++ {
			if sshPassCache == "" {
				sshPassCache = readPassword("  SSH key passphrase")
			}
			signer, err = gossh.ParsePrivateKeyWithPassphrase(keyData, []byte(sshPassCache))
			if err == nil {
				break
			}
			fmt.Println("  Wrong passphrase, try again.")
			sshPassCache = ""
		}
		if err != nil {
			return nil, fmt.Errorf("could not unlock SSH key %s", cfg.SSHKey)
		}
	}
	client, err := sshDial(cfg.VPSIP, cfg.SSHUser, []gossh.AuthMethod{gossh.PublicKeys(signer)})
	if err != nil && strings.Contains(err.Error(), "unable to authenticate") {
		return nil, errKeyNotAuthorized
	}
	return client, err
}

func clearInbox(baseURL, token string) error {
	req, err := http.NewRequest(http.MethodDelete, baseURL+"/mail?token="+token, nil)
	if err != nil {
		return err
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("wrong token")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

func checkServerVersion(baseURL string) (string, error) {
	resp, err := apiClient.Get(baseURL + "/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), nil
}

// latestRelease returns the latest release tag and a map of asset name to its
// download URL from the GitHub releases API.
func latestRelease() (tag string, assets map[string]string, err error) {
	return releaseByURL("https://api.github.com/repos/" + githubRepo + "/releases/latest")
}

// releaseByTag fetches a specific release by tag name.
func releaseByTag(tag string) (string, map[string]string, error) {
	return releaseByURL("https://api.github.com/repos/" + githubRepo + "/releases/tags/" + tag)
}

func releaseByURL(url string) (tag string, assets map[string]string, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("GitHub API: %s", resp.Status)
	}
	var data struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", nil, err
	}
	assets = map[string]string{}
	for _, a := range data.Assets {
		assets[a.Name] = a.URL
	}
	return data.TagName, assets, nil
}

// downloadTo fetches url and writes it to dest, replacing any existing file.
func downloadTo(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s", resp.Status)
	}
	tmp := dest + ".download"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(dest)
	return os.Rename(tmp, dest)
}

// ensureServerBinary makes sure quick-mail-server exists locally, downloading the
// latest released binary if it is missing.
func ensureServerBinary() error {
	if _, err := os.Stat("quick-mail-server"); err == nil {
		return nil
	}
	fmt.Print("Downloading latest server binary... ")
	_, assets, err := latestRelease()
	if err != nil {
		fmt.Println("failed")
		return fmt.Errorf("server binary missing and release lookup failed: %w", err)
	}
	url, ok := assets["quick-mail-server"]
	if !ok {
		fmt.Println("failed")
		return fmt.Errorf("server binary missing and not in latest release")
	}
	if err := downloadTo(url, "quick-mail-server"); err != nil {
		fmt.Println("failed")
		return err
	}
	fmt.Println("ok")
	return nil
}

// selfUpdate replaces the running executable with the file at url. On Windows the
// running exe is renamed aside (it cannot be overwritten) and cleaned up on next
// launch. A restart is required to run the new version.
func selfUpdate(url string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	newPath := exe + ".new"
	if err := downloadTo(url, newPath); err != nil {
		return err
	}
	oldPath := exe + ".old"
	os.Remove(oldPath)
	if err := os.Rename(exe, oldPath); err != nil {
		os.Remove(newPath)
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		os.Rename(oldPath, exe) // rollback
		return err
	}
	return nil
}

// updateAll updates the server binary (and redeploys it) and the client itself to
// the latest GitHub release.
func updateAll(cfg Config) {
	fmt.Println("Checking for updates...")
	tag, assets, err := latestRelease()
	if err != nil {
		fmt.Println("Update check failed:", err)
		return
	}
	latest := strings.TrimPrefix(tag, "v")
	fmt.Printf("Latest release: %s (current client %s)\n", tag, version)

	// Update and redeploy the server (admin only; guests have no SSH access).
	if !cfg.Guest {
		if url, ok := assets["quick-mail-server"]; ok {
			fmt.Print("  Downloading server binary... ")
			if err := downloadTo(url, "quick-mail-server"); err != nil {
				fmt.Println("error:", err)
			} else {
				fmt.Println("ok")
				if err := deployServer(cfg); err != nil {
					fmt.Println("  Deploy error:", err)
				}
			}
		} else {
			fmt.Println("  No server binary in the latest release.")
		}
	}

	// Update the client itself.
	if latest == version {
		fmt.Println("  Client is up to date.")
		return
	}
	url, ok := assets["quick-mail.exe"]
	if !ok {
		fmt.Println("  No client binary in the latest release.")
		return
	}
	fmt.Print("  Updating client to " + tag + "... ")
	if err := selfUpdate(url); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("ok")
	fmt.Println("  Client updated. Restart quick-mail to use " + tag + ".")
}

// provisionVPS connects to the VPS with the SSH key, runs one-time setup if the
// systemd service is missing, then deploys the current server binary. It is the
// single entry point for getting the server running, with no manual choices.
func provisionVPS(r *bufio.Reader, cfg *Config) {
	if err := ensureServerBinary(); err != nil {
		fmt.Println(err)
		return
	}

	var client *gossh.Client
	for {
		fmt.Print("Connecting to VPS (SSH key)... ")
		c, err := sshConnectCfg(*cfg)
		if err == nil {
			client = c
			fmt.Println("ok")
			break
		}
		fmt.Println("FAILED")
		if err == errKeyNotAuthorized {
			if !guideAuthorizeKey(r, *cfg) {
				return
			}
			continue
		}
		fmt.Println("  " + err.Error())
		return
	}
	defer client.Close()

	// Adopt the server's existing token if it already has one. On a shared
	// server, the first person to set it up defines the token; everyone after
	// must reuse it instead of overwriting it (which would invalidate the
	// others). Only push our own token when the server has none yet.
	if existing := readServerToken(client, *cfg); existing != "" && existing != cfg.Token {
		cfg.Token = existing
		saveConfig(*cfg)
		fmt.Println("Using the server's existing shared token.")
	}

	// One-time setup if the service or a valid root-owned sudoers rule is missing,
	// or if passwordless ufw is not yet available (older sudoers without ufw).
	needSetup := false
	if _, err := sshRun(client, "test -f /etc/systemd/system/quick-mail-server.service"); err != nil {
		needSetup = true
	} else if _, err := sshRun(client, `test "$(stat -c %u /etc/sudoers.d/quick-mail 2>/dev/null)" = "0"`); err != nil {
		needSetup = true
	} else if _, err := sshRun(client, "sudo -n /usr/sbin/ufw status >/dev/null 2>&1"); err != nil {
		needSetup = true
	}
	if needSetup {
		if err := oneTimeSetup(client, *cfg); err != nil {
			fmt.Println("Setup error:", err)
			return
		}
	}

	if err := deployWith(client, *cfg); err != nil {
		fmt.Println("Deploy error:", err)
	}
}

// guideAuthorizeKey prints the public key the user must add to the server
// after a server reset, and waits for the user to retry. Returns false if the
// user chooses to stop.
func guideAuthorizeKey(r *bufio.Reader, cfg Config) bool {
	pubLine := sshPublicKeyLine(cfg.SSHKey)
	fmt.Println()
	fmt.Println("Your SSH key is not authorized on the server (it was likely reset).")
	fmt.Println("Add this public key to the server (your VPS provider's dashboard, or")
	fmt.Println("~/.ssh/authorized_keys for user " + cfg.SSHUser + "). Copy the whole line:")
	fmt.Println()
	if pubLine != "" {
		fmt.Println(pubLine)
	}
	fmt.Println()
	ans := promptLine(r, "Press Enter after adding the key to retry (or type 'skip')", "")
	return strings.ToLower(strings.TrimSpace(ans)) != "skip"
}

// sshPublicKeyLine returns the full single-line public key (the contents of
// <keyPath>.pub) for the user to copy and paste verbatim.
func sshPublicKeyLine(keyPath string) string {
	data, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// oneTimeSetup configures passwordless sudo (setcap + systemctl) and installs the
// systemd unit. It asks for the sudo password once.
func oneTimeSetup(client *gossh.Client, cfg Config) error {
	fmt.Println("First-time server setup (one sudo password needed).")
	pass := readPassword("  Sudo password for " + cfg.SSHUser)
	home := "/home/" + cfg.SSHUser

	// Passwordless sudo for the few commands deploy needs.
	sudoers := cfg.SSHUser + " ALL=(ALL) NOPASSWD: /usr/sbin/setcap, " +
		"/usr/sbin/ufw, " +
		"/usr/bin/systemctl restart quick-mail-server, " +
		"/usr/bin/systemctl start quick-mail-server, " +
		"/usr/bin/systemctl stop quick-mail-server, " +
		"/usr/bin/systemctl status quick-mail-server\n"
	fmt.Print("  Configuring passwordless sudo... ")
	if err := sshRunIn(client, "cat > /tmp/quick-mail-sudoers", sudoers); err != nil {
		return fmt.Errorf("write sudoers: %w", err)
	}
	if out, err := sshSudoRun(client,
		"sh -c 'mv /tmp/quick-mail-sudoers /etc/sudoers.d/quick-mail && chown root:root /etc/sudoers.d/quick-mail && chmod 440 /etc/sudoers.d/quick-mail'",
		pass); err != nil {
		return fmt.Errorf("install sudoers: %s", strings.TrimSpace(out+" "+err.Error()))
	}
	fmt.Println("ok")

	// Systemd unit reads the token from an EnvironmentFile in the home dir.
	fmt.Print("  Installing systemd service... ")
	unit := "[Unit]\nDescription=Quick Mail Server\nAfter=network.target\n\n" +
		"[Service]\nType=simple\nUser=" + cfg.SSHUser + "\nWorkingDirectory=" + home + "\n" +
		"EnvironmentFile=" + home + "/quick-mail.env\n" +
		"ExecStart=" + home + "/quick-mail-server\nRestart=always\nRestartSec=5\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
	if err := sshRunIn(client, "cat > /tmp/quick-mail-server.service", unit); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if out, err := sshSudoRun(client,
		"sh -c 'mv /tmp/quick-mail-server.service /etc/systemd/system/ && chown root:root /etc/systemd/system/quick-mail-server.service && systemctl daemon-reload && systemctl enable quick-mail-server'",
		pass); err != nil {
		return fmt.Errorf("install unit: %s", strings.TrimSpace(out+" "+err.Error()))
	}
	fmt.Println("ok")

	// Open the required ports in the host firewall (ufw), if it is active.
	fmt.Print("  Opening firewall ports (25, " + cfg.VPSPort + ")... ")
	if _, err := sshSudoRun(client, "sh -c 'command -v ufw >/dev/null && ufw status | grep -q active && (ufw allow 25/tcp; ufw allow "+cfg.VPSPort+"/tcp) || true'", pass); err != nil {
		fmt.Println("skipped (" + err.Error() + ")")
	} else {
		fmt.Println("ok")
	}
	return nil
}

// deployServer connects with the SSH key and deploys. Used by the 'deploy' command.
func deployServer(cfg Config) error {
	if err := ensureServerBinary(); err != nil {
		return err
	}
	client, err := sshConnectCfg(cfg)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer client.Close()
	return deployWith(client, cfg)
}

// readServerToken returns the TOKEN currently configured on the server (from its
// env file), or "" if the server has none yet. Used to adopt a shared token so
// multiple people on one server keep working without re-running setup.
func readServerToken(client *gossh.Client, cfg Config) string {
	home := "/home/" + cfg.SSHUser
	out, err := sshRun(client, "cat "+home+"/quick-mail.env 2>/dev/null")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOKEN=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "TOKEN="))
		}
	}
	return ""
}

// deployWith writes the token env file, uploads the binary, applies setcap, and
// restarts the systemd service. All privileged steps are passwordless after
// oneTimeSetup. Falls back to nohup if the service is not installed.
func deployWith(client *gossh.Client, cfg Config) error {
	home := "/home/" + cfg.SSHUser
	remoteBin := home + "/quick-mail-server"
	remoteTmp := home + "/quick-mail-server.tmp"

	// Token env file. Only write it when the server has no token yet, so a later
	// client on a shared server never clobbers the established shared token.
	if readServerToken(client, cfg) == "" {
		fmt.Print("  Setting token... ")
		if err := sshRunIn(client, "sh -c 'cat > "+home+"/quick-mail.env && chmod 600 "+home+"/quick-mail.env'",
			"TOKEN="+cfg.Token+"\n"); err != nil {
			return fmt.Errorf("write env: %w", err)
		}
		fmt.Println("ok")
	}

	fmt.Print("  Uploading binary... ")
	if err := sshUpload(client, "quick-mail-server", remoteTmp); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	fmt.Println("ok")

	hasSvc := false
	if _, err := sshRun(client, "test -f /etc/systemd/system/quick-mail-server.service"); err == nil {
		hasSvc = true
	}

	fmt.Print("  Restarting server... ")
	var remote string
	if hasSvc {
		remote = fmt.Sprintf(
			"chmod +x %s && mv %s %s &&"+
				" sudo -n setcap 'cap_net_bind_service=+ep' %s &&"+
				" sudo -n systemctl restart quick-mail-server &&"+
				" sleep 2 && systemctl is-active quick-mail-server",
			remoteTmp, remoteTmp, remoteBin, remoteBin)
	} else {
		// Fallback: no systemd unit yet, run directly.
		remote = fmt.Sprintf(
			"pkill quick-mail-server 2>/dev/null; sleep 1;"+
				" chmod +x %s; mv %s %s;"+
				" sudo -n setcap 'cap_net_bind_service=+ep' %s 2>/dev/null;"+
				" cd %s && set -a && . ./quick-mail.env && set +a &&"+
				" nohup ./quick-mail-server >> mailserver.log 2>&1 & sleep 2; pgrep -a quick-mail-server",
			remoteTmp, remoteTmp, remoteBin, remoteBin, home)
	}
	out, err := sshRun(client, remote)
	fmt.Println()
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			fmt.Println("  " + line)
		}
	}
	if err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return nil
}

func updateDNS(token, vpsIP, dom string) error {
	zid, _, err := fetchZone(token)
	if err != nil {
		return err
	}
	if err := updateMXWithZone(token, zid, vpsIP, dom); err != nil {
		return fmt.Errorf("MX: %w", err)
	}
	if err := upsertTXT(token, zid, dom, "v=spf1 ip4:"+vpsIP+" -all"); err != nil {
		return fmt.Errorf("SPF: %w", err)
	}
	if err := upsertTXT(token, zid, "_dmarc."+dom, "v=DMARC1; p=reject; rua=mailto:postmaster@"+dom); err != nil {
		return fmt.Errorf("DMARC: %w", err)
	}
	return nil
}

func updateMXWithZone(token, zid, vpsIP, dom string) error {
	mailHost := "mail." + dom

	res, _ := cfReq(token, "GET", "/zones/"+zid+"/dns_records?type=A&name="+mailHost, nil)
	aItems, _ := res["result"].([]interface{})
	if len(aItems) > 0 {
		aRec, _ := aItems[0].(map[string]interface{})
		aID, _ := aRec["id"].(string)
		cfReq(token, "PUT", "/zones/"+zid+"/dns_records/"+aID, map[string]interface{}{
			"type": "A", "name": mailHost, "content": vpsIP, "ttl": 1, "proxied": false,
		})
	} else {
		cfReq(token, "POST", "/zones/"+zid+"/dns_records", map[string]interface{}{
			"type": "A", "name": mailHost, "content": vpsIP, "ttl": 1, "proxied": false,
		})
	}

	res, _ = cfReq(token, "GET", "/zones/"+zid+"/dns_records?type=MX", nil)
	if items, ok := res["result"].([]interface{}); ok {
		for _, item := range items {
			rec, _ := item.(map[string]interface{})
			id, _ := rec["id"].(string)
			cfReq(token, "DELETE", "/zones/"+zid+"/dns_records/"+id, nil)
		}
	}

	addRes, err := cfReq(token, "POST", "/zones/"+zid+"/dns_records", map[string]interface{}{
		"type": "MX", "name": dom, "content": mailHost, "priority": 10, "ttl": 1,
	})
	if err != nil {
		return err
	}
	if ok, _ := addRes["success"].(bool); !ok {
		return fmt.Errorf("could not add MX record: %s", addRes)
	}
	return nil
}

func pause(r *bufio.Reader) {
	fmt.Print("Press Enter to exit.")
	r.ReadString('\n')
}
