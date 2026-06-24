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
	serverVersion = "3"
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
		}
	}
	return cfg
}

func saveConfig(cfg Config) {
	catchAllVal := "false"
	if cfg.CatchAll {
		catchAllVal = "true"
	}
	os.WriteFile(configFile, []byte(
		"vps_ip="+cfg.VPSIP+"\n"+
			"vps_port="+cfg.VPSPort+"\n"+
			"token="+cfg.Token+"\n"+
			"cf_token="+cfg.CFToken+"\n"+
			"domain="+cfg.Domain+"\n"+
			"ssh_user="+cfg.SSHUser+"\n"+
			"ssh_key="+cfg.SSHKey+"\n"+
			"catch_all="+catchAllVal+"\n",
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

func loadLocalMailboxes() []string {
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

func saveLocalMailboxes(list []string) {
	os.WriteFile(mailboxesFile, []byte(strings.Join(list, "\n")+"\n"), 0600)
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

func setupWizard(r *bufio.Reader, cfg *Config) {
	fmt.Println("=== First-time setup ===")
	fmt.Println()

	// Step 1: VPS server
	fmt.Println("Step 1: VPS server")
	cfg.VPSIP = promptLine(r, "  VPS IP address", cfg.VPSIP)
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
	fmt.Println("Step 2: Cloudflare DNS (optional but recommended)")
	fmt.Println("  This auto-configures MX, SPF and DMARC records and detects your domain.")
	fmt.Println("  Required token permissions: Zone > DNS > Edit, Zone > Zone > Read")
	fmt.Println("  Hint: use the 'Edit zone DNS' template, then add Zone:Read.")
	fmt.Println()
	openTok := promptLine(r, "  Open the Cloudflare token page in your browser now? (y/n)", "y")
	if strings.ToLower(openTok) == "y" {
		openURL("https://dash.cloudflare.com/profile/api-tokens")
	}
	cfg.CFToken = promptLine(r, "  Cloudflare API token (press Enter to skip)", cfg.CFToken)
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
	fmt.Println("  catch-all  - accept mail for any address (simpler, but flagged by validators)")
	fmt.Println("  list       - only accept mail for addresses you explicitly allow (recommended)")
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
		fmt.Printf("VPS: %s  Token: %s  Mode: ", cfg.VPSIP, cfg.Token)
		if cfg.CatchAll {
			fmt.Println("catch-all")
		} else {
			fmt.Println("list")
		}
		fmt.Println("Press Enter to continue, or type 'setup' to reconfigure.")
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

	// Update DNS if CF token provided
	if cfg.CFToken != "" {
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
	fmt.Print("Connecting to VPS... ")
	if err := ping(baseURL, cfg.Token); err != nil {
		fmt.Println("not reachable")
		if !firstRun {
			provisionVPS(r, &cfg)
			time.Sleep(2 * time.Second)
		}
		if err := ping(baseURL, cfg.Token); err != nil {
			fmt.Println()
			fmt.Println("The server is running but its port is not reachable from here.")
			fmt.Println("Open these inbound ports in your VPS provider's firewall:")
			fmt.Println("  TCP " + cfg.VPSPort + "  (quick-mail API)")
			fmt.Println("  TCP 25    (SMTP, to receive mail)")
			fmt.Println("Then run quick-mail again.")
			pause(r)
			return
		}
	}
	fmt.Println("ok")

	// Version check: auto-deploy the updated binary on mismatch.
	if v, err := checkServerVersion(baseURL); err == nil && v != serverVersion {
		fmt.Printf("Updating server (%s -> %s)...\n", v, serverVersion)
		if err3 := deployServer(cfg); err3 != nil {
			fmt.Println("Deploy error:", err3)
		} else {
			time.Sleep(2 * time.Second)
		}
	}

	// Push mailbox list to server
	if cfg.CatchAll {
		fmt.Print("Pushing catch-all mode to server... ")
		if err := pushMailboxes(baseURL, cfg.Token, []string{}); err != nil {
			fmt.Println("Warning:", err)
		} else {
			fmt.Println("ok")
		}
	} else {
		localList := loadLocalMailboxes()
		if firstRun && len(localList) == 0 {
			fmt.Println()
			fmt.Println("No mailboxes configured yet.")
			fmt.Println("Add addresses now (one per line, blank to finish):")
			for {
				addr := promptLine(r, "  Address", "")
				if addr == "" {
					break
				}
				addr = strings.ToLower(addr)
				localList = append(localList, addr)
			}
			if len(localList) > 0 {
				saveLocalMailboxes(localList)
			}
		}
		fmt.Printf("Pushing %d mailboxes to server... ", len(localList))
		if err := pushMailboxes(baseURL, cfg.Token, localList); err != nil {
			fmt.Println("Warning:", err)
		} else {
			fmt.Println("ok")
		}
	}

	fmt.Println()
	if cfg.CatchAll {
		fmt.Println("Mode: catch-all (accepting all addresses)")
	} else {
		fmt.Println("Mode: verified list")
		fmt.Println("Commands: add <email>  |  del <email>  |  list")
	}
	fmt.Println("Global commands: clear (delete all mail)  |  deploy (re-deploy server)  |  setup (re-provision VPS)  |  update (update client + server)")
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
				list := loadLocalMailboxes()
				for _, e := range list {
					if e == arg {
						fmt.Println("Already in list:", arg)
						goto nextCmd
					}
				}
				list = append(list, arg)
				saveLocalMailboxes(list)
				if err := pushMailboxes(baseURL, cfg.Token, list); err != nil {
					fmt.Println("Warning pushing to server:", err)
				}
				fmt.Println("Added:", arg)
			case "del":
				if cfg.CatchAll {
					fmt.Println("Not in list mode.")
					continue
				}
				if arg == "" {
					fmt.Println("Usage: del user@" + cfg.Domain)
					continue
				}
				arg = strings.ToLower(arg)
				list := loadLocalMailboxes()
				newList := list[:0]
				for _, e := range list {
					if e != arg {
						newList = append(newList, e)
					}
				}
				saveLocalMailboxes(newList)
				if err := pushMailboxes(baseURL, cfg.Token, newList); err != nil {
					fmt.Println("Warning pushing to server:", err)
				}
				fmt.Println("Removed:", arg)
			case "list":
				if cfg.CatchAll {
					fmt.Println("Catch-all mode: no allowlist.")
					continue
				}
				list := loadLocalMailboxes()
				if len(list) == 0 {
					fmt.Println("No mailboxes yet. Use: add user@" + cfg.Domain)
				} else {
					for _, e := range list {
						fmt.Println(" ", e)
					}
				}
			case "clear":
				if err := clearInbox(baseURL, cfg.Token); err != nil {
					fmt.Println("Error:", err)
				} else {
					fmt.Println("Inbox cleared.")
				}
			case "deploy":
				if err := deployServer(cfg); err != nil {
					fmt.Println("Deploy error:", err)
				}
			case "update":
				updateAll(cfg)
			case "init", "setup":
				provisionVPS(r, &cfg)
			}
		nextCmd:
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
	resp.Body.Close()
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
	resp, err := http.Get("https://api.github.com/repos/" + githubRepo + "/releases/latest")
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

	// Update and redeploy the server.
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
