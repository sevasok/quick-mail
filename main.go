package main

import (
"bufio"
"bytes"
"encoding/json"
"fmt"
"io"
"net/http"
"os"
"path/filepath"
"strings"
"time"

gossh "golang.org/x/crypto/ssh"
"golang.org/x/term"
)

const (
configFile    = "sokolabs-mail.cfg"
mailboxesFile = "mailboxes.txt"
cfAPI         = "https://api.cloudflare.com/client/v4"
serverVersion = "2"
)

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
cfg := Config{VPSPort: "8080", CatchAll: true, Domain: "sokolabs.net", SSHUser: "admin", SSHKey: filepath.Join(home, ".ssh", "id_ed25519")}
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
resp, err := http.DefaultClient.Do(req)
if err != nil {
return err
}
resp.Body.Close()
return nil
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

func openURL(url string) {
// best-effort; ignore errors
for _, cmd := range [][]string{
{"cmd", "/c", "start", url},
{"xdg-open", url},
{"open", url},
} {
if _, err := os.Stat("/proc"); err == nil && cmd[0] == "cmd" {
continue
}
_ = cmd
}
// on Windows just print it
}

func setupWizard(r *bufio.Reader, cfg *Config) {
fmt.Println("=== First-time setup ===")
fmt.Println()

// Step 1: VPS server
fmt.Println("Step 1: VPS server")
cfg.VPSIP = promptLine(r, "  VPS IP address", cfg.VPSIP)
if cfg.Token == "" {
cfg.Token = "mysecrettoken"
}
cfg.Token = promptLine(r, "  Shared token (set as TOKEN= when starting server)", cfg.Token)
fmt.Println()

// Deploy and init
if _, err := os.Stat("sokolabs-server"); err == nil {
fmt.Println("  Found sokolabs-server binary in current directory.")
fmt.Println()
fmt.Println("  1) Init VPS (SSH with password - sets up setcap + optional systemd service)")
fmt.Println("  2) Deploy binary only (SSH with key - assumes init already done)")
fmt.Println("  3) Skip")
choice := promptLine(r, "  Choice", "1")
switch strings.TrimSpace(choice) {
case "1":
cfg.SSHUser = promptLine(r, "  SSH user", cfg.SSHUser)
cfg.SSHKey = promptLine(r, "  SSH key path (for future deploys)", cfg.SSHKey)
initVPS(r, cfg)
fmt.Print("  Deploying server binary... ")
if err := deployServer(*cfg); err != nil {
fmt.Println("Error:", err)
} else {
fmt.Println("ok")
}
case "2":
cfg.SSHUser = promptLine(r, "  SSH user", cfg.SSHUser)
cfg.SSHKey = promptLine(r, "  SSH key path", cfg.SSHKey)
fmt.Println()
if err := deployServer(*cfg); err != nil {
fmt.Println("  Deploy error:", err)
} else {
fmt.Println("  Server deployed successfully.")
}
}
fmt.Println()
}

// Step 2: Cloudflare DNS
fmt.Println("Step 2: Cloudflare DNS (optional but recommended)")
fmt.Println("  This auto-configures MX, SPF and DMARC records and detects your domain.")
fmt.Println("  Create a token at: https://dash.cloudflare.com/profile/api-tokens")
fmt.Println("  Required permissions: Zone > DNS > Edit, Zone > Zone > Read")
fmt.Println("  Hint: use the 'Edit zone DNS' template, then add Zone:Read.")
fmt.Println()
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

fmt.Println("sokolabs.net Mail Receiver")
fmt.Println()

firstRun := isFirstRun(cfg)
if firstRun {
setupWizard(r, &cfg)
} else {
// Quick re-confirm with ability to change
fmt.Printf("VPS: %s  Token: %s  Mode: ", cfg.VPSIP, cfg.Token)
if cfg.CatchAll { fmt.Println("catch-all") } else { fmt.Println("list") }
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

// Check connectivity
fmt.Print("Connecting to VPS... ")
if err := ping(baseURL, cfg.Token); err != nil {
fmt.Println("FAILED")
fmt.Println()
fmt.Println("Cannot reach the server. Make sure it is running:")
fmt.Println("  chmod +x ./sokolabs-server")
fmt.Println("  sudo setcap 'cap_net_bind_service=+ep' ./sokolabs-server")
fmt.Println("  TOKEN=" + cfg.Token + " nohup ./sokolabs-server >> mailserver.log 2>&1 &")
fmt.Println()
if _, err2 := os.Stat("sokolabs-server"); err2 == nil {
fmt.Print("Deploy sokolabs-server to VPS now? (y/n): ")
yn, _ := r.ReadString('\n')
if strings.ToLower(strings.TrimSpace(yn)) == "y" {
if err3 := deployServer(cfg); err3 != nil {
fmt.Println("Deploy error:", err3)
}
}
}
pause(r)
return
}
fmt.Println("ok")

// Version check
if v, err := checkServerVersion(baseURL); err == nil && v != serverVersion {
fmt.Printf("Warning: server version %q, client expects %q\n", v, serverVersion)
if _, err2 := os.Stat("sokolabs-server"); err2 == nil {
fmt.Print("Deploy updated server now? (y/n): ")
yn, _ := r.ReadString('\n')
if strings.ToLower(strings.TrimSpace(yn)) == "y" {
if err3 := deployServer(cfg); err3 != nil {
fmt.Println("Deploy error:", err3)
} else {
time.Sleep(2 * time.Second)
}
}
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
fmt.Println("Global commands: clear (delete all mail)  |  deploy (re-deploy server binary)  |  init (SSH init/setup VPS)")
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
if cfg.CatchAll { fmt.Println("Not in list mode. Re-run and choose 'list' mode."); continue }
if arg == "" { fmt.Println("Usage: add email@sokolabs.net"); continue }
arg = strings.ToLower(arg)
list := loadLocalMailboxes()
for _, e := range list {
if e == arg { fmt.Println("Already in list:", arg); goto nextCmd }
}
list = append(list, arg)
saveLocalMailboxes(list)
if err := pushMailboxes(baseURL, cfg.Token, list); err != nil {
fmt.Println("Warning pushing to server:", err)
}
fmt.Println("Added:", arg)
case "del":
if cfg.CatchAll { fmt.Println("Not in list mode."); continue }
if arg == "" { fmt.Println("Usage: del email@sokolabs.net"); continue }
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
if cfg.CatchAll { fmt.Println("Catch-all mode: no allowlist."); continue }
list := loadLocalMailboxes()
if len(list) == 0 {
fmt.Println("No mailboxes yet. Use 'add email@sokolabs.net'.")
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
case "init":
initVPS(r, &cfg)
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
resp, err := http.Get(url)
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

// sshSudoRun runs cmd via "sudo -S cmd" using sudoPass for authentication.
func sshSudoRun(client *gossh.Client, cmd, sudoPass string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(sudoPass + "\n")
	out, err := sess.CombinedOutput("sudo -S " + cmd)
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
		// key has a passphrase
		if sshPassCache == "" {
			sshPassCache = readPassword("SSH key passphrase")
		}
		signer, err = gossh.ParsePrivateKeyWithPassphrase(keyData, []byte(sshPassCache))
		if err != nil {
			sshPassCache = ""
			return nil, fmt.Errorf("parse SSH key: %w", err)
		}
	}
	return sshDial(cfg.VPSIP, cfg.SSHUser, []gossh.AuthMethod{gossh.PublicKeys(signer)})
}

func clearInbox(baseURL, token string) error {
	req, err := http.NewRequest(http.MethodDelete, baseURL+"/mail?token="+token, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func checkServerVersion(baseURL string) (string, error) {
	resp, err := http.Get(baseURL + "/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), nil
}

func initVPS(r *bufio.Reader, cfg *Config) {
	fmt.Println()
	fmt.Println("=== VPS Init ===")
	fmt.Println("Connects to your VPS with a password and sets up:")
	fmt.Println("  - Passwordless sudo for setcap (lets the server bind port 25)")
	fmt.Println("  - Systemd service for auto-start on reboot (optional)")
	fmt.Println()

	cfg.SSHUser = promptLine(r, "SSH user", cfg.SSHUser)
	pass := readPassword("SSH/sudo password")

	fmt.Print("Connecting... ")
	client, err := sshDial(cfg.VPSIP, cfg.SSHUser, []gossh.AuthMethod{gossh.Password(pass)})
	if err != nil {
		fmt.Println("FAILED:", err)
		return
	}
	defer client.Close()
	fmt.Println("ok")

	// Sudoers rule: write to /tmp (no sudo), then move into place with sudo
	fmt.Print("Setting up setcap permissions... ")
	if err := sshRunIn(client, "cat > /tmp/sokolabs-setcap",
		"admin ALL=(ALL) NOPASSWD: /usr/sbin/setcap\n"); err != nil {
		fmt.Println("Warning (write tmp):", err)
	} else {
		out, err := sshSudoRun(client,
			"sh -c 'mv /tmp/sokolabs-setcap /etc/sudoers.d/sokolabs-setcap && chmod 440 /etc/sudoers.d/sokolabs-setcap'",
			pass)
		if err != nil {
			fmt.Printf("Warning: %v", err)
			if out != "" {
				fmt.Printf(" (%s)", out)
			}
			fmt.Println()
		} else {
			fmt.Println("ok")
		}
	}

	// Systemd service
	doSvc := promptLine(r, "Install systemd service for auto-start on reboot? (y/n)", "y")
	if strings.ToLower(doSvc) == "y" {
		fmt.Print("Installing systemd service... ")
		svc := "[Unit]\nDescription=Sokolabs Mail Server\nAfter=network.target\n\n" +
			"[Service]\nType=simple\nUser=admin\nWorkingDirectory=/home/admin\n" +
			"Environment=TOKEN=" + cfg.Token + "\n" +
			"ExecStart=/home/admin/sokolabs-server\nRestart=always\nRestartSec=5\n\n" +
			"[Install]\nWantedBy=multi-user.target\n"

		// Write service file to /tmp (no sudo needed)
		if err := sshRunIn(client, "cat > /tmp/sokolabs-server.service", svc); err != nil {
			fmt.Println("Warning (write tmp):", err)
		} else {
			out, err := sshSudoRun(client,
				"sh -c 'mv /tmp/sokolabs-server.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable sokolabs-server'",
				pass)
			if err != nil {
				fmt.Printf("Warning: %v", err)
				if out != "" {
					fmt.Printf(" (%s)", out)
				}
				fmt.Println()
			} else {
				fmt.Println("ok")
			}
		}
	}

	fmt.Println()
	fmt.Println("Init complete. Use 'deploy' to push the server binary.")
}

func deployServer(cfg Config) error {
	const remoteBin = "/home/admin/sokolabs-server"
	const remoteTmp = "/home/admin/sokolabs-server2"

	if _, err := os.Stat("sokolabs-server"); err != nil {
		return fmt.Errorf("sokolabs-server binary not found in current directory")
	}

	client, err := sshConnectCfg(cfg)
	if err != nil {
		return fmt.Errorf("SSH connect: %w", err)
	}
	defer client.Close()

	fmt.Print("  Uploading binary... ")
	if err := sshUpload(client, "sokolabs-server", remoteTmp); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	fmt.Println("ok")

	fmt.Print("  Restarting server... ")
	remote := fmt.Sprintf(
		"pkill sokolabs-server 2>/dev/null; sleep 1;"+
			" chmod +x %s; mv %s %s;"+
			" sudo setcap 'cap_net_bind_service=+ep' %s 2>/dev/null && echo '[setcap ok]' || echo '[setcap failed - run sudo setcap in Webdock terminal if port 25 breaks]';"+
			" cd /home/admin && TOKEN=%s nohup ./sokolabs-server >> mailserver.log 2>&1 & sleep 2; pgrep -a sokolabs-server",
		remoteTmp, remoteTmp, remoteBin, remoteBin, cfg.Token,
	)
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