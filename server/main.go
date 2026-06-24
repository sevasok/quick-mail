package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const serverVersion = "5"

// adminTokenMinLen is the minimum length for a token to qualify as the admin
// (owner) token. Guest tokens are deliberately shorter, so a guest token can
// never be mistaken for the admin token (length + identity are both checked).
const adminTokenMinLen = 16

type Email struct {
	ID      int64    `json:"id"`
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Body    string   `json:"body"`
	Time    int64    `json:"time"`
}

var (
	mu          sync.RWMutex
	store       []Email
	nextID      int64 = 1
	secret      string
	tlsCfg      *tls.Config
	mailboxes   map[string]bool
	guestTokens map[string]string // guest token -> name (non-admin)
	hostname    string
)

func loadMailboxes() {
	mailboxes = map[string]bool{}
	data, err := os.ReadFile("mailboxes.txt")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.ToLower(line))
		if line != "" && !strings.HasPrefix(line, "#") {
			mailboxes[line] = true
		}
	}
	fmt.Printf("Loaded %d mailboxes\n", len(mailboxes))
}

func saveMailboxes(m map[string]bool) {
	lines := make([]string, 0, len(m))
	for k := range m {
		lines = append(lines, k)
	}
	os.WriteFile("mailboxes.txt", []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func loadGuestTokens() {
	guestTokens = map[string]string{}
	data, err := os.ReadFile("guests.txt")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		name := ""
		if len(parts) == 2 {
			name = parts[1]
		}
		guestTokens[parts[0]] = name
	}
	fmt.Printf("Loaded %d guest tokens\n", len(guestTokens))
}

func saveGuestTokens() {
	var b strings.Builder
	for tok, name := range guestTokens {
		b.WriteString(tok + " " + name + "\n")
	}
	os.WriteFile("guests.txt", []byte(b.String()), 0600)
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func main() {
	secret = os.Getenv("TOKEN")
	if secret == "" {
		secret = "changeme"
		fmt.Println("Warning: TOKEN not set, using 'changeme'")
	}

	// Hostname for SMTP banner: HOSTNAME env > system hostname
	hostname = os.Getenv("HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		hostname = "localhost"
	}
	fmt.Println("SMTP hostname:", hostname)

	// TLS: check ./fullchain.pem first, then scan /etc/letsencrypt/live/, then snakeoil
	tlsCandidates := []struct{ cert, key string }{
		{"./fullchain.pem", "./privkey.pem"},
	}
	if entries, err := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem"); err == nil {
		for _, cert := range entries {
			dir := filepath.Dir(cert)
			tlsCandidates = append(tlsCandidates, struct{ cert, key string }{
				cert, filepath.Join(dir, "privkey.pem"),
			})
		}
	}
	tlsCandidates = append(tlsCandidates, struct{ cert, key string }{
		"/etc/ssl/certs/ssl-cert-snakeoil.pem",
		"/etc/ssl/private/ssl-cert-snakeoil.key",
	})
	for _, p := range tlsCandidates {
		cert, err := tls.LoadX509KeyPair(p.cert, p.key)
		if err == nil {
			tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
			fmt.Println("TLS loaded from:", p.cert)
			break
		}
	}
	if tlsCfg == nil {
		fmt.Println("Warning: no TLS cert found, STARTTLS unavailable")
	}

	go startSMTP()
	loadMailboxes()
	loadGuestTokens()
	startHTTP()
}

func startSMTP() {
	ln, err := net.Listen("tcp", ":25")
	if err != nil {
		fmt.Fprintln(os.Stderr, "SMTP listen error:", err)
		os.Exit(1)
	}
	fmt.Println("SMTP listening on :25")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSMTP(conn)
	}
}

func handleSMTP(conn net.Conn) {
	defer conn.Close()
	doSession(conn, false)
}

func doSession(rw net.Conn, upgraded bool) {
	r := bufio.NewReader(rw)
	write := func(s string) {
		rw.SetWriteDeadline(time.Now().Add(30 * time.Second))
		rw.Write([]byte(s + "\r\n"))
	}

	if !upgraded {
		write("220 " + hostname + " ESMTP")
	}

	var from string
	var to []string
	var lines []string
	collecting := false

	for {
		// Refresh the deadline on each command so a stalled peer cannot hold the
		// connection (and its goroutine) open indefinitely under concurrent load.
		rw.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)

		if collecting {
			if line == "." {
				collecting = false
				saveEmail(from, to, lines)
				write("250 OK")
				from = ""
				to = nil
				lines = nil
			} else {
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				lines = append(lines, line)
			}
			continue
		}

		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			write("250-" + hostname)
			write("250-8BITMIME")
			write("250-PIPELINING")
			write("250-SIZE 52428800")
			if tlsCfg != nil && !upgraded {
				write("250 STARTTLS")
			} else {
				write("250 OK")
			}
		case up == "STARTTLS":
			if tlsCfg == nil {
				write("454 TLS not available")
				continue
			}
			write("220 Ready to start TLS")
			tlsConn := tls.Server(rw, tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			doSession(tlsConn, true)
			return
		case strings.HasPrefix(up, "MAIL FROM:"):
			from = extractAddr(line[10:])
			write("250 OK")
		case strings.HasPrefix(up, "RCPT TO:"):
			addr := strings.ToLower(extractAddr(line[8:]))
			if len(mailboxes) > 0 && !mailboxes[addr] {
				write("550 5.1.1 User unknown")
				continue
			}
			to = append(to, addr)
			write("250 OK")
		case up == "DATA":
			write("354 End with <CRLF>.<CRLF>")
			collecting = true
			lines = nil
		case up == "RSET":
			from = ""
			to = nil
			lines = nil
			write("250 OK")
		case up == "NOOP":
			write("250 OK")
		case strings.HasPrefix(up, "AUTH"):
			write("235 Authentication successful")
		case strings.HasPrefix(up, "QUIT"):
			write("221 Bye")
			return
		default:
			write("502 Command not implemented")
		}
	}
}

func extractAddr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s, ">"); j > i {
			return s[i+1 : j]
		}
	}
	return s
}

func parseEmailBody(rawLines []string) (subject, body string) {
	raw := strings.Join(rawLines, "\r\n")
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		// fallback: scan headers manually
		inH := true
		for i, l := range rawLines {
			if inH {
				if l == "" {
					inH = false
					body = strings.Join(rawLines[i+1:], "\n")
					break
				}
				if strings.HasPrefix(strings.ToUpper(l), "SUBJECT:") {
					subject = strings.TrimSpace(l[8:])
				}
			}
		}
		return
	}
	dec := new(mime.WordDecoder)
	subject, _ = dec.DecodeHeader(msg.Header.Get("Subject"))
	ct := msg.Header.Get("Content-Type")
	mediaType, params, merr := mime.ParseMediaType(ct)
	if merr != nil {
		b, _ := io.ReadAll(msg.Body)
		body = string(b)
		return
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, perr := mr.NextPart()
			if perr != nil {
				break
			}
			pmt, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
			if pmt == "text/plain" {
				var b []byte
				if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
					b, _ = io.ReadAll(quotedprintable.NewReader(p))
				} else {
					b, _ = io.ReadAll(p)
				}
				body = string(b)
				break
			}
		}
	} else {
		var b []byte
		if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
			b, _ = io.ReadAll(quotedprintable.NewReader(msg.Body))
		} else {
			b, _ = io.ReadAll(msg.Body)
		}
		body = string(b)
	}
	return
}

func saveEmail(from string, to []string, rawLines []string) {
	subject, body := parseEmailBody(rawLines)

	mu.Lock()
	e := Email{
		ID:      nextID,
		From:    from,
		To:      to,
		Subject: subject,
		Body:    strings.TrimSpace(body),
		Time:    time.Now().Unix(),
	}
	nextID++
	store = append(store, e)
	mu.Unlock()
	fmt.Printf("[%s] from=%s subject=%q\n", time.Now().Format("15:04:05"), from, subject)
}

func tokenOf(r *http.Request) string {
	tok := r.Header.Get("X-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return tok
}

// isAdminToken reports whether tok is the owner/admin token. Both the length
// and identity must match, so a (shorter) guest token is never treated as admin.
func isAdminToken(tok string) bool {
	return len(tok) >= adminTokenMinLen && tok == secret
}

// authAdmin accepts only the admin token (for guest-token management).
func authAdmin(r *http.Request) bool {
	return isAdminToken(tokenOf(r))
}

// guestRateLimit is the maximum number of requests a single guest token may
// make per second.
const guestRateLimit = 5

type rateCounter struct {
	windowStart time.Time
	count       int
}

var (
	guestRate   = map[string]*rateCounter{}
	guestRateMu sync.Mutex
)

// guestAllowed reports whether a guest token is within its per-second budget,
// counting this request if so. Uses a simple fixed 1-second window per token.
func guestAllowed(tok string) bool {
	guestRateMu.Lock()
	defer guestRateMu.Unlock()
	now := time.Now()
	rc := guestRate[tok]
	if rc == nil || now.Sub(rc.windowStart) >= time.Second {
		guestRate[tok] = &rateCounter{windowStart: now, count: 1}
		return true
	}
	if rc.count >= guestRateLimit {
		return false
	}
	rc.count++
	return true
}

// authWithRate authorizes a request and applies the guest rate limit. It writes
// the proper status (401 unauthorized or 429 too many requests) and returns
// false when the request should not proceed. Admins are never rate limited.
func authWithRate(w http.ResponseWriter, r *http.Request) bool {
	tok := tokenOf(r)
	if isAdminToken(tok) {
		return true
	}
	if tok == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	mu.RLock()
	_, ok := guestTokens[tok]
	mu.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	if !guestAllowed(tok) {
		w.WriteHeader(http.StatusTooManyRequests)
		return false
	}
	return true
}

func startHTTP() {
	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, serverVersion)
	})

	http.HandleFunc("/mail", func(w http.ResponseWriter, r *http.Request) {
		if !authWithRate(w, r) {
			return
		}
		switch r.Method {
		case http.MethodDelete:
			mu.Lock()
			store = store[:0]
			mu.Unlock()
			fmt.Fprint(w, "ok")
			fmt.Println("Inbox cleared")
		case http.MethodGet:
			after := int64(0)
			fmt.Sscan(r.URL.Query().Get("after"), &after)
			mu.RLock()
			defer mu.RUnlock()
			var out []Email
			for _, e := range store {
				if e.ID > after {
					out = append(out, e)
				}
			}
			if out == nil {
				out = []Email{}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		}
	})
	http.HandleFunc("/mailboxes", func(w http.ResponseWriter, r *http.Request) {
		if !authWithRate(w, r) {
			return
		}
		switch r.Method {
		case http.MethodGet:
			mu.RLock()
			list := make([]string, 0, len(mailboxes))
			for k := range mailboxes {
				list = append(list, k)
			}
			mu.RUnlock()
			json.NewEncoder(w).Encode(list)
		case http.MethodPost:
			// Incremental, merge-based change so concurrent clients never clobber
			// the shared list. op=add adds one address; op=del removes one. The
			// updated authoritative list is returned as JSON.
			op := r.URL.Query().Get("op")
			addr := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("addr")))
			if addr == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			if mailboxes == nil {
				mailboxes = map[string]bool{}
			}
			switch op {
			case "add":
				mailboxes[addr] = true
			case "del":
				delete(mailboxes, addr)
			default:
				mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			list := make([]string, 0, len(mailboxes))
			for k := range mailboxes {
				list = append(list, k)
			}
			saveMailboxes(mailboxes)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
			fmt.Printf("Mailbox %s: %s (now %d)\n", op, addr, len(list))
		case http.MethodPut:
			// Full-list replace is how mode is set (catch-all pushes an empty
			// list). Admin only: guests must not be able to change the mode.
			if !authAdmin(r) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// Client pushes the full authoritative list; replaces server state entirely.
			var list []string
			if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			m := map[string]bool{}
			for _, addr := range list {
				addr = strings.ToLower(strings.TrimSpace(addr))
				if addr != "" {
					m[addr] = true
				}
			}
			mu.Lock()
			mailboxes = m
			saveMailboxes(m)
			mu.Unlock()
			fmt.Fprintf(w, "ok, %d mailboxes", len(m))
			fmt.Printf("Mailboxes replaced: %d entries\n", len(m))
		}
	})
	// Guest-token management. Admin-only: only the owner (long admin token) may
	// create, list or revoke guest tokens.
	http.HandleFunc("/guests", func(w http.ResponseWriter, r *http.Request) {
		if !authAdmin(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		type guest struct {
			Name  string `json:"name"`
			Token string `json:"token"`
		}
		switch r.Method {
		case http.MethodGet:
			mu.RLock()
			out := make([]guest, 0, len(guestTokens))
			for tok, name := range guestTokens {
				out = append(out, guest{Name: name, Token: tok})
			}
			mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
		case http.MethodPost:
			name := strings.TrimSpace(r.URL.Query().Get("name"))
			if name == "" {
				name = "guest"
			}
			// Guest tokens are short (8 hex chars) and tagged non-admin by being
			// stored in guestTokens, so they can never pass the admin check.
			tok := randomHex(4)
			if tok == "" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			if guestTokens == nil {
				guestTokens = map[string]string{}
			}
			guestTokens[tok] = name
			saveGuestTokens()
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(guest{Name: name, Token: tok})
			fmt.Printf("Guest token created: %s (%s)\n", name, tok)
		case http.MethodDelete:
			if r.URL.Query().Get("all") == "1" {
				mu.Lock()
				n := len(guestTokens)
				guestTokens = map[string]string{}
				saveGuestTokens()
				mu.Unlock()
				fmt.Fprintf(w, "revoked %d", n)
				fmt.Printf("All guest tokens revoked (%d)\n", n)
				return
			}
			which := strings.TrimSpace(r.URL.Query().Get("revoke"))
			if which == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			if _, ok := guestTokens[which]; ok {
				delete(guestTokens, which)
			} else {
				for tok, name := range guestTokens {
					if name == which {
						delete(guestTokens, tok)
					}
				}
			}
			saveGuestTokens()
			mu.Unlock()
			fmt.Fprint(w, "ok")
			fmt.Printf("Guest token revoked: %s\n", which)
		}
	})
	fmt.Println("HTTP API listening on :8080")
	// Explicit timeouts keep many concurrent clients (polling and pushing at the
	// same time) from exhausting sockets via slow or stuck connections.
	srv := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	srv.ListenAndServe()
}
