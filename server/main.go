package main

import (
"bufio"
"crypto/tls"
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

type Email struct {
ID      int64    `json:"id"`
From    string   `json:"from"`
To      []string `json:"to"`
Subject string   `json:"subject"`
Body    string   `json:"body"`
Time    int64    `json:"time"`
}

const serverVersion = "2"

var (
mu        sync.RWMutex
store     []Email
nextID    int64 = 1
secret    string
tlsCfg    *tls.Config
mailboxes map[string]bool
hostname  string
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
write := func(s string) { rw.Write([]byte(s + "\r\n")) }

if !upgraded {
write("220 " + hostname + " ESMTP")
}

var from string
var to []string
var lines []string
collecting := false

for {
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
from = ""; to = nil; lines = nil
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
from = ""; to = nil; lines = nil
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
				if l == "" { inH = false; body = strings.Join(rawLines[i+1:], "\n"); break }
				if strings.HasPrefix(strings.ToUpper(l), "SUBJECT:") { subject = strings.TrimSpace(l[8:]) }
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
			if perr != nil { break }
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

func auth(r *http.Request) bool {
tok := r.Header.Get("X-Token")
if tok == "" {
tok = r.URL.Query().Get("token")
}
return tok == secret
}

func startHTTP() {
http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
fmt.Fprint(w, serverVersion)
})

http.HandleFunc("/mail", func(w http.ResponseWriter, r *http.Request) {
if !auth(r) {
w.WriteHeader(http.StatusUnauthorized)
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
		if !auth(r) {
			w.WriteHeader(http.StatusUnauthorized)
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
		case http.MethodPut:
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
	fmt.Println("HTTP API listening on :8080")
	http.ListenAndServe(":8080", nil)
}