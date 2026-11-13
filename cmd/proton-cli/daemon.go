package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// The daemon holds the unlocked keyrings in memory (the Bridge model) so
// decrypt commands stop asking for the account password on every run.
// It listens on a Unix socket (same-user only) for decrypt requests and
// serves a read-only ICS feed over HTTP on localhost. Nothing decrypted
// is ever written to disk; when the daemon exits the keyrings are gone
// and the user must start it again (re-enter the account password).
//
// Security trade-off, accepted by design: any process running as the
// same user can talk to the daemon over its socket and ask it to
// decrypt. This is the same gap ssh-agent, gpg-agent and Proton Bridge
// itself have. The socket is 0600 in the user's config directory and
// there is no network listener other than the localhost-only ICS feed.

const (
	// defaultICSPort is the HTTP port for the read-only ICS feed.
	defaultICSPort = 8765
	// defaultICSDaysPast / defaultICSDaysFuture bound the ICS feed window.
	defaultICSDaysPast   = 30
	defaultICSDaysFuture = 365
)

// daemonSocketPathOverride, when non-empty, replaces the daemon socket
// path. Tests set it to a temp-dir socket; production never sets it.
var daemonSocketPathOverride string

// daemonSocketPath returns the Unix socket path for the daemon, in the
// same config directory as the session file.
func daemonSocketPath() (string, error) {
	if daemonSocketPathOverride != "" {
		return daemonSocketPathOverride, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "proton-cli", "daemon.sock"), nil
}

// daemonRequest is one JSON request over the Unix socket (one request per
// connection; no persistent connection state).
type daemonRequest struct {
	Op         string                `json:"op"`
	CalendarID string                `json:"calendar_id,omitempty"`
	Body       string                `json:"body,omitempty"`       // armored PGP body (mail)
	KeyPacket  string                `json:"key_packet,omitempty"` // base64 (attachment)
	Data       string                `json:"data,omitempty"`       // base64 (attachment data)
	Event      *proton.CalendarEvent `json:"event,omitempty"`      // calendar event
}

// daemonResponse is one JSON response over the Unix socket. Body is
// base64-encoded plaintext (mail body / attachment data).
type daemonResponse struct {
	OK          bool   `json:"ok"`
	Running     bool   `json:"running,omitempty"`
	ICSPort     int    `json:"ics_port,omitempty"`
	Body        string `json:"body,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
	Error       string `json:"error,omitempty"`
}

// errDaemonUnavailable reports that no daemon answered the socket, so
// the caller should fall back to prompting for the account password.
var errDaemonUnavailable = errors.New("proton-cli daemon is not running")

// daemonDial connects to the daemon socket with a short timeout.
func daemonDial() (net.Conn, error) {
	p, err := daemonSocketPath()
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("unix", p)
	if err != nil {
		return nil, errDaemonUnavailable
	}
	return conn, nil
}

// daemonRoundTrip sends one request and reads one response. A deadline
// keeps a hung daemon from hanging the CLI.
func daemonRoundTrip(req daemonRequest) (daemonResponse, error) {
	conn, err := daemonDial()
	if err != nil {
		return daemonResponse{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return daemonResponse{}, errDaemonUnavailable
	}
	var resp daemonResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return daemonResponse{}, errDaemonUnavailable
	}
	return resp, nil
}

// pingDaemon reports whether a daemon is running and its ICS port.
// It returns running=false (not an error) when no daemon answers.
func pingDaemon() (running bool, icsPort int) {
	resp, err := daemonRoundTrip(daemonRequest{Op: "ping"})
	if err != nil || !resp.OK {
		return false, 0
	}
	return resp.Running, resp.ICSPort
}

// daemonDecryptMailBody decrypts an armored mail body via the daemon.
func daemonDecryptMailBody(body string) ([]byte, error) {
	resp, err := daemonRoundTrip(daemonRequest{Op: "decrypt_mail_body", Body: body})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("daemon decrypt: %s", resp.Error)
	}
	return base64.StdEncoding.DecodeString(resp.Body)
}

// daemonDecryptAttachment decrypts an attachment data packet via the
// daemon. keyPacket is the attachment's base64 key packet.
func daemonDecryptAttachment(keyPacket string, data []byte) ([]byte, error) {
	resp, err := daemonRoundTrip(daemonRequest{
		Op:        "decrypt_attachment",
		KeyPacket: keyPacket,
		Data:      base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("daemon decrypt: %s", resp.Error)
	}
	return base64.StdEncoding.DecodeString(resp.Body)
}

// daemonDecryptEvent decrypts one calendar event via the daemon.
func daemonDecryptEvent(calendarID string, ev *proton.CalendarEvent) (summary, location, description string, err error) {
	resp, err := daemonRoundTrip(daemonRequest{Op: "decrypt_event", CalendarID: calendarID, Event: ev})
	if err != nil {
		return "", "", "", err
	}
	if !resp.OK {
		return "", "", "", fmt.Errorf("daemon decrypt: %s", resp.Error)
	}
	return resp.Summary, resp.Location, resp.Description, nil
}

// daemon holds the unlocked keyrings in memory and serves decrypt
// requests over a Unix socket plus an ICS feed over HTTP on localhost.
type daemon struct {
	addrKR *crypto.KeyRing

	// calKR caches the unlocked calendar keyring per calendar ID,
	// unlocked on first use from the held address keyring.
	calKR map[string]*crypto.KeyRing
	calMu sync.Mutex

	client *proton.Client
	mgr    *proton.Manager

	icsPort       int
	icsPastDays   int
	icsFutureDays int

	listener net.Listener
	httpSrv  *http.Server

	done     chan struct{}
	shutdown sync.Once
}

// stop signals the daemon to shut down. It is safe to call twice.
func (d *daemon) stop() {
	d.shutdown.Do(func() { close(d.done) })
}

// calendarKeyring returns the unlocked calendar keyring for calendarID,
// unlocking (and caching) it on first use via the held address keyring.
func (d *daemon) calendarKeyring(ctx context.Context, calendarID string) (*crypto.KeyRing, error) {
	d.calMu.Lock()
	defer d.calMu.Unlock()
	if kr, ok := d.calKR[calendarID]; ok {
		return kr, nil
	}
	kr, err := d.unlockCalendarKeyring(ctx, calendarID)
	if err != nil {
		return nil, err
	}
	d.calKR[calendarID] = kr
	return kr, nil
}

// unlockCalendarKeyring unlocks one calendar's keys with the held address
// keyring. It mirrors the calendar unlock in cmdEvents (members,
// passphrase, keys); the only difference is the address keyring is
// already held instead of being unlocked from a fresh password prompt.
func (d *daemon) unlockCalendarKeyring(ctx context.Context, calendarID string) (*crypto.KeyRing, error) {
	members, err := d.client.GetCalendarMembers(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar members: %w", err)
	}
	addrs, err := d.client.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	var memberID string
	for _, member := range members {
		for _, addr := range addrs {
			if strings.EqualFold(addr.Email, member.Email) {
				memberID = member.ID
				break
			}
		}
		if memberID != "" {
			break
		}
	}
	if memberID == "" {
		return nil, fmt.Errorf("no calendar member matches a user address")
	}

	passphrase, err := d.client.GetCalendarPassphrase(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar passphrase: %w", err)
	}
	rawPass, err := passphrase.Decrypt(memberID, d.addrKR)
	if err != nil {
		return nil, fmt.Errorf("decrypt calendar passphrase: %w", err)
	}
	defer zero(rawPass)

	keys, err := d.client.GetCalendarKeys(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar keys: %w", err)
	}
	calKR, err := keys.Unlock(rawPass)
	if err != nil {
		return nil, fmt.Errorf("unlock calendar keys: %w", err)
	}
	if calKR.CountDecryptionEntities() == 0 {
		return nil, fmt.Errorf("unlock calendar keys: no calendar keys could be unlocked")
	}
	return calKR, nil
}

// handleRequest serves one daemon request. The second return value
// reports whether the daemon should shut down after replying.
func (d *daemon) handleRequest(ctx context.Context, req daemonRequest) (daemonResponse, bool) {
	switch req.Op {
	case "ping":
		return daemonResponse{OK: true, Running: true, ICSPort: d.icsPort}, false
	case "stop":
		return daemonResponse{OK: true}, true
	case "decrypt_mail_body":
		enc, err := crypto.NewPGPMessageFromArmored(req.Body)
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("parse armored body: %v", err)}, false
		}
		dec, err := d.addrKR.Decrypt(enc, nil, crypto.GetUnixTime())
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("decrypt body: %v", err)}, false
		}
		return daemonResponse{OK: true, Body: base64.StdEncoding.EncodeToString(dec.GetBinary())}, false
	case "decrypt_attachment":
		keyPacket := decodeKeyPacket(req.KeyPacket)
		if len(keyPacket) == 0 {
			return daemonResponse{Error: "empty or invalid key packet"}, false
		}
		data, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("decode data: %v", err)}, false
		}
		split := crypto.NewPGPSplitMessage(keyPacket, data)
		dec, err := d.addrKR.Decrypt(split.GetPGPMessage(), nil, crypto.GetUnixTime())
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("decrypt attachment: %v", err)}, false
		}
		return daemonResponse{OK: true, Body: base64.StdEncoding.EncodeToString(dec.GetBinary())}, false
	case "decrypt_event":
		if req.Event == nil {
			return daemonResponse{Error: "missing event"}, false
		}
		calKR, err := d.calendarKeyring(ctx, req.CalendarID)
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("unlock calendar keys: %v", err)}, false
		}
		summary, location, description, err := decryptEventDetails(req.Event, calKR, d.addrKR)
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("decrypt event: %v", err)}, false
		}
		return daemonResponse{OK: true, Summary: summary, Location: location, Description: description}, false
	default:
		return daemonResponse{Error: fmt.Sprintf("unknown op %q", req.Op)}, false
	}
}

// handleConn serves one socket connection (one request, one response).
func (d *daemon) handleConn(conn net.Conn) {
	defer conn.Close()
	var req daemonRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	resp, shutdown := d.handleRequest(context.Background(), req)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		return
	}
	if shutdown {
		d.stop()
	}
}

// serveSocket accepts connections until the listener is closed, either
// by shutdown (d.done, e.g. a `daemon stop` request) or directly.
func (d *daemon) serveSocket() {
	go func() {
		<-d.done
		d.listener.Close()
	}()
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			// Listener closed on shutdown.
			return
		}
		go d.handleConn(conn)
	}
}

// buildICSFeed fetches every calendar's events in the feed window and
// decrypts them with the held keyrings. It fetches fresh on every call,
// so a subscribing calendar sees current data on its next poll. A fetch
// failure is an error (the handler serves 503, never a stale feed); an
// individual event that fails to decrypt is skipped, not fatal.
func (d *daemon) buildICSFeed(ctx context.Context) (string, error) {
	cals, err := d.client.GetCalendars(ctx)
	if err != nil {
		return "", fmt.Errorf("list calendars: %w", err)
	}
	now := time.Now()
	from := now.AddDate(0, 0, -d.icsPastDays)
	to := now.AddDate(0, 0, d.icsFutureDays)
	filter := url.Values{
		"Begin": []string{strconv.FormatInt(from.Unix(), 10)},
		"End":   []string{strconv.FormatInt(to.Unix(), 10)},
	}
	var events []icsEvent
	for _, cal := range cals {
		first, err := d.client.GetCalendarEvents(ctx, cal.ID, 0, calendarPageSize, filter)
		if err != nil {
			return "", fmt.Errorf("list events for calendar %s: %w", cal.ID, err)
		}
		evs, err := listCalendarEvents(ctx, d.client, cal.ID, filter, first)
		if err != nil {
			return "", fmt.Errorf("list events for calendar %s: %w", cal.ID, err)
		}
		calKR, err := d.calendarKeyring(ctx, cal.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "daemon: calendar %s: %v (skipped)\n", cal.ID, err)
			continue
		}
		for _, ev := range evs {
			// The server may ignore Begin/End; filter locally too.
			if ev.StartTime < to.Unix() && ev.EndTime > from.Unix() {
				summary, location, description, err := decryptEventDetails(&ev, calKR, d.addrKR)
				if err != nil {
					fmt.Fprintf(os.Stderr, "daemon: event %s: decrypt failed: %v (skipped)\n", ev.ID, err)
					continue
				}
				events = append(events, icsEvent{
					ID:          ev.ID,
					Start:       ev.StartTime,
					End:         ev.EndTime,
					FullDay:     bool(ev.FullDay),
					Summary:     summary,
					Location:    location,
					Description: description,
				})
			}
		}
	}
	return icsFeed(events, now), nil
}

// handleICSFeed serves the read-only feed. A fetch failure is a 503
// with a plain error, never a stale feed.
func (d *daemon) handleICSFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/calendar.ics" {
		http.NotFound(w, r)
		return
	}
	feed, err := d.buildICSFeed(r.Context())
	if err != nil {
		http.Error(w, "failed to build feed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="calendar.ics"`)
	_, _ = io.WriteString(w, feed)
}

// serveICS runs the localhost-only HTTP server for the feed.
func (d *daemon) serveICS() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/calendar.ics", d.handleICSFeed)
	d.httpSrv = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", d.icsPort),
		Handler: mux,
	}
	err := d.httpSrv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// cmdDaemon dispatches the daemon subcommands.
func cmdDaemon(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: proton-cli daemon <start|stop|status|ics> [flags]")
	}
	switch args[0] {
	case "start":
		return cmdDaemonStart(ctx, args[1:])
	case "stop":
		return cmdDaemonStop(ctx, args[1:])
	case "status":
		return cmdDaemonStatus(ctx, args[1:])
	case "ics":
		return cmdDaemonICS(ctx, args[1:])
	default:
		return fmt.Errorf("unknown daemon subcommand %q (start|stop|status|ics)", args[0])
	}
}

// cmdDaemonStart prompts once for the account password, unlocks the
// address keyring, and serves decrypt requests until stopped. It runs in
// the foreground; stop it with `proton-cli daemon stop` or Ctrl-C.
func cmdDaemonStart(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	icsPort := fs.Int("ics-port", defaultICSPort, "port for the read-only ICS feed on 127.0.0.1")
	icsPast := fs.Int("ics-days-past", defaultICSDaysPast, "days of past events in the ICS feed")
	icsFuture := fs.Int("ics-days-future", defaultICSDaysFuture, "days of future events in the ICS feed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *icsPort < 1 || *icsPort > 65535 {
		return fmt.Errorf("--ics-port must be 1-65535, got %d", *icsPort)
	}
	if *icsPast < 0 || *icsFuture < 0 {
		return fmt.Errorf("ICS window days must be >= 0, got --ics-days-past %d --ics-days-future %d", *icsPast, *icsFuture)
	}

	sockPath, err := daemonSocketPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(sockPath); err == nil {
		if running, _ := pingDaemon(); running {
			return fmt.Errorf("daemon is already running (socket %s)", sockPath)
		}
		// Stale socket: the previous daemon died without removing it.
		_ = os.Remove(sockPath)
	}

	pw, err := readSecretLine("Enter account password (via stdin):")
	if err != nil {
		return err
	}
	defer zero(pw)

	stored, err := loadSession()
	if err != nil {
		return err
	}
	if len(stored.Salts) == 0 {
		return fmt.Errorf("no key salts stored in session — run `proton-cli login` again to capture them")
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	// Persist rotated refresh tokens so later CLI invocations keep
	// working: the daemon shares the session file with them.
	c.AddAuthHandler(func(auth proton.Auth) {
		if auth.RefreshToken == "" {
			return
		}
		if s, err := loadSession(); err == nil && auth.RefreshToken != s.RefreshToken {
			_ = saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken, Salts: s.Salts})
		}
	})

	user, err := c.GetUser(ctx)
	if err != nil {
		m.Close()
		return fmt.Errorf("get user: %w", err)
	}
	primaryID := primaryKeyID(user.Keys)
	if primaryID == "" {
		m.Close()
		return fmt.Errorf("no primary user key — cannot derive salted key password")
	}
	salted, err := stored.Salts.SaltForKey(pw, primaryID)
	if err != nil {
		m.Close()
		return fmt.Errorf("derive salted key password: %w", err)
	}
	if len(salted) == 0 {
		m.Close()
		return fmt.Errorf("derive salted key password: empty result")
	}
	defer zero(salted)

	addrKR, err := unlockAddressKeyring(ctx, c, salted, "")
	if err != nil {
		m.Close()
		return err
	}

	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		m.Close()
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		m.Close()
		return err
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		m.Close()
		return fmt.Errorf("listen on daemon socket: %w", err)
	}
	// The listener creates the socket with the process umask; enforce 0600.
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		m.Close()
		return err
	}

	d := &daemon{
		addrKR:        addrKR,
		calKR:         make(map[string]*crypto.KeyRing),
		client:        c,
		mgr:           m,
		icsPort:       *icsPort,
		icsPastDays:   *icsPast,
		icsFutureDays: *icsFuture,
		listener:      ln,
		done:          make(chan struct{}),
	}

	go d.serveSocket()
	go func() {
		if err := d.serveICS(); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: ICS feed failed: %v\n", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "daemon started (socket %s)\nICS feed: http://127.0.0.1:%d/calendar.ics\n", sockPath, d.icsPort)

	// Shut down on SIGINT/SIGTERM or on a `daemon stop` request.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	select {
	case <-sigCh:
	case <-d.done:
	}

	ln.Close()
	if d.httpSrv != nil {
		_ = d.httpSrv.Shutdown(context.Background())
	}
	_ = os.Remove(sockPath)
	c.Close()
	m.Close()
	return nil
}

// cmdDaemonStop asks a running daemon to shut down.
func cmdDaemonStop(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := daemonRoundTrip(daemonRequest{Op: "stop"})
	if err != nil {
		if errors.Is(err, errDaemonUnavailable) {
			return fmt.Errorf("daemon is not running")
		}
		return err
	}
	if !resp.OK {
		return fmt.Errorf("daemon stop: %s", resp.Error)
	}
	fmt.Fprintln(os.Stderr, "daemon stopped")
	return nil
}

// cmdDaemonStatus reports whether a daemon is running (JSON).
func cmdDaemonStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	running, icsPort := pingDaemon()
	out := map[string]any{"running": running}
	if running {
		out["ics_url"] = fmt.Sprintf("http://127.0.0.1:%d/calendar.ics", icsPort)
	}
	return emitJSON(out)
}

// cmdDaemonICS prints the feed URL and the Apple Calendar subscription
// steps. The daemon must be running: the feed exists only while it
// holds the keyrings in memory.
func cmdDaemonICS(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon ics", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	running, icsPort := pingDaemon()
	if !running {
		return fmt.Errorf("daemon is not running — start it with `proton-cli daemon start` first")
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/calendar.ics", icsPort)
	fmt.Fprintf(os.Stdout, "ICS feed: %s\n\n", url)
	fmt.Fprint(os.Stdout, `Subscribe in Apple Calendar:
  Calendar > Add Account > Other > Add Subscribed Calendar, paste the URL above.
The feed is read-only and refreshes periodically; it is served only while
the daemon is running (start it with 'proton-cli daemon start').
`)
	return nil
}
