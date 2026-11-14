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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"golang.org/x/sys/unix"
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
	defaultICSDaysPast   = 7
	defaultICSDaysFuture = 90
	// icsFetchTimeout bounds one ICS feed fetch (list calendars, fetch
	// events, decrypt). The fetch runs detached from the HTTP request
	// (see handleICSFeed), so this is the only bound on a slow feed.
	icsFetchTimeout = 120 * time.Second
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

// daemonLogPath returns the daemon's log file path, next to the socket
// in the config directory. The backgrounded daemon writes its stdout
// and stderr there; a foreground daemon writes to the terminal instead.
func daemonLogPath() (string, error) {
	sockPath, err := daemonSocketPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(sockPath), "daemon.log"), nil
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
	ICSEnabled  bool   `json:"ics_enabled,omitempty"`
	Body        string `json:"body,omitempty"`
	Summary     string `json:"summary,omitempty"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
	AccessToken string `json:"access_token,omitempty"` // access_token op
	UID         string `json:"uid,omitempty"`          // access_token op
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

// pingDaemon reports whether a daemon is running, its ICS port, and
// whether the ICS feed is enabled. It returns running=false (not an
// error) when no daemon answers.
func pingDaemon() (running bool, icsPort int, icsEnabled bool) {
	resp, err := daemonRoundTrip(daemonRequest{Op: "ping"})
	if err != nil || !resp.OK {
		return false, 0, false
	}
	return resp.Running, resp.ICSPort, resp.ICSEnabled
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

// daemonToken is the current access token a CLI command builds its
// client from (see authedClientViaDaemon).
type daemonToken struct {
	UID         string
	AccessToken string
}

// daemonAccessToken asks a running daemon for its current access
// token, retrying once on a transient failure. errDaemonUnavailable
// means no daemon answered, so the caller falls back to the session
// file; any other error means the daemon is up but cannot vouch for a
// token, and the caller must not fall back to refreshing on its own.
func daemonAccessToken() (daemonToken, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		resp, err := daemonRoundTrip(daemonRequest{Op: "access_token"})
		if err != nil {
			if errors.Is(err, errDaemonUnavailable) {
				return daemonToken{}, err
			}
			lastErr = err
			continue
		}
		if !resp.OK {
			lastErr = fmt.Errorf("daemon access_token: %s", resp.Error)
			continue
		}
		if resp.AccessToken == "" {
			lastErr = errors.New("daemon returned an empty access token")
			continue
		}
		return daemonToken{UID: resp.UID, AccessToken: resp.AccessToken}, nil
	}
	return daemonToken{}, lastErr
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
//
// The daemon is the single owner of the auth token: it is the only
// process that refreshes the refresh token, and CLI commands get
// their access token from it (see accessTokenForCLI). The tracked
// tokens below are updated on every refresh (auth handler) and on
// every client rebuild, so the daemon always hands out the token its
// held client is actually using.
type daemon struct {
	addrKR *crypto.KeyRing

	// calKR caches the unlocked calendar keyring per calendar ID,
	// unlocked on first use from the held address keyring.
	calKR map[string]*crypto.KeyRing
	// verifyKR caches the signature-verification keyring per calendar
	// ID: the held address keys plus the other members' public keys
	// (see buildVerificationKeyring). Guarded by calMu with calKR.
	verifyKR map[string]*crypto.KeyRing
	// verifyKRauthors records, per calendar ID, the author addresses
	// whose public keys are already in verifyKR, so a ring built for
	// one author is rebuilt (not reused) when a new author appears.
	// Guarded by calMu with verifyKR.
	verifyKRauthors map[string]map[string]bool
	calMu           sync.Mutex

	// mu guards client and the tracked tokens. mgr is set once at
	// construction and never swapped, so it needs no guard.
	mu           sync.RWMutex
	client       *proton.Client
	mgr          *proton.Manager
	uid          string
	accessToken  string
	refreshToken string

	icsPort       int
	icsPastDays   int
	icsFutureDays int

	// icsMu guards icsEnabled, icsCache, icsCacheOrder, icsCacheReady,
	// icsCacheUpdated and icsRefreshStop. The cache holds the raw
	// calendar events exactly as Proton returns them, still encrypted;
	// nothing decrypted is ever stored there (see ics_cache.go).
	icsMu           sync.Mutex
	icsEnabled      bool
	icsCache        map[string][]proton.CalendarEvent
	icsCacheOrder   []string
	icsCacheReady   bool
	icsCacheUpdated time.Time
	icsRefreshStop  chan struct{}

	listener net.Listener
	httpSrv  *http.Server

	done     chan struct{}
	shutdown sync.Once
}

// newDaemon builds a daemon around an already-unlocked address
// keyring and an authenticated client. auth is the auth the client
// was built with; the daemon tracks its tokens from here on and
// registers the auth handler that keeps them (and the session file)
// current on every lazy refresh.
func newDaemon(c *proton.Client, m *proton.Manager, auth proton.Auth, addrKR *crypto.KeyRing, icsPort, icsPast, icsFuture int) *daemon {
	d := &daemon{
		addrKR:          addrKR,
		calKR:           make(map[string]*crypto.KeyRing),
		verifyKR:        make(map[string]*crypto.KeyRing),
		verifyKRauthors: make(map[string]map[string]bool),
		client:          c,
		mgr:             m,
		uid:             auth.UID,
		accessToken:     auth.AccessToken,
		refreshToken:    auth.RefreshToken,
		icsPort:         icsPort,
		icsPastDays:     icsPast,
		icsFutureDays:   icsFuture,
		done:            make(chan struct{}),
	}
	c.AddAuthHandler(d.authHandler)
	return d
}

// getClient returns the client the daemon currently serves with. The
// client is swapped (never mutated) by rebuildClient, so a caller
// that keeps using its snapshot is unaffected by a swap.
func (d *daemon) getClient() *proton.Client {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.client
}

// authHandler runs on every lazy refresh of the held client: it keeps
// the tracked tokens current and persists the rotation to the session
// file, so a later daemon start (or a no-daemon CLI run) picks up the
// latest token.
func (d *daemon) authHandler(auth proton.Auth) {
	if auth.RefreshToken == "" {
		return
	}
	d.mu.RLock()
	basedOn := d.refreshToken
	d.mu.RUnlock()
	d.persistRotatedToken(auth, basedOn)
	d.mu.Lock()
	d.uid = auth.UID
	d.accessToken = auth.AccessToken
	d.refreshToken = auth.RefreshToken
	d.mu.Unlock()
}

// persistRotatedToken saves a rotated refresh token to the session
// file, unless the file no longer belongs to this session: a fresh
// login replaces the file (different UID) and must not be clobbered,
// and a token newer than the one this refresh was based on means
// another refresh already superseded this one.
func (d *daemon) persistRotatedToken(auth proton.Auth, basedOn string) {
	s, err := loadSession()
	if err != nil {
		return
	}
	if s.UID != auth.UID {
		return
	}
	if basedOn != "" && s.RefreshToken != basedOn {
		return
	}
	if auth.RefreshToken == s.RefreshToken {
		return
	}
	_ = saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken, Salts: s.Salts})
}

// rebuildClient discards the held client and builds a fresh one from
// the current session file, e.g. after the held refresh token went
// stale. The old client is not closed: a request may still be using
// it, and closing would clear its tokens mid-flight; it is simply
// dropped and garbage-collected.
func (d *daemon) rebuildClient(ctx context.Context) error {
	s, err := loadSession()
	if err != nil {
		return err
	}
	c, auth, err := d.mgr.NewClientWithRefresh(ctx, s.UID, s.RefreshToken)
	if err != nil {
		return err
	}
	c.AddAuthHandler(d.authHandler)
	d.mu.Lock()
	d.client = c
	d.uid = auth.UID
	d.accessToken = auth.AccessToken
	d.refreshToken = auth.RefreshToken
	d.mu.Unlock()
	d.persistRotatedToken(auth, s.RefreshToken)
	return nil
}

// accessTokenForCLI returns a currently-valid access token for a CLI
// command. It probes the API with the held client (a cheap GetUser):
// if the access token has expired, the library refreshes it lazily
// (the only refresh path; the auth handler persists the rotation and
// updates the tracked token) and the probe retries with the fresh
// token. The returned token was therefore just proven valid. The
// library exposes no token expiry, so a probe is the only way to know
// the token is still good.
func (d *daemon) accessTokenForCLI(ctx context.Context) (daemonToken, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := d.getClient()
	_, err := client.GetUser(probeCtx)
	if err != nil {
		if isInvalidRefreshToken(err) {
			// The held refresh token is stale (e.g. the session
			// file was replaced by a fresh login). Rebuild from
			// the session file once and retry the probe.
			if rerr := d.rebuildClient(ctx); rerr != nil {
				return daemonToken{}, fmt.Errorf("daemon token refresh failed — restart the daemon or run `proton-cli login` again: %w", err)
			}
			client = d.getClient()
			if _, err := client.GetUser(probeCtx); err != nil {
				return daemonToken{}, fmt.Errorf("daemon token refresh failed — restart the daemon or run `proton-cli login` again: %w", err)
			}
		} else {
			// A non-auth probe failure (network blip): the tracked
			// token may still be valid. Return it best-effort and
			// let the caller's own requests surface the problem.
			fmt.Fprintf(os.Stderr, "daemon: access_token probe failed (%v); returning the tracked token\n", err)
		}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.accessToken == "" {
		return daemonToken{}, fmt.Errorf("daemon has no access token — restart the daemon")
	}
	return daemonToken{UID: d.uid, AccessToken: d.accessToken}, nil
}

// stop signals the daemon to shut down. It is safe to call twice.
func (d *daemon) stop() {
	d.shutdown.Do(func() { close(d.done) })
}

// calendarKeyring returns the unlocked calendar keyring for calendarID,
// unlocking (and caching) it on first use via the held address keyring.
// c is the client snapshot the caller is using for this operation.
func (d *daemon) calendarKeyring(ctx context.Context, c *proton.Client, calendarID string) (*crypto.KeyRing, error) {
	d.calMu.Lock()
	defer d.calMu.Unlock()
	if kr, ok := d.calKR[calendarID]; ok {
		return kr, nil
	}
	kr, err := d.unlockCalendarKeyring(ctx, c, calendarID)
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
func (d *daemon) unlockCalendarKeyring(ctx context.Context, c *proton.Client, calendarID string) (*crypto.KeyRing, error) {
	members, err := c.GetCalendarMembers(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar members: %w", err)
	}
	addrs, err := c.GetAddresses(ctx)
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

	passphrase, err := c.GetCalendarPassphrase(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar passphrase: %w", err)
	}
	rawPass, err := passphrase.Decrypt(memberID, d.addrKR)
	if err != nil {
		return nil, fmt.Errorf("decrypt calendar passphrase: %w", err)
	}
	defer zero(rawPass)

	keys, err := c.GetCalendarKeys(ctx, calendarID)
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

// verificationKeyring returns the signature-verification keyring for
// calendarID, building (and caching) it on first use. It wraps
// buildVerificationKeyring around the held address keyring, including
// the public keys of extraAuthors (the authors of the events being
// decrypted). A cached ring is rebuilt when an author appears that
// it was not built with, so a new author's events verify too.
func (d *daemon) verificationKeyring(ctx context.Context, c *proton.Client, calendarID string, extraAuthors []string) (*crypto.KeyRing, error) {
	d.calMu.Lock()
	defer d.calMu.Unlock()
	want := make(map[string]bool, len(extraAuthors))
	for _, e := range extraAuthors {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			want[e] = true
		}
	}
	if kr, ok := d.verifyKR[calendarID]; ok {
		covered := true
		for e := range want {
			if !d.verifyKRauthors[calendarID][e] {
				covered = false
				break
			}
		}
		if covered {
			return kr, nil
		}
	}
	authors := make([]string, 0, len(d.verifyKRauthors[calendarID])+len(want))
	for e := range d.verifyKRauthors[calendarID] {
		authors = append(authors, e)
	}
	for e := range want {
		if !d.verifyKRauthors[calendarID][e] {
			authors = append(authors, e)
		}
	}
	kr, err := buildVerificationKeyring(ctx, c, calendarID, d.addrKR, authors)
	if err != nil {
		return nil, err
	}
	d.verifyKR[calendarID] = kr
	covered := make(map[string]bool, len(authors))
	for _, e := range authors {
		covered[e] = true
	}
	d.verifyKRauthors[calendarID] = covered
	return kr, nil
}

// handleRequest serves one daemon request. The second return value
// reports whether the daemon should shut down after replying.
func (d *daemon) handleRequest(ctx context.Context, req daemonRequest) (daemonResponse, bool) {
	switch req.Op {
	case "ping":
		return daemonResponse{OK: true, Running: true, ICSPort: d.icsPort, ICSEnabled: d.icsIsEnabled()}, false
	case "ics_enable":
		d.setICSEnabled(true)
		return daemonResponse{OK: true, ICSPort: d.icsPort, ICSEnabled: true}, false
	case "ics_disable":
		d.setICSEnabled(false)
		return daemonResponse{OK: true, ICSEnabled: false}, false
	case "stop":
		return daemonResponse{OK: true}, true
	case "access_token":
		// Hand out a currently-valid access token for a CLI command.
		// The token lets the holder call Proton's API as the user,
		// but any same-user process can already read the refresh
		// token from the session file (0600, same user), so this op
		// does not widen the trust boundary the socket already has.
		tok, err := d.accessTokenForCLI(ctx)
		if err != nil {
			return daemonResponse{Error: err.Error()}, false
		}
		return daemonResponse{OK: true, UID: tok.UID, AccessToken: tok.AccessToken}, false
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
		calKR, err := d.calendarKeyring(ctx, d.getClient(), req.CalendarID)
		if err != nil && isInvalidRefreshToken(err) {
			// The held refresh token went stale; rebuild from the
			// session file once and retry.
			if rerr := d.rebuildClient(ctx); rerr == nil {
				calKR, err = d.calendarKeyring(ctx, d.getClient(), req.CalendarID)
			}
		}
		if err != nil {
			return daemonResponse{Error: fmt.Sprintf("unlock calendar keys: %v", err)}, false
		}
		verifyKR, err := d.verificationKeyring(ctx, d.getClient(), req.CalendarID, collectAuthorEmails([]proton.CalendarEvent{*req.Event}))
		if err != nil {
			// Fall back to the bare address keyring: this account's
			// own events still decrypt.
			fmt.Fprintf(os.Stderr, "daemon: calendar %s: verification keyring: %v (own events only)\n", req.CalendarID, err)
			verifyKR = d.addrKR
		}
		summary, location, description, err := decryptEventDetails(req.Event, calKR, verifyKR)
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

// buildICSFeedWithRetry builds the feed, rebuilding the daemon's
// client from the session file once and retrying if the held refresh
// token went stale (e.g. the session was replaced by a fresh login).
// A retry that still fails returns the original error.
func (d *daemon) buildICSFeedWithRetry(ctx context.Context) (string, error) {
	feed, err := d.buildICSFeed(ctx)
	if err == nil || !isInvalidRefreshToken(err) {
		return feed, err
	}
	if rerr := d.rebuildClient(ctx); rerr != nil {
		return "", err
	}
	return d.buildICSFeed(ctx)
}

// buildICSFeed builds the feed from the encrypted-events cache. It
// decrypts the cached (still-encrypted) events with the held keyrings
// on every call, so the feed is always generated fresh and nothing
// decrypted is stored. ICS must be enabled and the cache warm;
// otherwise it returns an error (the handler serves 503) rather than
// doing a slow on-demand full fetch. Calendars are served in the
// cache's fetch order, so the feed is deterministic.
// The ctx is the detached fetch context from handleICSFeed, not the
// HTTP request context, so a client disconnect cannot cancel the
// keyring lookups. The whole build uses one client snapshot, so a
// client swap mid-build cannot mix tokens within a single feed.
func (d *daemon) buildICSFeed(ctx context.Context) (string, error) {
	if !d.icsIsEnabled() {
		return "", errors.New("ICS is not enabled (run `proton-cli daemon ics enable`)")
	}
	snapshot, order, ready := d.icsCacheSnapshot()
	if !ready {
		return "", errors.New("ICS cache is warming up, try again shortly")
	}
	c := d.getClient()
	now := time.Now()
	from := now.AddDate(0, 0, -d.icsPastDays)
	to := now.AddDate(0, 0, d.icsFutureDays)
	var events []icsEvent
	for _, calID := range order {
		evs := snapshot[calID]
		calKR, err := d.calendarKeyring(ctx, c, calID)
		if err != nil {
			if isInvalidRefreshToken(err) {
				return "", err
			}
			fmt.Fprintf(os.Stderr, "daemon: calendar %s: %v (skipped)\n", calID, err)
			continue
		}
		verifyKR, err := d.verificationKeyring(ctx, c, calID, collectAuthorEmails(evs))
		if err != nil {
			if isInvalidRefreshToken(err) {
				return "", err
			}
			// Fall back to the bare address keyring: the feed still
			// includes this account's own events.
			fmt.Fprintf(os.Stderr, "daemon: calendar %s: verification keyring: %v (own events only)\n", calID, err)
			verifyKR = d.addrKR
		}
		for _, ev := range evs {
			// The server may ignore Begin/End; filter locally too.
			if ev.StartTime < to.Unix() && ev.EndTime > from.Unix() {
				summary, location, description, err := decryptEventDetails(&ev, calKR, verifyKR)
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

// handleICSFeed serves the read-only feed from the encrypted-events
// cache (see ics_cache.go). A failure is a 503 with a plain error,
// never a stale feed; ICS being disabled or the cache still warming
// up are 503s too, not a slow on-demand fetch.
//
// The build runs detached from the HTTP request context: it runs on a
// background context with icsFetchTimeout, so a subscribing calendar
// that gives up (or times out) cannot cancel it. The feed is
// generated fresh from the cached encrypted events on every request
// and discarded afterwards — nothing decrypted is cached.
func (d *daemon) handleICSFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/calendar.ics" {
		http.NotFound(w, r)
		return
	}
	fetchCtx, cancel := context.WithTimeout(context.Background(), icsFetchTimeout)
	defer cancel()
	feed, err := d.buildICSFeedWithRetry(fetchCtx)
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
// address keyring, and serves decrypt requests until stopped. By
// default it backgrounds itself after the prompt: the parent returns
// the terminal once the daemon answers its socket, and the daemon
// keeps running detached (its output goes to daemon.log next to the
// socket). --foreground keeps the old blocking behaviour, for
// supervisors (systemd/launchd) and debugging.
func cmdDaemonStart(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	icsPort := fs.Int("ics-port", defaultICSPort, "port for the read-only ICS feed on 127.0.0.1")
	icsPast := fs.Int("ics-days-past", defaultICSDaysPast, "days of past events in the ICS feed")
	icsFuture := fs.Int("ics-days-future", defaultICSDaysFuture, "days of future events in the ICS feed")
	ics := fs.Bool("ics", false, "enable the read-only ICS feed (encrypted-events cache + background refresh; off by default)")
	foreground := fs.Bool("foreground", false, "stay in the foreground instead of backgrounding after the prompt")
	daemonized := fs.Bool("daemonized", false, "internal: run as the backgrounded daemon child (do not use directly)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *icsPort < 1 || *icsPort > 65535 {
		return fmt.Errorf("--ics-port must be 1-65535, got %d", *icsPort)
	}
	if *icsPast < 0 || *icsFuture < 0 {
		return fmt.Errorf("ICS window days must be >= 0, got --ics-days-past %d --ics-days-future %d", *icsPast, *icsFuture)
	}

	if *daemonized {
		return cmdDaemonStartChild(ctx, *icsPort, *icsPast, *icsFuture, *ics)
	}

	sockPath, err := daemonSocketPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(sockPath); err == nil {
		if running, _, _ := pingDaemon(); running {
			return fmt.Errorf("daemon is already running (socket %s)", sockPath)
		}
		// Stale socket: the previous daemon died without removing it.
		// Removed before forking so the parent's readiness check
		// below can only succeed on the new child's socket.
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

	// The daemon is the single owner of the auth token, so its
	// startup uses the session file directly (never the daemon-first
	// path: no daemon is running yet, by the guard above).
	c, m, auth, err := authedClientDirect(ctx)
	if err != nil {
		return err
	}

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

	// Unlock here, in the foreground, so a wrong account password
	// fails immediately with a clear error instead of leaving a
	// backgrounded daemon that dies on startup.
	addrKR, err := unlockAddressKeyring(ctx, c, salted, "")
	if err != nil {
		m.Close()
		return err
	}

	if *foreground {
		d := newDaemon(c, m, auth, addrKR, *icsPort, *icsPast, *icsFuture)
		if *ics {
			d.setICSEnabled(true)
		}
		return runDaemon(d, sockPath)
	}

	logPath, err := daemonLogPath()
	if err != nil {
		c.Close()
		m.Close()
		return err
	}
	pid, err := spawnDaemonChild(salted, *icsPort, *icsPast, *icsFuture, *ics, logPath)
	c.Close()
	m.Close()
	if err != nil {
		return err
	}
	if *ics {
		fmt.Fprintf(os.Stderr, "daemon started (PID %d, socket %s)\nICS feed: http://127.0.0.1:%d/calendar.ics\nLog: %s\n", pid, sockPath, *icsPort, logPath)
	} else {
		fmt.Fprintf(os.Stderr, "daemon started (PID %d, socket %s)\nICS feed: disabled (run `proton-cli daemon ics enable` to enable it)\nLog: %s\n", pid, sockPath, logPath)
	}
	return nil
}

// cmdDaemonStartChild runs as the backgrounded daemon: it reads the
// salted key password from the anonymous pipe (fd 3) the parent
// passed, unlocks the keyring, and serves. It never prompts: a missing
// or empty pipe is a fatal startup error (logged to the daemon log).
func cmdDaemonStartChild(ctx context.Context, icsPort, icsPast, icsFuture int, ics bool) error {
	pipe := os.NewFile(3, "daemon-pipe")
	salted, err := io.ReadAll(pipe)
	_ = pipe.Close()
	if err != nil {
		return fmt.Errorf("read key password from parent: %w", err)
	}
	if len(salted) == 0 {
		return fmt.Errorf("no key password received from parent")
	}
	defer zero(salted)

	// The child is the daemon; it builds its client from the session
	// file directly, like the parent did before forking.
	c, m, auth, err := authedClientDirect(ctx)
	if err != nil {
		return err
	}

	addrKR, err := unlockAddressKeyring(ctx, c, salted, "")
	if err != nil {
		m.Close()
		return err
	}
	// The salted password unlocked the keyring; it is not needed again.
	zero(salted)

	sockPath, err := daemonSocketPath()
	if err != nil {
		m.Close()
		return err
	}
	d := newDaemon(c, m, auth, addrKR, icsPort, icsPast, icsFuture)
	if ics {
		d.setICSEnabled(true)
	}
	return runDaemon(d, sockPath)
}

// spawnDaemonChild re-execs this binary as a detached daemon child,
// passing the salted key password over an anonymous pipe (fd 3) and
// waiting until the child answers pings on the socket (up to ~10s).
// It returns the child's PID.
//
// The salted password never touches disk, argv or the environment:
// only the anonymous pipe carries it, and the child reads it once,
// unlocks the keyring, and zeroes it. Same-user processes can already
// talk to the daemon over its socket, so passing the already-derived
// salted password (which unlocks keys but cannot log in to Proton)
// over the pipe is within the accepted threat model.
func spawnDaemonChild(salted []byte, icsPort, icsPast, icsFuture int, ics bool, logPath string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("open daemon log %s: %w", logPath, err)
	}
	defer logFile.Close()

	r, w, err := os.Pipe()
	if err != nil {
		return 0, err
	}

	cmd := exec.Command(exe, "daemon", "start", "--daemonized",
		"--ics-port", strconv.Itoa(icsPort),
		"--ics-days-past", strconv.Itoa(icsPast),
		"--ics-days-future", strconv.Itoa(icsFuture),
		"--ics", strconv.FormatBool(ics))
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil // /dev/null: the child must not hold the terminal
	// Detach from the controlling terminal/session so the daemon
	// survives the terminal closing and never receives its signals.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}
	// The child has its own copy of the read end now.
	_ = r.Close()
	if _, err := w.Write(salted); err != nil {
		_ = w.Close()
		return 0, fmt.Errorf("send key password to daemon: %w", err)
	}
	_ = w.Close()

	// Wait for readiness: the child answers a ping only once it is
	// listening and serving. Fail fast if the child exits first.
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if running, _, _ := pingDaemon(); running {
			return cmd.Process.Pid, nil
		}
		select {
		case err := <-waitCh:
			return 0, fmt.Errorf("daemon exited during startup (%v); log tail:\n%s", err, logTail(logPath))
		case <-ticker.C:
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				return 0, fmt.Errorf("daemon did not answer within 10s; log tail:\n%s", logTail(logPath))
			}
		}
	}
}

// logTail returns the last few lines of the daemon log, for startup
// failure reports. A missing/unreadable log is not itself an error.
func logTail(logPath string) string {
	b, err := os.ReadFile(logPath)
	if err != nil {
		return "(no daemon log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return strings.Join(lines, "\n")
}

// runDaemon listens on the socket and serves decrypt requests plus the
// ICS feed until stopped (a `daemon stop` request or SIGINT/SIGTERM).
// It owns the daemon's client/manager and closes them on shutdown.
func runDaemon(d *daemon, sockPath string) error {
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		d.mgr.Close()
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		d.mgr.Close()
		return err
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		d.mgr.Close()
		return fmt.Errorf("listen on daemon socket: %w", err)
	}
	// The listener creates the socket with the process umask; enforce 0600.
	if err := os.Chmod(sockPath, 0o600); err != nil {
		ln.Close()
		d.mgr.Close()
		return err
	}
	d.listener = ln

	go d.serveSocket()
	go func() {
		if err := d.serveICS(); err != nil {
			fmt.Fprintf(os.Stderr, "daemon: ICS feed failed: %v\n", err)
		}
	}()

	if d.icsIsEnabled() {
		fmt.Fprintf(os.Stderr, "daemon started (socket %s)\nICS feed: http://127.0.0.1:%d/calendar.ics\n", sockPath, d.icsPort)
	} else {
		fmt.Fprintf(os.Stderr, "daemon started (socket %s)\nICS feed: disabled (run `proton-cli daemon ics enable` to enable it)\n", sockPath)
	}

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
	d.getClient().Close()
	d.mgr.Close()
	return nil
}

// stopDaemon asks a running daemon to shut down. It returns
// errDaemonUnavailable when no daemon answers.
func stopDaemon() error {
	resp, err := daemonRoundTrip(daemonRequest{Op: "stop"})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("daemon stop: %s", resp.Error)
	}
	return nil
}

// cmdDaemonStop asks a running daemon to shut down.
func cmdDaemonStop(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := stopDaemon(); err != nil {
		if errors.Is(err, errDaemonUnavailable) {
			return fmt.Errorf("daemon is not running")
		}
		return err
	}
	fmt.Fprintln(os.Stderr, "daemon stopped")
	return nil
}

// stdinIsTTY reports whether stdin is a terminal (as opposed to a
// pipe, a file, or /dev/null). A plain ModeCharDevice check is NOT
// enough: /dev/null is a character device too, and treating it as a
// terminal made non-interactive runs try to start a daemon — and,
// inside the test binary, re-exec the test suite as `daemon start`.
func stdinIsTTY() bool {
	_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), termiosGetRequest)
	return err == nil
}

// isTestBinary reports whether exe is a `go test` binary (they end
// in .test). See ensureDaemonForDecrypt.
func isTestBinary(exe string) bool {
	return strings.HasSuffix(exe, ".test")
}

// ensureDaemonForDecrypt makes a daemon available for a decrypt
// command: if one answers the socket it is used; otherwise, when
// stdin is a terminal, a daemon is started (it prompts once for the
// account password in this terminal, then backgrounds itself) and
// used. With piped stdin it returns false so the caller falls back
// to prompting for the account password per command, and scripted
// use never hangs waiting for a password that can never arrive.
// --no-daemon callers must not call this at all.
func ensureDaemonForDecrypt() bool {
	if running, _, _ := pingDaemon(); running {
		return true
	}
	if !stdinIsTTY() {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	// Never re-exec a test binary as the daemon: `go test` binaries
	// end in .test and run the suite when given `daemon start`,
	// which would spawn the suite again instead of a daemon.
	if isTestBinary(exe) {
		return false
	}
	// The child is a plain `daemon start`: it prompts on this
	// terminal, backgrounds itself, and exits once the daemon
	// answers. Its messages go to stderr so the caller's stdout
	// stays clean JSON.
	cmd := exec.Command(exe, "daemon", "start")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false
	}
	running, _, _ := pingDaemon()
	return running
}

// cmdDaemonStatus reports whether a daemon is running.
func cmdDaemonStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	addJSONFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	running, icsPort, icsEnabled := pingDaemon()
	out := map[string]any{"running": running, "ics_enabled": icsEnabled}
	if running && icsEnabled {
		out["ics_url"] = fmt.Sprintf("http://127.0.0.1:%d/calendar.ics", icsPort)
	}
	return emit(out, func() {
		if !running {
			fmt.Fprintln(os.Stdout, "daemon: not running")
			return
		}
		fmt.Fprintln(os.Stdout, "daemon: running")
		if icsEnabled {
			fmt.Fprintf(os.Stdout, "ICS feed: %s\n", out["ics_url"])
		} else {
			fmt.Fprintln(os.Stdout, "ICS: disabled (run `proton-cli daemon ics enable` to enable it)")
		}
	})
}

// cmdDaemonICS prints the feed URL and the Apple Calendar subscription
// steps, or enables/disables the feed on a running daemon
// (`daemon ics enable` / `daemon ics disable`). The daemon must be
// running for the bare form: the feed exists only while it holds the
// keyrings in memory. Enabling on a stopped daemon starts one with
// ICS enabled instead (equivalent to `daemon start --ics`).
func cmdDaemonICS(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("daemon ics", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if rest := fs.Args(); len(rest) > 0 {
		switch rest[0] {
		case "enable":
			return cmdDaemonICSEnable(ctx)
		case "disable":
			return cmdDaemonICSDisable(ctx)
		default:
			return fmt.Errorf("unknown daemon ics subcommand %q (enable|disable)", rest[0])
		}
	}
	running, icsPort, icsEnabled := pingDaemon()
	if !running {
		return fmt.Errorf("daemon is not running — start it with `proton-cli daemon start` first")
	}
	if !icsEnabled {
		fmt.Fprintln(os.Stdout, "ICS is not enabled.")
		fmt.Fprintln(os.Stdout, "Run `proton-cli daemon ics enable` to enable the ICS feed (it builds the encrypted-events cache in the background).")
		return nil
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

// cmdDaemonICSEnable enables the ICS feed on the running daemon. If no
// daemon is running, it starts one with ICS enabled (equivalent to
// `daemon start --ics`, prompting once for the account password).
func cmdDaemonICSEnable(ctx context.Context) error {
	if running, _, _ := pingDaemon(); running {
		resp, err := daemonRoundTrip(daemonRequest{Op: "ics_enable"})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("enable ICS: %s", resp.Error)
		}
		fmt.Fprintf(os.Stderr, "ICS enabled\nICS feed: http://127.0.0.1:%d/calendar.ics\n", resp.ICSPort)
		fmt.Fprintln(os.Stderr, "The encrypted-events cache is building in the background; wait for the \"ICS cache ready\" line in the daemon log before adding the calendar.")
		return nil
	}
	return cmdDaemonStart(ctx, []string{"--ics"})
}

// cmdDaemonICSDisable disables the ICS feed on the running daemon
// (stops the background refresh, clears the in-memory cache). The
// daemon itself keeps running.
func cmdDaemonICSDisable(ctx context.Context) error {
	if running, _, _ := pingDaemon(); !running {
		return fmt.Errorf("daemon is not running")
	}
	resp, err := daemonRoundTrip(daemonRequest{Op: "ics_disable"})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("disable ICS: %s", resp.Error)
	}
	fmt.Fprintln(os.Stderr, "ICS disabled (cache cleared)")
	return nil
}
