package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// session holds the refreshable auth state. The password is never stored.
type session struct {
	UID          string `json:"uid"`
	RefreshToken string `json:"refresh_token"`
	// Key salts, captured at login time. /core/v4/keys/salts requires a
	// short-lived post-login "password scope" that a refreshed token does
	// not carry, so they cannot be fetched by a later run. Salts are
	// per-key bcrypt salts; without the account password they unlock
	// nothing. Re-captured on every login.
	Salts proton.Salts `json:"salts,omitempty"`
}

// errNoSession reports that no session file exists at all, as opposed to
// a session file that is present but unreadable or corrupt.
var errNoSession = errors.New("no session file")

func sessionPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "proton-cli", "session.json"), nil
}

func loadSession() (session, error) {
	var s session

	p, err := sessionPath()
	if err != nil {
		return s, err
	}

	b, err := os.ReadFile(p)
	if err != nil {
		// A missing file means "never logged in"; any other read error
		// (permissions, I/O) means the file is there but unusable.
		if os.IsNotExist(err) {
			return s, fmt.Errorf("%w — run `proton-cli login` first", errNoSession)
		}
		return s, fmt.Errorf("read session file: %w", err)
	}

	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("corrupt session file: %w", err)
	}

	if s.UID == "" || s.RefreshToken == "" {
		return s, fmt.Errorf("incomplete session — run `proton-cli login` again")
	}

	return s, nil
}

func saveSession(s session) error {
	p, err := sessionPath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// MkdirAll leaves an existing directory's mode alone; enforce 0700.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}

	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	// WriteFile leaves an existing file's mode alone; enforce 0600.
	return os.Chmod(p, 0o600)
}

func clearSession() error {
	p, err := sessionPath()
	if err != nil {
		return err
	}

	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// isInvalidRefreshToken reports whether err (or anything it wraps)
// is a Proton invalid-refresh-token error (Code 10013). The library
// surfaces API errors as *proton.APIError through the resty
// ResponseError chain, so errors.As finds it through the wrapping.
func isInvalidRefreshToken(err error) bool {
	var apiErr *proton.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == proton.AuthRefreshTokenInvalid
	}
	return false
}

// newClientWithRefreshRetry builds a client from s via
// NewClientWithRefresh (which refreshes eagerly). On an
// invalid-refresh-token failure it re-reads the session file once and
// retries with the fresh token, so a rotation by another process that
// landed between the load and the refresh does not force a re-login.
// It returns the session the successful attempt used (for its salts).
func newClientWithRefreshRetry(ctx context.Context, m *proton.Manager, s session) (*proton.Client, proton.Auth, session, error) {
	c, auth, err := m.NewClientWithRefresh(ctx, s.UID, s.RefreshToken)
	if err == nil || !isInvalidRefreshToken(err) {
		return c, auth, s, err
	}
	fresh, err2 := loadSession()
	if err2 != nil || fresh.RefreshToken == s.RefreshToken {
		// Nothing newer to retry with; the original error stands.
		return nil, proton.Auth{}, s, err
	}
	c, auth, err = m.NewClientWithRefresh(ctx, fresh.UID, fresh.RefreshToken)
	return c, auth, fresh, err
}

// authedClient builds a client from the stored session, refreshing the access
// token as needed, and persists rotated refresh tokens.
//
// When a daemon is running it is the single owner of the auth token:
// the client is built from the daemon's current access token and
// cannot refresh on its own (the daemon refreshes). When no daemon
// answers, the session file is used directly — that path is safe
// because no daemon exists to race with.
func authedClient(ctx context.Context) (*proton.Client, *proton.Manager, error) {
	if running, _ := pingDaemon(); running {
		return authedClientViaDaemon(ctx)
	}
	c, m, _, err := authedClientDirect(ctx)
	return c, m, err
}

// authedClientViaDaemon builds a client from the access token the
// daemon hands out. The client carries no refresh token, so it cannot
// refresh on its own: if the access token expires mid-command the
// daemon is the only refresher, and a re-run fetches a fresh token
// (the daemon probes/refreshes on every access_token op).
func authedClientViaDaemon(ctx context.Context) (*proton.Client, *proton.Manager, error) {
	tok, err := daemonAccessToken()
	if err != nil {
		return nil, nil, fmt.Errorf("daemon could not provide an access token — restart the daemon (`proton-cli daemon start`) or run `proton-cli login` again: %w", err)
	}
	m := newManager()
	c := m.NewClient(tok.UID, tok.AccessToken, "")
	return c, m, nil
}

// authedClientDirect builds a client directly from the session file,
// refreshing the access token as needed, and persists rotated refresh
// tokens. Callers that ARE the daemon (daemon start) use this
// explicitly; ordinary commands go through authedClient, which prefers
// the daemon when one is running. It also returns the auth the client
// was built with, so the daemon can track its tokens.
func authedClientDirect(ctx context.Context) (*proton.Client, *proton.Manager, proton.Auth, error) {
	s, err := loadSession()
	if err != nil {
		return nil, nil, proton.Auth{}, err
	}

	m := newManager()

	c, auth, used, err := newClientWithRefreshRetry(ctx, m, s)
	if err != nil {
		m.Close()
		return nil, nil, proton.Auth{}, fmt.Errorf("session refresh failed — run `proton-cli login` again: %w", err)
	}

	if auth.RefreshToken != "" && auth.RefreshToken != used.RefreshToken {
		_ = saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken, Salts: used.Salts})
	}

	return c, m, auth, nil
}

// stdinReader is the single buffered reader for stdin. Secret reads share
// it: a fresh bufio.Reader per read could buffer past the first newline and
// discard the buffered bytes with the reader, breaking piped multi-line
// input (e.g. password + TOTP piped to login).
var stdinReader = bufio.NewReader(os.Stdin)

// waitForEnter waits for a single line on stdin (content ignored). Used to
// pause while the user solves a CAPTCHA in the browser.
func waitForEnter() error {
	line, err := stdinReader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return err
	}
	if len(line) == 0 && err == io.EOF {
		return fmt.Errorf("no input on stdin — solve the CAPTCHA, then run login again")
	}
	return nil
}

// readSecretLine reads one line from stdin (for passwords / TOTP codes) and
// trims the trailing newline. Callers must zero the returned slice when done.
func readSecretLine(prompt string) ([]byte, error) {
	fmt.Fprintln(os.Stderr, prompt)

	line, err := stdinReader.ReadBytes('\n')
	if err != nil {
		// Accept EOF-terminated input too (e.g. printf without newline).
		if len(line) == 0 {
			return nil, fmt.Errorf("no input on stdin")
		}
	}

	// Trim trailing \r and \n.
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}

	if len(line) == 0 {
		return nil, fmt.Errorf("empty input on stdin")
	}

	return line, nil
}

// zero overwrites a secret byte slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// primaryKeyID returns the ID of the key flagged primary, or "" when
// none is. proton.Keys.Primary panics when no key is primary, so call
// sites must use this instead of calling Primary() directly.
func primaryKeyID(keys proton.Keys) string {
	for _, k := range keys {
		if k.Primary {
			return k.ID
		}
	}
	return ""
}

// unlockAddressKeyring unlocks the address keyring for addressID and
// returns it, or the first usable address keyring when addressID is empty.
// keyPass is the SALTED key password (see SaltForKey in calendar.go),
// not the raw account password.
func unlockAddressKeyring(ctx context.Context, c *proton.Client, keyPass []byte, addressID string) (*crypto.KeyRing, error) {
	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	return unlockAddressKeyringForAddrs(keyPass, addressID, user, addrs)
}

// unlockAddressKeyringForAddrs unlocks the address keyring for addressID
// from an already-fetched user and address list, so callers that hold
// them (e.g. the calendar member loop) do not re-fetch them per attempt.
func unlockAddressKeyringForAddrs(keyPass []byte, addressID string, user proton.User, addrs []proton.Address) (*crypto.KeyRing, error) {
	userKR, err := user.Keys.Unlock(keyPass, nil)
	if err != nil {
		return nil, fmt.Errorf("unlock user keys (wrong account password?): %w", err)
	}

	for _, addr := range addrs {
		if addressID != "" && addr.ID != addressID {
			continue
		}

		if kr := addr.Keys.TryUnlock(keyPass, userKR); kr != nil && kr.CountDecryptionEntities() > 0 {
			return kr, nil
		}
	}

	return nil, fmt.Errorf("could not unlock any address key")
}
