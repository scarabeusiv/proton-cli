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

// authedClient builds a client from the stored session, refreshing the access
// token as needed, and persists rotated refresh tokens.
func authedClient(ctx context.Context) (*proton.Client, *proton.Manager, error) {
	s, err := loadSession()
	if err != nil {
		return nil, nil, err
	}

	m := newManager()

	c, auth, err := m.NewClientWithRefresh(ctx, s.UID, s.RefreshToken)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("session refresh failed — run `proton-cli login` again: %w", err)
	}

	if auth.RefreshToken != "" && auth.RefreshToken != s.RefreshToken {
		_ = saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken, Salts: s.Salts})
	}

	return c, m, nil
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
