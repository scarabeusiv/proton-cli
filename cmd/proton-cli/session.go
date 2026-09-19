package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// session holds the refreshable auth state. The password is never stored.
type session struct {
	UID          string `json:"uid"`
	RefreshToken string `json:"refresh_token"`
}

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
		return s, fmt.Errorf("no session — run `proton-cli login` first")
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

	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}

	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return os.WriteFile(p, b, 0o600)
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

	m := proton.New()

	c, auth, err := m.NewClientWithRefresh(ctx, s.UID, s.RefreshToken)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("session refresh failed — run `proton-cli login` again: %w", err)
	}

	if auth.RefreshToken != "" && auth.RefreshToken != s.RefreshToken {
		_ = saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken})
	}

	return c, m, nil
}

// readSecretLine reads one line from stdin (for passwords / TOTP codes) and
// trims the trailing newline. Callers must zero the returned slice when done.
func readSecretLine(prompt string) ([]byte, error) {
	fmt.Fprintln(os.Stderr, prompt)

	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadBytes('\n')
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

// unlockAddressKeyring unlocks the user's address keyrings with the mailbox
// password (usually the login password) and returns the keyring for the given
// address ID, or the first usable one when addressID is empty.
func unlockAddressKeyring(ctx context.Context, c *proton.Client, mailboxPassword []byte, addressID string) (*crypto.KeyRing, error) {
	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	userKR, err := user.Keys.Unlock(mailboxPassword, nil)
	if err != nil {
		return nil, fmt.Errorf("unlock user keys (wrong mailbox password?): %w", err)
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}

	for _, addr := range addrs {
		if addressID != "" && addr.ID != addressID {
			continue
		}

		if kr := addr.Keys.TryUnlock(mailboxPassword, userKR); kr != nil && kr.CountDecryptionEntities() > 0 {
			return kr, nil
		}
	}

	return nil, fmt.Errorf("could not unlock any address key")
}
