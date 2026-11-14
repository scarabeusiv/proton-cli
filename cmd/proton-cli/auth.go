package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/ProtonMail/go-proton-api"
)

func cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	addJSONFlag(fs)
	username := fs.String("username", "", "Proton username (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("--username is required")
	}

	password, err := readSecretLine("Enter Proton password (via stdin, will not be echoed anywhere):")
	if err != nil {
		return err
	}
	defer zero(password)

	m := newManager()
	defer m.Close()

	c, auth, err := m.NewClientWithLogin(ctx, *username, password)
	if err != nil {
		// Proton may demand human verification (CAPTCHA, Code 9001) on a
		// first login from a new client. The error carries a verification
		// token: the user solves it in the browser, then the login is
		// retried with the token attached.
		var apiErr *proton.APIError
		if errors.As(err, &apiErr) && apiErr.IsHVError() {
			if hv, hvErr := apiErr.GetHVDetails(); hvErr == nil {
				fmt.Fprintln(os.Stderr, "Proton wants human verification (CAPTCHA). Solve it in your browser, then press Enter here to continue:")
				fmt.Fprintf(os.Stderr, "https://verify.proton.me/?methods=%s&token=%s\n", strings.Join(hv.Methods, ","), url.QueryEscape(hv.Token))
				if waitErr := waitForEnter(); waitErr == nil {
					c, auth, err = m.NewClientWithLoginWithHVToken(ctx, *username, password, hv)
				} else {
					return fmt.Errorf("human verification not completed: %w", waitErr)
				}
			}
		}
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
	}
	defer c.Close()

	if auth.TwoFA.Enabled&proton.HasTOTP != 0 {
		code, err := readSecretLine("2FA required — enter TOTP code (via stdin):")
		if err != nil {
			return err
		}
		defer zero(code)

		// string(code) copies the code into an immutable string the GC
		// owns; it cannot be zeroed. The []byte is zeroed by the
		// deferred call above.
		if err := c.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: string(code)}); err != nil {
			return fmt.Errorf("2FA failed: %w", err)
		}
	}

	// Capture key salts now, while this login token still carries the
	// short-lived password scope: a refreshed token cannot fetch them.
	salts, err := c.GetSalts(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not capture key salts (%v) — decrypt will need a fresh login\n", err)
	}

	if err := saveSession(session{UID: auth.UID, RefreshToken: auth.RefreshToken, Salts: salts}); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	fmt.Fprintln(os.Stderr, "logged in; session stored (password was not saved)")
	return emit(map[string]string{"status": "logged_in", "uid": auth.UID}, func() {
		fmt.Fprintf(os.Stdout, "logged in as %s\n", auth.UID)
	})
}

func cmdLogout(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	addJSONFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Stop a running daemon first: its held token is about to be
	// revoked, and it would otherwise keep serving (and failing
	// refreshes) with a dead session. Best effort: a missing daemon
	// is not an error.
	_ = stopDaemon()

	// Best effort: revoke server-side before dropping local state.
	if c, m, _, err := authedClientDirect(ctx); err == nil {
		_ = c.AuthDelete(ctx)
		c.Close()
		m.Close()
	}

	if err := clearSession(); err != nil {
		return err
	}

	return emit(map[string]string{"status": "logged_out"}, func() {
		fmt.Fprintln(os.Stdout, "logged out")
	})
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	addJSONFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := loadSession()
	if err != nil {
		if errors.Is(err, errNoSession) {
			return emit(map[string]string{"status": "no_session"}, func() {
				fmt.Fprintln(os.Stdout, "status: no session")
			})
		}
		return emit(map[string]any{"status": "session_corrupt", "error": err.Error()}, func() {
			fmt.Fprintln(os.Stdout, "status: session corrupt")
			fmt.Fprintf(os.Stdout, "error: %v\n", err)
		})
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return emit(map[string]any{"status": "session_invalid", "uid": s.UID}, func() {
			fmt.Fprintln(os.Stdout, "status: session invalid")
			fmt.Fprintf(os.Stdout, "uid: %s\n", s.UID)
		})
	}
	defer c.Close()
	defer m.Close()

	user, err := c.GetUser(ctx)
	if err != nil {
		return emit(map[string]any{"status": "session_invalid", "uid": s.UID}, func() {
			fmt.Fprintln(os.Stdout, "status: session invalid")
			fmt.Fprintf(os.Stdout, "uid: %s\n", s.UID)
		})
	}

	return emit(map[string]any{
		"status":       "ok",
		"uid":          s.UID,
		"display_name": user.DisplayName,
	}, func() {
		fmt.Fprintln(os.Stdout, "status: ok")
		fmt.Fprintf(os.Stdout, "uid: %s\n", s.UID)
		fmt.Fprintf(os.Stdout, "display name: %s\n", user.DisplayName)
	})
}
