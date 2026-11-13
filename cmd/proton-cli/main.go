// Command proton-cli is a small command-line client for Proton Mail,
// Proton Calendar (read-only) and Proton Contacts, built on the official
// ProtonMail/go-proton-api library.
//
// Authentication state (a session UID + refresh token, never the password)
// lives in ~/.config/proton-cli/session.json with mode 0600. Passwords and
// TOTP codes are only ever read from stdin, never from argv, environment
// variables, files, or logs.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// The root context carries a timeout so a hung API call cannot hang
	// the CLI indefinitely. It is deliberately generous (10 minutes):
	// login may block on stdin while the user solves a human-verification
	// CAPTCHA in the browser, and the retry after that still uses this
	// context.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error

	switch os.Args[1] {
	case "login":
		err = cmdLogin(ctx, os.Args[2:])
	case "logout":
		err = cmdLogout(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(ctx, os.Args[2:])
	case "mail":
		err = cmdMail(ctx, os.Args[2:])
	case "calendars":
		err = cmdCalendars(ctx, os.Args[2:])
	case "events":
		err = cmdEvents(ctx, os.Args[2:])
	case "event-raw":
		err = cmdEventRaw(ctx, os.Args[2:])
	case "keys":
		err = cmdKeys(ctx, os.Args[2:])
	case "contacts":
		err = cmdContacts(ctx, os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `proton-cli — Proton Mail / Calendar / Contacts via the official go-proton-api.

Usage:
  proton-cli <command> [flags]

Commands:
  login      Authenticate (username flag; password via stdin, TOTP via stdin if 2FA)
  logout     Revoke the session and delete local auth state
  status     Show whether a session exists and if it still refreshes
  mail       Mail operations: list | read | send
  calendars  List Proton calendars
  events     List calendar events in a date range (read-only)
  event-raw  Diagnostic: print one event's part structure (no decrypt, no password)
  keys       Diagnostic: list key IDs/flags and stored key-salt IDs (no secrets)
  contacts   List/search contacts

Secrets are only read from stdin, never from argv or the environment.
Run 'proton-cli <command> -h' for command flags.
`)
}

// validateLimit checks a --limit flag value: negative limits are rejected
// (a negative cap would panic in make), 0 means "no limit".
func validateLimit(limit int) (int, error) {
	if limit < 0 {
		return 0, fmt.Errorf("--limit must be >= 0 (0 = no limit), got %d", limit)
	}
	return limit, nil
}

// emitJSON writes v as indented JSON to stdout.
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
