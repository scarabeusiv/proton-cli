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
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()

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
  keys       Diagnostic: list key IDs/flags and stored key-salt IDs (no secrets)
  contacts   List/search contacts

Secrets are only read from stdin, never from argv or the environment.
Run 'proton-cli <command> -h' for command flags.
`)
}

func newFlagSet(name string, args []string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	_ = fs.Parse(args)
	return fs
}

// emitJSON writes v as indented JSON to stdout.
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
