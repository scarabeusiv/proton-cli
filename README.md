# proton-cli

A small command-line client for Proton Mail, Proton Calendar (read-only)
and Proton Contacts, built on the official
[go-proton-api](https://github.com/ProtonMail/go-proton-api) library.

## Build

```sh
go build -o proton-cli ./cmd/proton-cli
```

Requires Go 1.27+.

## Auth

```sh
proton-cli login --username <proton username>
```

The password (and TOTP code, if 2FA is on) is read from stdin, never from
argv or the environment. A fresh login from a new client can trigger
Proton human verification (CAPTCHA); the CLI prints the verification URL
and waits for you to complete it before retrying.

The session (UID + refresh token, never the password) lives in
`~/.config/proton-cli/session.json` (0600). Key salts needed to derive
the salted account password are captured at login time and stored with
the session, because a refreshed token cannot fetch them later.

## Commands

- `login` / `logout` / `status` — authenticate, revoke, check the session
- `mail` — list / read / send mail
- `calendars` — list Proton calendars
- `events` — list calendar events in a date range; `--decrypt` decrypts
  titles and locations (account password via stdin, asked before the
  fetch so a wrong password fails fast)
- `contacts` — list / search contacts
- `keys` — diagnostic: key IDs/flags and stored key-salt IDs (no secrets)
- `event-raw` — diagnostic: one event's part structure (no decrypt)

## Notes

- Proton Calendar has no CalDAV; this CLI reads it through Proton's own
  API. Event titles/locations are end-to-end encrypted: `--decrypt`
  unlocks them with your account password. The Bridge IMAP password is
  a different thing and will not unlock the keys.
- Never run two proton-cli processes concurrently: they share one
  session file and Proton rotates refresh tokens, so each process's
  refresh invalidates the others' access tokens. Run exports
  sequentially.
- `events` passes Begin/End to the server and additionally filters the
  results locally, so it only ever returns events overlapping the
  requested date range.
