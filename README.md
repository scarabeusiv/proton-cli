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
  - `mail read [--decrypt] <message-id>` — attachment metadata is always listed; `--download-attachments` writes the attachments decrypted into `<message-id>-attachments` (or `--attachments-dir DIR`); requires `--decrypt`. `--decrypt` uses the daemon when it is running (no password prompt); `--no-daemon` forces the prompt
  - `mail send --to ... --subject ... --body-file ... [--attach FILE]...` — attach files (repeatable)
  - `mail mark-read | mark-unread | delete <message-id>...` — triage, several IDs per call
  - `mail labels` — list labels; `mail label <id>... --add <label-id> [--remove <label-id>]`; `mail create-label --name <name> [--color <hex>]`
- `calendars` — list Proton calendars
- `events` — list calendar events in a date range; `--decrypt` decrypts
  titles and locations (uses the daemon when it is running, so no
  password prompt; otherwise the account password is read from stdin,
  asked only when the range has events, and before the bulk of the fetch
  so a wrong password fails fast; `--no-daemon` forces the prompt)
- `contacts` — list / search contacts
- `keys` — diagnostic: key IDs/flags and stored key-salt IDs (no secrets)
- `event-raw` — diagnostic: one event's part structure (no decrypt)
- `daemon` — hold the unlocked keyring in memory: `start` | `stop` |
  `status` | `ics` (see Daemon below)

## Daemon

`proton-cli daemon start` prompts once for the account password, unlocks
the keyrings, and holds them in memory (the Proton Bridge model), so
`events --decrypt` and `mail read --decrypt` stop asking for the password
on every run. It listens on a Unix socket at
`~/.config/proton-cli/daemon.sock` (0600, same-user only) for decrypt
requests, and serves a read-only ICS feed over HTTP on localhost. When
it exits (`daemon stop`, logout, reboot) the keyrings are gone and it
must be started again. If the daemon is not running, decrypt commands
fall back to prompting for the account password, exactly as before;
`--no-daemon` forces that prompt path.

```sh
proton-cli daemon start [--ics-port 8765] [--ics-days-past 30] [--ics-days-future 365]
proton-cli daemon stop
proton-cli daemon status   # JSON: {"running": true, "ics_url": "..."}
proton-cli daemon ics      # print the feed URL and subscription steps
```

The ICS feed (`http://127.0.0.1:8765/calendar.ics` by default) contains
the decrypted events for the past 30 days through the next 365 days
(configurable with the `--ics-days-past` / `--ics-days-future` flags on
`daemon start`). It is regenerated from Proton on every request, so a
subscribing calendar sees current data on its next poll; a fetch
failure serves 503, never a stale feed. It is served only while the
daemon is running.

Subscribe in Apple Calendar: Calendar > Add Account > Other > Add
Subscribed Calendar, paste the feed URL. The feed is read-only (the
Calendar API has no event create/update/delete) and refreshes
periodically.

Security trade-off: any process running as the same user can talk to
the daemon over its socket and ask it to decrypt. This is the same gap
ssh-agent, gpg-agent and Proton Bridge itself have. Nothing decrypted
is ever written to disk, and the feed listens on 127.0.0.1 only, never
on all interfaces.

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
