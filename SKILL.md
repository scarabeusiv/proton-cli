---
name: "proton"
description: "Work with the user's Proton Mail, Proton Calendar (read-only), and Proton Contacts via the official go-proton-api library"
---

# Proton

## Purpose
Read and search Proton Mail, send mail, read Proton Calendar events, and look up contacts — backed by the official `ProtonMail/go-proton-api` Go library (the sanctioned integration path, confirmed 2026-09-19).

## Tooling
CLI: `./bin/proton-cli` (build with `go build -o bin/proton-cli ./cmd/proton-cli` from the repo root).

```
proton-cli login --username <user>            # password via stdin; TOTP via stdin if 2FA
proton-cli logout                             # revoke + delete local session
proton-cli status                             # check session health

proton-cli mail list [--label ID] [--unread] [--subject-substr X] [--from X] [--limit N]
proton-cli mail read [--decrypt] [--download-attachments [--attachments-dir DIR]] <message-id> # --decrypt reads account password from stdin
proton-cli mail send --to a@b [--cc c@d] --subject S --body-file PATH [--from addr] [--attach FILE]...
proton-cli mail mark-read|mark-unread|delete <message-id>...
proton-cli mail labels
proton-cli mail label <message-id>... --add <label-id> [--remove <label-id>]
proton-cli mail create-label --name <name> [--color <hex>]

proton-cli calendars
proton-cli events --calendar ID [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--decrypt] [--no-daemon]
proton-cli contacts [--query X] [--limit N]

proton-cli daemon start [--ics] [--ics-port 8765] [--ics-days-past 7] [--ics-days-future 90] [--foreground]  # unlock once, hold keyrings in memory; backgrounds itself after prompting unless --foreground
proton-cli daemon stop
proton-cli daemon status   # shows whether the ICS feed is enabled
proton-cli daemon ics   # print the ICS feed URL and Apple Calendar subscription steps (or "ICS is not enabled")
proton-cli daemon ics enable   # enable the ICS feed on a running daemon (starts it with ICS if not running)
proton-cli daemon ics disable  # disable the ICS feed on a running daemon (clears the cache)
```

Most commands emit JSON on stdout; errors go to stderr. The `keys` and
`event-raw` diagnostics print plain text instead of JSON. Label IDs: 0 = inbox, 1 = all mail, 5 = sent (see `proton-cli mail list --label 1` to discover more via message LabelIDs).

## Auth
No connector exists for Proton (username+password SRP login is not a supported connector scheme). Auth state is a session UID + refresh token at `~/.config/proton-cli/session.json` (mode 0600), created by `proton-cli login`. The password is never stored — only the refreshable session. See `references/auth-model.md` for the full credential model.

First-time setup needs the user's Proton password (and TOTP code if 2FA is on) supplied transiently — never stored, never logged. Ask for it only when actually running `login`.

## Operating Rules
1. Secrets only ever travel via stdin pipes. Never put passwords, TOTP codes, or account passwords in argv, environment variables, files, chat messages, or logs.
2. Never send email without showing the user the exact draft and receiving their approval first.
3. Calendar is read-only in this integration: list calendars and fetch events only. Do not attempt event create/update/delete — the library has no such endpoints.
4. `mail read` without `--decrypt` returns metadata + headers only; bodies need the account password (usually the login password), asked for transiently each time — unless the daemon is running, in which case it decrypts without prompting (`--no-daemon` forces the prompt). The first decrypt command starts the daemon when stdin is a terminal, so later commands reuse it. Attachment metadata (name, size, MIME type) is listed without a password; `--download-attachments` writes the attachments decrypted into `<message-id>-attachments` (or `--attachments-dir DIR`) and needs `--decrypt`.
5. The daemon (`daemon start`) holds the unlocked keyrings in memory so decrypt commands stop prompting. The read-only ICS feed on 127.0.0.1 is opt-in and off by default: enable it with `daemon start --ics`, or on a running daemon with `daemon ics enable` (which starts the daemon with ICS if it is not running); `daemon ics disable` turns it off again (stops the refresh, clears the cache) without restarting the daemon. When enabled, the daemon keeps the raw calendar events exactly as Proton returns them — still encrypted — in memory only (never on disk), refreshing them in the background every 15 minutes; each feed request decrypts from that cache, so it returns in seconds. Nothing decrypted is ever cached or written to disk. Wait for the "ICS cache ready" line in the daemon log before adding the calendar in Apple Calendar; until the cache is warm the feed serves 503. The feed covers the past 7 days through the next 90 days by default (`--ics-days-past` / `--ics-days-future` override) and exists only while the daemon runs. It backgrounds itself after prompting (`--foreground` keeps it in the foreground); its log is `daemon.log` next to the socket. The daemon is the single owner of the auth token: only it refreshes, and every command gets its access token from it while it runs — so concurrent CLI invocations cannot race each other's refreshes. Any process as the same user can ask the daemon to decrypt — the same gap ssh-agent, gpg-agent and Proton Bridge have. Nothing decrypted is ever written to disk.
6. If a command reports `session_invalid`, run `login` again — do not retry blindly.
7. Account password failures ("wrong account password?") mean unlocking the keys failed. The salted key password is derived from the account password with the salts stored in the session, so a session without salts, or a call that passes the raw password where the salted one is required, fails the same way. Check the salts and the unlock path before asking the user to re-enter the password.
