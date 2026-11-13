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
proton-cli mail read [--decrypt] <message-id> # --decrypt reads mailbox password from stdin
proton-cli mail send --to a@b [--cc c@d] --subject S --body-file PATH [--from addr]

proton-cli calendars
proton-cli events --calendar ID [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--decrypt]
proton-cli contacts [--query X] [--limit N]
```

Most commands emit JSON on stdout; errors go to stderr. The `keys` and
`event-raw` diagnostics print plain text instead of JSON. Label IDs: 0 = inbox, 1 = all mail, 5 = sent (see `proton-cli mail list --label 1` to discover more via message LabelIDs).

## Auth
No connector exists for Proton (username+password SRP login is not a supported connector scheme). Auth state is a session UID + refresh token at `~/.config/proton-cli/session.json` (mode 0600), created by `proton-cli login`. The password is never stored — only the refreshable session. See `references/auth-model.md` for the full credential model.

First-time setup needs the user's Proton password (and TOTP code if 2FA is on) supplied transiently — never stored, never logged. Ask for it only when actually running `login`.

## Operating Rules
1. Secrets only ever travel via stdin pipes. Never put passwords, TOTP codes, or mailbox passwords in argv, environment variables, files, chat messages, or logs.
2. Never send email without showing the user the exact draft and receiving their approval first.
3. Calendar is read-only in this integration: list calendars and fetch events only. Do not attempt event create/update/delete — the library has no such endpoints.
4. `mail read` without `--decrypt` returns metadata + headers only; bodies need the mailbox password (usually the login password), asked for transiently each time.
5. If a command reports `session_invalid`, run `login` again — do not retry blindly.
6. Mailbox password failures ("wrong mailbox password?") mean unlocking the keys failed — not necessarily that the login and mailbox passwords differ. The salted key password is derived from the mailbox password with the salts stored in the session, so a session without salts, or a call that passes the raw password where the salted one is required, fails the same way. Check the salts and the unlock path before asking the user about differing passwords.
