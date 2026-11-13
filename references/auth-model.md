# Proton skill — credential model

## Why not a connector
Proton authenticates with username + password via SRP (Secure Remote Password),
plus optional TOTP 2FA. `credentials.request_api_access` only supports `api_key`
and `oauth2_code` schemes — a password scheme is declined by name. There is no
scoped token: any integration holds full account credentials. This is accepted
by Tom (2026-09-19); handling must be airtight.

## What is stored
`~/.config/proton-cli/session.json` (mode 0600, outside the git repo):
```json
{"uid": "...", "refresh_token": "...", "salts": [{"ID": "...", "KeySalt": "..."}]}
```
- Created once by `proton-cli login`.
- The **password is never stored**. Every command refreshes the access token
  from the refresh token (`NewClientWithRefresh`) and persists rotated refresh
  tokens automatically.
- `proton-cli logout` revokes the session server-side (`AuthDelete`) and
  deletes the file.

## What is transient
- Login password: read from stdin by `login`, used once for the SRP exchange,
  zeroed afterwards. Never written to disk, never logged.
- TOTP code: read from stdin when `auth.TwoFA` indicates it is required.
- Mailbox password: read from stdin by `mail read --decrypt`,
  `mail send`, and `events --decrypt` whenever message bodies, sending, or
  calendar titles are needed. For most accounts this equals the login password,
  but Proton allows them to differ — hence asked each time, never stored.

## Supplying secrets from the agent
Pipe via stdin, e.g.:
```bash
printf '%s' "$PASSWORD" | proton-cli login --username user@example.com
```
The agent must only do this with a secret the user explicitly supplied for
transient use. Never `echo` a secret into a command line, never put it in
argv or the environment, never write it to a file, never print it.

## 2FA
If the account has TOTP 2FA, `login` prompts for the code on stdin after the
password step. The resulting session is a normal refreshable session — 2FA is
only needed at login time.

## Scope limits of this integration
- Mail: full (list/search metadata, read incl. decrypted bodies, send — sending creates a draft internally as part of the send; there is no standalone draft command).
- Calendar: read-only (list calendars, fetch events incl. decrypted titles).
  No create/update/delete — the library exposes no such endpoints.
- Contacts: read.
- Drive: not wired in v1 (library supports browse/download/upload; add if needed).

## Upgrading the library
The repo pins `github.com/ProtonMail/go-proton-api` in `go.mod`. To upgrade:
```bash
cd ~/workspace/skills/proton
go get github.com/ProtonMail/go-proton-api@latest  # or @<commit>
go mod tidy && go build -o bin/proton-cli ./cmd/proton-cli
git add go.mod go.sum && git commit -m "bump go-proton-api"
```
