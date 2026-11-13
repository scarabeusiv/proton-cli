package main

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// --- iCalendar serializer ---

func TestICSEscapeText(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{in: "plain", want: "plain"},
		{in: "a,b", want: `a\,b`},
		{in: "a;b", want: `a\;b`},
		{in: `a\b`, want: `a\\b`},
		{in: "a\nb", want: `a\nb`},
		{in: "a\r\nb", want: `a\nb`},
		{in: "a,b;c\\d\ne", want: `a\,b\;c\\d\ne`},
		{in: "", want: ""},
	}
	for _, tc := range cases {
		if got := escapeICSText(tc.in); got != tc.want {
			t.Errorf("escapeICSText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestICSFeedTimedEvent(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ev := icsEvent{
		ID:       "ev1",
		Start:    time.Date(2026, 11, 14, 22, 13, 20, 0, time.UTC).Unix(),
		End:      time.Date(2026, 11, 14, 23, 13, 20, 0, time.UTC).Unix(),
		Summary:  "Team, sync; bring notes",
		Location: "Room 1",
	}
	out := icsFeed([]icsEvent{ev}, now)
	for _, want := range []string{
		"BEGIN:VCALENDAR\r\n",
		"VERSION:2.0\r\n",
		"PRODID:-//proton-cli//Proton Calendar//EN\r\n",
		"UID:ev1@proton-cli\r\n",
		"DTSTAMP:20261113T120000Z\r\n",
		"DTSTART:20261114T221320Z\r\n",
		"DTEND:20261114T231320Z\r\n",
		`SUMMARY:Team\, sync\; bring notes` + "\r\n",
		"LOCATION:Room 1\r\n",
		"END:VEVENT\r\n",
		"END:VCALENDAR\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("icsFeed timed event missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "VALUE=DATE") {
		t.Errorf("icsFeed timed event must not use VALUE=DATE:\n%s", out)
	}
}

func TestICSFeedFullDayEvent(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ev := icsEvent{
		ID:      "ev2",
		Start:   time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC).Unix(),
		End:     time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC).Unix(),
		FullDay: true,
		Summary: "Holiday",
	}
	out := icsFeed([]icsEvent{ev}, now)
	for _, want := range []string{
		"UID:ev2@proton-cli\r\n",
		"DTSTART;VALUE=DATE:20261114\r\n",
		"DTEND;VALUE=DATE:20261115\r\n",
		"SUMMARY:Holiday\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("icsFeed full-day event missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DTSTART:20261114T") {
		t.Errorf("icsFeed full-day event must use DATE, not DATETIME:\n%s", out)
	}
}

func TestICSFeedUIDStable(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ev := icsEvent{ID: "ev9", Start: 1700000000, End: 1700003600, Summary: "X"}
	first := icsFeed([]icsEvent{ev}, now)
	// Regenerating later (a different DTSTAMP) must keep the same UID,
	// so a subscribing calendar does not duplicate the event.
	second := icsFeed([]icsEvent{ev}, now.Add(24*time.Hour))
	if !strings.Contains(second, "UID:ev9@proton-cli\r\n") {
		t.Errorf("icsFeed regeneration changed the UID:\n%s", second)
	}
	// And the event body (other than DTSTAMP) is identical.
	strip := func(s string) string {
		lines := strings.Split(s, "\r\n")
		var kept []string
		for _, l := range lines {
			if strings.HasPrefix(l, "DTSTAMP:") {
				continue
			}
			kept = append(kept, l)
		}
		return strings.Join(kept, "\r\n")
	}
	if strip(first) != strip(second) {
		t.Errorf("icsFeed regeneration changed the event body:\n%q\nvs\n%q", strip(first), strip(second))
	}
}

func TestICSFeedEmpty(t *testing.T) {
	out := icsFeed(nil, time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC))
	if !strings.HasPrefix(out, "BEGIN:VCALENDAR\r\n") || !strings.HasSuffix(out, "END:VCALENDAR\r\n") {
		t.Errorf("icsFeed empty = %q, want a VCALENDAR with no VEVENT", out)
	}
	if strings.Contains(out, "VEVENT") {
		t.Errorf("icsFeed empty must contain no VEVENT: %q", out)
	}
}

func TestICSFeedDescription(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ev := icsEvent{ID: "ev3", Start: 1700000000, End: 1700003600, Summary: "S", Description: "Line one\nLine two"}
	out := icsFeed([]icsEvent{ev}, now)
	if !strings.Contains(out, `DESCRIPTION:Line one\nLine two`+"\r\n") {
		t.Errorf("icsFeed description not escaped/present in:\n%s", out)
	}
	// An event without a description omits the property.
	out = icsFeed([]icsEvent{icsEvent{ID: "ev4", Start: 1700000000, End: 1700003600, Summary: "S"}}, now)
	if strings.Contains(out, "DESCRIPTION:") {
		t.Errorf("icsFeed must omit DESCRIPTION when empty:\n%s", out)
	}
}

// --- daemon socket protocol ---

// testKeyRing generates a fast (ed25519) PGP keyring for tests.
func testKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()
	key, err := crypto.GenerateKey("Test", "test@example.com", "ed25519", 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	return kr
}

// testEncryptArmor encrypts plaintext with kr's public key and returns
// the armored PGP message.
func testEncryptArmor(t *testing.T, kr *crypto.KeyRing, plaintext string) string {
	t.Helper()
	enc, err := kr.Encrypt(crypto.NewPlainMessageFromString(plaintext), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	armored, err := enc.GetArmored()
	if err != nil {
		t.Fatalf("GetArmored: %v", err)
	}
	return armored
}

// testEncryptSplit encrypts plain with a fresh session key and returns
// the key packet (base64) and the data packet, i.e. the two halves of a
// PGP split message as decryptAttachment expects them.
func testEncryptSplit(t *testing.T, kr *crypto.KeyRing, plain []byte) (keyPacket string, data []byte) {
	t.Helper()
	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}
	data, err = sk.Encrypt(crypto.NewPlainMessage(plain))
	if err != nil {
		t.Fatalf("SessionKey.Encrypt: %v", err)
	}
	kp, err := kr.EncryptSessionKey(sk)
	if err != nil {
		t.Fatalf("EncryptSessionKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(kp), data
}

// startTestDaemon starts a daemon serving on a temp-dir Unix socket.
// The caller must restore daemonSocketPathOverride when done (via the
// registered cleanup). The daemon is stopped via the stop op or the
// cleanup below.
func startTestDaemon(t *testing.T, d *daemon) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "daemon.sock")
	old := daemonSocketPathOverride
	daemonSocketPathOverride = sock
	t.Cleanup(func() { daemonSocketPathOverride = old })

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on test socket: %v", err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatalf("chmod test socket: %v", err)
	}
	d.listener = ln
	d.done = make(chan struct{})
	go d.serveSocket()
	t.Cleanup(func() {
		ln.Close()
		d.stop()
		_ = os.Remove(sock)
	})
	return sock
}

func TestDaemonPingAndStop(t *testing.T) {
	d := &daemon{addrKR: testKeyRing(t), calKR: make(map[string]*crypto.KeyRing), icsPort: 8765}
	startTestDaemon(t, d)

	running, port := pingDaemon()
	if !running {
		t.Fatal("pingDaemon: daemon is not running")
	}
	if port != 8765 {
		t.Errorf("pingDaemon port = %d, want 8765", port)
	}

	resp, err := daemonRoundTrip(daemonRequest{Op: "stop"})
	if err != nil {
		t.Fatalf("daemon stop: %v", err)
	}
	if !resp.OK {
		t.Fatalf("daemon stop not OK: %v", resp.Error)
	}
	// The daemon shuts down after replying; a later ping must fail.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if running, _ := pingDaemon(); !running {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon still answers after stop")
}

func TestDaemonPingAbsent(t *testing.T) {
	dir := t.TempDir()
	old := daemonSocketPathOverride
	daemonSocketPathOverride = filepath.Join(dir, "no-such.sock")
	t.Cleanup(func() { daemonSocketPathOverride = old })
	if running, _ := pingDaemon(); running {
		t.Fatal("pingDaemon reported running with no daemon present")
	}
	if _, err := daemonDecryptMailBody("x"); err != errDaemonUnavailable {
		t.Errorf("daemonDecryptMailBody without a daemon = %v, want errDaemonUnavailable", err)
	}
}

func TestDaemonDecryptMailBody(t *testing.T) {
	kr := testKeyRing(t)
	d := &daemon{addrKR: kr, calKR: make(map[string]*crypto.KeyRing), icsPort: 8765}
	startTestDaemon(t, d)

	armored := testEncryptArmor(t, kr, "Hello via daemon")
	plain, err := daemonDecryptMailBody(armored)
	if err != nil {
		t.Fatalf("daemonDecryptMailBody: %v", err)
	}
	if string(plain) != "Hello via daemon" {
		t.Errorf("daemonDecryptMailBody = %q, want %q", plain, "Hello via daemon")
	}

	// A body that is not a PGP message is a daemon error, not a fallback.
	if _, err := daemonDecryptMailBody("not a pgp message"); err == nil {
		t.Fatal("daemonDecryptMailBody with garbage: expected error, got nil")
	}
}

func TestDaemonDecryptAttachment(t *testing.T) {
	kr := testKeyRing(t)
	d := &daemon{addrKR: kr, calKR: make(map[string]*crypto.KeyRing), icsPort: 8765}
	startTestDaemon(t, d)

	plain := []byte("attachment bytes here")
	keyPacket, data := testEncryptSplit(t, kr, plain)
	got, err := daemonDecryptAttachment(keyPacket, data)
	if err != nil {
		t.Fatalf("daemonDecryptAttachment: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("daemonDecryptAttachment = %q, want %q", got, plain)
	}
	if _, err := daemonDecryptAttachment("!!!not-base64!!!", data); err == nil {
		t.Fatal("daemonDecryptAttachment with a bad key packet: expected error, got nil")
	}
}

func TestDaemonUnknownOp(t *testing.T) {
	d := &daemon{addrKR: testKeyRing(t), calKR: make(map[string]*crypto.KeyRing), icsPort: 8765}
	startTestDaemon(t, d)

	resp, err := daemonRoundTrip(daemonRequest{Op: "bogus"})
	if err != nil {
		t.Fatalf("daemonRoundTrip: %v", err)
	}
	if resp.OK {
		t.Fatal("daemon answered an unknown op with OK")
	}
	if !strings.Contains(resp.Error, "unknown op") {
		t.Errorf("daemon unknown op error = %q, want it to mention unknown op", resp.Error)
	}
}

// --- daemon-owns-token ops ---

// rotatingDaemon starts a test daemon whose client was built against
// the rotating mock (single-use refresh tokens, Bearer-checked
// endpoints), so the tests below can exercise the 10013 recovery
// paths. The mock's current tokens are test-refresh / test-access;
// the session file is seeded with the same refresh token.
func rotatingDaemon(t *testing.T) (*mockAPI, *daemon) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	m := &mockAPI{t: t, rotatingRefresh: true, currentRefresh: "test-refresh", currentAccess: "test-access"}
	newMockAPIServer(t, m)
	if err := saveSession(session{UID: "test-uid", RefreshToken: "test-refresh"}); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	c, mgr, auth, err := authedClientDirect(context.Background())
	if err != nil {
		t.Fatalf("authedClientDirect: %v", err)
	}
	// The eager refresh rotated test-refresh -> refresh-1 /
	// access-1; the daemon is the only owner of that client now.
	return m, newDaemon(c, mgr, auth, testKeyRing(t), 8765, 30, 365)
}

// TestDaemonAccessTokenOp covers the daemon-owns-token path: the op
// hands out the daemon's current access token, and an expired access
// token triggers a lazy refresh (via the probe) so the op still
// returns a fresh token — and the rotation is persisted.
func TestDaemonAccessTokenOp(t *testing.T) {
	m, d := rotatingDaemon(t)
	startTestDaemon(t, d)

	tok, err := daemonAccessToken()
	if err != nil {
		t.Fatalf("daemonAccessToken: %v", err)
	}
	if tok.UID != "test-uid" || tok.AccessToken != "access-1" {
		t.Errorf("daemonAccessToken = %+v, want UID test-uid / access-1", tok)
	}

	// Expire just the access token: the next op must refresh lazily
	// (refresh token still valid) and hand out the fresh token.
	m.expireAccessToken()
	tok, err = daemonAccessToken()
	if err != nil {
		t.Fatalf("daemonAccessToken after expiry: %v", err)
	}
	if tok.AccessToken != "access-2" {
		t.Errorf("daemonAccessToken after expiry = %q, want access-2", tok.AccessToken)
	}
	s, err := loadSession()
	if err != nil {
		t.Fatalf("loadSession after refresh: %v", err)
	}
	if s.RefreshToken != "refresh-2" {
		t.Errorf("session refresh token = %q, want refresh-2", s.RefreshToken)
	}
}

// TestDaemonAccessTokenOpRecoversFromStaleToken is the regression
// test for the reported 503: another process rotated (and saved) the
// refresh token after the daemon started, so the daemon's held
// refresh token is consumed. The op must still hand out a fresh
// token — the probe's lazy refresh fails with 10013, the daemon
// rebuilds its client from the session file and retries.
func TestDaemonAccessTokenOpRecoversFromStaleToken(t *testing.T) {
	m, d := rotatingDaemon(t)
	startTestDaemon(t, d)

	// Another process rotates the token (as a CLI run does).
	c2, mgr2, _, err := authedClientDirect(context.Background())
	if err != nil {
		t.Fatalf("rotating authedClientDirect: %v", err)
	}
	c2.Close()
	mgr2.Close()

	tok, err := daemonAccessToken()
	if err != nil {
		t.Fatalf("daemonAccessToken after rotation: %v", err)
	}
	m.mu.Lock()
	want := m.currentAccess
	m.mu.Unlock()
	if tok.AccessToken != want {
		t.Errorf("daemonAccessToken after rotation = %q, want the mock's current %q", tok.AccessToken, want)
	}
}

// TestDaemonBuildICSFeedRecoversFromStaleToken is the same recovery
// at the feed level: the 503 the daemon served was a feed build
// failing on a stale refresh token. After a rotation by another
// process, the feed must still build (empty VCALENDAR here — the
// mock has no calendars).
func TestDaemonBuildICSFeedRecoversFromStaleToken(t *testing.T) {
	_, d := rotatingDaemon(t)

	c2, mgr2, _, err := authedClientDirect(context.Background())
	if err != nil {
		t.Fatalf("rotating authedClientDirect: %v", err)
	}
	c2.Close()
	mgr2.Close()

	feed, err := d.buildICSFeedWithRetry(context.Background())
	if err != nil {
		t.Fatalf("buildICSFeedWithRetry after rotation: %v", err)
	}
	if !strings.HasPrefix(feed, "BEGIN:VCALENDAR\r\n") || !strings.HasSuffix(feed, "END:VCALENDAR\r\n") {
		t.Errorf("buildICSFeedWithRetry = %q, want an empty VCALENDAR", feed)
	}
}

// TestStdinIsTTY pins the /dev/null regression: in `go test` stdin
// is /dev/null, which IS a character device — a ModeCharDevice check
// alone returned true for it, so decrypt commands tried to start a
// daemon (and, in the test binary, re-exec'd the suite as
// `daemon start`, recursing until the suite timed out).
func TestStdinIsTTY(t *testing.T) {
	if stdinIsTTY() {
		t.Error("stdinIsTTY with test stdin = true, want false")
	}
}

func TestIsTestBinary(t *testing.T) {
	if !isTestBinary("/tmp/go-build123/b001/proton-cli.test") {
		t.Error("isTestBinary(test binary) = false, want true")
	}
	if isTestBinary("/Users/fluff/bin/proton-cli") {
		t.Error("isTestBinary(real binary) = true, want false")
	}
}

// TestEnsureDaemonForDecrypt covers the on-demand start: with a
// daemon answering it is used; with none and non-TTY stdin (as in
// `go test`) it does not spawn one, and the caller falls back to
// prompting.
func TestEnsureDaemonForDecrypt(t *testing.T) {
	dir := t.TempDir()
	old := daemonSocketPathOverride
	daemonSocketPathOverride = filepath.Join(dir, "no-such.sock")
	t.Cleanup(func() { daemonSocketPathOverride = old })

	if ensureDaemonForDecrypt() {
		t.Fatal("ensureDaemonForDecrypt with no daemon and piped stdin: got true, want false")
	}

	d := &daemon{addrKR: testKeyRing(t), calKR: make(map[string]*crypto.KeyRing), icsPort: 8765}
	startTestDaemon(t, d)
	if !ensureDaemonForDecrypt() {
		t.Fatal("ensureDaemonForDecrypt with a running daemon: got false, want true")
	}
}
