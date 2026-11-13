// Unit tests for the pure, dependency-free logic in proton-cli.
//
// These complement cmd/proton-cli/main_test.go (PR #3), which covers
// validateLimit, parseAddrList, isBareAddress, formatKeyMeta and
// defaultSender. Nothing tested there is re-tested here; the test
// function names are distinct so the two files merge cleanly.
package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	gomail "net/mail"
)

func TestDecodeKeyPacket(t *testing.T) {
	cases := []struct {
		in   string
		want []byte // nil means "want nil"
	}{
		{in: "", want: nil},
		{in: "aGVsbG8=", want: []byte("hello")},
		{in: "!!!not-base64!!!", want: nil},
		{in: "aGVsbG8", want: nil}, // missing padding: StdEncoding rejects it
		{in: "AAEC", want: []byte{0, 1, 2}},
	}
	for _, tc := range cases {
		got := decodeKeyPacket(tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("decodeKeyPacket(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIcalProp(t *testing.T) {
	ical := "BEGIN:VEVENT\r\nUID:abc-123\r\nSUMMARY:Hello World\r\nLOCATION:Paris\r\nEND:VEVENT"
	if got := icalProp(ical, "SUMMARY"); got != "Hello World" {
		t.Errorf("icalProp SUMMARY = %q, want %q", got, "Hello World")
	}
	if got := icalProp(ical, "LOCATION"); got != "Paris" {
		t.Errorf("icalProp LOCATION = %q, want %q", got, "Paris")
	}
	if got := icalProp(ical, "DESCRIPTION"); got != "" {
		t.Errorf("icalProp missing property = %q, want empty", got)
	}
	// Property names match exactly: lowercase does not match.
	if got := icalProp(ical, "summary"); got != "" {
		t.Errorf("icalProp lowercase name = %q, want empty", got)
	}
	// Parameters after the property name are ignored.
	if got := icalProp("SUMMARY;LANGUAGE=en:Bonjour", "SUMMARY"); got != "Bonjour" {
		t.Errorf("icalProp with params = %q, want %q", got, "Bonjour")
	}
	// A colon inside the value is part of the value.
	if got := icalProp("SUMMARY:Hello: World", "SUMMARY"); got != "Hello: World" {
		t.Errorf("icalProp colon in value = %q, want %q", got, "Hello: World")
	}
	// Folded continuation lines are unfolded.
	if got := icalProp("SUMMARY:Hello\n World", "SUMMARY"); got != "HelloWorld" {
		t.Errorf("icalProp folded = %q, want %q", got, "HelloWorld")
	}
	// Escapes in the value are unescaped.
	if got := icalProp("SUMMARY:Hello\\nWorld", "SUMMARY"); got != "Hello\nWorld" {
		t.Errorf("icalProp escaped = %q, want %q", got, "Hello\nWorld")
	}
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{in: "a\nb\nc", want: []string{"a", "b", "c"}},
		{in: "a\r\nb\r\n", want: []string{"a", "b"}},
		{in: "a", want: []string{"a"}},
		{in: "a\n", want: []string{"a"}},
		{in: "", want: nil},
		{in: "\n", want: []string{""}},
	}
	for _, tc := range cases {
		got := splitLines(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitLines(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("splitLines(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestIndexOf(t *testing.T) {
	if got := indexOf("hello", 'l'); got != 2 {
		t.Errorf("indexOf(hello, l) = %d, want 2", got)
	}
	if got := indexOf("hello", 'x'); got != -1 {
		t.Errorf("indexOf(hello, x) = %d, want -1", got)
	}
	if got := indexOf("", 'a'); got != -1 {
		t.Errorf("indexOf(empty, a) = %d, want -1", got)
	}
	if got := indexOf("a:b:c", ':'); got != 1 {
		t.Errorf("indexOf(a:b:c, :) = %d, want 1", got)
	}
}

func TestUnescapeICalText(t *testing.T) {
	cases := map[string]string{
		`Hello\nWorld`:  "Hello\nWorld",
		`Hello\NWorld`:  "Hello\nWorld",
		`a\,b`:          "a,b",
		`a\;b`:          "a;b",
		`a\\b`:          `a\b`,
		`a\xb`:          "axb",  // unknown escape: the char itself
		`abc\`:          `abc\`, // trailing backslash is kept
		``:              "",
		`no escapes`:    "no escapes",
		`multi\n\nline`: "multi\n\nline",
	}
	for in, want := range cases {
		if got := unescapeICalText(in); got != want {
			t.Errorf("unescapeICalText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDateOr(t *testing.T) {
	fallback := time.Date(2026, 11, 13, 15, 4, 5, 0, time.UTC)

	// Empty input falls back to the fallback date truncated to midnight.
	got, err := parseDateOr("", fallback)
	if err != nil {
		t.Fatalf("parseDateOr(\"\") error: %v", err)
	}
	want := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parseDateOr(\"\") = %v, want %v", got, want)
	}

	// A valid date parses as midnight UTC.
	got, err = parseDateOr("2026-11-13", fallback)
	if err != nil {
		t.Fatalf("parseDateOr(2026-11-13) error: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("parseDateOr(2026-11-13) = %v, want %v", got, want)
	}

	// Bad formats are errors, not silent fallbacks.
	for _, bad := range []string{"13/11/2026", "2026-13-01", "2026-11-13T10:00", "tomorrow", "2026-2-3"} {
		if _, err := parseDateOr(bad, fallback); err == nil {
			t.Errorf("parseDateOr(%q): expected error, got nil", bad)
		}
	}
}

func TestSummarize(t *testing.T) {
	m := proton.MessageMetadata{
		ID:      "msg1",
		Subject: "Hello",
		Sender:  &gomail.Address{Address: "alice@example.com"},
		ToList: []*gomail.Address{
			{Address: "bob@example.com"},
			nil, // nil entries are skipped
			{Address: "carol@example.com"},
		},
		Time:           1700000000, // 2023-11-14T22:13:20Z
		Unread:         true,
		LabelIDs:       []string{"0", "5"},
		NumAttachments: 2,
	}
	s := summarize(m)
	if s.ID != "msg1" || s.Subject != "Hello" || s.From != "alice@example.com" {
		t.Errorf("summarize identity = %+v", s)
	}
	if len(s.To) != 2 || s.To[0] != "bob@example.com" || s.To[1] != "carol@example.com" {
		t.Errorf("summarize To = %v, want [bob@example.com carol@example.com]", s.To)
	}
	if s.TimeRFC3339 != "2023-11-14T22:13:20Z" {
		t.Errorf("summarize TimeRFC3339 = %q, want %q", s.TimeRFC3339, "2023-11-14T22:13:20Z")
	}
	if !s.Unread {
		t.Error("summarize Unread = false, want true")
	}
	if len(s.Labels) != 2 || s.Attachments != 2 {
		t.Errorf("summarize Labels/Attachments = %v/%d, want [0 5]/2", s.Labels, s.Attachments)
	}

	// Nil sender means an empty From, not a crash.
	m.Sender = nil
	m.ToList = nil
	s = summarize(m)
	if s.From != "" {
		t.Errorf("summarize nil sender From = %q, want empty", s.From)
	}
	if len(s.To) != 0 {
		t.Errorf("summarize nil ToList = %v, want empty", s.To)
	}
}

func TestDecryptEventDetailsNoParts(t *testing.T) {
	ev := &proton.CalendarEvent{ID: "ev1"}
	summary, location, err := decryptEventDetails(ev, nil, nil)
	if err == nil {
		t.Fatal("decryptEventDetails with no parts: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no parts to decrypt") {
		t.Errorf("decryptEventDetails error = %v, want it to mention no parts", err)
	}
	if summary != "" || location != "" {
		t.Errorf("decryptEventDetails no parts = %q/%q, want empty", summary, location)
	}
}

func TestDecryptEventDetailsPlainPart(t *testing.T) {
	// A plain (neither encrypted nor signed) part needs no keyring:
	// decryptPart returns its data as-is.
	ev := &proton.CalendarEvent{
		ID: "ev1",
		SharedEvents: []proton.CalendarEventPart{
			{Type: 0, Data: "BEGIN:VEVENT\nSUMMARY:Hello\nLOCATION:Paris\nEND:VEVENT"},
		},
	}
	summary, location, err := decryptEventDetails(ev, nil, nil)
	if err != nil {
		t.Fatalf("decryptEventDetails plain part error: %v", err)
	}
	if summary != "Hello" || location != "Paris" {
		t.Errorf("decryptEventDetails = %q/%q, want Hello/Paris", summary, location)
	}
}

func TestDecryptEventDetailsPlainPartNoFields(t *testing.T) {
	ev := &proton.CalendarEvent{
		ID: "ev1",
		SharedEvents: []proton.CalendarEventPart{
			{Type: 0, Data: "BEGIN:VEVENT\nUID:x\nEND:VEVENT"},
		},
	}
	_, _, err := decryptEventDetails(ev, nil, nil)
	if err == nil {
		t.Fatal("decryptEventDetails with no SUMMARY/LOCATION: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no SUMMARY/LOCATION") {
		t.Errorf("decryptEventDetails error = %v, want it to mention SUMMARY/LOCATION", err)
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 255}
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("zero: byte %d = %d, want 0", i, v)
		}
	}
	// Zeroing nil / empty slices must not panic.
	zero(nil)
	zero([]byte{})
}

func TestSessionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	want := session{
		UID:          "test-uid",
		RefreshToken: "test-refresh",
		Salts:        proton.Salts{{ID: "key1", KeySalt: "c2FsdA=="}},
	}
	if err := saveSession(want); err != nil {
		t.Fatalf("saveSession: %v", err)
	}

	p, err := sessionPath()
	if err != nil {
		t.Fatalf("sessionPath: %v", err)
	}
	if got := filepath.Join(dir, "proton-cli", "session.json"); p != got {
		t.Errorf("sessionPath = %q, want %q", p, got)
	}

	// The session file is 0600 and its directory 0700.
	if fi, err := os.Stat(p); err != nil {
		t.Fatalf("stat session file: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("session file mode = %o, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(p)); err != nil {
		t.Fatalf("stat session dir: %v", err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("session dir mode = %o, want 0700", fi.Mode().Perm())
	}

	got, err := loadSession()
	if err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got.UID != want.UID || got.RefreshToken != want.RefreshToken {
		t.Errorf("loadSession = %+v, want %+v", got, want)
	}
	if len(got.Salts) != 1 || got.Salts[0].ID != "key1" || got.Salts[0].KeySalt != "c2FsdA==" {
		t.Errorf("loadSession salts = %+v, want the stored salt", got.Salts)
	}

	// Re-saving over a pre-existing lax-mode file re-enforces 0600.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := saveSession(want); err != nil {
		t.Fatalf("saveSession (re-save): %v", err)
	}
	if fi, err := os.Stat(p); err != nil {
		t.Fatalf("stat after re-save: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("session file mode after re-save = %o, want 0600", fi.Mode().Perm())
	}

	// clearSession removes the file; a later load reports no session.
	if err := clearSession(); err != nil {
		t.Fatalf("clearSession: %v", err)
	}
	if _, err := loadSession(); !errors.Is(err, errNoSession) {
		t.Errorf("loadSession after clear: err = %v, want errNoSession", err)
	}
	// Clearing twice is fine.
	if err := clearSession(); err != nil {
		t.Errorf("clearSession twice: %v", err)
	}
}

func TestLoadSessionErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// No file at all: errNoSession, not a generic error.
	if _, err := loadSession(); !errors.Is(err, errNoSession) {
		t.Errorf("loadSession missing file: err = %v, want errNoSession", err)
	}

	p, err := sessionPath()
	if err != nil {
		t.Fatalf("sessionPath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Corrupt JSON.
	if err := os.WriteFile(p, []byte("not json{"), 0o600); err != nil {
		t.Fatalf("write corrupt session: %v", err)
	}
	if _, err := loadSession(); err == nil || !strings.Contains(err.Error(), "corrupt session file") {
		t.Errorf("loadSession corrupt file: err = %v, want a corrupt-session error", err)
	}

	// Valid JSON but missing UID / refresh token.
	if err := os.WriteFile(p, []byte(`{"uid":"","refresh_token":""}`), 0o600); err != nil {
		t.Fatalf("write incomplete session: %v", err)
	}
	if _, err := loadSession(); err == nil || !strings.Contains(err.Error(), "incomplete session") {
		t.Errorf("loadSession incomplete: err = %v, want an incomplete-session error", err)
	}
}

// TestSaltForKey pins the go-proton-api contract the repo relies on:
// SaltForKey errors when no salt exists for the key ID, but returns
// (nil, nil) — no error, empty result — when the salt entry exists with
// an empty KeySalt. Callers must therefore check len(salted) == 0 after
// SaltForKey, not just err; a nil salted password cannot unlock anything
// and only fails later as a misleading "wrong mailbox password?" error.
func TestSaltForKey(t *testing.T) {
	// No salt for the key: an error, not a silent nil.
	if out, err := (proton.Salts{}).SaltForKey([]byte("password"), "no-such-key"); err == nil {
		t.Errorf("SaltForKey with no salts: out len %d, err nil; want an error", len(out))
	}
	salts := proton.Salts{{ID: "other-key", KeySalt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
	if out, err := salts.SaltForKey([]byte("password"), "no-such-key"); err == nil {
		t.Errorf("SaltForKey with a different key ID: out len %d, err nil; want an error", len(out))
	}

	// Salt entry present but KeySalt empty: (nil, nil) — fail-open.
	// This is the case the len(salted) == 0 defence exists for.
	empty := proton.Salts{{ID: "key1", KeySalt: ""}}
	out, err := empty.SaltForKey([]byte("password"), "key1")
	if err != nil {
		t.Errorf("SaltForKey with empty KeySalt: unexpected error %v", err)
	}
	if len(out) != 0 {
		t.Errorf("SaltForKey with empty KeySalt: got %d bytes, want 0", len(out))
	}
}
