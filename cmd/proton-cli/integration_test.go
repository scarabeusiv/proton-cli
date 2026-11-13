// Integration tests for proton-cli.
//
// Two layers, both hermetic (no real Proton credentials, no network
// access to Proton):
//
//   - CLI-level tests run the compiled binary with a clean HOME /
//     XDG_CONFIG_HOME, exercising flag parsing, usage errors and the
//     no-session paths end to end.
//   - API-mock tests point the client at an httptest server (via the
//     apiHostURL override in manager.go) that mimics the Proton API
//     endpoints the commands call, and drive the real command
//     functions against it, verifying the JSON they emit.
//
// The mock only implements the endpoints these tests need
// (/auth/v4/refresh, /calendar/v1, /calendar/v1/{id}/events,
// /core/v4/users, /mail/v4/messages). Anything else returns 404, so a
// command hitting an unexpected endpoint fails loudly instead of
// silently passing.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// ---------------------------------------------------------------------------
// Test binary (for the CLI-level tests)
// ---------------------------------------------------------------------------

var (
	testBinaryOnce sync.Once
	testBinaryPath string
	testBinaryErr  error
)

// getTestBinary builds the CLI binary once per test run and returns its path.
func getTestBinary(t *testing.T) string {
	t.Helper()
	testBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "proton-cli-testbin-")
		if err != nil {
			testBinaryErr = err
			return
		}
		path := filepath.Join(dir, "proton-cli")
		cmd := exec.Command("go", "build", "-o", path, ".")
		out, err := cmd.CombinedOutput()
		if err != nil {
			testBinaryErr = fmt.Errorf("build test binary: %w: %s", err, out)
			return
		}
		testBinaryPath = path
	})
	if testBinaryErr != nil {
		t.Fatal(testBinaryErr)
	}
	return testBinaryPath
}

// runCLI runs the test binary with a hermetic environment (a fresh HOME
// and XDG_CONFIG_HOME, so it can never see a real session) and returns
// its stdout, stderr and exit code.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := getTestBinary(t)
	home := t.TempDir()
	cfg := t.TempDir()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+cfg,
	)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		exitCode = 0
	} else if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else {
		t.Fatalf("runCLI %v: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestCLIUsageNoArgs(t *testing.T) {
	_, stderr, code := runCLI(t)
	if code != 2 {
		t.Errorf("no args: exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("no args: stderr = %q, want it to contain Usage:", stderr)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	_, stderr, code := runCLI(t, "bogus")
	if code != 2 {
		t.Errorf("unknown command: exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("unknown command: stderr = %q, want it to mention unknown command", stderr)
	}
}

func TestCLIHelp(t *testing.T) {
	_, stderr, code := runCLI(t, "help")
	if code != 0 {
		t.Errorf("help: exit code = %d, want 0", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("help: stderr = %q, want it to contain Usage:", stderr)
	}
}

func TestCLIMailNoSubcommand(t *testing.T) {
	_, stderr, code := runCLI(t, "mail")
	if code != 1 {
		t.Errorf("mail with no subcommand: exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "usage: proton-cli mail") {
		t.Errorf("mail with no subcommand: stderr = %q, want the mail usage", stderr)
	}
}

func TestCLIMailSendMissingFlags(t *testing.T) {
	_, stderr, code := runCLI(t, "mail", "send")
	if code != 1 {
		t.Errorf("mail send with no flags: exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "--to and --subject are required") {
		t.Errorf("mail send with no flags: stderr = %q, want the --to/--subject error", stderr)
	}
}

func TestCLIEventsMissingCalendar(t *testing.T) {
	_, stderr, code := runCLI(t, "events")
	if code != 1 {
		t.Errorf("events with no --calendar: exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "--calendar is required") {
		t.Errorf("events with no --calendar: stderr = %q, want the --calendar error", stderr)
	}
}

func TestCLIMailReadMissingID(t *testing.T) {
	_, stderr, code := runCLI(t, "mail", "read")
	if code != 1 {
		t.Errorf("mail read with no id: exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "usage: proton-cli mail read") {
		t.Errorf("mail read with no id: stderr = %q, want the read usage", stderr)
	}
}

func TestCLIDaemonNoSubcommand(t *testing.T) {
	_, stderr, code := runCLI(t, "daemon")
	if code == 0 {
		t.Fatal("daemon with no subcommand: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "usage: proton-cli daemon") {
		t.Errorf("daemon with no subcommand: stderr = %q, want the daemon usage", stderr)
	}
}

func TestCLIDaemonUnknownSubcommand(t *testing.T) {
	_, stderr, code := runCLI(t, "daemon", "bogus")
	if code == 0 {
		t.Fatal("daemon bogus: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "unknown daemon subcommand") {
		t.Errorf("daemon bogus: stderr = %q, want unknown daemon subcommand", stderr)
	}
}

func TestCLIDaemonStatusNotRunning(t *testing.T) {
	out, _, code := runCLI(t, "daemon", "status")
	if code != 0 {
		t.Fatalf("daemon status: exit code %d, want 0", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("daemon status output is not JSON: %v (%q)", err, out)
	}
	if got["running"] != false {
		t.Errorf("daemon status = %v, want running=false", got)
	}
}

func TestCLIDaemonStopNotRunning(t *testing.T) {
	_, stderr, code := runCLI(t, "daemon", "stop")
	if code == 0 {
		t.Fatal("daemon stop with no daemon: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "daemon is not running") {
		t.Errorf("daemon stop: stderr = %q, want daemon is not running", stderr)
	}
}

func TestCLIDaemonICSNotRunning(t *testing.T) {
	_, stderr, code := runCLI(t, "daemon", "ics")
	if code == 0 {
		t.Fatal("daemon ics with no daemon: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "daemon is not running") {
		t.Errorf("daemon ics: stderr = %q, want daemon is not running", stderr)
	}
}

func TestCLIDaemonStartBadPort(t *testing.T) {
	_, stderr, code := runCLI(t, "daemon", "start", "--ics-port", "0")
	if code == 0 {
		t.Fatal("daemon start --ics-port 0: expected non-zero exit, got 0")
	}
	if !strings.Contains(stderr, "--ics-port must be 1-65535") {
		t.Errorf("daemon start --ics-port 0: stderr = %q, want the port range error", stderr)
	}
}

func TestCLIStatusNoSession(t *testing.T) {
	stdout, _, code := runCLI(t, "status")
	if code != 0 {
		t.Errorf("status with no session: exit code = %d, want 0", code)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("status with no session: stdout is not JSON: %v (%q)", err, stdout)
	}
	if got["status"] != "no_session" {
		t.Errorf("status with no session = %v, want {status: no_session}", got)
	}
}

func TestCLICalendarsNoSession(t *testing.T) {
	_, stderr, code := runCLI(t, "calendars")
	if code != 1 {
		t.Errorf("calendars with no session: exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "no session") {
		t.Errorf("calendars with no session: stderr = %q, want it to mention no session", stderr)
	}
}

// ---------------------------------------------------------------------------
// Mock Proton API (httptest) for the command-level tests
// ---------------------------------------------------------------------------

// mockAPI is a minimal fake Proton API. It only implements the endpoints
// the tested commands call; anything else is a 404 so a command hitting
// an unexpected endpoint fails loudly.
type mockAPI struct {
	t *testing.T

	// refreshErr makes POST /auth/v4/refresh fail.
	refreshErr bool
	// refreshFailFirst makes the first POST /auth/v4/refresh fail with
	// 10013 (a stale token); later refreshes use the normal path.
	refreshFailFirst bool
	// onRefresh, when set, runs on every POST /auth/v4/refresh before
	// the response is written. Tests use it to simulate another
	// process rotating (and saving) the session mid-refresh.
	onRefresh func()
	// calendarsErr makes GET /calendar/v1 fail.
	calendarsErr bool
	// eventsFullPages makes the events endpoint return a full page
	// (100 events) on every page, so listCalendarEvents hits its cap.
	eventsFullPages bool
	// rotatingRefresh makes POST /auth/v4/refresh enforce single-use
	// refresh tokens (a presented token other than the current one
	// fails with 10013) and makes the calendar/user endpoints reject
	// a stale access token with 401, mimicking Proton's rotation.
	rotatingRefresh bool

	calendars []map[string]any
	events    []map[string]any // paged by 100, in order
	user      map[string]any
	addresses []map[string]any
	messages  []map[string]any
	// currentRefresh/currentAccess are the tokens the rotating mock
	// currently accepts. Tests seed them and the session file alike.
	currentRefresh string
	currentAccess  string
	refreshSeq     int

	mu           sync.Mutex
	eventQueries []url.Values // Begin/End seen on the events endpoint
	refreshCalls int
}

// expireAccessToken makes the rotating mock reject the current access
// token (as if it expired) while leaving the refresh token valid, so
// the next API call triggers a lazy refresh.
func (m *mockAPI) expireAccessToken() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentAccess = "access-expired"
}

// validAccess reports whether r carries the mock's current access
// token. Only meaningful with rotatingRefresh.
func (m *mockAPI) validAccess(r *http.Request) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return r.Header.Get("Authorization") == "Bearer "+m.currentAccess
}

func (m *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/auth/v4/refresh":
		m.mu.Lock()
		m.refreshCalls++
		calls := m.refreshCalls
		m.mu.Unlock()
		if m.onRefresh != nil {
			m.onRefresh()
		}
		if m.refreshErr {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"Code":10013,"Error":"invalid refresh token"}`)
			return
		}
		if m.refreshFailFirst && calls == 1 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"Code":10013,"Error":"invalid refresh token"}`)
			return
		}
		if m.rotatingRefresh {
			var req struct {
				RefreshToken string
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			m.mu.Lock()
			if req.RefreshToken != m.currentRefresh {
				m.mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"Code":10013,"Error":"invalid refresh token"}`)
				return
			}
			m.refreshSeq++
			m.currentRefresh = fmt.Sprintf("refresh-%d", m.refreshSeq)
			m.currentAccess = fmt.Sprintf("access-%d", m.refreshSeq)
			acc, ref := m.currentAccess, m.currentRefresh
			m.mu.Unlock()
			// Top-level tokens: the library's refresh response is
			// `struct { Auth }` with promoted fields, so it reads
			// AccessToken/RefreshToken at the top level, not nested
			// under "Auth".
			fmt.Fprintf(w, `{"Code":1000,"UID":"test-uid","AccessToken":%q,"RefreshToken":%q}`, acc, ref)
			return
		}
		fmt.Fprint(w, `{"Code":1000,"UID":"test-uid","AccessToken":"test-access","RefreshToken":"test-refresh-new"}`)
	case r.Method == http.MethodGet && r.URL.Path == "/calendar/v1":
		if m.rotatingRefresh && !m.validAccess(r) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":10012,"Error":"invalid access token"}`)
			return
		}
		if m.calendarsErr {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"Code":2000,"Error":"calendar list failed"}`)
			return
		}
		writeJSON(w, map[string]any{"Code": 1000, "Calendars": m.calendars})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/calendar/v1/") && strings.HasSuffix(r.URL.Path, "/events"):
		if m.rotatingRefresh && !m.validAccess(r) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":10012,"Error":"invalid access token"}`)
			return
		}
		m.mu.Lock()
		m.eventQueries = append(m.eventQueries, r.URL.Query())
		m.mu.Unlock()
		page, _ := strconv.Atoi(r.URL.Query().Get("Page"))
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("PageSize"))
		if pageSize <= 0 {
			pageSize = 100
		}
		var out []map[string]any
		if m.eventsFullPages {
			out = make([]map[string]any, 0, pageSize)
			for i := 0; i < pageSize; i++ {
				out = append(out, map[string]any{
					"ID":         fmt.Sprintf("ev-full-%d-%d", page, i),
					"CalendarID": "cal1",
					"StartTime":  1700000000,
					"EndTime":    1700003600,
					"FullDay":    0,
				})
			}
		} else {
			start := page * pageSize
			if start < len(m.events) {
				end := start + pageSize
				if end > len(m.events) {
					end = len(m.events)
				}
				out = m.events[start:end]
			}
		}
		writeJSON(w, map[string]any{"Code": 1000, "Events": out})
	case r.Method == http.MethodGet && r.URL.Path == "/core/v4/users":
		if m.rotatingRefresh && !m.validAccess(r) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":10012,"Error":"invalid access token"}`)
			return
		}
		writeJSON(w, map[string]any{"Code": 1000, "User": m.user})
	case r.Method == http.MethodGet && r.URL.Path == "/core/v4/addresses":
		if m.rotatingRefresh && !m.validAccess(r) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"Code":10012,"Error":"invalid access token"}`)
			return
		}
		writeJSON(w, map[string]any{"Code": 1000, "Addresses": m.addresses})
	case r.Method == http.MethodPost && r.URL.Path == "/mail/v4/messages":
		// Serves both the count request (Limit 0) and the page
		// request: the count reader only looks at Total, the page
		// reader only at Messages.
		writeJSON(w, map[string]any{"Code": 1000, "Total": len(m.messages), "Messages": m.messages})
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"Code":404,"Error":"mock has no handler for %s %s"}`, r.Method, r.URL.Path)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(b)
}

// newMockAPIServer starts an httptest server backed by m and points the
// CLI at it (via the apiHostURL override), without writing a session.
// Tests that manage the session file themselves (rotating-token tests,
// the CLI-level daemon test) use this; the rest use newMockAPI.
func newMockAPIServer(t *testing.T, m *mockAPI) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	old := apiHostURL
	apiHostURL = srv.URL
	t.Cleanup(func() { apiHostURL = old })
	return srv
}

// newMockAPI starts an httptest server backed by m and points the CLI at
// it (via the apiHostURL override). It also writes a fake session into a
// fresh XDG_CONFIG_HOME so the commands can authenticate. The override
// and the server are restored/closed when the test ends.
func newMockAPI(t *testing.T, m *mockAPI) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	old := apiHostURL
	apiHostURL = srv.URL
	t.Cleanup(func() { apiHostURL = old })

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := saveSession(session{UID: "test-uid", RefreshToken: "test-refresh"}); err != nil {
		t.Fatalf("saveSession for mock: %v", err)
	}
	return srv
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// what fn wrote there, plus fn's error.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fnErr := fn()
	w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String(), fnErr
}

func testCalendars() []map[string]any {
	return []map[string]any{
		{"ID": "cal1", "Name": "Test Cal", "Description": "d", "Color": "#ff0000", "Display": 1},
	}
}

func testEvents() []map[string]any {
	return []map[string]any{
		{"ID": "ev1", "CalendarID": "cal1", "StartTime": 1700000000, "EndTime": 1700003600, "FullDay": 0},
		{"ID": "ev2", "CalendarID": "cal1", "StartTime": 1700004600, "EndTime": 1700005500, "FullDay": 0},
	}
}

func testMessages() []map[string]any {
	return []map[string]any{
		{
			"ID": "m1", "Subject": "Hello",
			"Sender":         map[string]any{"Name": "Alice", "Address": "alice@example.com"},
			"ToList":         []map[string]any{{"Address": "bob@example.com"}},
			"Time":           1700000000,
			"Unread":         1,
			"LabelIDs":       []string{"0"},
			"NumAttachments": 0,
		},
		{
			"ID": "m2", "Subject": "World",
			"Sender":         map[string]any{"Name": "Carol", "Address": "carol@example.com"},
			"ToList":         []map[string]any{{"Address": "dave@example.com"}},
			"Time":           1700003600,
			"Unread":         0,
			"LabelIDs":       []string{"0"},
			"NumAttachments": 1,
		},
	}
}

func TestIntegrationCalendars(t *testing.T) {
	m := &mockAPI{t: t, calendars: testCalendars()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdCalendars(context.Background(), []string{})
	})
	if err != nil {
		t.Fatalf("cmdCalendars: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdCalendars output is not JSON: %v (%q)", err, out)
	}
	if len(got) != 1 || got[0]["id"] != "cal1" || got[0]["name"] != "Test Cal" {
		t.Errorf("cmdCalendars = %v, want one calendar cal1/Test Cal", got)
	}
}

func TestIntegrationEvents(t *testing.T) {
	m := &mockAPI{t: t, calendars: testCalendars(), events: testEvents()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdEvents(context.Background(), []string{
			"--calendar", "cal1", "--from", "2023-11-14", "--to", "2023-11-15",
		})
	})
	if err != nil {
		t.Fatalf("cmdEvents: %v", err)
	}
	var got []eventSummary
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdEvents output is not JSON: %v (%q)", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("cmdEvents returned %d events, want 2: %q", len(got), out)
	}
	if got[0].ID != "ev1" || got[0].StartText != "2023-11-14T22:13:20Z" || got[0].EndText != "2023-11-14T23:13:20Z" {
		t.Errorf("cmdEvents[0] = %+v, want ev1 22:13:20Z-23:13:20Z", got[0])
	}
	if got[1].ID != "ev2" || got[1].StartText != "2023-11-14T23:30:00Z" || got[1].EndText != "2023-11-14T23:45:00Z" {
		t.Errorf("cmdEvents[1] = %+v, want ev2 23:30:00Z-23:45:00Z", got[1])
	}

	// The Begin/End filter was sent to the server for the requested range.
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.eventQueries) == 0 {
		t.Fatal("no events request reached the mock")
	}
	q := m.eventQueries[0]
	// 2023-11-14 00:00 UTC and 2023-11-15 00:00 UTC.
	if q.Get("Begin") != "1699920000" || q.Get("End") != "1700006400" {
		t.Errorf("events request Begin/End = %q/%q, want 1699920000/1700006400", q.Get("Begin"), q.Get("End"))
	}
}

func TestIntegrationEventsDecryptEmptyRange(t *testing.T) {
	// No events at all: --decrypt must not prompt for the account password.
	m := &mockAPI{t: t, calendars: testCalendars(), events: nil}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdEvents(context.Background(), []string{
			"--calendar", "cal1", "--from", "2023-11-14", "--to", "2023-11-15", "--decrypt",
		})
	})
	if err != nil {
		t.Fatalf("cmdEvents --decrypt on empty range: %v", err)
	}
	if strings.TrimSpace(out) != "[]" {
		t.Errorf("cmdEvents --decrypt on empty range = %q, want []", out)
	}
}

func TestIntegrationStatus(t *testing.T) {
	m := &mockAPI{t: t, user: map[string]any{"ID": "u1", "DisplayName": "Tester", "Name": "Tester", "Email": "t@example.com"}}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdStatus(context.Background(), []string{})
	})
	if err != nil {
		t.Fatalf("cmdStatus: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdStatus output is not JSON: %v (%q)", err, out)
	}
	if got["status"] != "ok" || got["display_name"] != "Tester" {
		t.Errorf("cmdStatus = %v, want {status: ok, display_name: Tester}", got)
	}
}

func TestIntegrationMailList(t *testing.T) {
	m := &mockAPI{t: t, messages: testMessages()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdMailList(context.Background(), []string{})
	})
	if err != nil {
		t.Fatalf("cmdMailList: %v", err)
	}
	var got []mailSummary
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdMailList output is not JSON: %v (%q)", err, out)
	}
	if len(got) != 2 || got[0].ID != "m1" || got[1].ID != "m2" {
		t.Errorf("cmdMailList = %v, want m1 and m2", got)
	}
	if got[0].From != "alice@example.com" || got[0].Subject != "Hello" || !got[0].Unread {
		t.Errorf("cmdMailList[0] = %+v, want alice/Hello/unread", got[0])
	}

	// Client-side filters: --unread keeps only the unread message,
	// --subject matches case-insensitively.
	out, err = captureStdout(t, func() error {
		return cmdMailList(context.Background(), []string{"--unread"})
	})
	if err != nil {
		t.Fatalf("cmdMailList --unread: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdMailList --unread output is not JSON: %v", err)
	}
	if len(got) != 1 || got[0].ID != "m1" {
		t.Errorf("cmdMailList --unread = %v, want only m1", got)
	}

	out, err = captureStdout(t, func() error {
		return cmdMailList(context.Background(), []string{"--subject", "WORLD"})
	})
	if err != nil {
		t.Fatalf("cmdMailList --subject: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdMailList --subject output is not JSON: %v", err)
	}
	if len(got) != 1 || got[0].ID != "m2" {
		t.Errorf("cmdMailList --subject WORLD = %v, want only m2", got)
	}
}

func TestIntegrationListCalendarEventsPaging(t *testing.T) {
	// 150 events: page 0 returns 100, page 1 returns 50, then stop.
	events := make([]map[string]any, 0, 150)
	for i := 0; i < 150; i++ {
		events = append(events, map[string]any{
			"ID": fmt.Sprintf("ev-%03d", i), "CalendarID": "cal1",
			"StartTime": 1700000000, "EndTime": 1700003600, "FullDay": 0,
		})
	}
	m := &mockAPI{t: t, events: events}
	newMockAPI(t, m)

	c, mgr, err := authedClient(context.Background())
	if err != nil {
		t.Fatalf("authedClient: %v", err)
	}
	defer c.Close()
	defer mgr.Close()

	first, err := c.GetCalendarEvents(context.Background(), "cal1", 0, calendarPageSize, url.Values{})
	if err != nil {
		t.Fatalf("GetCalendarEvents page 0: %v", err)
	}
	got, err := listCalendarEvents(context.Background(), c, "cal1", url.Values{}, first)
	if err != nil {
		t.Fatalf("listCalendarEvents: %v", err)
	}
	if len(got) != 150 {
		t.Errorf("listCalendarEvents returned %d events, want 150", len(got))
	}
}

func TestIntegrationListCalendarEventsFailClosed(t *testing.T) {
	// The server returns a full page on every page: the list must fail
	// closed at the page cap instead of looping forever.
	m := &mockAPI{t: t, eventsFullPages: true}
	newMockAPI(t, m)

	c, mgr, err := authedClient(context.Background())
	if err != nil {
		t.Fatalf("authedClient: %v", err)
	}
	defer c.Close()
	defer mgr.Close()

	first, err := c.GetCalendarEvents(context.Background(), "cal1", 0, calendarPageSize, url.Values{})
	if err != nil {
		t.Fatalf("GetCalendarEvents page 0: %v", err)
	}
	_, err = listCalendarEvents(context.Background(), c, "cal1", url.Values{}, first)
	if err == nil {
		t.Fatal("listCalendarEvents with endless full pages: expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded 100 pages") {
		t.Errorf("listCalendarEvents error = %v, want it to mention the 100-page cap", err)
	}
}

func TestIntegrationRefreshFailure(t *testing.T) {
	m := &mockAPI{t: t, refreshErr: true}
	newMockAPI(t, m)

	err := cmdCalendars(context.Background(), []string{})
	if err == nil {
		t.Fatal("cmdCalendars with a failing refresh: expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "session refresh failed") {
		t.Errorf("cmdCalendars error = %v, want it to mention session refresh", err)
	}
}

// testEncryptedMockEvent builds a mock calendar event whose SharedEvents
// part is an armored PGP message (encrypted to kr) carrying the given
// iCal payload. The part is encrypted, not signed, so only the calendar
// keyring is needed to decrypt it.
func testEncryptedMockEvent(t *testing.T, kr *crypto.KeyRing, id string, start, end int64, fullDay bool, ical string) map[string]any {
	t.Helper()
	armored := testEncryptArmor(t, kr, ical)
	fd := 0
	if fullDay {
		fd = 1
	}
	return map[string]any{
		"ID":              id,
		"CalendarID":      "cal1",
		"StartTime":       start,
		"EndTime":         end,
		"FullDay":         fd,
		"SharedKeyPacket": "",
		"SharedEvents": []map[string]any{
			{"Type": 1, "Data": armored, "MemberID": "", "Signature": "", "Author": ""},
		},
	}
}

// testDaemonWithMockAPI builds a daemon whose client points at the mock
// API and whose calendar keyring cache holds kr for cal1, so decrypts
// of the mock events succeed without any real Proton credentials.
func testDaemonWithMockAPI(t *testing.T, kr *crypto.KeyRing) *daemon {
	t.Helper()
	c, mgr, auth, err := authedClientDirect(context.Background())
	if err != nil {
		t.Fatalf("authedClientDirect: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
		mgr.Close()
	})
	// Build via newDaemon so the daemon tracks the tokens the
	// access_token op hands out (a struct literal leaves them empty).
	d := newDaemon(c, mgr, auth, kr, 8765, 30, 365)
	d.calKR["cal1"] = kr
	return d
}

func TestIntegrationDaemonICSFeed(t *testing.T) {
	kr := testKeyRing(t)
	now := time.Now()
	timed := testEncryptedMockEvent(t, kr, "ev-feed",
		now.Add(1*time.Hour).Unix(), now.Add(2*time.Hour).Unix(), false,
		"BEGIN:VEVENT\nSUMMARY:Feed Test\nLOCATION:Room 9\nDESCRIPTION:Notes here\nEND:VEVENT")
	// A full-day event tomorrow (midnight to midnight, exclusive end).
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	day := testEncryptedMockEvent(t, kr, "ev-day",
		tomorrow.Unix(), tomorrow.Add(24*time.Hour).Unix(), true,
		"BEGIN:VEVENT\nSUMMARY:Day Off\nEND:VEVENT")
	m := &mockAPI{t: t, calendars: testCalendars(), events: []map[string]any{timed, day}}
	newMockAPI(t, m)

	d := testDaemonWithMockAPI(t, kr)
	srv := httptest.NewServer(http.HandlerFunc(d.handleICSFeed))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/calendar.ics")
	if err != nil {
		t.Fatalf("GET /calendar.ics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /calendar.ics status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/calendar") {
		t.Errorf("GET /calendar.ics Content-Type = %q, want text/calendar", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read feed: %v", err)
	}
	feed := string(body)
	for _, want := range []string{
		"BEGIN:VCALENDAR",
		"UID:ev-feed@proton-cli",
		"SUMMARY:Feed Test",
		"LOCATION:Room 9",
		"DESCRIPTION:Notes here",
		"UID:ev-day@proton-cli",
		"SUMMARY:Day Off",
		"DTSTART;VALUE=DATE:",
		"END:VCALENDAR",
	} {
		if !strings.Contains(feed, want) {
			t.Errorf("ICS feed missing %q in:\n%s", want, feed)
		}
	}
	// The timed event uses DATETIME, not DATE.
	if !strings.Contains(feed, "DTSTART:"+time.Unix(now.Add(1*time.Hour).Unix(), 0).UTC().Format("20060102T150405Z")) {
		t.Errorf("ICS feed timed event missing DATETIME DTSTART in:\n%s", feed)
	}
}

func TestIntegrationDaemonICSFeedFetchFailure(t *testing.T) {
	// A fetch failure must serve 503 with a plain error, never a stale feed.
	m := &mockAPI{t: t, calendarsErr: true}
	newMockAPI(t, m)
	d := testDaemonWithMockAPI(t, testKeyRing(t))
	srv := httptest.NewServer(http.HandlerFunc(d.handleICSFeed))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/calendar.ics")
	if err != nil {
		t.Fatalf("GET /calendar.ics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /calendar.ics status = %d, want 503", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read error body: %v", err)
	}
	if !strings.Contains(string(body), "failed to build feed") {
		t.Errorf("GET /calendar.ics error body = %q, want it to mention the failed feed", body)
	}
}

func TestIntegrationDaemonDecryptNoPrompt(t *testing.T) {
	kr := testKeyRing(t)
	now := time.Now()
	from := now.Format("2006-01-02")
	to := now.Add(48 * time.Hour).Format("2006-01-02")
	ev := testEncryptedMockEvent(t, kr, "ev-daemon",
		now.Add(1*time.Hour).Unix(), now.Add(2*time.Hour).Unix(), false,
		"BEGIN:VEVENT\nSUMMARY:Daemon Test\nLOCATION:Room 2\nEND:VEVENT")
	m := &mockAPI{t: t, calendars: testCalendars(), events: []map[string]any{ev}}
	newMockAPI(t, m)

	d := testDaemonWithMockAPI(t, kr)
	startTestDaemon(t, d)

	// No stdin is provided: if the command prompted for the account
	// password, readSecretLine would fail with "no input on stdin".
	// Success proves the daemon served the decrypt.
	out, err := captureStdout(t, func() error {
		return cmdEvents(context.Background(), []string{
			"--calendar", "cal1", "--from", from, "--to", to, "--decrypt",
		})
	})
	if err != nil {
		t.Fatalf("cmdEvents --decrypt via daemon: %v", err)
	}
	var got []eventSummary
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdEvents output is not JSON: %v (%q)", err, out)
	}
	if len(got) != 1 {
		t.Fatalf("cmdEvents via daemon returned %d events, want 1: %q", len(got), out)
	}
	if got[0].Summary != "Daemon Test" || got[0].Location != "Room 2" {
		t.Errorf("cmdEvents via daemon = %q/%q, want Daemon Test/Room 2", got[0].Summary, got[0].Location)
	}
}

func TestIntegrationEventsDecryptFallbackPrompts(t *testing.T) {
	// No daemon running: --decrypt on a non-empty range must prompt for
	// the account password. stdin is an empty reader, so the prompt
	// fails with "no input on stdin" — proving the fallback prompts
	// instead of silently succeeding.
	oldReader := stdinReader
	stdinReader = bufio.NewReader(strings.NewReader(""))
	t.Cleanup(func() { stdinReader = oldReader })

	dir := t.TempDir()
	oldSock := daemonSocketPathOverride
	daemonSocketPathOverride = filepath.Join(dir, "no-such.sock")
	t.Cleanup(func() { daemonSocketPathOverride = oldSock })

	m := &mockAPI{t: t, calendars: testCalendars(), events: testEvents()}
	newMockAPI(t, m)
	_, err := captureStdout(t, func() error {
		return cmdEvents(context.Background(), []string{
			"--calendar", "cal1", "--from", "2023-11-14", "--to", "2023-11-15", "--decrypt",
		})
	})
	if err == nil {
		t.Fatal("cmdEvents --decrypt with no daemon and no stdin: expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "no input on stdin") {
		t.Errorf("cmdEvents --decrypt fallback error = %v, want it to mention no input on stdin", err)
	}
}

// ---------------------------------------------------------------------------
// Daemon-owns-token and backgrounding tests
// ---------------------------------------------------------------------------

// runCLIEnv runs the test binary like runCLI, but with a caller-chosen
// HOME/XDG_CONFIG_HOME shared across calls (so a daemon started by one
// call is visible to the next), extra environment, and stdin input. It
// fails the test if the command does not finish within 15s — a daemon
// start that blocks in the foreground must fail loudly here, not hang
// the suite.
func runCLIEnv(t *testing.T, home, cfg, stdin string, extraEnv []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := getTestBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+cfg,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		exitCode = 0
	} else if ee, ok := err.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else {
		t.Fatalf("runCLIEnv %v: %v", args, err)
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// writeSessionFile writes s as the session file under cfgDir
// (<cfgDir>/proton-cli/session.json, 0600), as a child process with
// XDG_CONFIG_HOME=cfgDir would read it.
func writeSessionFile(t *testing.T, cfgDir string, s session) {
	t.Helper()
	dir := filepath.Join(cfgDir, "proton-cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir session dir: %v", err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), b, 0o600); err != nil {
		t.Fatalf("write session file: %v", err)
	}
}

// freePort returns a free localhost TCP port for a test daemon's ICS feed.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// testDaemonCredentials builds a fake user/address key pair for the
// CLI-level daemon test: PGP keys locked with the salted password
// derived from the test account password ("test-password"), the
// matching salts, and the session + mock user/address maps that serve
// them. The caller writes the session file and serves the maps.
func testDaemonCredentials(t *testing.T) (sess session, user, address map[string]any) {
	t.Helper()
	const password = "test-password"
	const userKeyID = "user-key-1"
	const addrKeyID = "addr-key-1"

	userKey, err := crypto.GenerateKey("Test", "test@example.com", "ed25519", 0)
	if err != nil {
		t.Fatalf("GenerateKey user: %v", err)
	}
	addrKey, err := crypto.GenerateKey("Test", "test@example.com", "ed25519", 0)
	if err != nil {
		t.Fatalf("GenerateKey address: %v", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("rand salt: %v", err)
	}
	salts := proton.Salts{{ID: userKeyID, KeySalt: base64.StdEncoding.EncodeToString(salt)}}
	salted, err := salts.SaltForKey([]byte(password), userKeyID)
	if err != nil {
		t.Fatalf("SaltForKey: %v", err)
	}
	if len(salted) == 0 {
		t.Fatalf("SaltForKey returned empty")
	}
	lockedUser, err := userKey.Lock(salted)
	if err != nil {
		t.Fatalf("Lock user key: %v", err)
	}
	armoredUser, err := lockedUser.Armor()
	if err != nil {
		t.Fatalf("Armor user key: %v", err)
	}
	lockedAddr, err := addrKey.Lock(salted)
	if err != nil {
		t.Fatalf("Lock address key: %v", err)
	}
	armoredAddr, err := lockedAddr.Armor()
	if err != nil {
		t.Fatalf("Armor address key: %v", err)
	}
	zero(salted)
	sess = session{UID: "test-uid", RefreshToken: "test-refresh", Salts: salts}
	user = map[string]any{
		"ID": "u1", "Name": "Tester", "DisplayName": "Tester", "Email": "test@example.com",
		// Active must be 1: the library's Keys.Unlock only tries
		// active keys, and an omitted field unmarshals to false.
		"Keys": []map[string]any{{"ID": userKeyID, "Primary": 1, "Active": 1, "PrivateKey": armoredUser}},
	}
	address = map[string]any{
		"ID": "addr1", "Email": "test@example.com",
		"Keys": []map[string]any{{"ID": addrKeyID, "Primary": 1, "Active": 1, "PrivateKey": armoredAddr}},
	}
	return sess, user, address
}

// TestAuthedClientDirectRetryAfterRotation covers the no-daemon
// fallback: a refresh that fails with 10013 because another process
// rotated (and saved) between the load and the refresh is retried
// once with the re-read token.
func TestAuthedClientDirectRetryAfterRotation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	m := &mockAPI{t: t, refreshFailFirst: true}
	m.onRefresh = func() {
		// Simulate the other process's rotation landing: the
		// session file now holds a token the mock accepts.
		p, err := sessionPath()
		if err != nil {
			return
		}
		b, _ := json.Marshal(session{UID: "test-uid", RefreshToken: "test-refresh-rotated"})
		_ = os.WriteFile(p, b, 0o600)
	}
	newMockAPIServer(t, m)
	if err := saveSession(session{UID: "test-uid", RefreshToken: "test-refresh-stale"}); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	c, mgr, _, err := authedClientDirect(context.Background())
	if err != nil {
		t.Fatalf("authedClientDirect: %v", err)
	}
	defer c.Close()
	defer mgr.Close()
	s, err := loadSession()
	if err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if s.RefreshToken != "test-refresh-new" {
		t.Errorf("session refresh token = %q, want test-refresh-new", s.RefreshToken)
	}
}

// TestCLIDaemonStartBackgrounds is the end-to-end test for the
// backgrounding daemon: the real binary prompts for the account
// password, backgrounds itself, and answers status/calendars/stop.
// It runs against the rotating mock (via PROTON_CLI_API_HOST) with a
// hermetic config dir, never the live session.
//
// Skipped where os.UserConfigDir ignores XDG_CONFIG_HOME (macOS):
// there the child binary would read the real config dir.
func TestCLIDaemonStartBackgrounds(t *testing.T) {
	cfg := t.TempDir()
	home := t.TempDir()
	probe := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", probe)
	if dir, err := os.UserConfigDir(); err != nil || !strings.HasPrefix(dir, probe) {
		t.Skip("os.UserConfigDir ignores XDG_CONFIG_HOME on this platform")
	}

	sess, user, address := testDaemonCredentials(t)
	m := &mockAPI{t: t, rotatingRefresh: true, currentRefresh: "test-refresh", currentAccess: "test-access",
		calendars: testCalendars(), user: user, addresses: []map[string]any{address}}
	srv := newMockAPIServer(t, m)
	env := []string{"PROTON_CLI_API_HOST=" + srv.URL}
	writeSessionFile(t, cfg, sess)

	port := freePort(t)
	// Stop the daemon on the way out even if the test fails.
	t.Cleanup(func() {
		_, _, _ = runCLIEnv(t, home, cfg, "", env, "daemon", "stop")
	})

	_, stderr, code := runCLIEnv(t, home, cfg, "test-password\n", env, "daemon", "start", "--ics-port", strconv.Itoa(port))
	if code != 0 {
		t.Fatalf("daemon start: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stderr, "daemon started") || !strings.Contains(stderr, "PID") || !strings.Contains(stderr, "Log:") {
		t.Errorf("daemon start stderr = %q, want PID/socket/ICS/log lines", stderr)
	}
	logPath := filepath.Join(cfg, "proton-cli", "daemon.log")
	if b, err := os.ReadFile(logPath); err != nil {
		t.Errorf("daemon log missing: %v", err)
	} else if !strings.Contains(string(b), "daemon started") {
		t.Errorf("daemon log = %q, want a startup line", b)
	}

	out, _, code := runCLIEnv(t, home, cfg, "", env, "daemon", "status")
	if code != 0 {
		t.Fatalf("daemon status: exit %d", code)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("daemon status is not JSON: %v (%q)", err, out)
	}
	if status["running"] != true {
		t.Errorf("daemon status = %v, want running=true", status)
	}

	// A command goes through the daemon for its access token. The
	// rotating mock rejects any other token, so success proves the
	// daemon-token path.
	out, _, code = runCLIEnv(t, home, cfg, "", env, "calendars")
	if code != 0 {
		t.Fatalf("calendars via daemon: exit %d", code)
	}
	if !strings.Contains(out, "Test Cal") {
		t.Errorf("calendars via daemon = %q, want the mock calendar", out)
	}

	_, _, code = runCLIEnv(t, home, cfg, "", env, "daemon", "stop")
	if code != 0 {
		t.Fatalf("daemon stop: exit %d", code)
	}
	out, _, code = runCLIEnv(t, home, cfg, "", env, "daemon", "status")
	if code != 0 {
		t.Fatalf("daemon status after stop: exit %d", code)
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("daemon status after stop is not JSON: %v", err)
	}
	if status["running"] != false {
		t.Errorf("daemon status after stop = %v, want running=false", status)
	}
}
