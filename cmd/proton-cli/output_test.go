// Tests for the human-readable default output and the --json flag.
//
// Output is human-readable text by default; --json restores the exact
// JSON shape a command used to print. The existing integration tests
// keep verifying the JSON shape by passing --json; these tests prove
// the default is readable text and --json still yields JSON.
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// notJSON fails the test if out parses as JSON.
func assertNotJSON(t *testing.T, out string) {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(out), &v); err == nil {
		t.Errorf("output parses as JSON, want human-readable text: %q", out)
	}
}

func TestHumanReadableStatusDefault(t *testing.T) {
	stdout, _, code := runCLI(t, "status")
	if code != 0 {
		t.Fatalf("status with no session: exit code = %d, want 0", code)
	}
	if stdout != "status: no session\n" {
		t.Errorf("status default = %q, want %q", stdout, "status: no session\n")
	}
	assertNotJSON(t, stdout)
}

func TestJSONFlagStatus(t *testing.T) {
	stdout, _, code := runCLI(t, "status", "--json")
	if code != 0 {
		t.Fatalf("status --json with no session: exit code = %d, want 0", code)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("status --json: stdout is not JSON: %v (%q)", err, stdout)
	}
	if got["status"] != "no_session" {
		t.Errorf("status --json = %v, want {status: no_session}", got)
	}
}

func TestHumanReadableDaemonStatusDefault(t *testing.T) {
	out, _, code := runCLI(t, "daemon", "status")
	if code != 0 {
		t.Fatalf("daemon status: exit code %d, want 0", code)
	}
	if out != "daemon: not running\n" {
		t.Errorf("daemon status default = %q, want %q", out, "daemon: not running\n")
	}
	assertNotJSON(t, out)
}

func TestJSONFlagDaemonStatus(t *testing.T) {
	out, _, code := runCLI(t, "daemon", "status", "--json")
	if code != 0 {
		t.Fatalf("daemon status --json: exit code %d, want 0", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("daemon status --json: stdout is not JSON: %v (%q)", err, out)
	}
	if got["running"] != false {
		t.Errorf("daemon status --json = %v, want running=false", got)
	}
}

func TestHumanReadableCalendarsDefault(t *testing.T) {
	m := &mockAPI{t: t, calendars: testCalendars()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdCalendars(context.Background(), []string{})
	})
	if err != nil {
		t.Fatalf("cmdCalendars: %v", err)
	}
	if !strings.Contains(out, "Test Cal") || !strings.Contains(out, "cal1") {
		t.Errorf("cmdCalendars default = %q, want it to name Test Cal (cal1)", out)
	}
	assertNotJSON(t, out)
}

func TestJSONFlagCalendars(t *testing.T) {
	m := &mockAPI{t: t, calendars: testCalendars()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdCalendars(context.Background(), []string{"--json"})
	})
	if err != nil {
		t.Fatalf("cmdCalendars --json: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("cmdCalendars --json output is not JSON: %v (%q)", err, out)
	}
	if len(got) != 1 || got[0]["id"] != "cal1" || got[0]["name"] != "Test Cal" {
		t.Errorf("cmdCalendars --json = %v, want one calendar cal1/Test Cal", got)
	}
}

func TestHumanReadableEventsDefault(t *testing.T) {
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
	// ev1's start time and id must be visible; the output is lines,
	// not a JSON array.
	if !strings.Contains(out, "2023-11-14T22:13:20Z") || !strings.Contains(out, "ev1") {
		t.Errorf("cmdEvents default = %q, want ev1 at 2023-11-14T22:13:20Z", out)
	}
	assertNotJSON(t, out)
}

func TestHumanReadableEventsEmptyRangeDefault(t *testing.T) {
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
	if strings.TrimSpace(out) != "no events" {
		t.Errorf("cmdEvents --decrypt on empty range = %q, want %q", out, "no events")
	}
	assertNotJSON(t, out)
}

func TestHumanReadableMailListDefault(t *testing.T) {
	m := &mockAPI{t: t, messages: testMessages()}
	newMockAPI(t, m)

	out, err := captureStdout(t, func() error {
		return cmdMailList(context.Background(), []string{})
	})
	if err != nil {
		t.Fatalf("cmdMailList: %v", err)
	}
	if !strings.Contains(out, "Hello") || !strings.Contains(out, "m1") {
		t.Errorf("cmdMailList default = %q, want Hello (m1)", out)
	}
	assertNotJSON(t, out)
}
