package main

import (
	"strings"
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestValidateLimit(t *testing.T) {
	if _, err := validateLimit(-1); err == nil {
		t.Error("validateLimit(-1): expected an error, got nil")
	}
	if got, err := validateLimit(0); err != nil || got != 0 {
		t.Errorf("validateLimit(0) = %d, %v; want 0, nil", got, err)
	}
	if got, err := validateLimit(25); err != nil || got != 25 {
		t.Errorf("validateLimit(25) = %d, %v; want 25, nil", got, err)
	}
}

func TestParseAddrList(t *testing.T) {
	cases := []struct {
		in      string
		want    []string // expected Address fields, in order
		wantErr bool
	}{
		{in: "", want: nil},
		{in: "alice@example.com", want: []string{"alice@example.com"}},
		{in: "Alice <alice@example.com>", want: []string{"alice@example.com"}},
		{in: "alice@example.com, bob@example.com", want: []string{"alice@example.com", "bob@example.com"}},
		{in: "alice@example.com,", want: []string{"alice@example.com"}},
		{in: ",", want: nil},
		// net/mail rejects these, but they are deliverable bare addresses,
		// so the fallback must accept them.
		{in: "alice@example.com.", want: []string{"alice@example.com."}},
		{in: "alice@sub..example.com", want: []string{"alice@sub..example.com"}},
		// Not a bare address either: must be an error, not a silent pass-through.
		{in: "plainaddress", wantErr: true},
		{in: "alice@example.com, bad address", wantErr: true},
		{in: "alice@@example.com", wantErr: true},
	}

	for _, tc := range cases {
		got, err := parseAddrList(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseAddrList(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAddrList(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseAddrList(%q): got %d addresses, want %d", tc.in, len(got), len(tc.want))
			continue
		}
		for i, want := range tc.want {
			if got[i].Address != want {
				t.Errorf("parseAddrList(%q)[%d].Address = %q, want %q", tc.in, i, got[i].Address, want)
			}
		}
	}
}

func TestIsBareAddress(t *testing.T) {
	cases := map[string]bool{
		"alice@example.com":         true,
		"alice@sub..example.com":    true,
		"alice@example.com.":        true,
		"plainaddress":              false,
		"alice@@example.com":        false,
		"alice@":                    false,
		"@example.com":              false,
		"alice@exam ple.com":        false,
		"alice@example.com>":        false,
		"Alice <alice@example.com>": false,
	}
	for in, want := range cases {
		if got := isBareAddress(in); got != want {
			t.Errorf("isBareAddress(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFormatKeyMeta(t *testing.T) {
	cases := []struct {
		id, want string
		primary  bool
		active   bool
		hasToken bool
	}{
		{"key1", "  id=key1 primary=true active=true has_token=true", true, true, true},
		{"key2", "  id=key2 primary=false active=false has_token=false", false, false, false},
		{"key3", "  id=key3 primary=true active=false has_token=true", true, false, true},
	}
	for _, tc := range cases {
		got := formatKeyMeta(tc.id, tc.primary, tc.active, tc.hasToken)
		if got != tc.want {
			t.Errorf("formatKeyMeta(%q, %v, %v, %v) = %q, want %q", tc.id, tc.primary, tc.active, tc.hasToken, got, tc.want)
		}
		if strings.Contains(got, "%!") {
			t.Errorf("formatKeyMeta(%q, ...) contains a formatting error marker: %q", tc.id, got)
		}
	}
}

func TestDefaultSender(t *testing.T) {
	disabled := proton.Address{Email: "old@example.com", Send: proton.Bool(true), Status: proton.AddressStatusDisabled}
	noSend := proton.Address{Email: "recv@example.com", Send: proton.Bool(false), Status: proton.AddressStatusEnabled}
	usable := proton.Address{Email: "main@example.com", Send: proton.Bool(true), Status: proton.AddressStatusEnabled}

	if got := defaultSender([]proton.Address{disabled, noSend, usable}); got.Email != "main@example.com" {
		t.Errorf("defaultSender skipped the usable address, got %q", got.Email)
	}
	// None usable: fall back to the first address rather than failing.
	if got := defaultSender([]proton.Address{disabled, noSend}); got.Email != "old@example.com" {
		t.Errorf("defaultSender with no usable address = %q, want the first address", got.Email)
	}
	if got := defaultSender([]proton.Address{usable}); got.Email != "main@example.com" {
		t.Errorf("defaultSender single address = %q, want main@example.com", got.Email)
	}
}
