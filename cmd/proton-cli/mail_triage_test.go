// Tests for the mail triage commands (mail_triage.go).
package main

import (
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestParseMessageIDs(t *testing.T) {
	ids, err := parseMessageIDs("mark-read", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("parseMessageIDs: %v", err)
	}
	if len(ids) != 3 || ids[0] != "a" || ids[2] != "c" {
		t.Errorf("parseMessageIDs = %v, want [a b c]", ids)
	}

	// No IDs is a usage error, not a silent no-op.
	if _, err := parseMessageIDs("delete", nil); err == nil {
		t.Errorf("parseMessageIDs with no IDs: expected error, got nil")
	}
	if _, err := parseMessageIDs("delete", []string{}); err == nil {
		t.Errorf("parseMessageIDs with empty args: expected error, got nil")
	}
}

func TestSummarizeLabel(t *testing.T) {
	l := proton.Label{
		ID:    "lbl-1",
		Name:  "Receipts",
		Color: "#e67e22",
		Type:  proton.LabelTypeLabel,
		Path:  []string{"Receipts"},
	}
	got := summarizeLabel(l)
	if got.ID != "lbl-1" || got.Name != "Receipts" || got.Color != "#e67e22" {
		t.Errorf("summarizeLabel = %+v, want id lbl-1 name Receipts color #e67e22", got)
	}
	if got.Type != int(proton.LabelTypeLabel) {
		t.Errorf("summarizeLabel type = %d, want %d", got.Type, int(proton.LabelTypeLabel))
	}
	if len(got.Path) != 1 || got.Path[0] != "Receipts" {
		t.Errorf("summarizeLabel path = %v, want [Receipts]", got.Path)
	}
}
