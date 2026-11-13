// Tests for the mail attachment helpers (mail_attachments.go).
package main

import (
	"os"
	"path/filepath"
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestSanitizeAttachmentName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "report.pdf", want: "report.pdf"},
		{in: "a/b/report.pdf", want: "report.pdf"},
		{in: "../../etc/passwd", want: "passwd"},
		{in: "/etc/passwd", want: "passwd"},
		{in: "a/../b.txt", want: "b.txt"},
		{in: "", want: ""},
		{in: ".", want: ""},
		{in: "..", want: ""},
		{in: "/", want: ""},
		{in: "no-extension", want: "no-extension"},
		{in: "sp ace.txt", want: "sp ace.txt"},
	}
	for _, tc := range cases {
		if got := sanitizeAttachmentName(tc.in); got != tc.want {
			t.Errorf("sanitizeAttachmentName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUniqueAttachmentPath(t *testing.T) {
	dir := t.TempDir()
	used := make(map[string]bool)
	claim := func(name string, used map[string]bool) string {
		t.Helper()
		got, err := uniqueAttachmentPath(dir, name, used)
		if err != nil {
			t.Fatalf("uniqueAttachmentPath(%q) error: %v", name, err)
		}
		return got
	}

	// First claim of a name is used as-is.
	if got := claim("report.pdf", used); got != filepath.Join(dir, "report.pdf") {
		t.Errorf("first claim = %q, want %q", got, filepath.Join(dir, "report.pdf"))
	}
	// Second claim of the same name gets -2.
	if got := claim("report.pdf", used); got != filepath.Join(dir, "report-2.pdf") {
		t.Errorf("second claim = %q, want %q", got, filepath.Join(dir, "report-2.pdf"))
	}
	// Third claim gets -3.
	if got := claim("report.pdf", used); got != filepath.Join(dir, "report-3.pdf") {
		t.Errorf("third claim = %q, want %q", got, filepath.Join(dir, "report-3.pdf"))
	}
	// A name without an extension gets the suffix appended, not an extension.
	if got := claim("notes", used); got != filepath.Join(dir, "notes") {
		t.Errorf("extensionless first claim = %q, want %q", got, filepath.Join(dir, "notes"))
	}
	if got := claim("notes", used); got != filepath.Join(dir, "notes-2") {
		t.Errorf("extensionless second claim = %q, want %q", got, filepath.Join(dir, "notes-2"))
	}

	// A file already on disk (not claimed in this run) also forces a suffix.
	if err := os.WriteFile(filepath.Join(dir, "existing.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := make(map[string]bool)
	if got := claim("existing.txt", fresh); got != filepath.Join(dir, "existing-2.txt") {
		t.Errorf("on-disk collision = %q, want %q", got, filepath.Join(dir, "existing-2.txt"))
	}

	// An unreadable directory must error out, not loop forever: every
	// candidate stat fails the same way. (Skipped for root, which can
	// stat regardless of permissions.)
	if os.Geteuid() != 0 {
		bad := t.TempDir()
		if err := os.Chmod(bad, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(bad, 0o700)
		if _, err := uniqueAttachmentPath(bad, "x.txt", make(map[string]bool)); err == nil {
			t.Error("uniqueAttachmentPath in an unreadable directory: expected an error, got nil")
		}
	}
}

func TestAttachmentMIMEType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "photo.jpg", want: "image/jpeg"},
		{in: "photo.jpeg", want: "image/jpeg"},
		{in: "doc.pdf", want: "application/pdf"},
		{in: "page.html", want: "text/html"},
		{in: "notes.txt", want: "text/plain"},
		{in: "archive.zip", want: "application/zip"},
		{in: "file.unknownext", want: "application/octet-stream"},
		{in: "noextension", want: "application/octet-stream"},
		{in: "UPPER.PNG", want: "image/png"},
	}
	for _, tc := range cases {
		if got := attachmentMIMEType(tc.in); got != tc.want {
			t.Errorf("attachmentMIMEType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStringList(t *testing.T) {
	var l stringList
	if got := l.String(); got != "" {
		t.Errorf("empty stringList = %q, want empty", got)
	}
	if err := l.Set("a.txt"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := l.Set("b.txt"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(l) != 2 || l[0] != "a.txt" || l[1] != "b.txt" {
		t.Errorf("stringList = %v, want [a.txt b.txt]", []string(l))
	}
	if got := l.String(); got != "a.txt,b.txt" {
		t.Errorf("stringList.String() = %q, want %q", got, "a.txt,b.txt")
	}
}

func TestSummarizeAttachment(t *testing.T) {
	att := proton.Attachment{
		ID:          "att-1",
		Name:        "report.pdf",
		Size:        1234,
		MIMEType:    "application/pdf",
		Disposition: proton.AttachmentDisposition,
	}
	got := summarizeAttachment(att)
	if got.ID != "att-1" || got.Name != "report.pdf" || got.Size != 1234 {
		t.Errorf("summarizeAttachment = %+v, want id att-1 name report.pdf size 1234", got)
	}
	if got.MIMEType != "application/pdf" || got.Disposition != "attachment" {
		t.Errorf("summarizeAttachment mime/disposition = %q/%q, want application/pdf/attachment", got.MIMEType, got.Disposition)
	}
	if got.Path != "" {
		t.Errorf("summarizeAttachment path = %q, want empty (not downloaded)", got.Path)
	}
}
