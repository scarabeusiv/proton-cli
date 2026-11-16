package main

import (
	"bufio"
	"strings"
	"testing"
)

// readSecretLine under `go test` runs with a non-terminal stdin, so
// these cases cover the piped-input path: a plain line read, so
// scripting (e.g. password + TOTP piped to login) keeps working. The
// terminal path (echo disabled for the read) cannot be exercised
// without a PTY; it is verified manually against a real terminal.
func TestReadSecretLinePiped(t *testing.T) {
	if stdinIsTTY() {
		t.Skip("stdin is a terminal; piped-input cases need a pipe")
	}
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "line", input: "s3cret\n", want: "s3cret"},
		{name: "crlf trimmed", input: "s3cret\r\n", want: "s3cret"},
		{name: "eof terminated", input: "s3cret", want: "s3cret"},
		{name: "empty input", input: "", wantErr: "no input on stdin"},
		{name: "empty line", input: "\n", wantErr: "empty input on stdin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldReader := stdinReader
			stdinReader = bufio.NewReader(strings.NewReader(tc.input))
			t.Cleanup(func() { stdinReader = oldReader })

			got, err := readSecretLine("prompt:")
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("readSecretLine(%q) = %q, nil error; want error %q",
						tc.input, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("readSecretLine(%q) error = %v; want it to mention %q",
						tc.input, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSecretLine(%q) error = %v; want %q", tc.input, err, tc.want)
			}
			if string(got) != tc.want {
				t.Errorf("readSecretLine(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}
