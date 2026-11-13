package main

import (
	"fmt"
	"strings"
	"time"
)

// icsEvent is one decrypted calendar event, ready for the feed.
type icsEvent struct {
	ID          string
	Start       int64 // Unix seconds (UTC)
	End         int64 // Unix seconds (UTC); exclusive for full-day events
	FullDay     bool
	Summary     string
	Location    string
	Description string
}

// escapeICSText escapes a value per RFC 5545 section 3.3.11 (TEXT):
// backslash, semicolon, comma and newline. A carriage return is dropped
// (a CRLF line break becomes the escaped \n via the \n case).
func escapeICSText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case ';':
			b.WriteString(`\;`)
		case ',':
			b.WriteString(`\,`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			// Dropped; see above.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// icsDateTime formats t as a UTC DATETIME (YYYYMMDDTHHMMSSZ).
func icsDateTime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

// icsDate formats t as a DATE (YYYYMMDD).
func icsDate(t time.Time) string {
	return t.UTC().Format("20060102")
}

// icsFeed renders a complete VCALENDAR document for events, with DTSTAMP
// set to now (the time the feed was generated). The UID is stable per
// Proton event ID, so regenerating the feed does not duplicate events in
// a subscribing calendar. Line endings are CRLF, as RFC 5545 requires.
func icsFeed(events []icsEvent, now time.Time) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//proton-cli//Proton Calendar//EN\r\n")
	b.WriteString("CALSCALE:GREGORIAN\r\n")
	b.WriteString("METHOD:PUBLISH\r\n")
	stamp := icsDateTime(now)
	for _, ev := range events {
		b.WriteString("BEGIN:VEVENT\r\n")
		fmt.Fprintf(&b, "UID:%s@proton-cli\r\n", ev.ID)
		fmt.Fprintf(&b, "DTSTAMP:%s\r\n", stamp)
		if ev.FullDay {
			fmt.Fprintf(&b, "DTSTART;VALUE=DATE:%s\r\n", icsDate(time.Unix(ev.Start, 0)))
			fmt.Fprintf(&b, "DTEND;VALUE=DATE:%s\r\n", icsDate(time.Unix(ev.End, 0)))
		} else {
			fmt.Fprintf(&b, "DTSTART:%s\r\n", icsDateTime(time.Unix(ev.Start, 0)))
			fmt.Fprintf(&b, "DTEND:%s\r\n", icsDateTime(time.Unix(ev.End, 0)))
		}
		if ev.Summary != "" {
			fmt.Fprintf(&b, "SUMMARY:%s\r\n", escapeICSText(ev.Summary))
		}
		if ev.Location != "" {
			fmt.Fprintf(&b, "LOCATION:%s\r\n", escapeICSText(ev.Location))
		}
		if ev.Description != "" {
			fmt.Fprintf(&b, "DESCRIPTION:%s\r\n", escapeICSText(ev.Description))
		}
		b.WriteString("END:VEVENT\r\n")
	}
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}
