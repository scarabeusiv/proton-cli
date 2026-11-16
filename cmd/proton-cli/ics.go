package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// icsEvent is one decrypted calendar event, ready for the feed.
// RRule is the raw RRULE value ("" when the event does not recur);
// ExDates are the full EXDATE lines (with any parameters) verbatim;
// RecurrenceID is the full RECURRENCE-ID line verbatim ("" unless this
// event overrides one occurrence of a recurring series). TZID is the
// IANA timezone of the event's DTSTART as given in the decrypted iCal
// payload ("" when the payload has none, e.g. a UTC or all-day event).
// A timed event with a TZID is emitted with DTSTART;TZID=... so its
// recurrence keeps its local time across DST; without one it is emitted
// as UTC, as before.
type icsEvent struct {
	ID           string
	Start        int64 // Unix seconds (UTC)
	End          int64 // Unix seconds (UTC); exclusive for full-day events
	FullDay      bool
	Summary      string
	Location     string
	Description  string
	RRule        string
	ExDates      []string
	RecurrenceID string
	TZID         string
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

// collectEventZones returns the distinct IANA timezones referenced by
// the timed events' TZIDs, each loaded via time.LoadLocation. A TZID
// that cannot be loaded is left out, so the event falls back to UTC
// (see icsFeed) rather than breaking the feed. All-day events carry no
// timezone and are ignored.
func collectEventZones(events []icsEvent) map[string]*time.Location {
	zones := make(map[string]*time.Location)
	for _, ev := range events {
		if ev.FullDay || ev.TZID == "" {
			continue
		}
		if _, ok := zones[ev.TZID]; ok {
			continue
		}
		if loc, err := time.LoadLocation(ev.TZID); err == nil {
			zones[ev.TZID] = loc
		}
	}
	return zones
}

// icsFeed renders a complete VCALENDAR document for events, with DTSTAMP
// set to now (the time the feed was generated). The UID is stable per
// Proton event ID, so regenerating the feed does not duplicate events in
// a subscribing calendar. Line endings are CRLF, as RFC 5545 requires.
//
// A timed event whose decrypted payload carried a TZID is emitted with
// DTSTART;TZID=... / DTEND;TZID=... in that timezone's local time, so a
// recurring event keeps its local time across DST (a UTC DTSTART would
// pin the recurrence to a fixed UTC instant, shifting it by an hour when
// DST changes). The feed carries a VTIMEZONE for every timezone it
// references, so it is self-contained. Timed events without a TZID and
// all-day events keep the previous UTC / VALUE=DATE forms.
func icsFeed(events []icsEvent, now time.Time) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//proton-cli//Proton Calendar//EN\r\n")
	b.WriteString("CALSCALE:GREGORIAN\r\n")
	b.WriteString("METHOD:PUBLISH\r\n")
	stamp := icsDateTime(now)
	zones := collectEventZones(events)
	ids := make([]string, 0, len(zones))
	for tzid := range zones {
		ids = append(ids, tzid)
	}
	sort.Strings(ids)
	for _, tzid := range ids {
		if vt, err := vtimezone(tzid, now.Year()); err == nil {
			b.WriteString(vt)
		}
	}
	for _, ev := range events {
		b.WriteString("BEGIN:VEVENT\r\n")
		fmt.Fprintf(&b, "UID:%s@proton-cli\r\n", ev.ID)
		fmt.Fprintf(&b, "DTSTAMP:%s\r\n", stamp)
		if ev.FullDay {
			fmt.Fprintf(&b, "DTSTART;VALUE=DATE:%s\r\n", icsDate(time.Unix(ev.Start, 0)))
			fmt.Fprintf(&b, "DTEND;VALUE=DATE:%s\r\n", icsDate(time.Unix(ev.End, 0)))
		} else if loc, ok := zones[ev.TZID]; ok {
			fmt.Fprintf(&b, "DTSTART;TZID=%s:%s\r\n", ev.TZID, time.Unix(ev.Start, 0).In(loc).Format("20060102T150405"))
			fmt.Fprintf(&b, "DTEND;TZID=%s:%s\r\n", ev.TZID, time.Unix(ev.End, 0).In(loc).Format("20060102T150405"))
		} else {
			fmt.Fprintf(&b, "DTSTART:%s\r\n", icsDateTime(time.Unix(ev.Start, 0)))
			fmt.Fprintf(&b, "DTEND:%s\r\n", icsDateTime(time.Unix(ev.End, 0)))
		}
		if ev.RRule != "" {
			fmt.Fprintf(&b, "RRULE:%s\r\n", ev.RRule)
		}
		for _, ex := range ev.ExDates {
			fmt.Fprintf(&b, "%s\r\n", ex)
		}
		if ev.RecurrenceID != "" {
			fmt.Fprintf(&b, "%s\r\n", ev.RecurrenceID)
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
