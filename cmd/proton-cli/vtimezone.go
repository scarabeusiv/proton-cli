package main

import (
	"fmt"
	"strings"
	"time"
)

// The blank import embeds Go's timezone database in the binary so
// time.LoadLocation works even on a system without /usr/share/zoneinfo.
// Without it the feed would silently fall back to UTC on such a system,
// and no VTIMEZONE could be generated.
import _ "time/tzdata"

// vtimezone renders a VTIMEZONE component for the given IANA timezone,
// derived from Go's timezone database. The feed is self-contained: a
// client without a built-in timezone database can still interpret
// DTSTART;TZID=... correctly.
//
// For a zone that observes daylight saving time it emits a DAYLIGHT
// component (the spring transition) and a STANDARD component (the
// autumn transition), each with a yearly RRULE inferred from the
// transition pattern over a five-year window around refYear. When the
// pattern is not stable (the zone changed its rules), it falls back to
// explicit components, one per observed transition, with no RRULE.
// A zone without daylight saving time gets a single STANDARD component
// with a fixed offset.
func vtimezone(tzid string, refYear int) (string, error) {
	loc, err := time.LoadLocation(tzid)
	if err != nil {
		return "", err
	}
	start := time.Date(refYear-2, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(refYear+3, 1, 1, 0, 0, 0, 0, time.UTC)
	trans := zoneTransitions(loc, start, end)
	if len(trans) == 0 {
		// No offset change in the window: a fixed-offset zone.
		name, off := start.In(loc).Zone()
		var b strings.Builder
		b.WriteString("BEGIN:VTIMEZONE\r\n")
		fmt.Fprintf(&b, "TZID:%s\r\n", tzid)
		b.WriteString("BEGIN:STANDARD\r\n")
		b.WriteString("DTSTART:19700101T000000\r\n")
		fmt.Fprintf(&b, "TZOFFSETFROM:%s\r\n", formatUTCOffset(off))
		fmt.Fprintf(&b, "TZOFFSETTO:%s\r\n", formatUTCOffset(off))
		fmt.Fprintf(&b, "TZNAME:%s\r\n", name)
		b.WriteString("END:STANDARD\r\n")
		b.WriteString("END:VTIMEZONE\r\n")
		return b.String(), nil
	}
	// Split into DST-start (offset increases) and DST-end (offset
	// decreases) transitions.
	var starts, ends []zoneTransition
	for _, tr := range trans {
		if tr.toOff > tr.fromOff {
			starts = append(starts, tr)
		} else if tr.toOff < tr.fromOff {
			ends = append(ends, tr)
		}
	}
	// Try to infer a stable yearly rule for each direction.
	startRule, startOK := inferDSTrule(starts)
	endRule, endOK := inferDSTrule(ends)
	if startOK && endOK {
		// Both directions have a stable rule: one DAYLIGHT and one
		// STANDARD component with RRULEs.
		var b strings.Builder
		b.WriteString("BEGIN:VTIMEZONE\r\n")
		fmt.Fprintf(&b, "TZID:%s\r\n", tzid)
		writeVTIMEZONEComponent(&b, "DAYLIGHT", startRule, starts[0])
		writeVTIMEZONEComponent(&b, "STANDARD", endRule, ends[0])
		b.WriteString("END:VTIMEZONE\r\n")
		return b.String(), nil
	}
	// Irregular rules (or a zone that only ever moves one way): emit
	// one component per observed transition, no RRULE.
	var b strings.Builder
	b.WriteString("BEGIN:VTIMEZONE\r\n")
	fmt.Fprintf(&b, "TZID:%s\r\n", tzid)
	for _, tr := range trans {
		kind := "STANDARD"
		if tr.toOff > tr.fromOff {
			kind = "DAYLIGHT"
		}
		local := tr.at.In(time.FixedZone("", tr.fromOff))
		fmt.Fprintf(&b, "BEGIN:%s\r\n", kind)
		fmt.Fprintf(&b, "DTSTART:%s\r\n", local.Format("20060102T150405"))
		fmt.Fprintf(&b, "TZOFFSETFROM:%s\r\n", formatUTCOffset(tr.fromOff))
		fmt.Fprintf(&b, "TZOFFSETTO:%s\r\n", formatUTCOffset(tr.toOff))
		fmt.Fprintf(&b, "TZNAME:%s\r\n", tr.toName)
		fmt.Fprintf(&b, "END:%s\r\n", kind)
	}
	b.WriteString("END:VTIMEZONE\r\n")
	return b.String(), nil
}

// zoneTransition is one offset change in a timezone.
type zoneTransition struct {
	at       time.Time // UTC instant of the transition
	fromOff  int       // offset in seconds before the transition
	toOff    int       // offset in seconds after the transition
	fromName string    // abbreviation before the transition
	toName   string    // abbreviation after the transition
}

// zoneTransitions returns the offset transitions in loc between start
// and end (UTC), found by sampling the offset every six hours and
// binary-searching each change to the second.
func zoneTransitions(loc *time.Location, start, end time.Time) []zoneTransition {
	const step = 6 * time.Hour
	var out []zoneTransition
	prev := start
	_, prevOff := start.In(loc).Zone()
	for t := start.Add(step); !t.After(end); t = t.Add(step) {
		_, off := t.In(loc).Zone()
		if off != prevOff {
			at := findTransitionInstant(loc, prev, t, off)
			fromName, fromOff := at.Add(-time.Second).In(loc).Zone()
			toName, toOff := at.In(loc).Zone()
			out = append(out, zoneTransition{at: at, fromOff: fromOff, toOff: toOff, fromName: fromName, toName: toName})
			prevOff = off
		}
		prev = t
	}
	return out
}

// findTransitionInstant returns the first instant in (lo, hi] whose
// offset equals hiOff. lo must have a different offset than hi. The
// search runs to one-second precision; DST transitions land on minute
// boundaries, so this is exact.
func findTransitionInstant(loc *time.Location, lo, hi time.Time, hiOff int) time.Time {
	loUnix, hiUnix := lo.Unix(), hi.Unix()
	for hiUnix-loUnix > 1 {
		mid := (loUnix + hiUnix) / 2
		_, off := time.Unix(mid, 0).In(loc).Zone()
		if off == hiOff {
			hiUnix = mid
		} else {
			loUnix = mid
		}
	}
	return time.Unix(hiUnix, 0).UTC()
}

// dstRule is a yearly DST transition rule, inferred from observed
// transitions. occur is 1-4, or -1 for the last occurrence of the
// weekday in the month. clock is the local time of day ("HHMMSS") in
// the offset in effect before the transition.
type dstRule struct {
	month   time.Month
	weekday time.Weekday
	occur   int
	clock   string
	fromOff int
	toOff   int
}

// inferDSTrule returns the single yearly rule shared by all the given
// transitions, or ok=false when they disagree (the zone changed its
// rules). An empty input returns ok=false.
func inferDSTrule(trans []zoneTransition) (dstRule, bool) {
	if len(trans) == 0 {
		return dstRule{}, false
	}
	first := dstRuleFor(trans[0])
	for _, tr := range trans[1:] {
		if dstRuleFor(tr) != first {
			return dstRule{}, false
		}
	}
	return first, true
}

// dstRuleFor derives the yearly rule for one transition. The local
// date/time is taken in the offset in effect before the transition
// (TZOFFSETFROM), which is the local time the clocks change at.
func dstRuleFor(tr zoneTransition) dstRule {
	local := tr.at.In(time.FixedZone("", tr.fromOff))
	day := local.Day()
	occur := -1
	if day <= daysInMonth(local.Year(), local.Month())-7 {
		occur = (day-1)/7 + 1
	}
	return dstRule{
		month:   local.Month(),
		weekday: local.Weekday(),
		occur:   occur,
		clock:   local.Format("150405"),
		fromOff: tr.fromOff,
		toOff:   tr.toOff,
	}
}

// daysInMonth returns the number of days in the given month.
func daysInMonth(year int, month time.Month) int {
	// Day 0 of the next month is the last day of this month.
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// writeVTIMEZONEComponent writes one STANDARD or DAYLIGHT component
// for a stable yearly rule. first is the earliest observed transition
// following the rule; its local date provides the DTSTART.
func writeVTIMEZONEComponent(b *strings.Builder, kind string, rule dstRule, first zoneTransition) {
	local := first.at.In(time.FixedZone("", first.fromOff))
	dayAbbr := [...]string{"SU", "MO", "TU", "WE", "TH", "FR", "SA"}[rule.weekday]
	fmt.Fprintf(b, "BEGIN:%s\r\n", kind)
	fmt.Fprintf(b, "DTSTART:%s\r\n", local.Format("20060102T150405"))
	fmt.Fprintf(b, "TZOFFSETFROM:%s\r\n", formatUTCOffset(rule.fromOff))
	fmt.Fprintf(b, "TZOFFSETTO:%s\r\n", formatUTCOffset(rule.toOff))
	fmt.Fprintf(b, "TZNAME:%s\r\n", first.toName)
	fmt.Fprintf(b, "RRULE:FREQ=YEARLY;BYMONTH=%d;BYDAY=%d%s\r\n", int(rule.month), rule.occur, dayAbbr)
	fmt.Fprintf(b, "END:%s\r\n", kind)
}

// formatUTCOffset formats an offset in seconds east of UTC as
// +HHMM (or +HHMMSS when the offset has a seconds component).
func formatUTCOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	if s == 0 {
		return fmt.Sprintf("%s%02d%02d", sign, h, m)
	}
	return fmt.Sprintf("%s%02d%02d%02d", sign, h, m, s)
}
