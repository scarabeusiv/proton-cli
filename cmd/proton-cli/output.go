package main

import (
	"fmt"
	"os"
	"strings"
)

// Human-readable printers for command output. Each prints the same
// facts the --json form carries, in concise plain lines. Fields that
// are only meaningful to machines (opaque IDs, hex colours, the
// full parsed headers) stay in the JSON form.

// printCalendars prints a calendar list: one line per calendar,
// "name (id) - description [hidden]". The colour is a UI hint and is
// only in --json output.
func printCalendars(cals []map[string]any) {
	if len(cals) == 0 {
		fmt.Fprintln(os.Stdout, "no calendars")
		return
	}
	for _, cal := range cals {
		name, _ := cal["name"].(string)
		id, _ := cal["id"].(string)
		desc, _ := cal["description"].(string)
		display, _ := cal["display"].(bool)
		line := fmt.Sprintf("%s (%s)", name, id)
		if desc != "" {
			line += " - " + desc
		}
		if !display {
			line += " [hidden]"
		}
		fmt.Fprintln(os.Stdout, line)
	}
}

// printEvents prints an event list: one line per event,
// "start - end  summary @ location (all day) (id: ...)". The calendar
// ID is the same for every row (one --calendar per call) so it is
// omitted.
func printEvents(events []eventSummary) {
	if len(events) == 0 {
		fmt.Fprintln(os.Stdout, "no events")
		return
	}
	for _, ev := range events {
		line := ev.StartText + " - " + ev.EndText
		if ev.Summary != "" {
			line += "  " + ev.Summary
		}
		if ev.Location != "" {
			line += " @ " + ev.Location
		}
		if ev.FullDay {
			line += " (all day)"
		}
		line += " (id: " + ev.ID + ")"
		fmt.Fprintln(os.Stdout, line)
	}
}

// printMailList prints a message list: one line per message,
// "time  from  subject (unread) (N attachments) (id: ...)".
func printMailList(msgs []mailSummary) {
	if len(msgs) == 0 {
		fmt.Fprintln(os.Stdout, "no messages")
		return
	}
	for _, m := range msgs {
		line := m.TimeRFC3339 + "  " + m.From + "  " + m.Subject
		if m.Unread {
			line += " (unread)"
		}
		if m.Attachments > 0 {
			line += fmt.Sprintf(" (%d attachments)", m.Attachments)
		}
		line += " (id: " + m.ID + ")"
		fmt.Fprintln(os.Stdout, line)
	}
}

// printMailRead prints one message: headers, attachment list, then
// the body (or the hint when the body is still encrypted). The full
// parsed headers are only in --json output.
func printMailRead(out map[string]any) {
	summary, _ := out["summary"].(mailSummary)
	fmt.Fprintf(os.Stdout, "Subject: %s\n", summary.Subject)
	fmt.Fprintf(os.Stdout, "From: %s\n", summary.From)
	if len(summary.To) > 0 {
		fmt.Fprintf(os.Stdout, "To: %s\n", strings.Join(summary.To, ", "))
	}
	fmt.Fprintf(os.Stdout, "Time: %s\n", summary.TimeRFC3339)
	if atts, _ := out["attachments"].([]attachmentInfo); len(atts) > 0 {
		fmt.Fprintln(os.Stdout, "Attachments:")
		for _, a := range atts {
			line := fmt.Sprintf("  %s (%d bytes)", a.Name, a.Size)
			if a.Path != "" {
				line += " -> " + a.Path
			}
			fmt.Fprintln(os.Stdout, line)
		}
	}
	if body, ok := out["body"].(string); ok {
		fmt.Fprintln(os.Stdout, body)
	} else if hint, _ := out["body_hint"].(string); hint != "" {
		fmt.Fprintln(os.Stdout, hint)
	}
}

// printContacts prints a contact list: one line per contact,
// "name: email1, email2 (id: ...)".
func printContacts(contacts []map[string]any) {
	if len(contacts) == 0 {
		fmt.Fprintln(os.Stdout, "no contacts")
		return
	}
	for _, ct := range contacts {
		name, _ := ct["name"].(string)
		id, _ := ct["id"].(string)
		var emails []string
		if list, _ := ct["emails"].([]map[string]string); list != nil {
			for _, e := range list {
				if e["email"] != "" {
					emails = append(emails, e["email"])
				}
			}
		}
		line := name
		if len(emails) > 0 {
			line += ": " + strings.Join(emails, ", ")
		}
		line += " (id: " + id + ")"
		fmt.Fprintln(os.Stdout, line)
	}
}

// printLabels prints a label list: one line per label.
func printLabels(labels []labelSummary) {
	if len(labels) == 0 {
		fmt.Fprintln(os.Stdout, "no labels")
		return
	}
	for _, l := range labels {
		printLabel(l)
	}
}

// printLabel prints one label: "name (id: ..., color: ...) path: a/b".
// The numeric label type is only in --json output.
func printLabel(l labelSummary) {
	line := fmt.Sprintf("%s (id: %s, color: %s)", l.Name, l.ID, l.Color)
	if len(l.Path) > 0 {
		line += " path: " + strings.Join(l.Path, "/")
	}
	fmt.Fprintln(os.Stdout, line)
}
