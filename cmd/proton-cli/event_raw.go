package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strings"

	proton "github.com/ProtonMail/go-proton-api"
)

// cmdEventRaw is a diagnostic: it prints the STRUCTURE of one calendar
// event (part counts, part types, data lengths, key-packet presence)
// without decrypting anything and without needing a password. It can
// fetch the single-event endpoint or the first event of the list
// endpoint, so the two responses can be compared.
func cmdEventRaw(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("event-raw", flag.ContinueOnError)
	calendarID := fs.String("calendar", "", "calendar ID")
	eventID := fs.String("event", "", "event ID (single-event endpoint)")
	listFirst := fs.Bool("list-first", false, "print the first event of the list endpoint instead")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *calendarID == "" {
		return fmt.Errorf("--calendar is required")
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	var ev proton.CalendarEvent
	if *listFirst {
		events, err := c.GetCalendarEvents(ctx, *calendarID, 0, 1, url.Values{})
		if err != nil {
			return fmt.Errorf("list events: %w", err)
		}
		if len(events) == 0 {
			return fmt.Errorf("list returned no events")
		}
		ev = events[0]
		fmt.Println("source: list endpoint, first event")
	} else {
		if *eventID == "" {
			return fmt.Errorf("--event is required (or use --list-first)")
		}
		ev, err = c.GetCalendarEvent(ctx, *calendarID, *eventID)
		if err != nil {
			return fmt.Errorf("get event: %w", err)
		}
		fmt.Println("source: single-event endpoint")
	}

	fmt.Printf("event id: %s\n", ev.ID)
	fmt.Printf("start: %d end: %d full_day: %v\n", ev.StartTime, ev.EndTime, bool(ev.FullDay))
	fmt.Printf("calendar key packet: present=%v len=%d\n", ev.CalendarKeyPacket != "", len(ev.CalendarKeyPacket))
	fmt.Printf("shared key packet: present=%v len=%d\n", ev.SharedKeyPacket != "", len(ev.SharedKeyPacket))
	printParts("shared", ev.SharedEvents)
	printParts("personal", ev.PersonalEvents)
	printParts("calendar", ev.CalendarEvents)
	printParts("attendees", ev.AttendeesEvents)
	return nil
}

func printParts(name string, parts []proton.CalendarEventPart) {
	fmt.Printf("%s parts: %d\n", name, len(parts))
	for _, p := range parts {
		shape := "base64?"
		if strings.HasPrefix(p.Data, "-----BEGIN") {
			shape = "armored"
		}
		fmt.Printf("  type=%d data_len=%d shape=%s sig_len=%d author=%s member=%s\n",
			int(p.Type), len(p.Data), shape, len(p.Signature), p.Author, p.MemberID)
	}
}
