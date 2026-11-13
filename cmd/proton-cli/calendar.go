package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strconv"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func cmdCalendars(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("calendars", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	cals, err := c.GetCalendars(ctx)
	if err != nil {
		return fmt.Errorf("list calendars: %w", err)
	}

	out := make([]map[string]any, 0, len(cals))
	for _, cal := range cals {
		out = append(out, map[string]any{
			"id":          cal.ID,
			"name":        cal.Name,
			"description": cal.Description,
			"color":       cal.Color,
			"display":     bool(cal.Display),
		})
	}

	return emitJSON(out)
}

type eventSummary struct {
	ID        string `json:"id"`
	Calendar  string `json:"calendar_id"`
	Start     int64  `json:"start_time"`
	End       int64  `json:"end_time"`
	StartText string `json:"start_rfc3339"`
	EndText   string `json:"end_rfc3339"`
	FullDay   bool   `json:"full_day"`
	Summary   string `json:"summary,omitempty"`
	Location  string `json:"location,omitempty"`
}

// listCalendarEvents pages through the calendar API at a page size the
// server accepts. The library's GetAllCalendarEvents uses PageSize=150,
// which the calendar endpoint rejects (400 Code 2021).
func listCalendarEvents(ctx context.Context, c *proton.Client, calendarID string, filter url.Values) ([]proton.CalendarEvent, error) {
	const pageSize = 100
	var all []proton.CalendarEvent
	for page := 0; ; page++ {
		evs, err := c.GetCalendarEvents(ctx, calendarID, page, pageSize, filter)
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
		if len(evs) < pageSize {
			break
		}
	}
	return all, nil
}

func cmdEvents(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	calendarID := fs.String("calendar", "", "calendar ID (required)")
	from := fs.String("from", "", "start date YYYY-MM-DD (default: today)")
	to := fs.String("to", "", "end date YYYY-MM-DD exclusive (default: from + 1 day)")
	decrypt := fs.Bool("decrypt", false, "decrypt event titles (reads mailbox password from stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *calendarID == "" {
		return fmt.Errorf("--calendar is required (see `proton-cli calendars`)")
	}

	fromT, err := parseDateOr(*from, time.Now())
	if err != nil {
		return err
	}
	toT, err := parseDateOr(*to, fromT.Add(24*time.Hour))
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	filter := url.Values{
		"Begin": []string{strconv.FormatInt(fromT.Unix(), 10)},
		"End":   []string{strconv.FormatInt(toT.Unix(), 10)},
	}

	// Optional: set up calendar decryption so titles resolve. This runs
	// BEFORE fetching events, so a bad password fails fast instead of
	// after the (slow) multi-page fetch.
	var calKR, addrKR *crypto.KeyRing

	if *decrypt {
		mbpw, err := readSecretLine("Enter mailbox password (via stdin):")
		if err != nil {
			return err
		}
		defer zero(mbpw)

		// Key salts were captured at login time (a refreshed token cannot
		// fetch them). If this session predates that, log in again.
		stored, err := loadSession()
		if err != nil {
			return err
		}
		if len(stored.Salts) == 0 {
			return fmt.Errorf("no key salts stored in session — run `proton-cli login` again to capture them")
		}
		user, err := c.GetUser(ctx)
		if err != nil {
			return fmt.Errorf("get user: %w", err)
		}
		salted, err := stored.Salts.SaltForKey(mbpw, user.Keys.Primary().ID)
		if err != nil {
			return fmt.Errorf("derive salted key password: %w", err)
		}
		defer zero(salted)

		// Use the member's address keyring to unlock the calendar passphrase.
		members, err := c.GetCalendarMembers(ctx, *calendarID)
		if err != nil {
			return fmt.Errorf("get calendar members: %w", err)
		}

		addrs, err := c.GetAddresses(ctx)
		if err != nil {
			return fmt.Errorf("get addresses: %w", err)
		}

		var memberID string

		for _, member := range members {
			for _, addr := range addrs {
				if addr.Email == member.Email {
					kr, err := unlockAddressKeyring(ctx, c, salted, addr.ID)
					if err != nil {
						continue
					}
					addrKR = kr
					memberID = member.ID
					break
				}
			}
			if addrKR != nil {
				break
			}
		}

		if addrKR == nil {
			return fmt.Errorf("could not unlock a keyring for any calendar member")
		}

		passphrase, err := c.GetCalendarPassphrase(ctx, *calendarID)
		if err != nil {
			return fmt.Errorf("get calendar passphrase: %w", err)
		}

		rawPass, err := passphrase.Decrypt(memberID, addrKR)
		if err != nil {
			return fmt.Errorf("decrypt calendar passphrase: %w", err)
		}

		keys, err := c.GetCalendarKeys(ctx, *calendarID)
		if err != nil {
			return fmt.Errorf("get calendar keys: %w", err)
		}

		calKR, err = keys.Unlock(rawPass)
		if err != nil {
			return fmt.Errorf("unlock calendar keys: %w", err)
		}
	}

	events, err := listCalendarEvents(ctx, c, *calendarID, filter)
	if err != nil {
		return fmt.Errorf("list events: %w", err)
	}

	out := make([]eventSummary, 0, len(events))
	for _, ev := range events {
		s := eventSummary{
			ID:        ev.ID,
			Calendar:  ev.CalendarID,
			Start:     ev.StartTime,
			End:       ev.EndTime,
			StartText: time.Unix(ev.StartTime, 0).UTC().Format(time.RFC3339),
			EndText:   time.Unix(ev.EndTime, 0).UTC().Format(time.RFC3339),
			FullDay:   bool(ev.FullDay),
		}

		if *decrypt && calKR != nil {
			s.Summary, s.Location = decryptEventDetails(&ev, calKR, addrKR)
		}

		out = append(out, s)
	}

	return emitJSON(out)
}

// decryptEventDetails decodes the personal event part and extracts the
// SUMMARY and LOCATION properties from the iCal payload. Best effort:
// returns "" for anything missing or undecodable.
func decryptEventDetails(ev *proton.CalendarEvent, calKR, addrKR *crypto.KeyRing) (summary, location string) {
	for i := range ev.PersonalEvents {
		part := &ev.PersonalEvents[i]
		if err := part.Decode(calKR, addrKR, nil); err != nil {
			continue
		}
		if summary == "" {
			summary = icalProp(part.Data, "SUMMARY")
		}
		if location == "" {
			location = icalProp(part.Data, "LOCATION")
		}
		if summary != "" && location != "" {
			break
		}
	}
	return summary, location
}

// icalProp pulls the named property out of an iCal VEVENT payload,
// unfolding continuation lines.
func icalProp(ical, prop string) string {
	var unfolded []string
	var current string

	lines := splitLines(ical)
	for _, line := range lines {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			current += line[1:]
			continue
		}
		if current != "" {
			unfolded = append(unfolded, current)
		}
		current = line
	}
	if current != "" {
		unfolded = append(unfolded, current)
	}

	for _, line := range unfolded {
		// Property may carry parameters: SUMMARY;X=1:value
		name := line
		if idx := indexOf(line, ':'); idx >= 0 {
			name = line[:idx]
		}
		if idx := indexOf(name, ';'); idx >= 0 {
			name = name[:idx]
		}
		if name == prop {
			if idx := indexOf(line, ':'); idx >= 0 {
				return unescapeICalText(line[idx+1:])
			}
		}
	}

	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func unescapeICalText(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n', 'N':
				out = append(out, '\n')
			case ',':
				out = append(out, ',')
			case ';':
				out = append(out, ';')
			case '\\':
				out = append(out, '\\')
			default:
				out = append(out, s[i+1])
			}
			i++
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func parseDateOr(s string, fallback time.Time) (time.Time, error) {
	if s == "" {
		y, mo, d := fallback.Date()
		return time.Date(y, mo, d, 0, 0, 0, 0, fallback.Location()), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("bad date %q, want YYYY-MM-DD", s)
	}
	return t, nil
}
