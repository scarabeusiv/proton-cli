package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
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
// which the calendar endpoint rejects (400 Code 2021). The page count is
// capped: a server returning full pages forever would otherwise loop
// forever and grow memory without bound. Failing closed (instead of
// silently truncating) keeps a truncated list from passing as complete.
func listCalendarEvents(ctx context.Context, c *proton.Client, calendarID string, filter url.Values) ([]proton.CalendarEvent, error) {
	const pageSize = 100
	const maxPages = 100
	var all []proton.CalendarEvent
	for page := 0; page < maxPages; page++ {
		evs, err := c.GetCalendarEvents(ctx, calendarID, page, pageSize, filter)
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
		if len(evs) < pageSize {
			return all, nil
		}
	}
	return nil, fmt.Errorf("calendar event list exceeded %d pages of %d events; refusing to fetch more", maxPages, pageSize)
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
		// SaltForKey returns only the last 31 bytes of the 60-byte bcrypt
		// output; the first 29 bytes stay in a slice inside the library
		// that this code never sees, so only the returned subslice can
		// be zeroed here.
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
		// The passphrase is only needed to unlock the keys.
		zero(rawPass)
	}

	events, err := listCalendarEvents(ctx, c, *calendarID, filter)
	if err != nil {
		return fmt.Errorf("list events: %w", err)
	}

	out := make([]eventSummary, 0, len(events))
	decryptFailed := 0
	var firstDecryptErr error
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
			var err error
			s.Summary, s.Location, err = decryptEventDetails(&ev, calKR, addrKR)
			if err != nil {
				decryptFailed++
				if firstDecryptErr == nil {
					firstDecryptErr = err
				}
			}
		}

		out = append(out, s)
	}

	// A total decrypt failure must be visible, not silently empty.
	if *decrypt && decryptFailed > 0 {
		fmt.Fprintf(os.Stderr, "decrypt: %d/%d events failed to decrypt (first error: %v)\n", decryptFailed, len(events), firstDecryptErr)
	}

	return emitJSON(out)
}

// decryptEventDetails extracts the SUMMARY and LOCATION properties from an
// event's decrypted iCal payload. The canonical body lives in SharedEvents,
// encrypted with the shared session key (SharedKeyPacket); PersonalEvents
// and CalendarEvents hold member annotations, encrypted with the calendar
// session key (CalendarKeyPacket). Returns an error when no part could be
// decrypted, or when parts decrypted but carried neither field.
func decryptEventDetails(ev *proton.CalendarEvent, calKR, addrKR *crypto.KeyRing) (summary, location string, err error) {
	sharedKP := decodeKeyPacket(ev.SharedKeyPacket)
	calKP := decodeKeyPacket(ev.CalendarKeyPacket)
	partSets := []struct {
		parts []proton.CalendarEventPart
		kp    []byte
	}{
		{ev.SharedEvents, sharedKP},
		{ev.PersonalEvents, calKP},
		{ev.CalendarEvents, calKP},
	}
	decryptedAny := false
	for _, set := range partSets {
		for _, part := range set.parts {
			data, derr := decryptPart(part, calKR, addrKR, set.kp)
			if derr != nil {
				err = derr
				continue
			}
			decryptedAny = true
			if summary == "" {
				summary = icalProp(data, "SUMMARY")
			}
			if location == "" {
				location = icalProp(data, "LOCATION")
			}
			if summary != "" && location != "" {
				return summary, location, nil
			}
		}
	}
	if !decryptedAny {
		if err == nil {
			err = fmt.Errorf("event has no parts to decrypt")
		}
		return summary, location, err
	}
	if summary == "" && location == "" {
		return summary, location, fmt.Errorf("parts decrypted but no SUMMARY/LOCATION found")
	}
	return summary, location, nil
}

// decodeKeyPacket base64-decodes a key packet string; returns nil for an
// empty or malformed packet instead of panicking (the library helper
// panics on malformed base64).
func decodeKeyPacket(packet string) []byte {
	if packet == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(packet)
	if err != nil {
		return nil
	}
	return raw
}

// decryptPart replicates proton.CalendarEventPart.Decode but returns the
// decrypted string (the upstream method's assignment is lost in some
// versions) and takes the event's calendar key packet, without which the
// split-message parts cannot be decrypted.
func decryptPart(part proton.CalendarEventPart, calKR, addrKR *crypto.KeyRing, kp []byte) (string, error) {
	data := part.Data

	if part.Type&proton.CalendarEventTypeEncrypted != 0 {
		var enc *crypto.PGPMessage

		if len(kp) > 0 {
			raw, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return "", fmt.Errorf("base64 decode: %w", err)
			}
			enc = crypto.NewPGPSplitMessage(kp, raw).GetPGPMessage()
		} else {
			var err error
			if enc, err = crypto.NewPGPMessageFromArmored(data); err != nil {
				return "", fmt.Errorf("parse armored: %w", err)
			}
		}

		dec, err := calKR.Decrypt(enc, nil, crypto.GetUnixTime())
		if err != nil {
			return "", fmt.Errorf("decrypt: %w", err)
		}

		data = dec.GetString()
	}

	if part.Type&proton.CalendarEventTypeSigned != 0 {
		sig, err := crypto.NewPGPSignatureFromArmored(part.Signature)
		if err != nil {
			return "", fmt.Errorf("parse sig: %w", err)
		}
		if err := addrKR.VerifyDetached(crypto.NewPlainMessageFromString(data), sig, crypto.GetUnixTime()); err != nil {
			return "", fmt.Errorf("verify sig: %w", err)
		}
	}

	return data, nil
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
