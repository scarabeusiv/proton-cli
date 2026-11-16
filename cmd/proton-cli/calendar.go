package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

func cmdCalendars(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("calendars", flag.ContinueOnError)
	addJSONFlag(fs)
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

	return emit(out, func() { printCalendars(out) })
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

// calendarPageSize is the page size the calendar endpoint accepts.
// The library's GetAllCalendarEvents uses PageSize=150, which the
// calendar endpoint rejects (400 Code 2021).
const calendarPageSize = 100

// calendarPageBatchSize is how many calendar pages are fetched
// concurrently in one batch. The server ignores the Begin/End filter
// and returns every event in the calendar, 100 per page, and a single
// page takes 10-30s server-side; fetching pages one at a time makes a
// whole calendar take minutes and the ICS feed exceed its timeout.
// Pages are independent (page N does not depend on page N-1), so they
// are fetched concurrently. A short page ends the list; the batch
// that contains it is still fully fetched (the pages after a short
// page return empty).
const calendarPageBatchSize = 12

// listCalendarEvents pages through the calendar API. first is the
// already-fetched page 0; the remaining pages are fetched here, so the
// caller can inspect page 0 (e.g. to skip a password prompt for an empty
// range) without re-fetching it. The remaining pages are fetched in
// parallel batches (see calendarPageBatchSize): the server returns the
// whole calendar regardless of the window, so a sequential fetch takes
// minutes. The page count is capped: a server returning full pages
// forever would otherwise loop forever and grow memory without bound.
// Failing closed (instead of silently truncating) keeps a truncated
// list from passing as complete.
func listCalendarEvents(ctx context.Context, c *proton.Client, calendarID string, filter url.Values, first []proton.CalendarEvent) ([]proton.CalendarEvent, error) {
	const maxPages = 100
	all := append([]proton.CalendarEvent{}, first...)
	if len(first) < calendarPageSize {
		return all, nil
	}
	for page := 1; page < maxPages; {
		batchEnd := page + calendarPageBatchSize
		if batchEnd > maxPages {
			batchEnd = maxPages
		}
		// Fetch pages [page, batchEnd) concurrently. Each goroutine
		// writes only its own slot, so no synchronisation is needed
		// beyond the WaitGroup; the client is safe for concurrent
		// use (the library's own fetchPaged does the same).
		type pageResult struct {
			evs []proton.CalendarEvent
			err error
		}
		results := make([]pageResult, batchEnd-page)
		var wg sync.WaitGroup
		for i := page; i < batchEnd; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				evs, err := c.GetCalendarEvents(ctx, calendarID, i, calendarPageSize, filter)
				results[i-page] = pageResult{evs: evs, err: err}
			}(i)
		}
		wg.Wait()
		// Append in page order. A short page ends the list; pages
		// after it in this batch return empty.
		short := false
		for _, r := range results {
			if r.err != nil {
				return nil, r.err
			}
			all = append(all, r.evs...)
			if len(r.evs) < calendarPageSize {
				short = true
			}
		}
		if short {
			return all, nil
		}
		page = batchEnd
	}
	return nil, fmt.Errorf("calendar event list exceeded %d pages of %d events; refusing to fetch more", maxPages, calendarPageSize)
}

func cmdEvents(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	addJSONFlag(fs)
	calendarID := fs.String("calendar", "", "calendar ID (required)")
	from := fs.String("from", "", "start date YYYY-MM-DD (default: today)")
	to := fs.String("to", "", "end date YYYY-MM-DD exclusive (default: from + 1 day)")
	decrypt := fs.Bool("decrypt", false, "decrypt event titles (reads account password from stdin)")
	noDaemon := fs.Bool("no-daemon", false, "do not use the daemon; always prompt for the account password")
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

	// Fetch the first page before asking for the account password, so
	// an empty range never prompts. A wrong password still fails fast:
	// only this one cheap request happens before the prompt.
	first, err := c.GetCalendarEvents(ctx, *calendarID, 0, calendarPageSize, filter)
	if err != nil {
		return fmt.Errorf("list events: %w", err)
	}
	if len(first) == 0 {
		return emit([]eventSummary{}, func() { fmt.Fprintln(os.Stdout, "no events") })
	}

	// Optional: set up calendar decryption so titles resolve. This runs
	// after the first page is fetched, so a bad password still fails
	// before the bulk of the (slow) multi-page fetch.
	var calKR, addrKR *crypto.KeyRing
	useDaemon := false
	if *decrypt && !*noDaemon {
		// The first decrypt command starts the daemon (prompting
		// once) when stdin is a terminal; later commands reuse it.
		// The client above was built before the daemon started, so
		// it may hold a pre-daemon refresh token — but its access
		// token is fresh (just issued), so it cannot expire during
		// this short command.
		useDaemon = ensureDaemonForDecrypt()
	}

	if *decrypt && !useDaemon {
		pw, err := readSecretLine("Enter account password (via stdin):")
		if err != nil {
			return err
		}
		defer zero(pw)

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
		// Primary() panics when no key is flagged primary, so look the
		// primary key up by hand first.
		primaryID := primaryKeyID(user.Keys)
		if primaryID == "" {
			return fmt.Errorf("no primary user key — cannot derive salted key password")
		}
		salted, err := stored.Salts.SaltForKey(pw, primaryID)
		if err != nil {
			return fmt.Errorf("derive salted key password: %w", err)
		}
		// SaltForKey swallows MailboxPassword errors and returns
		// (nil, nil); an empty result cannot unlock anything.
		if len(salted) == 0 {
			return fmt.Errorf("derive salted key password: empty result")
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
				if strings.EqualFold(addr.Email, member.Email) {
					kr, err := unlockAddressKeyringForAddrs(salted, addr.ID, user, addrs)
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
		// Unlock silently skips keys that fail, so it can return an
		// empty keyring with a nil error. Fail fast instead of
		// surfacing later as "N/N events failed to decrypt".
		if calKR.CountDecryptionEntities() == 0 {
			return fmt.Errorf("unlock calendar keys: no calendar keys could be unlocked")
		}
	}

	events, err := listCalendarEvents(ctx, c, *calendarID, filter, first)
	if err != nil {
		return fmt.Errorf("list events: %w", err)
	}

	// Begin/End are passed to the server, but the server may ignore
	// them — filter locally too, so only events overlapping the
	// requested range are ever returned.
	fromUnix, toUnix := fromT.Unix(), toT.Unix()
	inRange := make([]proton.CalendarEvent, 0, len(events))
	for _, ev := range events {
		if ev.StartTime < toUnix && ev.EndTime > fromUnix {
			inRange = append(inRange, ev)
		}
	}
	events = inRange

	// Verify shared-calendar events too: the verification ring adds
	// the other members' public keys and the public keys of the
	// events' authors (see buildVerificationKeyring).
	var verifyKR *crypto.KeyRing
	if *decrypt && !useDaemon && addrKR != nil {
		var verr error
		verifyKR, verr = buildVerificationKeyring(ctx, c, *calendarID, addrKR, collectAuthorEmails(events))
		if verr != nil {
			// Fall back to the bare address keyring: this account's
			// own events still decrypt.
			fmt.Fprintf(os.Stderr, "verification keyring: %v (own events only)\n", verr)
			verifyKR = addrKR
		}
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

		if *decrypt {
			var err error
			if useDaemon {
				s.Summary, s.Location, _, err = daemonDecryptEvent(*calendarID, &ev)
			} else if calKR != nil {
				var det eventDetails
				det, err = decryptEventDetails(&ev, calKR, verifyKR)
				s.Summary, s.Location = det.Summary, det.Location
			}
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

	return emit(out, func() { printEvents(out) })
}

// collectAuthorEmails returns the distinct author emails found on the
// events and their parts, for verification-key fetching. An event part
// is signed by its author's address key, and the calendar member list
// may name a different address for the same person (or none at all),
// so the author addresses are fetched as well as the members'.
// Non-email authors are ignored.
func collectAuthorEmails(events []proton.CalendarEvent) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(email string) {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" || !strings.Contains(email, "@") || seen[email] {
			return
		}
		seen[email] = true
		out = append(out, email)
	}
	for _, ev := range events {
		add(ev.Author)
		for _, part := range ev.SharedEvents {
			add(part.Author)
		}
		for _, part := range ev.CalendarEvents {
			add(part.Author)
		}
		for _, part := range ev.PersonalEvents {
			add(part.Author)
		}
		for _, part := range ev.AttendeesEvents {
			add(part.Author)
		}
	}
	return out
}

// addVerificationKeys fetches the public keys for one address and adds
// them to vr, returning how many were added. An address whose keys
// cannot be fetched, or that yields no keys, is logged and skipped
// (returns 0, nil) rather than failing the caller. Only a local
// keyring failure (AddKey) returns an error.
func addVerificationKeys(ctx context.Context, c *proton.Client, vr *crypto.KeyRing, email string) (int, error) {
	pub, _, err := c.GetPublicKeys(ctx, email)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verification keyring: get public keys for %s: %v (skipped)\n", email, err)
		return 0, nil
	}
	pkr, err := pub.GetKeyRing()
	if err != nil {
		fmt.Fprintf(os.Stderr, "verification keyring: public keys for %s: %v (skipped)\n", email, err)
		return 0, nil
	}
	n := 0
	for _, k := range pkr.GetKeys() {
		if err := vr.AddKey(k); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		fmt.Fprintf(os.Stderr, "verification keyring: no public keys for %s (skipped)\n", email)
	}
	return n, nil
}

// buildVerificationKeyring returns the keyring used to verify calendar
// event signatures for calendarID: the account's own address keys
// (base) plus the public keys of the calendar's other members and of
// extraAuthors (the authors of the events being decrypted).
// Event parts are signed by their author's address key, so a shared
// calendar's events fail verification with "signature made by unknown
// entity" unless the author's public key is in the ring. The member
// list alone is not sufficient: it may name an address whose keys
// differ from the address that signed the event, or an address with
// no published keys. Members and authors matching the account's own
// addresses are skipped: their keys are already in base. An address
// whose public keys cannot be fetched is skipped (its events fail
// verification and are logged, as before) rather than failing the
// whole feed.
func buildVerificationKeyring(ctx context.Context, c *proton.Client, calendarID string, base *crypto.KeyRing, extraAuthors []string) (*crypto.KeyRing, error) {
	members, err := c.GetCalendarMembers(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("get calendar members: %w", err)
	}
	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("get addresses: %w", err)
	}
	own := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		own[strings.ToLower(a.Email)] = true
	}
	vr, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, k := range base.GetKeys() {
		if err := vr.AddKey(k); err != nil {
			return nil, err
		}
	}
	seen := make(map[string]bool)
	fetch := func(email string) error {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" || own[email] || seen[email] {
			return nil
		}
		seen[email] = true
		_, err := addVerificationKeys(ctx, c, vr, email)
		return err
	}
	for _, m := range members {
		if err := fetch(m.Email); err != nil {
			return nil, err
		}
	}
	for _, email := range extraAuthors {
		if err := fetch(email); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(os.Stderr, "verification keyring: calendar %s: %d members, %d authors, %d keys\n", calendarID, len(members), len(extraAuthors), len(vr.GetKeys()))
	return vr, nil
}

// eventDetails is the decrypted content of one calendar event. RRule is
// the raw RRULE value ("" when the event does not recur); ExDates are
// the full EXDATE lines verbatim (parameters preserved); RecurrenceID
// is the full RECURRENCE-ID line verbatim ("" unless this event
// overrides one occurrence of a recurring series). TZID is the IANA
// timezone of the event's DTSTART as given in the payload ("" when
// DTSTART has none, e.g. a UTC or all-day event).
type eventDetails struct {
	Summary      string
	Location     string
	Description  string
	RRule        string
	ExDates      []string
	RecurrenceID string
	TZID         string
}

// decryptEventDetails extracts the SUMMARY, LOCATION and DESCRIPTION
// properties from an event's decrypted iCal payload, plus the recurrence
// properties (RRULE, EXDATE, RECURRENCE-ID) when present. The canonical body
// lives in SharedEvents, encrypted with the shared session key
// (SharedKeyPacket); PersonalEvents and CalendarEvents hold member
// annotations, encrypted with the calendar session key
// (CalendarKeyPacket). Recurrence lives in the same canonical VEVENT as the
// summary, so it is taken from the first part that carries it. Returns an
// error when no part could be decrypted, or when parts decrypted but carried
// neither field. DESCRIPTION is optional: it is captured when present in a
// part decrypted before the early return below (the canonical VEVENT carries
// it alongside SUMMARY/LOCATION).
func decryptEventDetails(ev *proton.CalendarEvent, calKR, addrKR *crypto.KeyRing) (eventDetails, error) {
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
	var out eventDetails
	var err error
	decryptedAny := false
	for _, set := range partSets {
		for _, part := range set.parts {
			// Decode decrypts in place (part.Data) and verifies the
			// signature; it is the library method, not a local copy.
			if derr := part.Decode(calKR, addrKR, set.kp); derr != nil {
				err = derr
				continue
			}
			data := part.Data
			decryptedAny = true
			if out.Summary == "" {
				out.Summary = icalProp(data, "SUMMARY")
			}
			if out.Location == "" {
				out.Location = icalProp(data, "LOCATION")
			}
			if out.Description == "" {
				out.Description = icalProp(data, "DESCRIPTION")
			}
			// RRULE/RECURRENCE-ID occur once, EXDATE may repeat.
			if out.RRule == "" {
				out.RRule = icalProp(data, "RRULE")
			}
			if out.RecurrenceID == "" {
				out.RecurrenceID = icalPropLine(data, "RECURRENCE-ID")
			}
			if len(out.ExDates) == 0 {
				out.ExDates = icalPropLines(data, "EXDATE")
			}
			if out.TZID == "" {
				out.TZID = icalDTSTARTZone(data)
			}
			if out.Summary != "" && out.Location != "" {
				return out, nil
			}
		}
	}
	if !decryptedAny {
		if err == nil {
			err = fmt.Errorf("event has no parts to decrypt")
		}
		return out, err
	}
	if out.Summary == "" && out.Location == "" {
		return out, fmt.Errorf("parts decrypted but no SUMMARY/LOCATION found")
	}
	return out, nil
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

// unfoldICalLines splits an iCal payload into logical lines, unfolding
// continuation lines (a line starting with a space or tab continues the
// previous line).
func unfoldICalLines(ical string) []string {
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
	return unfolded
}

// icalPropName returns the property name of an unfolded iCal line,
// stripping any parameters (e.g. "SUMMARY;X=1:value" -> "SUMMARY").
func icalPropName(line string) string {
	name := line
	if idx := indexOf(line, ':'); idx >= 0 {
		name = line[:idx]
	}
	if idx := indexOf(name, ';'); idx >= 0 {
		name = name[:idx]
	}
	return name
}

// icalProp pulls the named property out of an iCal VEVENT payload,
// unfolding continuation lines.
func icalProp(ical, prop string) string {
	for _, line := range unfoldICalLines(ical) {
		if icalPropName(line) == prop {
			if idx := indexOf(line, ':'); idx >= 0 {
				return unescapeICalText(line[idx+1:])
			}
		}
	}
	return ""
}

// icalPropLine returns the first full unfolded line for prop (parameters
// preserved), or "" when absent. Used for properties whose parameters
// matter (RECURRENCE-ID).
func icalPropLine(ical, prop string) string {
	for _, line := range unfoldICalLines(ical) {
		if icalPropName(line) == prop {
			return line
		}
	}
	return ""
}

// icalPropLines returns every full unfolded line for prop (parameters
// preserved). Used for properties that may repeat (EXDATE).
func icalPropLines(ical, prop string) []string {
	var out []string
	for _, line := range unfoldICalLines(ical) {
		if icalPropName(line) == prop {
			out = append(out, line)
		}
	}
	return out
}

// icalDTSTARTZone returns the TZID parameter of the DTSTART property in
// an iCal VEVENT payload, or "" when DTSTART has none (a UTC value with
// a Z suffix, or a DATE value). A recurring event keeps its local time
// across DST only when DTSTART carries its timezone, so the feed emits
// DTSTART;TZID=... for such events; without a TZID the event is emitted
// as UTC, as before.
func icalDTSTARTZone(ical string) string {
	line := icalPropLine(ical, "DTSTART")
	if line == "" {
		return ""
	}
	// The parameters sit between the property name and the first ':'.
	idx := indexOf(line, ':')
	if idx < 0 {
		return ""
	}
	for _, p := range strings.Split(line[len("DTSTART"):idx], ";") {
		if v, ok := strings.CutPrefix(p, "TZID="); ok {
			// A quoted TZID is rare; unquote it.
			return strings.Trim(v, `"`)
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
