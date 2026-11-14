package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
)

// icsCacheRefreshInterval is how often the daemon re-fetches the
// encrypted calendar events into the ICS cache, in the background.
// The feed always serves from the cache, so a refresh never blocks a
// feed request; the feed is at most this stale.
const icsCacheRefreshInterval = 15 * time.Minute

// calEvents is one calendar's fetched events (still encrypted).
type calEvents struct {
	cal proton.Calendar
	evs []proton.CalendarEvent
	err error
}

// fetchAllCalendarEvents fetches every calendar's events and returns
// them per calendar, in calendar order. The server ignores Begin/End,
// so the whole calendar comes back per calendar. The returned events
// are still encrypted; nothing is decrypted here. Calendars are
// fetched concurrently, and each calendar's pages in parallel batches
// (see listCalendarEvents). A fetch failure for any calendar is an
// error.
func fetchAllCalendarEvents(ctx context.Context, c *proton.Client, filter url.Values) ([]calEvents, error) {
	cals, err := c.GetCalendars(ctx)
	if err != nil {
		return nil, fmt.Errorf("list calendars: %w", err)
	}
	fetched := make([]calEvents, len(cals))
	var wg sync.WaitGroup
	for i, cal := range cals {
		wg.Add(1)
		go func(i int, cal proton.Calendar) {
			defer wg.Done()
			first, err := c.GetCalendarEvents(ctx, cal.ID, 0, calendarPageSize, filter)
			if err != nil {
				fetched[i] = calEvents{cal: cal, err: fmt.Errorf("list events for calendar %s: %w", cal.ID, err)}
				return
			}
			evs, err := listCalendarEvents(ctx, c, cal.ID, filter, first)
			if err != nil {
				fetched[i] = calEvents{cal: cal, err: fmt.Errorf("list events for calendar %s: %w", cal.ID, err)}
				return
			}
			fetched[i] = calEvents{cal: cal, evs: evs}
		}(i, cal)
	}
	wg.Wait()
	for _, r := range fetched {
		if r.err != nil {
			return nil, r.err
		}
	}
	return fetched, nil
}

// icsIsEnabled reports whether the ICS feed is enabled on this daemon.
// The cache and background refresh only run while it is enabled.
func (d *daemon) icsIsEnabled() bool {
	d.icsMu.Lock()
	defer d.icsMu.Unlock()
	return d.icsEnabled
}

// setICSEnabled turns the ICS feed on or off at runtime. Enabling
// starts the encrypted-events cache build and the background refresh;
// disabling stops the refresh and clears the cache. It is idempotent.
// The daemon itself (token owner, keyrings, decrypt) is unaffected.
func (d *daemon) setICSEnabled(enabled bool) {
	d.icsMu.Lock()
	if enabled == d.icsEnabled {
		d.icsMu.Unlock()
		return
	}
	d.icsEnabled = enabled
	if enabled {
		d.icsRefreshStop = make(chan struct{})
		stop := d.icsRefreshStop
		d.icsMu.Unlock()
		go d.icsRefreshLoop(stop)
		return
	}
	if d.icsRefreshStop != nil {
		close(d.icsRefreshStop)
		d.icsRefreshStop = nil
	}
	d.icsCache = nil
	d.icsCacheOrder = nil
	d.icsCacheReady = false
	d.icsMu.Unlock()
}

// icsRefreshLoop builds the cache immediately, then refreshes it every
// icsCacheRefreshInterval. It exits when ICS is disabled (stop closed)
// or the daemon shuts down (d.done closed).
func (d *daemon) icsRefreshLoop(stop chan struct{}) {
	ticker := time.NewTicker(icsCacheRefreshInterval)
	defer ticker.Stop()
	d.refreshICSCache(context.Background())
	for {
		select {
		case <-ticker.C:
			d.refreshICSCache(context.Background())
		case <-stop:
			return
		case <-d.done:
			return
		}
	}
}

// icsWindowFilter builds the Begin/End filter for the feed window.
// The server ignores it, so the cache holds every event and the feed
// filters locally; it is passed for consistency with a direct fetch.
func (d *daemon) icsWindowFilter() url.Values {
	now := time.Now()
	from := now.AddDate(0, 0, -d.icsPastDays)
	to := now.AddDate(0, 0, d.icsFutureDays)
	return url.Values{
		"Begin": []string{strconv.FormatInt(from.Unix(), 10)},
		"End":   []string{strconv.FormatInt(to.Unix(), 10)},
	}
}

// refreshICSCache fetches every calendar's events (still encrypted)
// and replaces the in-memory cache. It never decrypts. On error it
// logs and keeps the previous cache; on success it logs the ready /
// refreshed line with the event count. If ICS was disabled while the
// fetch was in flight, the result is discarded. A stale held refresh
// token is rebuilt once and the fetch retried, like buildICSFeed.
func (d *daemon) refreshICSCache(ctx context.Context) {
	fetchCtx, cancel := context.WithTimeout(ctx, icsFetchTimeout)
	defer cancel()
	c := d.getClient()
	fetched, err := fetchAllCalendarEvents(fetchCtx, c, d.icsWindowFilter())
	if err != nil && isInvalidRefreshToken(err) {
		if rerr := d.rebuildClient(ctx); rerr == nil {
			fetched, err = fetchAllCalendarEvents(fetchCtx, d.getClient(), d.icsWindowFilter())
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "daemon: ICS cache refresh failed: %v (keeping previous cache)\n", err)
		return
	}
	d.icsMu.Lock()
	defer d.icsMu.Unlock()
	if !d.icsEnabled {
		return // disabled while fetching; discard
	}
	total := 0
	cache := make(map[string][]proton.CalendarEvent, len(fetched))
	var order []string
	for _, r := range fetched {
		cache[r.cal.ID] = r.evs
		order = append(order, r.cal.ID)
		total += len(r.evs)
	}
	first := !d.icsCacheReady
	d.icsCache = cache
	d.icsCacheOrder = order
	d.icsCacheReady = true
	d.icsCacheUpdated = time.Now()
	if first {
		fmt.Fprintf(os.Stderr, "daemon: ICS cache ready: %d events\n", total)
	} else {
		fmt.Fprintf(os.Stderr, "daemon: ICS cache refreshed: %d events\n", total)
	}
}

// icsCacheSnapshot returns a deep copy of the cached encrypted events
// (in deterministic calendar order) and whether the cache is ready.
// The copy is independent of the cache: decrypting it cannot mutate
// the cached encrypted events, so the cache never holds decrypted
// data.
func (d *daemon) icsCacheSnapshot() (map[string][]proton.CalendarEvent, []string, bool) {
	d.icsMu.Lock()
	defer d.icsMu.Unlock()
	if !d.icsCacheReady {
		return nil, nil, false
	}
	out := make(map[string][]proton.CalendarEvent, len(d.icsCache))
	for id, evs := range d.icsCache {
		cp := make([]proton.CalendarEvent, len(evs))
		for i, ev := range evs {
			cp[i] = cloneCalendarEvent(ev)
		}
		out[id] = cp
	}
	order := append([]string(nil), d.icsCacheOrder...)
	return out, order, true
}

// cloneCalendarEvent deep-copies a calendar event, including its
// encrypted part slices, so decrypting the copy cannot mutate the
// cached original. Part structs hold only strings and scalars, so a
// value copy of each part is independent (Decode replaces part.Data,
// it never mutates the string bytes in place). Attendees are never
// mutated by any decrypt path, so a shallow slice copy suffices there.
func cloneCalendarEvent(ev proton.CalendarEvent) proton.CalendarEvent {
	out := ev
	out.SharedEvents = cloneEventParts(ev.SharedEvents)
	out.CalendarEvents = cloneEventParts(ev.CalendarEvents)
	out.AttendeesEvents = cloneEventParts(ev.AttendeesEvents)
	out.PersonalEvents = cloneEventParts(ev.PersonalEvents)
	out.Attendees = append([]proton.CalendarAttendee(nil), ev.Attendees...)
	return out
}

func cloneEventParts(parts []proton.CalendarEventPart) []proton.CalendarEventPart {
	if parts == nil {
		return nil
	}
	out := make([]proton.CalendarEventPart, len(parts))
	copy(out, parts)
	return out
}
