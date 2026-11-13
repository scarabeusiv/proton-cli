package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
)

func cmdContacts(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("contacts", flag.ContinueOnError)
	query := fs.String("query", "", "filter: name or email contains (case-insensitive, client-side)")
	limitFlag := fs.Int("limit", 50, "max contacts to return (0 = no limit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	limit, err := validateLimit(*limitFlag)
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	// Page through contacts and stop once the limit is reached, instead
	// of fetching all contacts and limiting client-side.
	const contactPageSize = 100
	out := make([]map[string]any, 0, limit)
	for page := 0; ; page++ {
		batch, err := c.GetContacts(ctx, page, contactPageSize)
		if err != nil {
			return fmt.Errorf("list contacts: %w", err)
		}
		for _, ct := range batch {
			if *query != "" {
				hay := strings.ToLower(ct.Name)
				for _, ce := range ct.ContactEmails {
					hay += " " + strings.ToLower(ce.Name+" "+ce.Email)
				}
				if !strings.Contains(hay, strings.ToLower(*query)) {
					continue
				}
			}

			emails := make([]map[string]string, 0, len(ct.ContactEmails))
			for _, ce := range ct.ContactEmails {
				emails = append(emails, map[string]string{
					"name":  ce.Name,
					"email": ce.Email,
				})
			}

			out = append(out, map[string]any{
				"id":     ct.ID,
				"name":   ct.Name,
				"emails": emails,
			})

			if limit > 0 && len(out) >= limit {
				return emitJSON(out)
			}
		}
		if len(batch) < contactPageSize {
			break
		}
	}

	return emitJSON(out)
}
