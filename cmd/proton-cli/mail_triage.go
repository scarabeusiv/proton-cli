package main

import (
	"context"
	"flag"
	"fmt"

	proton "github.com/ProtonMail/go-proton-api"
)

// labelSummary is the JSON shape for a label.
type labelSummary struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Color string   `json:"color"`
	Type  int      `json:"type"`
	Path  []string `json:"path"`
}

func summarizeLabel(l proton.Label) labelSummary {
	return labelSummary{
		ID:    l.ID,
		Name:  l.Name,
		Color: l.Color,
		Type:  int(l.Type),
		Path:  l.Path,
	}
}

// parseMessageIDs parses a triage command's args (no flags, only
// positional message IDs) and requires at least one.
func parseMessageIDs(cmd string, args []string) ([]string, error) {
	fs := flag.NewFlagSet("mail "+cmd, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() == 0 {
		return nil, fmt.Errorf("usage: proton-cli mail %s requires at least one <message-id>", cmd)
	}
	return fs.Args(), nil
}

func cmdMailMarkRead(ctx context.Context, args []string) error {
	ids, err := parseMessageIDs("mark-read", args)
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	if err := c.MarkMessagesRead(ctx, ids...); err != nil {
		return fmt.Errorf("mark read: %w", err)
	}
	return emitJSON(map[string]any{"status": "marked-read", "ids": ids})
}

func cmdMailMarkUnread(ctx context.Context, args []string) error {
	ids, err := parseMessageIDs("mark-unread", args)
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	if err := c.MarkMessagesUnread(ctx, ids...); err != nil {
		return fmt.Errorf("mark unread: %w", err)
	}
	return emitJSON(map[string]any{"status": "marked-unread", "ids": ids})
}

func cmdMailDelete(ctx context.Context, args []string) error {
	ids, err := parseMessageIDs("delete", args)
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	if err := c.DeleteMessage(ctx, ids...); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return emitJSON(map[string]any{"status": "deleted", "ids": ids})
}

func cmdMailLabels(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail labels", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	labels, err := c.GetLabels(ctx)
	if err != nil {
		return fmt.Errorf("list labels: %w", err)
	}
	out := make([]labelSummary, 0, len(labels))
	for _, l := range labels {
		out = append(out, summarizeLabel(l))
	}
	return emitJSON(out)
}

func cmdMailLabel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail label", flag.ContinueOnError)
	add := fs.String("add", "", "label ID to add")
	remove := fs.String("remove", "", "label ID to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *add == "" && *remove == "" {
		return fmt.Errorf("usage: proton-cli mail label <message-id>... --add <label-id> [--remove <label-id>]")
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: proton-cli mail label <message-id>... --add <label-id> [--remove <label-id>]")
	}
	ids := fs.Args()

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	if *add != "" {
		if err := c.LabelMessages(ctx, ids, *add); err != nil {
			return fmt.Errorf("add label %s: %w", *add, err)
		}
	}
	if *remove != "" {
		if err := c.UnlabelMessages(ctx, ids, *remove); err != nil {
			return fmt.Errorf("remove label %s: %w", *remove, err)
		}
	}
	return emitJSON(map[string]any{"status": "labelled", "ids": ids, "added": *add, "removed": *remove})
}

func cmdMailCreateLabel(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail create-label", flag.ContinueOnError)
	name := fs.String("name", "", "label name (required)")
	color := fs.String("color", "#808080", "label colour as a hex code (e.g. #e67e22)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("usage: proton-cli mail create-label --name <name> [--color <hex>]")
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	label, err := c.CreateLabel(ctx, proton.CreateLabelReq{
		Name:  *name,
		Color: *color,
		Type:  proton.LabelTypeLabel,
	})
	if err != nil {
		return fmt.Errorf("create label: %w", err)
	}
	return emitJSON(summarizeLabel(label))
}
