package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	proton "github.com/ProtonMail/go-proton-api"
	gomail "net/mail"
)

func cmdMail(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: proton-cli mail <list|read|send> [flags]")
	}

	switch args[0] {
	case "list":
		return cmdMailList(ctx, args[1:])
	case "read":
		return cmdMailRead(ctx, args[1:])
	case "send":
		return cmdMailSend(ctx, args[1:])
	default:
		return fmt.Errorf("unknown mail subcommand %q (list|read|send)", args[0])
	}
}

type mailSummary struct {
	ID          string   `json:"id"`
	Subject     string   `json:"subject"`
	From        string   `json:"from"`
	To          []string `json:"to"`
	Time        int64    `json:"time"`
	TimeRFC3339 string   `json:"time_rfc3339"`
	Unread      bool     `json:"unread"`
	Labels      []string `json:"labels"`
	Attachments int      `json:"attachments"`
}

func summarize(m proton.MessageMetadata) mailSummary {
	from := ""
	if m.Sender != nil {
		from = m.Sender.Address
	}

	to := make([]string, 0, len(m.ToList))
	for _, a := range m.ToList {
		if a != nil {
			to = append(to, a.Address)
		}
	}

	return mailSummary{
		ID:          m.ID,
		Subject:     m.Subject,
		From:        from,
		To:          to,
		Time:        m.Time,
		TimeRFC3339: time.Unix(m.Time, 0).UTC().Format(time.RFC3339),
		Unread:      bool(m.Unread),
		Labels:      m.LabelIDs,
		Attachments: m.NumAttachments,
	}
}

func cmdMailList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail list", flag.ContinueOnError)
	label := fs.String("label", "", "filter by label ID (e.g. 0=inbox, 1=all mail, 5=sent)")
	unreadOnly := fs.Bool("unread", false, "only unread messages")
	subject := fs.String("subject", "", "filter: subject contains (case-insensitive, client-side)")
	from := fs.String("from", "", "filter: sender contains (case-insensitive, client-side)")
	limitFlag := fs.Int("limit", 25, "max messages to return (0 = no limit)")
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

	filter := proton.MessageFilter{Desc: proton.Bool(true)}
	if *label != "" {
		filter.LabelID = *label
	}

	metas, err := c.GetMessageMetadata(ctx, filter)
	if err != nil {
		return fmt.Errorf("list messages: %w", err)
	}

	out := make([]mailSummary, 0, limit)
	for _, mm := range metas {
		if *unreadOnly && !bool(mm.Unread) {
			continue
		}
		if *subject != "" && !strings.Contains(strings.ToLower(mm.Subject), strings.ToLower(*subject)) {
			continue
		}
		if *from != "" {
			sender := ""
			if mm.Sender != nil {
				sender = strings.ToLower(mm.Sender.Address + " " + mm.Sender.Name)
			}
			if !strings.Contains(sender, strings.ToLower(*from)) {
				continue
			}
		}
		out = append(out, summarize(mm))
		if limit > 0 && len(out) >= limit {
			break
		}
	}

	return emitJSON(out)
}

func cmdMailRead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail read", flag.ContinueOnError)
	decrypt := fs.Bool("decrypt", false, "decrypt the body (reads mailbox password from stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: proton-cli mail read [--decrypt] <message-id>")
	}
	id := fs.Arg(0)

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	msg, err := c.GetMessage(ctx, id)
	if err != nil {
		return fmt.Errorf("get message: %w", err)
	}

	out := map[string]any{
		"summary": summarize(msg.MessageMetadata),
		"headers": msg.ParsedHeaders,
	}

	if *decrypt {
		mbpw, err := readSecretLine("Enter mailbox password (via stdin):")
		if err != nil {
			return err
		}
		defer zero(mbpw)

		kr, err := unlockAddressKeyring(ctx, c, mbpw, msg.AddressID)
		if err != nil {
			return err
		}

		body, err := msg.Decrypt(kr)
		if err != nil {
			return fmt.Errorf("decrypt body: %w", err)
		}
		out["body"] = string(body)
	} else {
		out["body"] = nil
		out["body_hint"] = "re-run with --decrypt to read the encrypted body"
	}

	return emitJSON(out)
}

func cmdMailSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail send", flag.ContinueOnError)
	to := fs.String("to", "", "recipient address, comma-separated for several (required)")
	cc := fs.String("cc", "", "cc addresses, comma-separated")
	subject := fs.String("subject", "", "subject (required)")
	bodyFile := fs.String("body-file", "", "path to file with the message body (plain text)")
	fromAddr := fs.String("from", "", "sender address (defaults to first address)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *to == "" || *subject == "" {
		return fmt.Errorf("--to and --subject are required")
	}
	if *bodyFile == "" {
		return fmt.Errorf("--body-file is required")
	}

	body, err := os.ReadFile(*bodyFile)
	if err != nil {
		return fmt.Errorf("read body file: %w", err)
	}

	mbpw, err := readSecretLine("Enter mailbox password (via stdin) — needed to encrypt the draft:")
	if err != nil {
		return err
	}
	defer zero(mbpw)

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return fmt.Errorf("get addresses: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no sending addresses on this account")
	}

	sender := addrs[0]
	if *fromAddr != "" {
		found := false
		for _, a := range addrs {
			if strings.EqualFold(a.Email, *fromAddr) {
				sender = a
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no such sender address %q", *fromAddr)
		}
	}

	kr, err := unlockAddressKeyring(ctx, c, mbpw, sender.ID)
	if err != nil {
		return err
	}

	toAddrs, err := parseAddrList(*to)
	if err != nil {
		return err
	}
	ccAddrs, err := parseAddrList(*cc)
	if err != nil {
		return err
	}

	draft, err := c.CreateDraft(ctx, kr, proton.CreateDraftReq{
		Message: proton.DraftTemplate{
			Subject: *subject,
			Sender:  &gomail.Address{Address: sender.Email},
			ToList:  toAddrs,
			CCList:  ccAddrs,
			Body:    string(body),
		},
	})
	if err != nil {
		return fmt.Errorf("create draft: %w", err)
	}

	// Build send packages: encrypted for recipients we have keys for,
	// cleartext otherwise.
	allRecipients := append(append([]*gomail.Address{}, toAddrs...), ccAddrs...)
	prefs := make(map[string]proton.SendPreferences, len(allRecipients))

	for _, rcpt := range allRecipients {
		keys, rt, err := c.GetPublicKeys(ctx, rcpt.Address)
		if err != nil {
			return fmt.Errorf("get public keys for %s: %w", rcpt.Address, err)
		}

		sp := proton.SendPreferences{
			SignatureType: proton.DetachedSignature,
			MIMEType:      rfc822.TextPlain,
		}

		if rt == proton.RecipientTypeInternal && len(keys) > 0 {
			kr, err := keys.GetKeyRing()
			if err != nil {
				return fmt.Errorf("keyring for %s: %w", rcpt.Address, err)
			}
			sp.Encrypt = true
			sp.PubKey = kr
			sp.EncryptionScheme = proton.InternalScheme
		} else if len(keys) > 0 {
			kr, err := keys.GetKeyRing()
			if err != nil {
				return fmt.Errorf("keyring for %s: %w", rcpt.Address, err)
			}
			sp.Encrypt = true
			sp.PubKey = kr
			sp.EncryptionScheme = proton.PGPInlineScheme
		} else {
			sp.Encrypt = false
			sp.EncryptionScheme = proton.ClearScheme
		}

		prefs[rcpt.Address] = sp
	}

	var req proton.SendDraftReq
	if err := req.AddTextPackage(kr, string(body), rfc822.TextPlain, prefs, nil); err != nil {
		return fmt.Errorf("build send package: %w", err)
	}

	sent, err := c.SendDraft(ctx, draft.ID, req)
	if err != nil {
		return fmt.Errorf("send draft %s: %w", draft.ID, err)
	}

	return emitJSON(map[string]string{"status": "sent", "id": sent.ID})
}

func parseAddrList(s string) ([]*gomail.Address, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]*gomail.Address, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		a, err := gomail.ParseAddress(p)
		if err != nil {
			// Fall back to treating it as a bare address, but only
			// if it looks like one (local@domain, no spaces or
			// delimiters). Re-parsing the same string would fail
			// again deterministically, so the fallback could never run.
			if !isBareAddress(p) {
				return nil, fmt.Errorf("bad address %q: %w", p, err)
			}
			a = &gomail.Address{Address: p}
		}
		out = append(out, a)
	}
	return out, nil
}

// isBareAddress reports whether s looks like a plain local@domain address
// with no display name, spaces, or delimiters.
func isBareAddress(s string) bool {
	if strings.Count(s, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(s, "@")
	if local == "" || domain == "" {
		return false
	}
	return !strings.ContainsAny(s, " \t<>(),;:\"")
}
