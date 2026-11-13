package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	gomail "net/mail"
)

func cmdMail(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: proton-cli mail <list|read|send|mark-read|mark-unread|delete|labels|label|create-label> [flags]")
	}

	switch args[0] {
	case "list":
		return cmdMailList(ctx, args[1:])
	case "read":
		return cmdMailRead(ctx, args[1:])
	case "send":
		return cmdMailSend(ctx, args[1:])
	case "mark-read":
		return cmdMailMarkRead(ctx, args[1:])
	case "mark-unread":
		return cmdMailMarkUnread(ctx, args[1:])
	case "delete":
		return cmdMailDelete(ctx, args[1:])
	case "labels":
		return cmdMailLabels(ctx, args[1:])
	case "label":
		return cmdMailLabel(ctx, args[1:])
	case "create-label":
		return cmdMailCreateLabel(ctx, args[1:])
	default:
		return fmt.Errorf("unknown mail subcommand %q (list|read|send|mark-read|mark-unread|delete|labels|label|create-label)", args[0])
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

	// Page through metadata and stop once the limit is reached, instead
	// of fetching the whole mailbox and limiting client-side.
	const mailPageSize = 100
	out := make([]mailSummary, 0, limit)
	for page := 0; ; page++ {
		metas, err := c.GetMessageMetadataPage(ctx, page, mailPageSize, filter)
		if err != nil {
			return fmt.Errorf("list messages: %w", err)
		}
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
				return emitJSON(out)
			}
		}
		if len(metas) < mailPageSize {
			break
		}
	}

	return emitJSON(out)
}

func cmdMailRead(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail read", flag.ContinueOnError)
	decrypt := fs.Bool("decrypt", false, "decrypt the body (reads account password from stdin)")
	noDaemon := fs.Bool("no-daemon", false, "do not use the daemon; always prompt for the account password")
	downloadAtt := fs.Bool("download-attachments", false, "download attachments (decrypted) into a directory; requires --decrypt")
	attDir := fs.String("attachments-dir", "", "directory for downloaded attachments (default: <message-id>-attachments)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: proton-cli mail read [--decrypt] [--download-attachments] [--attachments-dir DIR] <message-id>")
	}
	if *downloadAtt && !*decrypt {
		return fmt.Errorf("--download-attachments requires --decrypt")
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

	// Attachment metadata is not encrypted, so it is listed even
	// without --decrypt; downloading fills in each entry's path.
	atts := make([]attachmentInfo, 0, len(msg.Attachments))
	for _, att := range msg.Attachments {
		atts = append(atts, summarizeAttachment(att))
	}
	out["attachments"] = atts

	if *decrypt {
		// The daemon holds the unlocked keyring in memory; when it
		// answers, decrypt through it and never prompt. Otherwise
		// fall back to the local prompt path, exactly as before.
		useDaemon := false
		if !*noDaemon {
			useDaemon, _ = pingDaemon()
		}

		var kr *crypto.KeyRing
		if !useDaemon {
			pw, err := readSecretLine("Enter account password (via stdin):")
			if err != nil {
				return err
			}
			defer zero(pw)

			// The key password is the SALTED password, not the raw account
			// password: derive it from the salts captured at login.
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
			primaryID := primaryKeyID(user.Keys)
			if primaryID == "" {
				return fmt.Errorf("no primary user key — cannot derive salted key password")
			}
			salted, err := stored.Salts.SaltForKey(pw, primaryID)
			if err != nil {
				return fmt.Errorf("derive salted key password: %w", err)
			}
			if len(salted) == 0 {
				return fmt.Errorf("derive salted key password: empty salted password")
			}
			defer zero(salted)

			kr, err = unlockAddressKeyring(ctx, c, salted, msg.AddressID)
			if err != nil {
				return err
			}
		}

		if useDaemon {
			body, err := daemonDecryptMailBody(msg.Body)
			if err != nil {
				return fmt.Errorf("decrypt body: %w", err)
			}
			out["body"] = string(body)
		} else {
			body, err := msg.Decrypt(kr)
			if err != nil {
				return fmt.Errorf("decrypt body: %w", err)
			}
			out["body"] = string(body)
		}

		if *downloadAtt {
			dir := *attDir
			if dir == "" {
				dir = id + "-attachments"
			}
			var decrypt attachmentDecrypter
			if useDaemon {
				decrypt = func(att proton.Attachment, data []byte) ([]byte, error) {
					return daemonDecryptAttachment(att.KeyPackets, data)
				}
			} else {
				decrypt = func(att proton.Attachment, data []byte) ([]byte, error) {
					return decryptAttachment(kr, att, data)
				}
			}
			if err := downloadAttachments(ctx, c, decrypt, msg, dir, atts); err != nil {
				return err
			}
		}
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
	fromAddr := fs.String("from", "", "sender address (defaults to first usable address)")
	var attachFiles stringList
	fs.Var(&attachFiles, "attach", "file to attach (repeatable)")
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

	// Parse recipients before touching the server or the password: a bad
	// or empty address list must fail before any draft exists.
	toAddrs, err := parseAddrList(*to)
	if err != nil {
		return err
	}
	if len(toAddrs) == 0 {
		return fmt.Errorf("--to must contain at least one recipient address")
	}
	ccAddrs, err := parseAddrList(*cc)
	if err != nil {
		return err
	}

	pw, err := readSecretLine("Enter account password (via stdin) — needed to encrypt the draft:")
	if err != nil {
		return err
	}
	defer zero(pw)

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

	sender := defaultSender(addrs)
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

	// The key password is the SALTED password, not the raw account
	// password: derive it from the salts captured at login.
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
	primaryID := primaryKeyID(user.Keys)
	if primaryID == "" {
		return fmt.Errorf("no primary user key — cannot derive salted key password")
	}
	salted, err := stored.Salts.SaltForKey(pw, primaryID)
	if err != nil {
		return fmt.Errorf("derive salted key password: %w", err)
	}
	if len(salted) == 0 {
		return fmt.Errorf("derive salted key password: empty salted password")
	}
	defer zero(salted)

	kr, err := unlockAddressKeyring(ctx, c, salted, sender.ID)
	if err != nil {
		return err
	}

	// Build send preferences (recipient key lookups) BEFORE creating the
	// draft, so a lookup failure leaves no orphaned draft behind.
	allRecipients := append(append([]*gomail.Address{}, toAddrs...), ccAddrs...)
	prefs, err := buildSendPrefs(ctx, c, allRecipients)
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

	for _, path := range attachFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			discardDraft(ctx, c, draft.ID)
			return fmt.Errorf("read attachment %s: %w", path, err)
		}
		if _, err := c.UploadAttachment(ctx, kr, proton.CreateAttachmentReq{
			MessageID:   draft.ID,
			Filename:    filepath.Base(path),
			MIMEType:    rfc822.MIMEType(attachmentMIMEType(path)),
			Disposition: proton.AttachmentDisposition,
			Body:        data,
		}); err != nil {
			discardDraft(ctx, c, draft.ID)
			return fmt.Errorf("upload attachment %s: %w", path, err)
		}
	}

	var req proton.SendDraftReq
	if err := req.AddTextPackage(kr, string(body), rfc822.TextPlain, prefs, nil); err != nil {
		discardDraft(ctx, c, draft.ID)
		return fmt.Errorf("build send package: %w", err)
	}

	sent, err := c.SendDraft(ctx, draft.ID, req)
	if err != nil {
		discardDraft(ctx, c, draft.ID)
		return fmt.Errorf("send draft %s: %w", draft.ID, err)
	}

	return emitJSON(map[string]string{"status": "sent", "id": sent.ID})
}

// defaultSender picks the sending address: the first address that can
// send (Send flag set, status enabled), falling back to the first
// address when none qualifies.
func defaultSender(addrs []proton.Address) proton.Address {
	for _, a := range addrs {
		if bool(a.Send) && a.Status == proton.AddressStatusEnabled {
			return a
		}
	}
	return addrs[0]
}

// buildSendPrefs resolves per-recipient send preferences: encrypted for
// recipients we have keys for, cleartext otherwise.
func buildSendPrefs(ctx context.Context, c *proton.Client, recipients []*gomail.Address) (map[string]proton.SendPreferences, error) {
	prefs := make(map[string]proton.SendPreferences, len(recipients))

	for _, rcpt := range recipients {
		keys, rt, err := c.GetPublicKeys(ctx, rcpt.Address)
		if err != nil {
			return nil, fmt.Errorf("get public keys for %s: %w", rcpt.Address, err)
		}

		sp := proton.SendPreferences{
			SignatureType: proton.DetachedSignature,
			MIMEType:      rfc822.TextPlain,
		}

		if rt == proton.RecipientTypeInternal && len(keys) > 0 {
			kr, err := keys.GetKeyRing()
			if err != nil {
				return nil, fmt.Errorf("keyring for %s: %w", rcpt.Address, err)
			}
			sp.Encrypt = true
			sp.PubKey = kr
			sp.EncryptionScheme = proton.InternalScheme
		} else if len(keys) > 0 {
			kr, err := keys.GetKeyRing()
			if err != nil {
				return nil, fmt.Errorf("keyring for %s: %w", rcpt.Address, err)
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

	return prefs, nil
}

// discardDraft deletes a draft left behind when sending fails, warning
// instead of failing when the delete itself fails.
func discardDraft(ctx context.Context, c *proton.Client, draftID string) {
	if err := c.DeleteMessage(ctx, draftID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not delete orphaned draft %s: %v\n", draftID, err)
	}
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
