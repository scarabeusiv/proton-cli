package main

import (
	"context"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// attachmentInfo is the JSON shape for one message attachment. Path is
// set only when the attachment was downloaded to disk.
type attachmentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	MIMEType    string `json:"mime_type"`
	Disposition string `json:"disposition"`
	Path        string `json:"path,omitempty"`
}

func summarizeAttachment(att proton.Attachment) attachmentInfo {
	return attachmentInfo{
		ID:          att.ID,
		Name:        att.Name,
		Size:        att.Size,
		MIMEType:    string(att.MIMEType),
		Disposition: string(att.Disposition),
	}
}

// stringList is a flag.Value that collects repeated flags (e.g. --attach).
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// attachmentMIMEType guesses a MIME type from a file's extension,
// falling back to application/octet-stream for unknown extensions.
// Any charset or other parameters from the system MIME database are
// stripped: the attachment upload takes a bare media type.
func attachmentMIMEType(path string) string {
	mt := mime.TypeByExtension(filepath.Ext(path))
	if mt == "" {
		return "application/octet-stream"
	}
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = strings.TrimSpace(mt[:i])
	}
	if mt == "" {
		return "application/octet-stream"
	}
	return mt
}

// sanitizeAttachmentName strips any directory components from an
// attachment name, so a crafted name cannot escape the download
// directory (e.g. "../../etc/passwd"). It returns "" when nothing
// usable remains.
func sanitizeAttachmentName(name string) string {
	name = filepath.Base(name)
	switch name {
	case ".", "..", "/", "":
		return ""
	}
	return name
}

// uniqueAttachmentPath returns a path inside dir for name that does not
// collide with a file already on disk or one already claimed in this
// run (tracked in used). A colliding name gets a numeric suffix before
// its extension: report.pdf, report-2.pdf, report-3.pdf. A stat error
// other than "not exist" (e.g. the directory is unreadable) is returned
// instead of looping: every candidate would fail the same way and the
// suffix loop would never terminate.
func uniqueAttachmentPath(dir, name string, used map[string]bool) (string, error) {
	candidate := filepath.Join(dir, name)
	if !used[candidate] {
		free, err := pathFree(candidate)
		if err != nil {
			return "", err
		}
		if free {
			used[candidate] = true
			return candidate, nil
		}
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 2; ; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
		if used[candidate] {
			continue
		}
		free, err := pathFree(candidate)
		if err != nil {
			return "", err
		}
		if free {
			used[candidate] = true
			return candidate, nil
		}
	}
}

// pathFree reports whether no file exists at path. A stat error other
// than "not exist" is returned as an error.
func pathFree(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return false, nil
	}
	if os.IsNotExist(err) {
		return true, nil
	}
	return false, err
}

// decryptAttachment decrypts a downloaded attachment: the attachment's
// key packet (base64) plus the downloaded data packet, unlocked with the
// address keyring. Mirrors Message.Decrypt (no signature verification).
func decryptAttachment(kr *crypto.KeyRing, att proton.Attachment, data []byte) ([]byte, error) {
	keyPacket := decodeKeyPacket(att.KeyPackets)
	if len(keyPacket) == 0 {
		return nil, fmt.Errorf("attachment %s: empty or invalid key packet", att.ID)
	}
	split := crypto.NewPGPSplitMessage(keyPacket, data)
	plain, err := kr.Decrypt(split.GetPGPMessage(), nil, crypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("attachment %s: decrypt: %w", att.ID, err)
	}
	return plain.GetBinary(), nil
}

// attachmentDecrypter decrypts one attachment's downloaded data packet.
// It is a function so the same download loop serves both the local
// keyring path and the daemon path.
type attachmentDecrypter func(att proton.Attachment, data []byte) ([]byte, error)

// downloadAttachments downloads and decrypts every attachment of msg
// into dir, creating dir when needed, and fills in the Path of each
// entry in atts (aligned with msg.Attachments by index). A failure on
// any attachment aborts the download and reports which one failed;
// files already written stay on disk.
func downloadAttachments(ctx context.Context, c *proton.Client, decrypt attachmentDecrypter, msg proton.Message, dir string, atts []attachmentInfo) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create attachments directory %s: %w", dir, err)
	}
	used := make(map[string]bool)
	for i, att := range msg.Attachments {
		name := sanitizeAttachmentName(att.Name)
		if name == "" {
			// Fall back to the attachment ID so the file is still saved.
			name = att.ID
		}
		data, err := c.GetAttachment(ctx, att.ID)
		if err != nil {
			return fmt.Errorf("download attachment %s (%s): %w", att.ID, att.Name, err)
		}
		plain, err := decrypt(att, data)
		if err != nil {
			return err
		}
		path, err := uniqueAttachmentPath(dir, name, used)
		if err != nil {
			return fmt.Errorf("attachment %s (%s): %w", att.ID, att.Name, err)
		}
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			return fmt.Errorf("write attachment %s: %w", path, err)
		}
		atts[i].Path = path
		atts[i].Size = int64(len(plain))
	}
	return nil
}
