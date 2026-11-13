package main

import (
	"context"
	"fmt"
)

// cmdKeys is a diagnostic: it prints key metadata (IDs, primary/active
// flags, whether an address key carries a token) and which key salts are
// stored in the session. It prints no private key material, no tokens,
// no passwords and no salts — only IDs and flags, enough to work out
// which key an unlock failure refers to and whether its salt is present.
func cmdKeys(ctx context.Context, args []string) error {
	s, err := loadSession()
	if err != nil {
		return err
	}

	c, m, err := authedClient(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	defer m.Close()

	user, err := c.GetUser(ctx)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	fmt.Printf("stored salts: %d\n", len(s.Salts))
	for _, salt := range s.Salts {
		fmt.Printf("  salt key id: %s\n", salt.ID)
	}

	fmt.Printf("user keys: %d\n", len(user.Keys))
	for _, k := range user.Keys {
		fmt.Println(formatKeyMeta(k.ID, bool(k.Primary), bool(k.Active), k.Token != ""))
	}
	// Primary() panics when no key is flagged primary.
	if id := primaryKeyID(user.Keys); id != "" {
		fmt.Printf("primary user key id: %s\n", id)
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return fmt.Errorf("get addresses: %w", err)
	}
	for _, addr := range addrs {
		fmt.Printf("address %s (%s) keys: %d\n", addr.Email, addr.ID, len(addr.Keys))
		for _, k := range addr.Keys {
			fmt.Println(formatKeyMeta(k.ID, bool(k.Primary), bool(k.Active), k.Token != ""))
		}
	}

	return nil
}

// formatKeyMeta renders one key's diagnostic line. The format string and
// the arguments are kept together here so a verb/argument mismatch cannot
// creep back in unnoticed (go vet also checks this).
func formatKeyMeta(id string, primary, active, hasToken bool) string {
	return fmt.Sprintf("  id=%s primary=%v active=%v has_token=%v", id, primary, active, hasToken)
}
