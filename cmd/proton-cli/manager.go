package main

import (
	"os"

	"github.com/ProtonMail/go-proton-api"
)

// protonAppVersion is the client identifier sent as the x-pm-appversion
// header. Proton validates the platform parsed from this string, and the
// library's default ("go-proton-api") is rejected with 400 Code 2064
// ("Platform `go` is not valid"). The library documents that the default
// must be changed for production use. This uses the current web-mail
// version published by Proton at https://mail.proton.me/assets/version.json;
// refresh it if Proton starts rejecting it (AppVersionBadCode 5003).
const protonAppVersion = "web-mail@5.0.141.8"

// apiHostURL overrides the default Proton API host when non-empty.
// Integration tests set it to an httptest server URL so the commands
// can be exercised end to end without real credentials or network
// access to Proton. Production code never sets it, so real runs always
// use the default host.
var apiHostURL string

// newManager builds a Proton API manager identifying as above.
func newManager() *proton.Manager {
	opts := []proton.Option{proton.WithAppVersion(protonAppVersion)}
	host := apiHostURL
	if host == "" {
		// Test/debug override: point the CLI at a local mock API
		// (used by the CLI-level daemon tests, which run the real
		// binary as a subprocess). Never set in production.
		host = os.Getenv("PROTON_CLI_API_HOST")
	}
	if host != "" {
		opts = append(opts, proton.WithHostURL(host))
	}
	return proton.New(opts...)
}
