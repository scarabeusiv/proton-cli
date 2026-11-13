package main

import (
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
	if apiHostURL != "" {
		opts = append(opts, proton.WithHostURL(apiHostURL))
	}
	return proton.New(opts...)
}
