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

// newManager builds a Proton API manager identifying as above.
func newManager() *proton.Manager {
	return proton.New(proton.WithAppVersion(protonAppVersion))
}
