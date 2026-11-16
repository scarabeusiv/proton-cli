//go:build darwin

package main

import "golang.org/x/sys/unix"

// termiosGetRequest is the ioctl request that fetches the terminal
// attributes: TIOCGETA on Darwin (there is no TCGETS there).
const termiosGetRequest = unix.TIOCGETA

// termiosSetRequest is the ioctl request that sets the terminal
// attributes: TIOCSETA on Darwin (there is no TCSETS there).
const termiosSetRequest = unix.TIOCSETA
