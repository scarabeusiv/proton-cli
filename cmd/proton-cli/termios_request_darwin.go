//go:build darwin

package main

import "golang.org/x/sys/unix"

// termiosGetRequest is the ioctl request that fetches the terminal
// attributes: TIOCGETA on Darwin (there is no TCGETS there).
const termiosGetRequest = unix.TIOCGETA
