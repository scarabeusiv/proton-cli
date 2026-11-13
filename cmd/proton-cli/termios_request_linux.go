//go:build linux

package main

import "golang.org/x/sys/unix"

// termiosGetRequest is the ioctl request that fetches the terminal
// attributes: TCGETS on Linux.
const termiosGetRequest = unix.TCGETS
