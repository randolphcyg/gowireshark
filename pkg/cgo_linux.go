//go:build linux

package pkg

// On Linux (including the Ubuntu 24 runtime container described in
// Dockerfile), glib flags come from pkg-config. The Dockerfile already
// installs libglib2.0-dev and supplies CGO_CFLAGS / CGO_LDFLAGS pointing at
// /app/include and /app/libs, so we only need the pkg-config directive here.

/*
#cgo pkg-config: glib-2.0
*/
import "C"
