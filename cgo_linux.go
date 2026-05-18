//go:build linux

package gowireshark

// On Linux, glib flags come from pkg-config. Wireshark include/library
// paths should be supplied by the local environment when they are not already
// available through the system toolchain.

/*
#cgo pkg-config: glib-2.0
*/
import "C"
