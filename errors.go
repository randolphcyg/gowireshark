package gowireshark

import "github.com/pkg/errors"

var (
	ErrInvalidFilter        = errors.New("invalid display filter")
	ErrInvalidFrameIndex    = errors.New("invalid frame index")
	ErrUnsupportedProtocol  = errors.New("unsupported protocol")
	ErrEmptySelection       = errors.New("empty frame selection")
	ErrFieldNotFound        = errors.New("field not found")
	ErrInvalidPreference    = errors.New("invalid preference")
	ErrInvalidProfile       = errors.New("invalid profile")
	ErrPreserveNotSupported = errors.New("preserve option not supported in best-effort pcap slice; use native wiretap for full metadata")
)
