package gowireshark

import "github.com/pkg/errors"

var (
	// ErrInvalidFilter reports an invalid Wireshark display filter.
	ErrInvalidFilter = errors.New("invalid display filter")
	// ErrInvalidFrameIndex reports an invalid 1-based frame number.
	ErrInvalidFrameIndex = errors.New("invalid frame index")
	// ErrUnsupportedProtocol reports a protocol argument that gowireshark cannot handle.
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
	// ErrEmptySelection reports that a frame selector matched no packets.
	ErrEmptySelection = errors.New("empty frame selection")
	// ErrFieldNotFound reports an unknown Wireshark display-filter field.
	ErrFieldNotFound = errors.New("field not found")
)
