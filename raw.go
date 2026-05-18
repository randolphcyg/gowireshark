package gowireshark

/*
#include "raw.h"
*/
import "C"
import (
	"context"
	"errors"
	"time"
	"unsafe"
)

// LinkType is a libpcap LINKTYPE/DLT value.
type LinkType int

const (
	// LinkTypeEthernet is the standard Ethernet DLT/LINKTYPE value.
	LinkTypeEthernet LinkType = 1
)

// RawPacket is a packet captured outside gowireshark and handed to libwireshark for dissection.
type RawPacket struct {
	Data           []byte
	Timestamp      time.Time
	CaptureLength  int
	OriginalLength int
	LinkType       LinkType
}

// DissectResult is one item emitted by DissectPackets.
type DissectResult struct {
	Packet RawPacket
	Frame  *FrameData
	Err    error
}

var (
	// ErrRawPacketEmpty reports a raw packet with no bytes.
	ErrRawPacketEmpty = errors.New("raw packet data is empty")
	// ErrRawPacketInvalidSize reports inconsistent captured/original lengths.
	ErrRawPacketInvalidSize = errors.New("raw packet lengths are invalid")
	// ErrRawPacketDissection reports a libwireshark failure while dissecting raw bytes.
	ErrRawPacketDissection = errors.New("raw packet dissection failed")
)

// DissectPacket dissects one raw packet captured by another component.
func DissectPacket(pkt RawPacket, opts ...Option) (*FrameData, error) {
	if len(pkt.Data) == 0 {
		return nil, ErrRawPacketEmpty
	}

	captureLen := pkt.CaptureLength
	if captureLen == 0 {
		captureLen = len(pkt.Data)
	}
	originalLen := pkt.OriginalLength
	if originalLen == 0 {
		originalLen = captureLen
	}
	if captureLen <= 0 || originalLen <= 0 || captureLen > len(pkt.Data) || captureLen > originalLen {
		return nil, ErrRawPacketInvalidSize
	}
	if pkt.LinkType == 0 {
		pkt.LinkType = LinkTypeEthernet
	}

	conf := newConfig(opts...)
	cOptions := C.CString(marshalConfig(conf))
	defer C.free(unsafe.Pointer(cOptions))

	var sec int64
	var nsec int
	if !pkt.Timestamp.IsZero() {
		sec = pkt.Timestamp.Unix()
		nsec = pkt.Timestamp.Nanosecond()
	}

	epanMu.Lock()
	json := C.dissect_raw_packet_json(
		(*C.uchar)(unsafe.Pointer(&pkt.Data[0])),
		C.int(captureLen),
		C.int(originalLen),
		C.long(sec),
		C.int(nsec),
		C.int(pkt.LinkType),
		cOptions,
	)
	epanMu.Unlock()
	if json == nil {
		return nil, ErrRawPacketDissection
	}
	defer C.free_c_string(json)

	return ParseFrameData([]byte(C.GoString(json)), opts...)
}

// DissectPackets dissects a raw packet stream sequentially and preserves packet order.
func DissectPackets(ctx context.Context, packets <-chan RawPacket, opts ...Option) <-chan DissectResult {
	out := make(chan DissectResult)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-packets:
				if !ok {
					return
				}
				frame, err := DissectPacket(pkt, opts...)
				select {
				case <-ctx.Done():
					return
				case out <- DissectResult{Packet: pkt, Frame: frame, Err: err}:
				}
			}
		}
	}()
	return out
}
