package gowireshark

/*
#include "tcp_follow.h"
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"runtime/cgo"
	"sync"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var errParseTCPFollowPacket = errors.New("failed to parse tcp follow packet")

// TCPFollowPacket is one payload fragment emitted by Wireshark's tcp_follow tap.
type TCPFollowPacket struct {
	StreamID  uint32  `json:"stream_id"`
	PacketID  uint32  `json:"packet_id"`
	Src       string  `json:"src"`
	Dst       string  `json:"dst"`
	Timestamp float64 `json:"timestamp"`
	Data      string  `json:"data,omitempty"`
	RawData   []byte  `json:"-"`
}

// TCPFollowHandler receives decoded payload fragments from the tcp_follow tap.
type TCPFollowHandler func(TCPFollowPacket)

// TCPFollowRegistration owns one active tcp_follow callback registration.
type TCPFollowRegistration struct {
	handle cgo.Handle
	once   sync.Once
}

// RegisterTCPFollowHandler installs one tcp_follow callback for the next offline dissection run.
func RegisterTCPFollowHandler(handler TCPFollowHandler) *TCPFollowRegistration {
	reg := &TCPFollowRegistration{handle: cgo.NewHandle(handler)}
	C.setTcpTapDataCallbackWithCtx(
		(C.TcpTapDataCallback)(C.tcpFollowDataCallback),
		C.uintptr_t(reg.handle),
	)
	return reg
}

// Close removes the callback registration and releases its cgo handle.
func (r *TCPFollowRegistration) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() {
		C.setTcpTapDataCallbackWithCtx(nil, 0)
		r.handle.Delete()
	})
}

//export tcpFollowDataCallback
func tcpFollowDataCallback(data *C.char, length C.int, ctx C.uintptr_t) {
	if data == nil || length <= 0 || ctx == 0 {
		return
	}
	handle := cgo.Handle(ctx)
	handler, ok := handle.Value().(TCPFollowHandler)
	if !ok || handler == nil {
		return
	}
	packet, err := parseTCPFollowPacket(C.GoBytes(unsafe.Pointer(data), length))
	if err != nil {
		slog.Debug("tcp follow packet parse failed", "err", err)
		return
	}
	handler(packet)
}

func parseTCPFollowPacket(src []byte) (TCPFollowPacket, error) {
	if len(src) == 0 {
		return TCPFollowPacket{}, errors.New("empty input data")
	}
	var packet TCPFollowPacket
	if err := sonic.Unmarshal(src, &packet); err != nil {
		return TCPFollowPacket{}, fmt.Errorf("%w: %v", errParseTCPFollowPacket, err)
	}
	if packet.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(packet.Data)
		if err != nil {
			return TCPFollowPacket{}, fmt.Errorf("base64 decode failed: %w", err)
		}
		packet.RawData = decoded
		packet.Data = ""
	}
	return packet, nil
}
