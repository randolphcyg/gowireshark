package gowireshark

/*
#cgo CFLAGS: -I${SRCDIR}/include
#include "reassembly.h"
*/
import "C"
import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var (
	ErrParseTcpStream = errors.New("fail to parse tcp stream")
)

type Packet struct {
	StreamID  uint32  `json:"stream_id"`
	PacketID  uint32  `json:"packet_id"`
	Src       string  `json:"src"`
	Dst       string  `json:"dst"`
	Timestamp float64 `json:"timestamp"`
	Data      string  `json:"data"`
	RawData   []byte
}

var (
	handles     = make(map[uintptr]*TCPReassembler)
	muTcpStream sync.Mutex
	nextID      uintptr = 1
)

type TCPReassembler struct {
	streamStore *TCPStreamStore
}

func NewTCPReassembler() *TCPReassembler {
	return &TCPReassembler{
		streamStore: NewTCPStreamStore(),
	}
}

func (r *TCPReassembler) RegisterCallback() uintptr {
	muTcpStream.Lock()
	id := nextID
	nextID++
	handles[id] = r
	muTcpStream.Unlock()

	C.setTcpTapDataCallbackWithCtx(
		(C.TcpTapDataCallback)(C.GetTcpTapDataCallback),
		unsafe.Pointer(id),
	)
	return id
}

func (r *TCPReassembler) UnregisterCallback(handle uintptr) {
	muTcpStream.Lock()
	delete(handles, handle)
	muTcpStream.Unlock()
}

type TCPStreamStore struct {
	sync.Mutex
	streams map[uint32][]Packet
}

func NewTCPStreamStore() *TCPStreamStore {
	return &TCPStreamStore{
		streams: make(map[uint32][]Packet),
	}
}

func (s *TCPStreamStore) AddPacket(packet Packet) {
	s.Lock()
	defer s.Unlock()
	s.streams[packet.StreamID] = append(s.streams[packet.StreamID], packet)
}

//export GetTcpTapDataCallback
func GetTcpTapDataCallback(data *C.char, length C.int, ctx unsafe.Pointer) {
	if data == nil || length <= 0 || ctx == nil {
		return
	}

	muTcpStream.Lock()
	handle := uintptr(ctx)
	reassembler, exists := handles[handle]
	muTcpStream.Unlock()

	if !exists || reassembler == nil {
		slog.Info("invalid reassembler handle", "handle", handle)
		return
	}

	goStr := C.GoStringN(data, length)

	if err := reassembler.handleTcpData(goStr); err != nil {
		slog.Info("TCP data handling failed", "err", err)
	}
}

func (r *TCPReassembler) handleTcpData(jsonStr string) error {
	packet, err := ParseTcpStream(jsonStr)
	if err != nil {
		return fmt.Errorf("parse tcp stream: %w", err)
	}
	r.streamStore.AddPacket(*packet)
	return nil
}

func ParseTcpStream(src string) (packet *Packet, err error) {
	if src == "" {
		return nil, errors.New("empty input data")
	}

	packet = &Packet{}
	if err = sonic.Unmarshal([]byte(src), packet); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParseTcpStream, err)
	}

	if len(packet.Data) > 0 {
		decodedData, decodeErr := base64.StdEncoding.DecodeString(packet.Data)
		if decodeErr != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", decodeErr)
		}
		packet.RawData = decodedData // Replace the Base64 string with the raw byte data
	}

	return packet, nil
}
