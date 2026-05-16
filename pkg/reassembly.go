package pkg

/*
#include "reassembly.h"
*/
import "C"
import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var (
	ErrParseTcpStream = errors.New("fail to parse tcp stream")
)

// Packet represents a single TCP segment within a reassembled stream.
type Packet struct {
	StreamID  uint32  `json:"stream_id"`
	PacketID  uint32  `json:"packet_id"`
	Src       string  `json:"src"`
	Dst       string  `json:"dst"`
	Timestamp float64 `json:"timestamp"`
	Data      string  `json:"data,omitempty"` // base64 encoded, cleared after decode
	RawData   []byte  `json:"-"`             // decoded payload bytes
}

// --- Handle registry for C callback routing ---

var (
	handlesMu sync.RWMutex
	handles   = make(map[uintptr]*TCPReassembler)
	nextID    uintptr = 1
)

// --- TCPReassembler ---

// TCPReassembler collects TCP stream data from wireshark's tcp_follow tap.
// Create with NewTCPReassembler, register before starting capture,
// and unregister when done.
type TCPReassembler struct {
	store   *TCPStreamStore
	onData  func(Packet) // optional per-packet callback
}

// TCPReassemblerOption configures a TCPReassembler.
type TCPReassemblerOption func(*TCPReassembler)

// WithOnData sets a callback invoked for each reassembled packet.
// Useful for real-time processing without polling the store.
func WithOnData(fn func(Packet)) TCPReassemblerOption {
	return func(r *TCPReassembler) {
		r.onData = fn
	}
}

// NewTCPReassembler creates a new TCP stream reassembler.
func NewTCPReassembler(opts ...TCPReassemblerOption) *TCPReassembler {
	r := &TCPReassembler{
		store: NewTCPStreamStore(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// RegisterCallback registers this reassembler to receive TCP tap data from C.
// Returns a handle that must be passed to UnregisterCallback when done.
func (r *TCPReassembler) RegisterCallback() uintptr {
	handlesMu.Lock()
	id := nextID
	nextID++
	handles[id] = r
	handlesMu.Unlock()

	C.setTcpTapDataCallbackWithCtx(
		(C.TcpTapDataCallback)(C.GetTcpTapDataCallback),
		unsafe.Pointer(id),
	)
	return id
}

// UnregisterCallback removes this reassembler from the callback registry.
func (r *TCPReassembler) UnregisterCallback(handle uintptr) {
	handlesMu.Lock()
	delete(handles, handle)
	handlesMu.Unlock()
}

// GetStream returns all packets for a given stream ID.
func (r *TCPReassembler) GetStream(streamID uint32) []Packet {
	return r.store.GetStream(streamID)
}

// GetAllStreams returns a copy of all collected streams.
func (r *TCPReassembler) GetAllStreams() map[uint32][]Packet {
	return r.store.GetAllStreams()
}

// StreamCount returns the number of distinct streams collected.
func (r *TCPReassembler) StreamCount() int {
	return r.store.StreamCount()
}

// Reset clears all collected stream data.
func (r *TCPReassembler) Reset() {
	r.store.Reset()
}

// --- TCPStreamStore ---

// TCPStreamStore is a thread-safe store for reassembled TCP stream packets.
type TCPStreamStore struct {
	mu         sync.RWMutex
	streams    map[uint32][]Packet
	maxStreams int // 0 = unlimited
	maxPackets int // max packets per stream, 0 = unlimited
}

// TCPStreamStoreOption configures a TCPStreamStore.
type TCPStreamStoreOption func(*TCPStreamStore)

// WithMaxStreams limits the number of streams stored (LRU eviction not implemented,
// oldest stream is dropped when limit is reached).
func WithMaxStreams(n int) TCPStreamStoreOption {
	return func(s *TCPStreamStore) {
		s.maxStreams = n
	}
}

// WithMaxPacketsPerStream limits packets stored per stream.
func WithMaxPacketsPerStream(n int) TCPStreamStoreOption {
	return func(s *TCPStreamStore) {
		s.maxPackets = n
	}
}

// NewTCPStreamStore creates a new stream store.
func NewTCPStreamStore(opts ...TCPStreamStoreOption) *TCPStreamStore {
	s := &TCPStreamStore{
		streams: make(map[uint32][]Packet),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// AddPacket adds a packet to the appropriate stream.
func (s *TCPStreamStore) AddPacket(packet Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce max streams limit
	if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
		if _, exists := s.streams[packet.StreamID]; !exists {
			// Evict the first stream found (simple eviction)
			for id := range s.streams {
				delete(s.streams, id)
				break
			}
		}
	}

	packets := s.streams[packet.StreamID]

	// Enforce max packets per stream
	if s.maxPackets > 0 && len(packets) >= s.maxPackets {
		return // drop packet
	}

	s.streams[packet.StreamID] = append(packets, packet)
}

// GetStream returns packets for a specific stream ID.
func (s *TCPStreamStore) GetStream(streamID uint32) []Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	packets := s.streams[streamID]
	if packets == nil {
		return nil
	}

	// Return a copy to avoid data races
	result := make([]Packet, len(packets))
	copy(result, packets)
	return result
}

// GetAllStreams returns a snapshot of all streams.
func (s *TCPStreamStore) GetAllStreams() map[uint32][]Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[uint32][]Packet, len(s.streams))
	for id, packets := range s.streams {
		cp := make([]Packet, len(packets))
		copy(cp, packets)
		result[id] = cp
	}
	return result
}

// StreamCount returns the number of distinct streams.
func (s *TCPStreamStore) StreamCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams)
}

// Reset clears all stored streams.
func (s *TCPStreamStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = make(map[uint32][]Packet)
}

// RemoveStream removes a specific stream by ID.
func (s *TCPStreamStore) RemoveStream(streamID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.streams, streamID)
}

// StreamIDs returns all stream IDs currently stored.
func (s *TCPStreamStore) StreamIDs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	return ids
}

// --- C Callback Bridge ---

//export GetTcpTapDataCallback
func GetTcpTapDataCallback(data *C.char, length C.int, ctx unsafe.Pointer) {
	if data == nil || length <= 0 || ctx == nil {
		return
	}

	handlesMu.RLock()
	handle := uintptr(ctx)
	reassembler, exists := handles[handle]
	handlesMu.RUnlock()

	if !exists || reassembler == nil {
		return
	}

	goBytes := C.GoBytes(unsafe.Pointer(data), length)

	if err := reassembler.handleTcpData(goBytes); err != nil {
		slog.Debug("TCP reassembly: data handling failed", "err", err)
	}
}

func (r *TCPReassembler) handleTcpData(jsonBytes []byte) error {
	packet, err := parseTcpPacket(jsonBytes)
	if err != nil {
		return err
	}

	r.store.AddPacket(packet)

	if r.onData != nil {
		r.onData(packet)
	}

	return nil
}

// parseTcpPacket parses a JSON TCP packet from the C tap callback.
func parseTcpPacket(src []byte) (Packet, error) {
	if len(src) == 0 {
		return Packet{}, errors.New("empty input data")
	}

	var packet Packet
	if err := sonic.Unmarshal(src, &packet); err != nil {
		return Packet{}, fmt.Errorf("%w: %v", ErrParseTcpStream, err)
	}

	// Decode base64 payload and release the encoded string
	if len(packet.Data) > 0 {
		decoded, err := base64.StdEncoding.DecodeString(packet.Data)
		if err != nil {
			return Packet{}, fmt.Errorf("base64 decode failed: %w", err)
		}
		packet.RawData = decoded
		packet.Data = "" // free the base64 string memory
	}

	return packet, nil
}

// --- Convenience helpers ---

// ReassembleStreamPayload concatenates all packet payloads for a stream in order.
func ReassembleStreamPayload(packets []Packet) []byte {
	if len(packets) == 0 {
		return nil
	}

	totalLen := 0
	for i := range packets {
		totalLen += len(packets[i].RawData)
	}

	result := make([]byte, 0, totalLen)
	for i := range packets {
		result = append(result, packets[i].RawData...)
	}
	return result
}

// StreamDuration returns the time span of a stream (last - first packet timestamp).
func StreamDuration(packets []Packet) time.Duration {
	if len(packets) < 2 {
		return 0
	}
	first := packets[0].Timestamp
	last := packets[len(packets)-1].Timestamp
	return time.Duration((last - first) * float64(time.Second))
}
