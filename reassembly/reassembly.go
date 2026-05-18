package reassembly

import (
	"sync"
	"time"

	"github.com/randolphcyg/gowireshark"
)

// Packet is one decoded tcp_follow payload fragment.
type Packet = gowireshark.TCPFollowPacket

// Reassembler collects TCP stream payloads while an offline dissection runs.
type Reassembler struct {
	store  *Store
	onData func(Packet)
	reg    *gowireshark.TCPFollowRegistration
}

// Option customizes a Reassembler.
type Option func(*Reassembler)

// WithOnData installs an optional callback for each collected packet.
func WithOnData(fn func(Packet)) Option {
	return func(r *Reassembler) { r.onData = fn }
}

// New creates a Reassembler.
func New(opts ...Option) *Reassembler {
	r := &Reassembler{store: NewStore()}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Register installs the tcp_follow callback and returns a close function.
func (r *Reassembler) Register() func() {
	r.reg = gowireshark.RegisterTCPFollowHandler(func(packet Packet) {
		r.store.Add(packet)
		if r.onData != nil {
			r.onData(packet)
		}
	})
	return r.Close
}

// Close releases the active callback registration, if any.
func (r *Reassembler) Close() {
	if r.reg != nil {
		r.reg.Close()
		r.reg = nil
	}
}

// Stream returns a snapshot of one stream.
func (r *Reassembler) Stream(streamID uint32) []Packet { return r.store.Stream(streamID) }

// Streams returns a snapshot of all streams.
func (r *Reassembler) Streams() map[uint32][]Packet { return r.store.Streams() }

// StreamCount reports the number of distinct streams currently stored.
func (r *Reassembler) StreamCount() int { return r.store.StreamCount() }

// Reset clears all collected stream data.
func (r *Reassembler) Reset() { r.store.Reset() }

// Store is a thread-safe TCP stream packet store.
type Store struct {
	mu         sync.RWMutex
	streams    map[uint32][]Packet
	maxStreams int
	maxPackets int
}

// StoreOption customizes a Store.
type StoreOption func(*Store)

// WithMaxStreams limits the number of streams retained.
func WithMaxStreams(n int) StoreOption { return func(s *Store) { s.maxStreams = n } }

// WithMaxPacketsPerStream limits retained packets per stream.
func WithMaxPacketsPerStream(n int) StoreOption { return func(s *Store) { s.maxPackets = n } }

// NewStore creates a Store.
func NewStore(opts ...StoreOption) *Store {
	s := &Store{streams: make(map[uint32][]Packet)}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Add stores one packet.
func (s *Store) Add(packet Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxStreams > 0 && len(s.streams) >= s.maxStreams {
		if _, exists := s.streams[packet.StreamID]; !exists {
			for id := range s.streams {
				delete(s.streams, id)
				break
			}
		}
	}
	packets := s.streams[packet.StreamID]
	if s.maxPackets > 0 && len(packets) >= s.maxPackets {
		return
	}
	s.streams[packet.StreamID] = append(packets, packet)
}

// Stream returns a snapshot of one stream.
func (s *Store) Stream(streamID uint32) []Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	packets := s.streams[streamID]
	if packets == nil {
		return nil
	}
	result := make([]Packet, len(packets))
	copy(result, packets)
	return result
}

// Streams returns a snapshot of all streams.
func (s *Store) Streams() map[uint32][]Packet {
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

// StreamCount reports how many streams are stored.
func (s *Store) StreamCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.streams)
}

// Reset clears all stored packets.
func (s *Store) Reset() {
	s.mu.Lock()
	s.streams = make(map[uint32][]Packet)
	s.mu.Unlock()
}

// StreamIDs returns the currently stored stream IDs.
func (s *Store) StreamIDs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	return ids
}

// Payload concatenates stream payloads in order.
func Payload(packets []Packet) []byte {
	if len(packets) == 0 {
		return nil
	}
	total := 0
	for _, packet := range packets {
		total += len(packet.RawData)
	}
	payload := make([]byte, 0, total)
	for _, packet := range packets {
		payload = append(payload, packet.RawData...)
	}
	return payload
}

// Duration returns the time span covered by packets.
func Duration(packets []Packet) time.Duration {
	if len(packets) < 2 {
		return 0
	}
	return time.Duration((packets[len(packets)-1].Timestamp - packets[0].Timestamp) * float64(time.Second))
}
