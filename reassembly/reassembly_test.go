package reassembly

import (
	"github.com/randolphcyg/gowireshark/internal/testfixture"
	"sync"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

func TestFollowTCPStream(t *testing.T) {
	pcapPath := testfixture.Pcap(t)

	reassembler := New()
	defer reassembler.Register()()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		frames, err := gowireshark.Frames(pcapPath,
			gowireshark.WithTCPFollow(true),
			gowireshark.WithDebug(false),
			gowireshark.WithIgnoreErrors(false))
		if err != nil {
			t.Errorf("Frames failed: %v", err)
			return
		}
		t.Logf("Total frames processed: %d", len(frames))
	}()

	wg.Wait()

	if reassembler.StreamCount() == 0 {
		t.Skip("No TCP streams found in test pcap (expected if no TCP traffic)")
		return
	}

	allStreams := reassembler.Streams()
	for streamID, packets := range allStreams {
		payload := Payload(packets)
		duration := Duration(packets)
		t.Logf("Stream %d: %d packets, %d bytes payload, duration: %v",
			streamID, len(packets), len(payload), duration)
	}
}

func TestTCPReassemblerWithCallback(t *testing.T) {
	pcapPath := testfixture.Pcap(t)

	var received int
	var mu sync.Mutex

	reassembler := New(WithOnData(func(p Packet) {
		mu.Lock()
		received++
		mu.Unlock()
	}))
	defer reassembler.Register()()

	frames, err := gowireshark.Frames(pcapPath,
		gowireshark.WithTCPFollow(true),
		gowireshark.WithDebug(false),
		gowireshark.WithIgnoreErrors(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Frames: %d", len(frames))

	mu.Lock()
	count := received
	mu.Unlock()

	if count == 0 {
		t.Skip("No TCP packets received via callback (expected if no TCP traffic)")
		return
	}

	t.Logf("OnData callback invoked %d times, store has %d streams", count, reassembler.StreamCount())
}

func TestTCPStreamStoreReset(t *testing.T) {
	store := NewStore()

	store.Add(Packet{StreamID: 1, PacketID: 1, RawData: []byte("hello")})
	store.Add(Packet{StreamID: 1, PacketID: 2, RawData: []byte("world")})
	store.Add(Packet{StreamID: 2, PacketID: 1, RawData: []byte("foo")})

	if store.StreamCount() != 2 {
		t.Fatalf("expected 2 streams, got %d", store.StreamCount())
	}

	packets := store.Stream(1)
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets in stream 1, got %d", len(packets))
	}

	payload := Payload(packets)
	if string(payload) != "helloworld" {
		t.Fatalf("expected 'helloworld', got %q", string(payload))
	}

	store.Reset()
	if store.StreamCount() != 0 {
		t.Fatalf("expected 0 streams after reset, got %d", store.StreamCount())
	}
}

func TestTCPStreamStoreMaxPackets(t *testing.T) {
	store := NewStore(WithMaxPacketsPerStream(3))

	for i := 0; i < 10; i++ {
		store.Add(Packet{StreamID: 1, PacketID: uint32(i), RawData: []byte{byte(i)}})
	}

	packets := store.Stream(1)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets (max limit), got %d", len(packets))
	}
}

func TestTCPStreamStoreMaxStreams(t *testing.T) {
	store := NewStore(WithMaxStreams(2))

	store.Add(Packet{StreamID: 1, PacketID: 1})
	store.Add(Packet{StreamID: 2, PacketID: 1})
	store.Add(Packet{StreamID: 3, PacketID: 1}) // should evict one

	if store.StreamCount() != 2 {
		t.Fatalf("expected 2 streams (max limit), got %d", store.StreamCount())
	}
}
