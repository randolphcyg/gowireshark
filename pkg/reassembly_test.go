package pkg

import (
	"sync"
	"testing"
)

func TestFollowTcpStream(t *testing.T) {
	pcapPath := getTestPcap(t)

	reassembler := NewTCPReassembler()
	handle := reassembler.RegisterCallback()
	defer reassembler.UnregisterCallback(handle)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		frames, err := GetAllFrames(pcapPath,
			PrintTcpStreams(true),
			WithDebug(false),
			IgnoreError(false))
		if err != nil {
			t.Errorf("GetAllFrames failed: %v", err)
			return
		}
		t.Logf("Total frames processed: %d", len(frames))
	}()

	wg.Wait()

	if reassembler.StreamCount() == 0 {
		t.Skip("No TCP streams found in test pcap (expected if no TCP traffic)")
		return
	}

	allStreams := reassembler.GetAllStreams()
	for streamID, packets := range allStreams {
		payload := ReassembleStreamPayload(packets)
		duration := StreamDuration(packets)
		t.Logf("Stream %d: %d packets, %d bytes payload, duration: %v",
			streamID, len(packets), len(payload), duration)
	}
}

func TestTCPReassemblerWithCallback(t *testing.T) {
	pcapPath := getTestPcap(t)

	var received int
	var mu sync.Mutex

	reassembler := NewTCPReassembler(WithOnData(func(p Packet) {
		mu.Lock()
		received++
		mu.Unlock()
	}))
	handle := reassembler.RegisterCallback()
	defer reassembler.UnregisterCallback(handle)

	frames, err := GetAllFrames(pcapPath,
		PrintTcpStreams(true),
		WithDebug(false),
		IgnoreError(true))
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
	store := NewTCPStreamStore()

	store.AddPacket(Packet{StreamID: 1, PacketID: 1, RawData: []byte("hello")})
	store.AddPacket(Packet{StreamID: 1, PacketID: 2, RawData: []byte("world")})
	store.AddPacket(Packet{StreamID: 2, PacketID: 1, RawData: []byte("foo")})

	if store.StreamCount() != 2 {
		t.Fatalf("expected 2 streams, got %d", store.StreamCount())
	}

	packets := store.GetStream(1)
	if len(packets) != 2 {
		t.Fatalf("expected 2 packets in stream 1, got %d", len(packets))
	}

	payload := ReassembleStreamPayload(packets)
	if string(payload) != "helloworld" {
		t.Fatalf("expected 'helloworld', got %q", string(payload))
	}

	store.Reset()
	if store.StreamCount() != 0 {
		t.Fatalf("expected 0 streams after reset, got %d", store.StreamCount())
	}
}

func TestTCPStreamStoreMaxPackets(t *testing.T) {
	store := NewTCPStreamStore(WithMaxPacketsPerStream(3))

	for i := 0; i < 10; i++ {
		store.AddPacket(Packet{StreamID: 1, PacketID: uint32(i), RawData: []byte{byte(i)}})
	}

	packets := store.GetStream(1)
	if len(packets) != 3 {
		t.Fatalf("expected 3 packets (max limit), got %d", len(packets))
	}
}

func TestTCPStreamStoreMaxStreams(t *testing.T) {
	store := NewTCPStreamStore(WithMaxStreams(2))

	store.AddPacket(Packet{StreamID: 1, PacketID: 1})
	store.AddPacket(Packet{StreamID: 2, PacketID: 1})
	store.AddPacket(Packet{StreamID: 3, PacketID: 1}) // should evict one

	if store.StreamCount() != 2 {
		t.Fatalf("expected 2 streams (max limit), got %d", store.StreamCount())
	}
}
