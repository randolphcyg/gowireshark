package gowireshark

import (
	"sync"
	"testing"
)

func TestFollowTcpStream(t *testing.T) {
	reassembler := NewTCPReassembler()
	handle := reassembler.RegisterCallback()
	defer reassembler.UnregisterCallback(handle)

	path := "./pcaps/https.pcapng"
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		frames, err := GetAllFrames(path,
			PrintTcpStreams(true), // TCP stream
			WithDebug(false),
			IgnoreError(false))
		if err != nil {
			t.Fatalf("GetAllFrames failed: %v", err)
		}
		t.Logf("Total frames processed: %d", len(frames))
	}()

	wg.Wait()

	if len(reassembler.streamStore.streams) == 0 {
		t.Error("No TCP streams captured")
		return
	}

	for streamID, packets := range reassembler.streamStore.streams {
		t.Logf("Stream %d: %d packets, total size: %d bytes",
			streamID, len(packets), calculateTotalSize(packets))
	}
}

func calculateTotalSize(packets []Packet) int {
	total := 0
	for _, p := range packets {
		total += len(p.RawData)
	}
	return total
}
