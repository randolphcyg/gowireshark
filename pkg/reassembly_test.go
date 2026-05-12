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

	if len(reassembler.streamStore.streams) == 0 {
		t.Skip("No TCP streams found in test pcap (expected if no TCP traffic)")
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
