package gowireshark

import (
	"context"
	"github.com/randolphcyg/gowireshark/internal/testfixture"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
)

func TestDissectPacketValidation(t *testing.T) {
	if _, err := DissectPacket(RawPacket{}); err != ErrRawPacketEmpty {
		t.Fatalf("expected ErrRawPacketEmpty, got %v", err)
	}
	if _, err := DissectPacket(RawPacket{Data: []byte{1, 2, 3}, CaptureLength: 4, OriginalLength: 4}); err != ErrRawPacketInvalidSize {
		t.Fatalf("expected ErrRawPacketInvalidSize, got %v", err)
	}
}

func TestDissectPacketMatchesOfflineFrame(t *testing.T) {
	pcapPath := testfixture.Pcap(t)
	file, err := os.Open(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Skipf("pcapgo cannot read %s: %v", pcapPath, err)
	}
	data, ci, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}

	rawFrame, err := DissectPacket(RawPacket{
		Data:           data,
		Timestamp:      ci.Timestamp,
		CaptureLength:  ci.CaptureLength,
		OriginalLength: ci.Length,
		LinkType:       LinkType(reader.LinkType()),
	})
	if err != nil {
		t.Fatal(err)
	}
	offlineFrame, err := FrameByNumberContext(t.Context(), pcapPath, 1)
	if err != nil {
		t.Fatal(err)
	}

	if rawFrame.BaseLayers.WSCol == nil || offlineFrame.BaseLayers.WSCol == nil {
		t.Fatalf("expected ws.col layer in both frames")
	}
	if rawFrame.BaseLayers.WSCol.Protocol != offlineFrame.BaseLayers.WSCol.Protocol {
		t.Fatalf("protocol mismatch: raw=%q offline=%q", rawFrame.BaseLayers.WSCol.Protocol, offlineFrame.BaseLayers.WSCol.Protocol)
	}
	if rawFrame.BaseLayers.Frame == nil || rawFrame.BaseLayers.Frame.Len != offlineFrame.BaseLayers.Frame.Len {
		t.Fatalf("frame length mismatch: raw=%v offline=%v", rawFrame.BaseLayers.Frame, offlineFrame.BaseLayers.Frame)
	}
}

func TestDissectPacketsPreservesOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	in := make(chan RawPacket, 1)
	in <- RawPacket{}
	close(in)

	result, ok := <-DissectPackets(ctx, in)
	if !ok {
		t.Fatal("expected one result")
	}
	if result.Err != ErrRawPacketEmpty {
		t.Fatalf("expected ErrRawPacketEmpty, got %v", result.Err)
	}
}
