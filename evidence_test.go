package gowireshark

import (
	"bytes"
	"errors"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSelectedFrameNumbersRangeValidation(t *testing.T) {
	_, err := SelectedFrameNumbers("unused.pcap", FrameSelector{Range: FrameRange{Start: 3, End: 2}})
	if !errors.Is(err, ErrInvalidFrameIndex) {
		t.Fatalf("expected ErrInvalidFrameIndex, got %v", err)
	}
}

func TestWritePcapSliceByRange(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSlice(pcap, &buf, FrameSelector{Range: FrameRange{Start: 1, End: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}
	if buf.Len() == 0 {
		t.Fatal("expected pcap bytes")
	}
}
