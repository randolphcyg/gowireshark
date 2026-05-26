package gowireshark

import (
	"bytes"
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestContextWrappers_Smoke(t *testing.T) {
	pcap := testfixture.Pcap(t)
	ctx := context.Background()

	if _, err := FramesContext(ctx, pcap, WithDisplayFilter("frame.number <= 1")); err != nil {
		t.Fatalf("FramesContext: %v", err)
	}
	if _, err := WriteFramesContext(ctx, pcap, &bytes.Buffer{}, WithDisplayFilter("frame.number <= 1")); err != nil {
		t.Fatalf("WriteFramesContext: %v", err)
	}
	if _, _, err := FramesPageContext(ctx, pcap, 1, 1); err != nil {
		t.Fatalf("FramesPageContext: %v", err)
	}
	if _, _, err := WriteFramesPageContext(ctx, pcap, 1, 1, &bytes.Buffer{}); err != nil {
		t.Fatalf("WriteFramesPageContext: %v", err)
	}
	if _, err := FollowStreamContext(ctx, pcap, "frame.number == 1", "udp"); err != nil {
		t.Fatalf("FollowStreamContext: %v", err)
	}
	if _, err := StreamsContext(ctx, pcap, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("StreamsContext: %v", err)
	}
	if _, err := ConversationsContext(ctx, pcap, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("ConversationsContext: %v", err)
	}
	if _, err := TimelineContext(ctx, pcap, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("TimelineContext: %v", err)
	}
	if _, err := TimelineByContext(ctx, pcap, time.Second, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("TimelineByContext: %v", err)
	}
	if _, err := FilesContext(ctx, pcap, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("FilesContext: %v", err)
	}
	if _, err := TapConversationsContext(ctx, pcap, "tcp", WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("TapConversationsContext: %v", err)
	}
	if _, err := TapEndpointsContext(ctx, pcap, "tcp", WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("TapEndpointsContext: %v", err)
	}
	if _, err := ExportObjectsContext(ctx, pcap, "http", WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("ExportObjectsContext: %v", err)
	}
	if err := WriteExportObjectContext(ctx, pcap, "bogus_proto", 1, &bytes.Buffer{}); !stderrors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("WriteExportObjectContext unsupported error=%v, want ErrUnsupportedProtocol", err)
	}
	if _, err := WriteExportObjectsContext(ctx, pcap, "http", t.TempDir(), WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("WriteExportObjectsContext: %v", err)
	}
	if _, err := ProtocolHierarchyContext(ctx, pcap, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("ProtocolHierarchyContext: %v", err)
	}
	if _, err := ServiceResponseTimesContext(ctx, pcap, "smb", WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("ServiceResponseTimesContext: %v", err)
	}
	if _, err := IOStatsContext(ctx, pcap, time.Second, WithDisplayFilter("frame.number <= 3")); err != nil {
		t.Fatalf("IOStatsContext: %v", err)
	}
}

func TestContextWrappers_CanceledBeforeOpen(t *testing.T) {
	pcap := testfixture.Pcap(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := FramesContext(ctx, pcap); !stderrors.Is(err, context.Canceled) {
		t.Fatalf("FramesContext canceled error=%v, want context.Canceled", err)
	}
}

func TestFrameNumberAPIs(t *testing.T) {
	pcap := testfixture.Pcap(t)
	ctx := context.Background()

	frame, err := FrameByNumberContext(ctx, pcap, 1)
	if err != nil {
		t.Fatalf("FrameByNumberContext: %v", err)
	}
	if frame.BaseLayers.Frame == nil || frame.BaseLayers.Frame.Number != 1 {
		t.Fatalf("unexpected frame: %#v", frame.BaseLayers.Frame)
	}

	frames, err := FramesByNumbersContext(ctx, pcap, []int{1, 2})
	if err != nil {
		t.Fatalf("FramesByNumbersContext: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames length: want 2 got %d", len(frames))
	}

	hex, err := HexDataByFrameNumberContext(ctx, pcap, 1)
	if err != nil {
		t.Fatalf("HexDataByFrameNumberContext: %v", err)
	}
	if hex == nil || len(hex.Hex) == 0 {
		t.Fatalf("expected non-empty hex data")
	}

	if _, err := FrameByNumberContext(ctx, pcap, 0); !stderrors.Is(err, ErrInvalidFrameNumber) {
		t.Fatalf("FrameByNumberContext invalid error=%v, want ErrInvalidFrameNumber", err)
	}
}
