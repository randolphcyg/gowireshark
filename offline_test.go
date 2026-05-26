package gowireshark

import (
	"bytes"
	"encoding/hex"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

// Test environment initialization, checking if plugins are supported.
func TestRuntimeVersionAndPlugins(t *testing.T) {
	v, err := RuntimeVersion(t.Context())
	if err != nil {
		t.Fatalf("RuntimeVersion: %v", err)
	}
	t.Logf("Wireshark Version: %s %t", v.Version, PluginsSupported())
}

// TestFrameByNumber_LeakCheck serves as a basic memory leak check and logic verification.
func TestFrameByNumber_LeakCheck(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	start := time.Now()
	for i := 1; i <= 100; i++ {
		frame, err := FrameByNumberContext(t.Context(), pcapFile, i)
		if err != nil {
			t.Fatalf("Failed to get frame %d: %v", i, err)
		}
		if frame == nil {
			t.Fatalf("Frame %d is nil", i)
		}
		if frame.BaseLayers.Frame.Number != i {
			t.Errorf("Frame number mismatch. Expected %d, got %d", i, frame.BaseLayers.Frame.Number)
		}
	}
	t.Logf("Processed 100 frames individually in %v", time.Since(start))
}

// BenchmarkParseFrameData benchmarks the JSON unmarshaling performance.
func BenchmarkParseFrameData(b *testing.B) {
	jsonStr := []byte(`{"_index":"1", "layers": { "frame": {"frame.number":"1"}, "ip": {"ip.src":"1.1.1.1"}, "eth": {} }}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseFrameData(jsonStr)
	}
}

// TestHexDataByFrameNumber tests retrieving the hex dump of a specific frame.
func TestHexDataByFrameNumber(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	hexData, err := HexDataByFrameNumber(pcapFile, 1)
	if err != nil || hexData == nil {
		t.Fatal(err)
	}
	if len(hexData.Hex) == 0 {
		t.Error("Expected hex data, got empty")
	}
}

// TestFrameByNumber tests dissecting a single frame by its frame number.
func TestFrameByNumber(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	frame, err := FrameByNumberContext(t.Context(), pcapFile, 1, WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame number:", frame.BaseLayers.Frame.Number)
	t.Log("Protocol:", frame.BaseLayers.WSCol.Protocol)

	if frame.BaseLayers.IP != nil {
		t.Log("IP Src:", frame.BaseLayers.IP.Src)
		t.Log("IP Dst:", frame.BaseLayers.IP.Dst)
	}

	if _, err := FrameByNumberContext(t.Context(), pcapFile, 999999); !stderrors.Is(err, ErrInvalidFrameNumber) {
		t.Fatalf("FrameByNumberContext out-of-range error=%v, want ErrInvalidFrameNumber", err)
	}
}

// TestFrames_Correctness verifies data integrity of Frames.
func TestFrames_Correctness(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	frames, err := Frames(pcapFile, WithDebug(true))
	if err != nil {
		t.Fatalf("Frames failed: %v", err)
	}
	if len(frames) == 0 {
		t.Fatalf("Expected frames, but got empty result")
	}

	for i, frame := range frames {
		expectedNum := i + 1
		if frame.BaseLayers.Frame.Number != expectedNum {
			t.Errorf("Frame sequence error at index %d: expected %d, got %d",
				i, expectedNum, frame.BaseLayers.Frame.Number)
			break
		}
	}
}

// TestFramesByNumbers_Random tests random access capabilities.
func TestFramesByNumbers_Random(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	targets := []int{1, 3, 5, 10, 999999}
	targetsMap := make(map[int]bool)
	for _, v := range targets {
		targetsMap[v] = true
	}

	frames, err := FramesByNumbers(pcapFile, targets, WithDebug(true))
	if err != nil {
		t.Fatalf("FramesByNumbers failed: %v", err)
	}
	if len(frames) == 0 {
		t.Fatalf("Expected some frames, got 0")
	}

	for _, f := range frames {
		num := f.BaseLayers.Frame.Number
		if !targetsMap[num] {
			t.Errorf("Received unexpected frame number: %d", num)
		}
		if num == 999999 {
			t.Errorf("Should not receive out of bounds frame: 999999")
		}
	}
}

// TestFramesPage validates the pagination logic.
func TestFramesPage(t *testing.T) {
	pcapFile := testfixture.Pcap(t)
	pageSize := 10

	tests := []struct {
		name        string
		page        int
		size        int
		expectEmpty bool
	}{
		{"FirstPage", 1, pageSize, false},
		{"SecondPage", 2, pageSize, false},
		{"OutOfBoundsPage", 999999, pageSize, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames, hasMore, err := FramesPage(pcapFile, tt.page, tt.size, WithDebug(true))
			if err != nil {
				t.Fatalf("FramesPage failed: %v", err)
			}

			if tt.expectEmpty {
				if len(frames) != 0 {
					t.Logf("Got %d frames for page %d (file may be large)", len(frames), tt.page)
				}
				return
			}

			if len(frames) == 0 {
				t.Logf("Got 0 frames, test file might be too small for page %d", tt.page)
				return
			}

			t.Logf("Page %d: %d frames, hasMore=%v", tt.page, len(frames), hasMore)

			if len(frames) > tt.size {
				t.Errorf("Result length %d exceeds page size %d", len(frames), tt.size)
			}
		})
	}
}

func TestValidateFilter(t *testing.T) {
	if err := ValidateFilter("frame.number == 1"); err != nil {
		t.Fatalf("expected valid display filter: %v", err)
	}
	if err := ValidateFilter("frame.number =="); err == nil {
		t.Fatal("expected invalid display filter error")
	}
}

func TestFrameCount(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	count, err := FrameCount(pcapFile)
	if err != nil {
		t.Fatalf("FrameCount failed: %v", err)
	}
	if count < 1 {
		t.Fatalf("FrameCount=%d, want at least one frame", count)
	}

	filteredCount, err := FrameCount(pcapFile, WithDisplayFilter("frame.number == 1"))
	if err != nil {
		t.Fatalf("filtered FrameCount failed: %v", err)
	}
	if filteredCount != 1 {
		t.Fatalf("filtered FrameCount=%d, want 1", filteredCount)
	}
}

func TestWriteFrames(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	var buf bytes.Buffer
	count, err := WriteFrames(pcapFile, &buf, WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatalf("WriteFrames failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("WriteFrames count=%d, want 2", count)
	}

	lines := nonEmptyLines(buf.String())
	if len(lines) != count {
		t.Fatalf("WriteFrames lines=%d, want %d", len(lines), count)
	}
	for _, line := range lines {
		if _, err := ParseFrameData([]byte(line)); err != nil {
			t.Fatalf("WriteFrames emitted invalid frame JSON: %v", err)
		}
	}
}

func TestWriteFramesPage(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	var buf bytes.Buffer
	count, hasMore, err := WriteFramesPage(pcapFile, 1, 2, &buf)
	if err != nil {
		t.Fatalf("WriteFramesPage failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("WriteFramesPage count=%d, want 2", count)
	}
	if !hasMore {
		t.Fatal("WriteFramesPage hasMore=false, want true for fixture with more than two frames")
	}

	lines := nonEmptyLines(buf.String())
	if len(lines) != count {
		t.Fatalf("WriteFramesPage lines=%d, want %d", len(lines), count)
	}
}

func TestFollowStream(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	if _, err := FollowStream(pcapFile, "", "icmp"); err == nil {
		t.Fatal("expected unsupported protocol error")
	}
	if _, err := FollowStream(pcapFile, "frame.number ==", "udp"); err == nil {
		t.Fatal("expected invalid filter error")
	}

	result, err := FollowStream(pcapFile, "frame.number == 1", "udp")
	if err != nil {
		t.Fatalf("FollowStream failed: %v", err)
	}
	if result == nil {
		t.Fatal("FollowStream returned nil result")
	}
	if result.PacketCount != 1 {
		t.Fatalf("FollowStream PacketCount=%d, want 1", result.PacketCount)
	}
}

func nonEmptyLines(s string) []string {
	raw := strings.Split(strings.TrimSpace(s), "\n")
	lines := raw[:0]
	for _, line := range raw {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// --- Benchmarks ---

func BenchmarkFrames(b *testing.B) {
	pcapFile := testfixture.Pcap(b)
	for i := 0; i < b.N; i++ {
		frames, err := Frames(pcapFile)
		if err != nil {
			b.Fatal(err)
		}
		if len(frames) == 0 {
			b.Fatal("Got 0 frames")
		}
	}
}

func BenchmarkFramesPage(b *testing.B) {
	pcapFile := testfixture.Pcap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := FramesPage(pcapFile, 1, 20)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkFramesPageDeep(b *testing.B) {
	pcapFile := testfixture.Pcap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := FramesPage(pcapFile, 100, 20)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkFramesByNumbers_Sparse(b *testing.B) {
	pcapFile := testfixture.Pcap(b)
	idxs := []int{1, 10, 50}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := FramesByNumbers(pcapFile, idxs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- FollowPayload.Bytes Tests ---

func TestFollowPayloadBytes(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	result, err := FollowStream(pcapFile, "frame.number <= 10", "udp")
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range result.Payloads {
		if p.HexData == "" {
			if len(p.Bytes) != 0 {
				t.Error("expected empty Bytes for empty HexData")
			}
			continue
		}
		decoded, decErr := hex.DecodeString(p.HexData)
		if decErr != nil {
			t.Fatalf("failed to decode HexData: %v", decErr)
		}
		if !bytes.Equal(decoded, p.Bytes) {
			t.Errorf("Bytes mismatch: decoded %d bytes from HexData, got %d Bytes", len(decoded), len(p.Bytes))
		}
	}
}

// --- WalkFrames Tests ---

func TestWalkFramesMatchesFrames(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	collected, err := Frames(pcapFile)
	if err != nil {
		t.Fatal(err)
	}

	var walked int
	walkErr := WalkFrames(pcapFile, func(frame *FrameData) error {
		if walked >= len(collected) {
			t.Error("WalkFrames yielded more frames than Frames")
			return errors.New("too many frames")
		}
		expected := collected[walked]
		if frame.BaseLayers.Frame == nil || expected.BaseLayers.Frame == nil {
			if frame.BaseLayers.Frame != nil || expected.BaseLayers.Frame != nil {
				t.Errorf("frame %d: Frame layer mismatch", walked+1)
			}
		} else if frame.BaseLayers.Frame.Number != expected.BaseLayers.Frame.Number {
			t.Errorf("frame %d: number mismatch walk=%d expected=%d",
				walked+1, frame.BaseLayers.Frame.Number, expected.BaseLayers.Frame.Number)
		} else if frame.BaseLayers.Frame.Protocols != expected.BaseLayers.Frame.Protocols {
			t.Errorf("frame %d: protocol mismatch walk=%q expected=%q",
				walked+1, frame.BaseLayers.Frame.Protocols, expected.BaseLayers.Frame.Protocols)
		}
		walked++
		return nil
	})

	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if walked != len(collected) {
		t.Fatalf("WalkFrames yielded %d frames, Frames yielded %d", walked, len(collected))
	}
}

func TestWalkFramesWalkFnError(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	sentinel := errors.New("stop early")
	var count int
	err := WalkFrames(pcapFile, func(frame *FrameData) error {
		count++
		if count >= 3 {
			return sentinel
		}
		return nil
	}, WithDisplayFilter("frame.number <= 100"))

	if !stderrors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if count < 3 {
		t.Fatalf("expected 3 walkFn calls, got %d", count)
	}
	if count != 3 {
		t.Fatalf("expected early stop after 3 walkFn calls, got %d", count)
	}
}

func TestFramesRepeatedScansMatch(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	first, err := Frames(pcapFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Frames(pcapFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(first) != len(second) {
		t.Fatalf("frame count mismatch: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		f1, f2 := first[i].BaseLayers.Frame, second[i].BaseLayers.Frame
		if f1 == nil || f2 == nil {
			if f1 != f2 {
				t.Fatalf("frame %d: nil frame mismatch", i+1)
			}
			continue
		}
		if f1.Number != f2.Number || f1.Protocols != f2.Protocols {
			t.Fatalf("frame %d mismatch: first=(%d,%q) second=(%d,%q)",
				i+1, f1.Number, f1.Protocols, f2.Number, f2.Protocols)
		}
	}
}

func TestWalkFramesFileNotFound(t *testing.T) {
	err := WalkFrames("/nonexistent/pcap/file.pcap", func(*FrameData) error { return nil })
	if !stderrors.Is(err, ErrFileNotFound) {
		t.Fatalf("expected ErrFileNotFound, got %v", err)
	}
}

func TestWalkFramesWithDisplayFilter(t *testing.T) {
	pcapFile := testfixture.Pcap(t)

	var walked int
	err := WalkFrames(pcapFile, func(frame *FrameData) error {
		walked++
		return nil
	}, WithDisplayFilter("frame.number <= 2"))

	if err != nil {
		t.Fatal(err)
	}
	if walked < 1 {
		t.Fatal("expected at least 1 frame with display filter")
	}
}

func BenchmarkWalkFrames(b *testing.B) {
	pcapFile := testfixture.Pcap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WalkFrames(pcapFile, func(*FrameData) error { return nil })
	}
}
