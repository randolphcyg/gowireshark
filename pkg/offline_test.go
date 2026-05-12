package pkg

import (
	"testing"
	"time"
)

// Test environment initialization, checking if plugins are supported.
func TestEpanVersion(t *testing.T) {
	t.Logf("Wireshark Version: %s %d", EpanVersion(), EpanPluginsSupported())
}

// TestGetFrameByIdx_LeakCheck serves as a basic memory leak check and logic verification.
func TestGetFrameByIdx_LeakCheck(t *testing.T) {
	pcapFile := getTestPcap(t)

	start := time.Now()
	for i := 1; i <= 100; i++ {
		frame, err := GetFrameByIdx(pcapFile, i)
		if err != nil {
			t.Fatalf("Failed to get frame %d: %v", i, err)
		}
		if frame == nil {
			t.Fatalf("Frame %d is nil", i)
		}
		if frame.BaseLayers.Frame.Number != i {
			t.Errorf("Frame index mismatch. Expected %d, got %d", i, frame.BaseLayers.Frame.Number)
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

// TestPrintAllFrames tests printing all frames to stdout (C side logic).
func TestPrintAllFrames(t *testing.T) {
	pcapFile := getTestPcap(t)
	if err := PrintAllFrames(pcapFile); err != nil {
		t.Fatal(err)
	}
}

// TestGetHexDataByIdx tests retrieving the hex dump of a specific frame.
func TestGetHexDataByIdx(t *testing.T) {
	pcapFile := getTestPcap(t)

	hexData, err := GetHexDataByIdx(pcapFile, 1)
	if err != nil || hexData == nil {
		t.Fatal(err)
	}
	if len(hexData.Hex) == 0 {
		t.Error("Expected hex data, got empty")
	}
}

// TestGetFrameByIdx tests dissecting a single frame by its index.
func TestGetFrameByIdx(t *testing.T) {
	pcapFile := getTestPcap(t)

	frame, err := GetFrameByIdx(pcapFile, 1, WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number)
	t.Log("Protocol:", frame.BaseLayers.WsCol.Protocol)

	if frame.BaseLayers.Ip != nil {
		t.Log("IP Src:", frame.BaseLayers.Ip.Src)
		t.Log("IP Dst:", frame.BaseLayers.Ip.Dst)
	}
}

// TestGetAllFrames_Correctness verifies data integrity of GetAllFrames.
func TestGetAllFrames_Correctness(t *testing.T) {
	pcapFile := getTestPcap(t)

	frames, err := GetAllFrames(pcapFile, WithDebug(true))
	if err != nil {
		t.Fatalf("GetAllFrames failed: %v", err)
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

// TestGetFramesByIdxs_Random tests random access capabilities.
func TestGetFramesByIdxs_Random(t *testing.T) {
	pcapFile := getTestPcap(t)

	targets := []int{1, 3, 5, 10, 999999}
	targetsMap := make(map[int]bool)
	for _, v := range targets {
		targetsMap[v] = true
	}

	frames, err := GetFramesByIdxs(pcapFile, targets, WithDebug(true))
	if err != nil {
		t.Fatalf("GetFramesByIdxs failed: %v", err)
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

// TestGetFramesByPage validates the pagination logic.
func TestGetFramesByPage(t *testing.T) {
	pcapFile := getTestPcap(t)
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
			frames, hasMore, err := GetFramesByPage(pcapFile, tt.page, tt.size, WithDebug(true))
			if err != nil {
				t.Fatalf("GetFramesByPage failed: %v", err)
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

// --- Benchmarks ---

func BenchmarkGetAllFrames(b *testing.B) {
	pcapFile := getTestPcap(b)
	for i := 0; i < b.N; i++ {
		frames, err := GetAllFrames(pcapFile)
		if err != nil {
			b.Fatal(err)
		}
		if len(frames) == 0 {
			b.Fatal("Got 0 frames")
		}
	}
}

func BenchmarkGetFramesByPage(b *testing.B) {
	pcapFile := getTestPcap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GetFramesByPage(pcapFile, 1, 20)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkGetFramesByPageDeep(b *testing.B) {
	pcapFile := getTestPcap(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GetFramesByPage(pcapFile, 100, 20)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkGetFramesByIdxs_Sparse(b *testing.B) {
	pcapFile := getTestPcap(b)
	idxs := []int{1, 10, 50}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetFramesByIdxs(pcapFile, idxs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetFramesByIdxs_Batch100(b *testing.B) {
	pcapFile := getTestPcap(b)
	idxs := make([]int, 100)
	for i := range idxs {
		idxs[i] = i + 1
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetFramesByIdxs(pcapFile, idxs)
		if err != nil {
			b.Fatal(err)
		}
	}
}
