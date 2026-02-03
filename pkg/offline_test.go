package pkg

import (
	"math/rand"
	"os"
	"testing"
	"time"
)

const inputFilepath = "../pcaps/mysql.pcapng"
const testPcapFile = "../pcaps/SAT-01-12-2018_0818.pcap"

// Test environment initialization, checking if plugins are supported.
func TestEpanVersion(t *testing.T) {
	t.Logf("Wireshark Version: %s %d", EpanVersion(), EpanPluginsSupported())
}

// TestGetFrameByIdx_LeakCheck serves as a basic memory leak check and logic verification.
// It repeatedly calls GetFrameByIdx to ensure no C memory is leaked over time.
func TestGetFrameByIdx_LeakCheck(t *testing.T) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	start := time.Now()
	// Process first 100 frames individually
	for i := 1; i <= 100; i++ {
		frame, err := GetFrameByIdx(testPcapFile, i)
		if err != nil {
			t.Fatalf("Failed to get frame %d: %v", i, err)
		}
		if frame == nil {
			t.Fatalf("Frame %d is nil", i)
		}
		// Basic assertion
		if frame.BaseLayers.Frame.Number != i {
			t.Errorf("Frame index mismatch. Expected %d, got %d", i, frame.BaseLayers.Frame.Number)
		}
	}
	t.Logf("Processed 100 frames individually in %v", time.Since(start))
}

// BenchmarkParseFrameData benchmarks the JSON unmarshaling performance.
// This isolates the Go-side parsing logic from C-side processing.
func BenchmarkParseFrameData(b *testing.B) {
	// A sample JSON string mimicking a dissected frame
	jsonStr := []byte(`{"_index":"1", "layers": { "frame": {"frame.number":"1"}, "ip": {"ip.src":"1.1.1.1"}, "eth": {} }}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseFrameData(jsonStr)
	}
}

// TestPrintAllFrames tests printing all frames to stdout (C side logic).
func TestPrintAllFrames(t *testing.T) {
	if _, err := os.Stat(inputFilepath); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}
	err := PrintAllFrames(inputFilepath)
	if err != nil {
		t.Fatal(err)
	}
}

// TestGetHexDataByIdx tests retrieving the hex dump of a specific frame.
func TestGetHexDataByIdx(t *testing.T) {
	if _, err := os.Stat(inputFilepath); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	hexData, err := GetHexDataByIdx(inputFilepath, 65)
	if err != nil || hexData == nil {
		t.Fatal(err)
	}

	// Check if data is populated
	if len(hexData.Hex) == 0 {
		t.Error("Expected hex data, got empty")
	}
}

// TestGetFrameByIdx tests dissecting a single frame by its index.
func TestGetFrameByIdx(t *testing.T) {
	if _, err := os.Stat(inputFilepath); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	frame, err := GetFrameByIdx(inputFilepath, 65, WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number, "===========================")
	t.Log("Protocol:", frame.BaseLayers.WsCol.Protocol)

	if frame.BaseLayers.Ip != nil {
		t.Log("IP Src:", frame.BaseLayers.Ip.Src)
		t.Log("IP Dst:", frame.BaseLayers.Ip.Dst)
	}
}

// TestCountFrames verifies the frame counting logic.
// It checks both a valid file and a non-existent file.
func TestCountFrames(t *testing.T) {
	tests := []struct {
		name        string
		filepath    string
		expectError bool
		minFrames   int
	}{
		{
			name:        "ValidFile",
			filepath:    testPcapFile,
			expectError: false,
			minFrames:   1,
		},
		{
			name:        "FileNotFound",
			filepath:    "pcaps/non_existent_file.pcap",
			expectError: true,
			minFrames:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.filepath); os.IsNotExist(err) && !tt.expectError {
				t.Skip("skipping valid file test; file not found")
			}

			count, err := CountFrames(tt.filepath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}

			t.Logf("File: %s, Count: %d", tt.filepath, count)
			if count < tt.minFrames {
				t.Errorf("Expected at least %d frames, got %d", tt.minFrames, count)
			}
		})
	}
}

// TestGetAllFrames_Correctness verifies data integrity of GetAllFrames.
// It checks if the frame count matches CountFrames and if frame numbers are sequential.
func TestGetAllFrames_Correctness(t *testing.T) {
	if _, err := os.Stat(inputFilepath); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	// 1. Get baseline count
	expectedCount, err := CountFrames(inputFilepath)
	if err != nil {
		t.Skip("Cannot count frames, skipping test")
	}

	// 2. Execute GetAllFrames
	frames, err := GetAllFrames(inputFilepath, WithDebug(true))
	if err != nil {
		t.Fatalf("GetAllFrames failed: %v", err)
	}

	// 3. Verify count
	if len(frames) != expectedCount {
		t.Errorf("Frame count mismatch: expected %d, got %d", expectedCount, len(frames))
	}

	// 4. Verify frame number continuity
	for i, frame := range frames {
		expectedNum := i + 1
		if frame.BaseLayers.Frame.Number != expectedNum {
			t.Errorf("Frame sequence error at index %d: expected frame number %d, got %d",
				i, expectedNum, frame.BaseLayers.Frame.Number)
			break // Stop on first error
		}
	}
}

// TestGetFramesByIdxs_Random tests random access capabilities.
// It verifies that requested frames (including boundary values) are correctly retrieved.
func TestGetFramesByIdxs_Random(t *testing.T) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	total, _ := CountFrames(testPcapFile)
	if total < 10 {
		t.Skip("Pcap file too small")
	}

	// Generate random indices
	var targets []int
	targetsMap := make(map[int]bool)

	// Add boundary values and an invalid value
	targets = append(targets, 1)         // First frame
	targets = append(targets, total)     // Last frame
	targets = append(targets, total+100) // Invalid frame (should be ignored)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 5; i++ {
		val := rand.Intn(total) + 1
		targets = append(targets, val)
	}

	// Track expected valid frames
	for _, v := range targets {
		if v <= total && v > 0 {
			targetsMap[v] = true
		}
	}

	t.Logf("Requesting indices: %v", targets)

	frames, err := GetFramesByIdxs(testPcapFile, targets, WithDebug(true))
	if err != nil {
		t.Fatalf("GetFramesByIdxs failed: %v", err)
	}

	// Verify count (should match unique valid targets)
	if len(frames) != len(targetsMap) {
		t.Errorf("Result count mismatch: expected %d (unique valid), got %d", len(targetsMap), len(frames))
	}

	// Verify content
	for _, f := range frames {
		num := f.BaseLayers.Frame.Number
		if !targetsMap[num] {
			t.Errorf("Received unexpected frame number: %d", num)
		}
		delete(targetsMap, num)
	}

	// Verify all requested frames were received
	if len(targetsMap) > 0 {
		t.Errorf("Missed frames: %v", targetsMap)
	}
}

// TestGetFramesByPage validates the pagination logic.
// Updated to match the new GetFramesByPage signature (returns total count, not total pages).
func TestGetFramesByPage(t *testing.T) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		t.Skip("skipping test; pcap file not found")
	}

	totalFrames, err := CountFrames(testPcapFile)
	if err != nil {
		t.Skipf("Skipping test, cannot open test file: %v", err)
	}
	t.Logf("Total frames in file: %d", totalFrames)

	pageSize := 10

	tests := []struct {
		name          string
		page          int
		size          int
		expectLen     int
		expectStartNo int
		expectError   bool
	}{
		{
			name:          "FirstPage",
			page:          1,
			size:          pageSize,
			expectLen:     pageSize,
			expectStartNo: 1,
			expectError:   false,
		},
		{
			name:          "SecondPage",
			page:          2,
			size:          pageSize,
			expectLen:     pageSize,
			expectStartNo: pageSize + 1,
			expectError:   false,
		},
		{
			name:          "OutOfBoundsPage",
			page:          999999,
			size:          pageSize,
			expectLen:     0,
			expectStartNo: 0,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totalPages := (totalFrames + tt.size - 1) / tt.size
			if tt.name != "OutOfBoundsPage" && tt.page > totalPages {
				t.Skipf("Test page %d is larger than total pages %d, skipping", tt.page, totalPages)
			}

			// Call the new API
			frames, count, err := GetFramesByPage(
				testPcapFile,
				tt.page,
				tt.size,
				WithDebug(true),
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			} else if err != nil {
				t.Fatalf("GetFramesByPage failed: %v", err)
			}

			// [CHANGED] Verify Total Count, NOT Total Pages
			// The API now returns the accurate total frames count.
			if count != totalFrames {
				t.Errorf("Total count mismatch: expected %d, got %d", totalFrames, count)
			}

			if tt.name != "OutOfBoundsPage" && len(frames) == 0 {
				t.Fatalf("Expected frames but got empty result")
			}
			if tt.name == "OutOfBoundsPage" {
				if len(frames) != 0 {
					t.Errorf("Expected 0 frames for out of bounds, got %d", len(frames))
				}
				return
			}

			if len(frames) > 0 {
				firstFrame := frames[0]
				t.Logf("Page %d First Frame Index: %s", tt.page, firstFrame.Index)

				if len(frames) > tt.size {
					t.Errorf("Result length %d exceeds page size %d", len(frames), tt.size)
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

// BenchmarkGetAllFrames measures the throughput of full file parsing.
func BenchmarkGetAllFrames(b *testing.B) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		b.Skip("skipping benchmark; pcap file not found")
	}

	for i := 0; i < b.N; i++ {
		frames, err := GetAllFrames(testPcapFile)
		if err != nil {
			b.Fatal(err)
		}
		if len(frames) == 0 {
			b.Fatal("Got 0 frames")
		}
	}
}

// BenchmarkGetFramesByPage measures pagination performance.
func BenchmarkGetFramesByPage(b *testing.B) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		b.Skip("skipping benchmark; pcap file not found")
	}

	b.ResetTimer()
	page := 1
	size := 20

	for i := 0; i < b.N; i++ {
		_, _, err := GetFramesByPage(testPcapFile, page, size)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// BenchmarkGetFramesByPageDeep measures pagination performance (deep page).
func BenchmarkGetFramesByPageDeep(b *testing.B) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		b.Skip("skipping benchmark; pcap file not found")
	}

	page := 100
	size := 20

	count, _ := CountFrames(testPcapFile)
	if count < page*size {
		b.Skip("Test file too small for deep pagination benchmark")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := GetFramesByPage(testPcapFile, page, size)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// BenchmarkGetFramesByIdxs_Sparse measures sparse random access performance.
func BenchmarkGetFramesByIdxs_Sparse(b *testing.B) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		b.Skip("skipping benchmark; pcap file not found")
	}

	total, _ := CountFrames(testPcapFile)
	idxs := []int{1, total / 2, total}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetFramesByIdxs(testPcapFile, idxs)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGetFramesByIdxs_Batch100 measures batch random access performance.
func BenchmarkGetFramesByIdxs_Batch100(b *testing.B) {
	if _, err := os.Stat(testPcapFile); os.IsNotExist(err) {
		b.Skip("skipping benchmark; pcap file not found")
	}

	total, _ := CountFrames(testPcapFile)
	if total < 200 {
		b.Skip("File too small")
	}

	rand.Seed(time.Now().UnixNano())
	idxs := make([]int, 0, 100)
	for i := 0; i < 100; i++ {
		idxs = append(idxs, rand.Intn(total)+1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetFramesByIdxs(testPcapFile, idxs)
		if err != nil {
			b.Fatal(err)
		}
	}
}
