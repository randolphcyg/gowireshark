package pkg

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// setupExtractDir creates a temp directory for extraction tests and sets ExtractFileDir.
// Returns a cleanup function that removes the directory.
func setupExtractDir(t *testing.T) func() {
	t.Helper()
	dir, err := os.MkdirTemp("", "gowireshark-extract-*")
	if err != nil {
		t.Fatal(err)
	}
	ExtractFileDir = dir
	return func() {
		os.RemoveAll(dir)
	}
}

// --- Unit Tests ---

func TestIsValidFileExtension(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		{"photo.jpg", true},
		{"document.pdf", true},
		{"archive.zip", true},
		{"script.py", true},
		{"noext", false},
		{"", false},
		{"file.unknownext123", false},
		{"image.PNG", true}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := IsValidFileExtension(tt.filename)
			if got != tt.want {
				t.Errorf("IsValidFileExtension(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal.txt", "normal.txt"},
		{"../../../etc/passwd", "passwd"},
		{"path/to/file.pdf", "file.pdf"},
		{"file\x00name.txt", "filename.txt"},
		{"back\\slash.doc", "back_slash.doc"},
		{"  spaces  .jpg  ", "spaces  .jpg"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractFilenameFromHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    string
	}{
		{
			"standard quoted",
			[]string{`Content-Disposition: attachment; filename="report.pdf"`},
			"report.pdf",
		},
		{
			"standard unquoted",
			[]string{`Content-Disposition: attachment; filename=data.csv`},
			"data.csv",
		},
		{
			"utf8 encoded",
			[]string{`Content-Disposition: attachment; filename*=UTF-8''%E6%B5%8B%E8%AF%95.pdf`},
			"测试.pdf",
		},
		{
			"no filename",
			[]string{`Content-Type: application/json`},
			"",
		},
		{
			"empty headers",
			[]string{},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFilenameFromHeaders(tt.headers)
			if got != tt.want {
				t.Errorf("extractFilenameFromHeaders() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateUniqueFilenameWithIncrement(t *testing.T) {
	cleanup := setupExtractDir(t)
	defer cleanup()

	// Create initial file
	first := GenerateUniqueFilenameWithIncrement("test.txt")
	if err := os.WriteFile(first, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Second call should generate test(1).txt
	second := GenerateUniqueFilenameWithIncrement("test.txt")
	if !strings.Contains(second, "test(1).txt") {
		t.Errorf("expected test(1).txt, got %s", second)
	}
}

func TestConcurrentFilenameGeneration(t *testing.T) {
	cleanup := setupExtractDir(t)
	defer cleanup()

	var wg sync.WaitGroup
	results := make([]string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = GenerateUniqueFilenameWithIncrement("concurrent.txt")
		}(i)
	}

	wg.Wait()

	// All results should be valid paths
	for i, r := range results {
		if r == "" {
			t.Errorf("result[%d] is empty", i)
		}
		if !strings.HasPrefix(r, ExtractFileDir) {
			t.Errorf("result[%d] = %q, not under ExtractFileDir", i, r)
		}
	}
}

// --- Integration Tests ---

// TestExtractHttpFiles tests HTTP file extraction from a pcap.
func TestExtractHttpFiles(t *testing.T) {
	pcapPath := getTestPcap(t)
	cleanup := setupExtractDir(t)
	defer cleanup()

	frames, err := GetAllFrames(pcapPath, WithDebug(false), IgnoreError(true))
	if err != nil {
		t.Fatal(err)
	}

	var httpFrameCount int
	for _, frame := range frames {
		if frame.BaseLayers.Http != nil {
			httpFrameCount++
			paths, err := ExtractHttpFile(frame.BaseLayers.Http)
			if err != nil {
				continue
			}
			for _, p := range paths {
				info, err := os.Stat(p)
				if err != nil {
					t.Errorf("extracted file not found: %s", p)
					continue
				}
				if info.Size() == 0 {
					t.Errorf("extracted file is empty: %s", p)
				}
				t.Logf("HTTP extracted: %s (%d bytes)", filepath.Base(p), info.Size())
			}
		}
	}

	if httpFrameCount == 0 {
		t.Skip("No HTTP frames found in test pcap")
	}
}

// TestExtractFiles tests the unified multi-protocol extraction API.
func TestExtractFiles(t *testing.T) {
	pcapPath := getTestPcap(t)
	cleanup := setupExtractDir(t)
	defer cleanup()

	frames, err := GetAllFrames(pcapPath, WithDebug(false), IgnoreError(true))
	if err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractFiles(frames)
	if err != nil {
		t.Fatal(err)
	}

	if len(extracted) == 0 {
		t.Skip("No files extracted from test pcap (expected if no file transfers)")
		return
	}

	protocols := make(map[string]int)
	for _, ef := range extracted {
		protocols[ef.Protocol]++

		// Verify file exists and is non-empty
		info, err := os.Stat(ef.Path)
		if err != nil {
			t.Errorf("extracted file not found: %s", ef.Path)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("extracted file is empty: %s", ef.Path)
		}
		if ef.Size != info.Size() {
			t.Errorf("size mismatch for %s: reported %d, actual %d", ef.Filename, ef.Size, info.Size())
		}

		t.Logf("[%s] %s (%d bytes) %s→%s",
			ef.Protocol, ef.Filename, ef.Size, ef.SrcAddr, ef.DstAddr)
	}

	t.Logf("Extraction summary: %d files total", len(extracted))
	for proto, count := range protocols {
		t.Logf("  %s: %d files", proto, count)
	}
}

// TestExtractFilesRequiresDir verifies that ExtractFiles fails gracefully without ExtractFileDir.
func TestExtractFilesRequiresDir(t *testing.T) {
	oldDir := ExtractFileDir
	ExtractFileDir = ""
	defer func() { ExtractFileDir = oldDir }()

	_, err := ExtractFiles(nil)
	if err == nil {
		t.Error("expected error when ExtractFileDir is empty")
	}
}

// TestWriteHexDataToFile tests the hex decoding and file writing.
func TestWriteHexDataToFile(t *testing.T) {
	cleanup := setupExtractDir(t)
	defer cleanup()

	path := filepath.Join(ExtractFileDir, "test_hex.bin")

	// "Hello" in hex with colons
	hexData := "48:65:6c:6c:6f"
	if err := writeHexDataToFile(path, hexData); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(content) != "Hello" {
		t.Errorf("expected 'Hello', got %q", string(content))
	}
}

// TestWriteHexDataToFileLarge tests hex decoding with a larger payload.
func TestWriteHexDataToFileLarge(t *testing.T) {
	cleanup := setupExtractDir(t)
	defer cleanup()

	path := filepath.Join(ExtractFileDir, "test_large.bin")

	// Generate 100KB of hex data (no colons)
	var builder strings.Builder
	for i := 0; i < 100*1024; i++ {
		builder.WriteString("ab")
	}
	hexData := builder.String()

	if err := writeHexDataToFile(path, hexData); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Size() != 100*1024 {
		t.Errorf("expected 102400 bytes, got %d", info.Size())
	}
}
