package extract

import (
	"github.com/randolphcyg/gowireshark/internal/testfixture"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

func setupExtractor(t *testing.T) (*Extractor, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "gowireshark-extract-*")
	if err != nil {
		t.Fatal(err)
	}
	extractor, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return extractor, func() {
		os.RemoveAll(dir)
	}
}

// --- Unit Tests ---

func TestValidFileExtension(t *testing.T) {
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
			got := isValidFileExtension(tt.filename)
			if got != tt.want {
				t.Errorf("isValidFileExtension(%q) = %v, want %v", tt.filename, got, tt.want)
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

func TestUniqueFilename(t *testing.T) {
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	// Create initial file
	first := extractor.uniqueFilename("test.txt")
	if err := os.WriteFile(first, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Second call should generate test(1).txt
	second := extractor.uniqueFilename("test.txt")
	if !strings.Contains(second, "test(1).txt") {
		t.Errorf("expected test(1).txt, got %s", second)
	}
}

func TestConcurrentFilenameGeneration(t *testing.T) {
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	var wg sync.WaitGroup
	results := make([]string, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = extractor.uniqueFilename("concurrent.txt")
		}(i)
	}

	wg.Wait()

	// All results should be valid paths
	for i, r := range results {
		if r == "" {
			t.Errorf("result[%d] is empty", i)
		}
		if !strings.HasPrefix(r, extractor.dir) {
			t.Errorf("result[%d] = %q, not under extractor.dir", i, r)
		}
	}
}

// --- Integration Tests ---

// TestExtractHTTPFiles tests HTTP file extraction from a pcap.
func TestExtractHTTPFiles(t *testing.T) {
	pcapPath := testfixture.Pcap(t)
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	frames, err := gowireshark.Frames(pcapPath, gowireshark.WithDebug(false), gowireshark.WithIgnoreErrors(true))
	if err != nil {
		t.Fatal(err)
	}

	var httpFrameCount int
	for _, frame := range frames {
		if frame.BaseLayers.HTTP != nil {
			httpFrameCount++
			paths, err := extractor.HTTPFiles(frame.BaseLayers.HTTP)
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
	pcapPath := testfixture.Pcap(t)
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	frames, err := gowireshark.Frames(pcapPath, gowireshark.WithDebug(false), gowireshark.WithIgnoreErrors(true))
	if err != nil {
		t.Fatal(err)
	}

	extracted, err := extractor.Files(frames)
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

func TestNewRequiresDir(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("expected error for empty extract directory")
	}
}

// TestWriteHexDataToFile tests the hex decoding and file writing.
func TestWriteHexDataToFile(t *testing.T) {
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	path := filepath.Join(extractor.dir, "test_hex.bin")

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
	extractor, cleanup := setupExtractor(t)
	defer cleanup()

	path := filepath.Join(extractor.dir, "test_large.bin")

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
