package pkg

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentFilenameGeneration(t *testing.T) {
	ExtractFileDir = "../testdir"
	filename := "example.txt"

	var wg sync.WaitGroup
	numFiles := 10

	for i := 0; i < numFiles; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newFilename := GenerateUniqueFilenameWithIncrement(filename)
			t.Log("Generated filename:", newFilename)
		}()
	}

	wg.Wait()
}

// TestExtractHttpFile extracts HTTP file objects from a pcap.
// Requires a pcap containing HTTP file transfers.
func TestExtractHttpFile(t *testing.T) {
	pcapPath := getTestPcap(t)

	frames, err := GetAllFrames(pcapPath, WithDebug(false), IgnoreError(false))
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, frame := range frames {
		if frame.BaseLayers.Http == nil {
			continue
		}
		found = true

		pwd, _ := os.Getwd()
		ExtractFileDir = filepath.Join(pwd, "testdir")
		genPath, err := ExtractHttpFile(frame.BaseLayers.Http)
		if err != nil {
			t.Log(err)
			continue
		}
		t.Log("Extracted:", genPath)
	}

	if !found {
		t.Skip("No HTTP frames found in test pcap (expected if not HTTP traffic)")
	}
}
