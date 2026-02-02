package pkg

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentFilenameGeneration(t *testing.T) {
	ExtractFileDir = "./testdir"
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

func TestExtractHttpFile(t *testing.T) {
	path := "./pcaps/ext.pcap"

	frames, err := GetAllFrames(path,
		WithDebug(false),
		IgnoreError(false))

	if err != nil {
		t.Fatal(err)
	}

	for _, frame := range frames {
		if frame.BaseLayers.Http == nil {
			continue
		}

		pwd, _ := os.Getwd()
		ExtractFileDir = filepath.Join(pwd, "testdir")
		genPath, err := ExtractHttpFile(frame.BaseLayers.Http)
		if err != nil {
			t.Log(err)
			continue
		}
		t.Log(genPath)
	}
}
