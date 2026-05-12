package pkg

import (
	"os"
	"path/filepath"
	"testing"
)

const testPcapDir = "../pcaps"

// getTestPcap returns a path to a pcap file for testing.
// Priority:
//  1. Environment variable GOWIRESHARK_TEST_PCAP (exact path)
//  2. First .pcap or .pcapng file found in ../pcaps/
//
// If no file is available, the test is skipped with a helpful message.
func getTestPcap(t testing.TB) string {
	t.Helper()

	// 1. Check env var
	if p := os.Getenv("GOWIRESHARK_TEST_PCAP"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		t.Skipf("GOWIRESHARK_TEST_PCAP=%q does not exist, skipping", p)
	}

	// 2. Auto-discover from pcaps directory
	entries, err := os.ReadDir(testPcapDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := filepath.Ext(e.Name())
			if ext == ".pcap" || ext == ".pcapng" {
				return filepath.Join(testPcapDir, e.Name())
			}
		}
	}

	t.Skip("skipping: no pcap file found.\n" +
		"Place any .pcap or .pcapng file in ./pcaps/ directory,\n" +
		"or set GOWIRESHARK_TEST_PCAP=/path/to/file.pcap")
	return ""
}

// getTestKeyFile returns a path to a TLS key file for testing.
// Falls back to env var GOWIRESHARK_TEST_KEY, then looks for *.key in pcaps dir.
func getTestKeyFile(t testing.TB) string {
	t.Helper()

	if p := os.Getenv("GOWIRESHARK_TEST_KEY"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	entries, _ := os.ReadDir(testPcapDir)
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".key" {
			return filepath.Join(testPcapDir, e.Name())
		}
	}

	t.Skip("skipping: no TLS key file found.\n" +
		"Place a .key file in ./pcaps/ directory, or set GOWIRESHARK_TEST_KEY")
	return ""
}
