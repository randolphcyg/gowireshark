// Package testfixture provides repository-local integration test fixtures.
package testfixture

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// Pcap returns an integration-test pcap path or skips the test when none is available.
func Pcap(t testing.TB) string {
	t.Helper()
	if path := os.Getenv("GOWIRESHARK_TEST_PCAP"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		t.Skipf("GOWIRESHARK_TEST_PCAP=%q does not exist, skipping", path)
	}
	matches, err := filepath.Glob(filepath.Join(repoRoot(), "pcaps", "*.pcap*"))
	if err == nil && len(matches) > 0 {
		return matches[0]
	}
	t.Skip("no pcap fixture found; place a .pcap/.pcapng file in ./pcaps or set GOWIRESHARK_TEST_PCAP")
	return ""
}

// KeyFile returns an integration-test TLS key path or skips the test when none is available.
func KeyFile(t testing.TB) string {
	t.Helper()
	if path := os.Getenv("GOWIRESHARK_TEST_KEY"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	matches, err := filepath.Glob(filepath.Join(repoRoot(), "pcaps", "*.key"))
	if err == nil && len(matches) > 0 {
		return matches[0]
	}
	t.Skip("no TLS key fixture found; place a .key file in ./pcaps or set GOWIRESHARK_TEST_KEY")
	return ""
}
