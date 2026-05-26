package bench

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
)

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func BenchPcap() string {
	if path := os.Getenv("GOWIRESHARK_BENCH_PCAP"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	matches, _ := filepath.Glob(filepath.Join(repoRoot(), "pcaps", "*.pcap*"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

func TsharkPath() string {
	if path := os.Getenv("GOWIRESHARK_TSHARK"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if p, err := exec.LookPath("tshark"); err == nil {
		return p
	}
	macOSPath := "/Applications/Wireshark.app/Contents/MacOS/tshark"
	if _, err := os.Stat(macOSPath); err == nil {
		return macOSPath
	}
	return ""
}

func BenchIterations() int {
	if s := os.Getenv("GOWIRESHARK_BENCH_ITER"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 30
}

func TsharkVersion(tsharkPath string) (string, error) {
	out, err := exec.Command(tsharkPath, "--version").Output()
	if err != nil {
		return "", err
	}
	return firstLine(string(out)), nil
}

func tsharkVersion(tsharkPath string) string {
	out, err := exec.Command(tsharkPath, "--version").Output()
	if err != nil {
		return "unknown"
	}
	return firstLine(string(out))
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
	}
	return s
}

func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

func tempDir() (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("gowireshark-bench-%d", os.Getpid()))
	if err := ensureDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}
