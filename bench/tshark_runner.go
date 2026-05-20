package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type TsharkRunner struct {
	pcap  string
	tshark string

	frameCount int
	hasTCP     bool
	initialized bool
}

func NewTsharkRunner(pcap, tshark string) *TsharkRunner {
	return &TsharkRunner{pcap: pcap, tshark: tshark}
}

func (r *TsharkRunner) init() error {
	if r.initialized {
		return nil
	}
	r.initialized = true

	countOut, err := r.runTshark("-r", r.pcap, "-T", "fields", "-e", "frame.number")
	if err != nil {
		return err
	}
	r.frameCount = countLines(countOut)

	checkOut, err := r.runTshark("-r", r.pcap, "-Y", "tcp", "-c", "1", "-T", "fields", "-e", "frame.number")
	if err == nil {
		r.hasTCP = countLines(checkOut) > 0
	}
	return nil
}

func (r *TsharkRunner) FrameLookup(frameNum int) (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-Y", fmt.Sprintf("frame.number == %d", frameNum),
		"-T", "json",
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countJSONFrames(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) ExpertInfo() (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-Y", "_ws.expert",
		"-T", "fields",
		"-e", "frame.number",
		"-e", "_ws.expert.severity",
		"-e", "_ws.expert.group",
		"-e", "_ws.expert.message",
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countLines(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) FollowStream(streamID int) (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-q",
		"-z", fmt.Sprintf("follow,tcp,raw,%d", streamID),
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countLines(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) StreamList() (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-q",
		"-z", "conv,tcp",
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countLines(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) StreamListTCP() (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-q",
		"-z", "conv,tcp",
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countLines(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) StreamListUDP() (records int, bytesOut int64, err error) {
	out, execErr := r.runTshark(
		"-r", r.pcap,
		"-q",
		"-z", "conv,udp",
	)
	if execErr != nil {
		return 0, 0, execErr
	}
	bytesOut = int64(len(out))
	records = countLines(out)
	return records, bytesOut, nil
}

func (r *TsharkRunner) StreamListAll() (records int, bytesOut int64, err error) {
	tcpOut, tcpErr := r.runTshark("-r", r.pcap, "-q", "-z", "conv,tcp")
	if tcpErr != nil {
		tcpOut = ""
	}
	udpOut, udpErr := r.runTshark("-r", r.pcap, "-q", "-z", "conv,udp")
	if udpErr != nil {
		udpOut = ""
	}
	if tcpErr != nil && udpErr != nil {
		return 0, 0, tcpErr
	}
	combined := tcpOut + udpOut
	bytesOut = int64(len(combined))
	records = countLines(combined)
	return records, bytesOut, nil
}

func (r *TsharkRunner) PcapSlice(tmpDir string, maxFrames int) (records int, bytesOut int64, err error) {
	outFile := filepath.Join(tmpDir, "tshark_slice.pcap")
	defer os.Remove(outFile)

	execErr := r.runTsharkQuiet(
		"-r", r.pcap,
		"-Y", fmt.Sprintf("frame.number <= %d", maxFrames),
		"-w", outFile,
	)
	if execErr != nil {
		return 0, 0, execErr
	}

	info, statErr := os.Stat(outFile)
	if statErr != nil {
		return 0, 0, statErr
	}
	bytesOut = info.Size()

	verifyOut, verifyErr := r.runTshark("-r", outFile, "-T", "fields", "-e", "frame.number")
	if verifyErr != nil {
		return 0, 0, verifyErr
	}
	records = countLines(verifyOut)
	return records, bytesOut, nil
}

func (r *TsharkRunner) FrameCount() int {
	_ = r.init()
	return r.frameCount
}

func (r *TsharkRunner) HasTCP() bool {
	_ = r.init()
	return r.hasTCP
}

func (r *TsharkRunner) runTshark(args ...string) (string, error) {
	cmd := exec.Command(r.tshark, args...)
	cmd.Stderr = nil
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("tshark %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func (r *TsharkRunner) runTsharkQuiet(args ...string) error {
	cmd := exec.Command(r.tshark, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	if s[len(s)-1] != '\n' {
		n++
	}
	return n
}

func countJSONFrames(s string) int {
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	n := 0
	for {
		var v any
		if err := dec.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			break
		}
		n++
	}
	return n
}

func pcapFrameCount(tsharkPath, pcap string) int {
	out, err := exec.Command(tsharkPath, "-r", pcap, "-T", "fields", "-e", "frame.number").Output()
	if err != nil {
		return 0
	}
	return countLines(string(out))
}

func tcpStreamID(tsharkPath, pcap string) (int, error) {
	out, err := exec.Command(tsharkPath, "-r", pcap, "-T", "fields", "-e", "tcp.stream", "-c", "1").Output()
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	return strconv.Atoi(s)
}