package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/randolphcyg/gowireshark/pkg"
)

// --- Live Capture State Management ---

type captureSession struct {
	Interface   string
	Filter      string
	StartTime   time.Time
	Packets     []capturedPacket
	RawFrames   []pkg.FrameData
	PacketLimit int
	mu          sync.Mutex
	running     bool
}

type capturedPacket struct {
	Number   int    `json:"number"`
	Time     string `json:"time"`
	Protocol string `json:"protocol"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Length   int    `json:"length"`
	Info     string `json:"info"`
}

var (
	capturesMu sync.RWMutex
	captures   = make(map[string]*captureSession)
)

func getCaptureSession(ifaceName string) *captureSession {
	capturesMu.RLock()
	defer capturesMu.RUnlock()
	return captures[ifaceName]
}

func startCaptureHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Pre-check: verify BPF device access
	if err := checkCapturePermission(); err != nil {
		return errorResult(err)
	}

	ifaceName, err := getRequiredStringArg(request, "interface")
	if err != nil {
		return errorResult(err)
	}
	filter, _ := getStringArg(request, "filter")
	packetCount := int(getFloatArg(request, "packet_count", 100))
	if packetCount < 1 {
		packetCount = 100
	}
	if packetCount > 10000 {
		packetCount = 10000
	}
	duration := int(getFloatArg(request, "duration", 10))
	if duration < 1 {
		duration = 10
	}
	if duration > 300 {
		duration = 300
	}
	promisc := true
	if val, ok := request.GetArguments()["promisc"]; ok {
		if b, ok := val.(bool); ok {
			promisc = b
		}
	}
	if session := getCaptureSession(ifaceName); session != nil && session.running {
		return errorResult(fmt.Errorf("capture already running on %s, stop it first", ifaceName))
	}
	session := &captureSession{
		Interface:   ifaceName,
		Filter:      filter,
		StartTime:   time.Now(),
		Packets:     make([]capturedPacket, 0, packetCount),
		RawFrames:   make([]pkg.FrameData, 0, packetCount),
		PacketLimit: packetCount,
		running:     true,
	}
	capturesMu.Lock()
	captures[ifaceName] = session
	capturesMu.Unlock()

	promiscInt := 1
	if !promisc {
		promiscInt = 0
	}
	go func() {
		defer func() {
			session.mu.Lock()
			session.running = false
			session.mu.Unlock()
		}()
		if err := pkg.StartLivePacketCapture(ifaceName, filter, packetCount, promiscInt, 100); err != nil {
			slog.Error("Live capture ended with error", "interface", ifaceName, "error", err)
		}
	}()

	go func() {
		time.Sleep(200 * time.Millisecond)
		ch := pkg.GetIfaceChannel(ifaceName)
		if ch == nil {
			slog.Error("Failed to get capture channel", "interface", ifaceName)
			return
		}
		timeout := time.After(time.Duration(duration) * time.Second)
		packetNum := 0
		for {
			select {
			case frame, ok := <-ch:
				if !ok {
					return
				}
				packetNum++
				pkt := capturedPacket{Number: packetNum}
				if frame.BaseLayers.Frame != nil {
					pkt.Length = frame.BaseLayers.Frame.Len
					pkt.Time = frame.BaseLayers.Frame.TimeRelative
				}
				if frame.BaseLayers.WsCol != nil {
					pkt.Protocol = frame.BaseLayers.WsCol.Protocol
					pkt.Info = frame.BaseLayers.WsCol.Info
					if frame.BaseLayers.Ip == nil {
						pkt.Src = frame.BaseLayers.WsCol.DefSrc
						pkt.Dst = frame.BaseLayers.WsCol.DefDst
					}
				}
				if frame.BaseLayers.Ip != nil {
					pkt.Src = frame.BaseLayers.Ip.Src
					pkt.Dst = frame.BaseLayers.Ip.Dst
				}
				session.mu.Lock()
				if len(session.Packets) < session.PacketLimit {
					session.Packets = append(session.Packets, pkt)
					session.RawFrames = append(session.RawFrames, frame)
				}
				session.mu.Unlock()
			case <-timeout:
				_ = pkg.StopLivePacketCapture(ifaceName)
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	result := map[string]interface{}{
		"interface": ifaceName, "filter": filter, "packetCount": packetCount,
		"duration": duration, "promisc": promisc, "status": "capturing",
		"startTime": session.StartTime.Format(time.RFC3339),
		"hint":      "Use get_capture_status/stop_capture/get_captured_packets/save_capture",
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return errorResult(fmt.Errorf("failed to serialize: %v", err))
	}
	return textResult(string(jsonBytes))
}

func stopCaptureHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaceName, err := getRequiredStringArg(request, "interface")
	if err != nil {
		return errorResult(err)
	}
	session := getCaptureSession(ifaceName)
	if session == nil {
		return errorResult(fmt.Errorf("no capture session found for %s", ifaceName))
	}
	session.mu.Lock()
	wasRunning := session.running
	session.mu.Unlock()
	if wasRunning {
		if err := pkg.StopLivePacketCapture(ifaceName); err != nil {
			slog.Warn("Stop capture returned error", "interface", ifaceName, "error", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	session.mu.Lock()
	packetsCaptured := len(session.Packets)
	elapsed := time.Since(session.StartTime).Seconds()
	session.mu.Unlock()
	result := map[string]interface{}{
		"interface": ifaceName, "status": "stopped",
		"packetsCaptured": packetsCaptured, "elapsedSeconds": elapsed,
		"hint": "Use get_captured_packets, save_capture, or export_frames",
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return errorResult(fmt.Errorf("failed to serialize: %v", err))
	}
	return textResult(string(jsonBytes))
}

func getCaptureStatusHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaceName, _ := getStringArg(request, "interface")
	if ifaceName != "" {
		session := getCaptureSession(ifaceName)
		if session == nil {
			return errorResult(fmt.Errorf("no capture session found for %s", ifaceName))
		}
		session.mu.Lock()
		result := map[string]interface{}{
			"interface": ifaceName, "filter": session.Filter, "running": session.running,
			"packetsCaptured": len(session.Packets), "packetLimit": session.PacketLimit,
			"startTime": session.StartTime.Format(time.RFC3339),
			"elapsedSeconds": time.Since(session.StartTime).Seconds(),
		}
		session.mu.Unlock()
		jsonBytes, _ := json.Marshal(result)
		return textResult(string(jsonBytes))
	}
	capturesMu.RLock()
	sessions := make([]map[string]interface{}, 0, len(captures))
	for name, s := range captures {
		s.mu.Lock()
		sessions = append(sessions, map[string]interface{}{
			"interface": name, "running": s.running, "packetsCaptured": len(s.Packets),
			"elapsedSeconds": time.Since(s.StartTime).Seconds(),
		})
		s.mu.Unlock()
	}
	capturesMu.RUnlock()
	result := map[string]interface{}{"sessions": sessions, "count": len(sessions)}
	jsonBytes, _ := json.Marshal(result)
	return textResult(string(jsonBytes))
}

func getCapturedPacketsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaceName, err := getRequiredStringArg(request, "interface")
	if err != nil {
		return errorResult(err)
	}
	session := getCaptureSession(ifaceName)
	if session == nil {
		return errorResult(fmt.Errorf("no capture session found for %s", ifaceName))
	}
	page := int(getFloatArg(request, "page", 1))
	if page < 1 {
		page = 1
	}
	size := int(getFloatArg(request, "size", 50))
	if size < 1 {
		size = 50
	}
	if size > 500 {
		size = 500
	}
	session.mu.Lock()
	totalPackets := len(session.Packets)
	running := session.running
	start := (page - 1) * size
	if start > totalPackets {
		start = totalPackets
	}
	end := start + size
	if end > totalPackets {
		end = totalPackets
	}
	var packets []capturedPacket
	if start < totalPackets {
		packets = make([]capturedPacket, end-start)
		copy(packets, session.Packets[start:end])
	}
	session.mu.Unlock()
	result := map[string]interface{}{
		"interface": ifaceName, "running": running, "packets": packets,
		"page": page, "pageSize": size, "count": len(packets),
		"totalPackets": totalPackets, "hasMore": end < totalPackets,
	}
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return errorResult(fmt.Errorf("failed to serialize: %v", err))
	}
	return textResult(string(jsonBytes))
}

func clearCaptureHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaceName, _ := getStringArg(request, "interface")
	if ifaceName != "" {
		session := getCaptureSession(ifaceName)
		if session == nil {
			return errorResult(fmt.Errorf("no capture session found for %s", ifaceName))
		}
		session.mu.Lock()
		if session.running {
			session.mu.Unlock()
			return errorResult(fmt.Errorf("cannot clear while running on %s", ifaceName))
		}
		session.mu.Unlock()
		capturesMu.Lock()
		delete(captures, ifaceName)
		capturesMu.Unlock()
		result := map[string]interface{}{"interface": ifaceName, "status": "cleared"}
		jsonBytes, _ := json.Marshal(result)
		return textResult(string(jsonBytes))
	}
	capturesMu.Lock()
	cleared := 0
	for name, s := range captures {
		s.mu.Lock()
		if !s.running {
			delete(captures, name)
			cleared++
		}
		s.mu.Unlock()
	}
	capturesMu.Unlock()
	result := map[string]interface{}{"status": "cleared", "sessionsCleared": cleared}
	jsonBytes, _ := json.Marshal(result)
	return textResult(string(jsonBytes))
}

// --- Save Capture ---

func saveCaptureHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ifaceName, err := getRequiredStringArg(request, "interface")
	if err != nil {
		return errorResult(err)
	}
	session := getCaptureSession(ifaceName)
	if session == nil {
		return errorResult(fmt.Errorf("no capture session found for %s", ifaceName))
	}
	session.mu.Lock()
	if session.running {
		session.mu.Unlock()
		return errorResult(fmt.Errorf("capture still running on %s, stop it first", ifaceName))
	}
	packetCount := len(session.RawFrames)
	session.mu.Unlock()
	if packetCount == 0 {
		return errorResult(fmt.Errorf("no packets captured on %s", ifaceName))
	}

	outputPath, _ := getStringArg(request, "output_path")
	if outputPath == "" {
		dir := getCaptureOutputDir()
		outputPath = filepath.Join(dir, fmt.Sprintf("capture_%s_%s.json",
			ifaceName, time.Now().Format("20060102_150405")))
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return errorResult(fmt.Errorf("create output dir: %v", err))
	}

	ext := filepath.Ext(outputPath)
	session.mu.Lock()
	frames := make([]pkg.FrameData, len(session.RawFrames))
	copy(frames, session.RawFrames)
	session.mu.Unlock()

	var writeErr error
	switch ext {
	case ".csv":
		writeErr = writeFramesCSV(outputPath, frames)
	default:
		if ext != ".json" {
			outputPath += ".json"
		}
		writeErr = writeFramesJSON(outputPath, frames)
	}
	if writeErr != nil {
		return errorResult(fmt.Errorf("write failed: %v", writeErr))
	}
	info, _ := os.Stat(outputPath)
	var fileSize int64
	if info != nil {
		fileSize = info.Size()
	}
	result := map[string]interface{}{
		"interface": ifaceName, "outputPath": outputPath,
		"format": filepath.Ext(outputPath), "packets": packetCount,
		"fileSize": fileSize, "status": "saved",
	}
	jsonBytes, _ := json.Marshal(result)
	return textResult(string(jsonBytes))
}

// --- Capture to pcap file (libpcap native, correct format) ---

func captureToPcapHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := checkCapturePermission(); err != nil {
		return errorResult(err)
	}

	ifaceName, err := getRequiredStringArg(request, "interface")
	if err != nil {
		return errorResult(err)
	}
	filter, _ := getStringArg(request, "filter")

	packetCount := int(getFloatArg(request, "packet_count", 100))
	if packetCount < 1 {
		packetCount = 100
	}
	if packetCount > 100000 {
		packetCount = 100000
	}

	duration := int(getFloatArg(request, "duration", 10))
	if duration < 1 {
		duration = 10
	}
	if duration > 300 {
		duration = 300
	}

	promisc := true
	if val, ok := request.GetArguments()["promisc"]; ok {
		if b, ok := val.(bool); ok {
			promisc = b
		}
	}

	outputPath, _ := getStringArg(request, "output_path")
	if outputPath == "" {
		dir := getCaptureOutputDir()
		outputPath = filepath.Join(dir, fmt.Sprintf("capture_%s_%s.pcap",
			ifaceName, time.Now().Format("20060102_150405")))
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return errorResult(fmt.Errorf("create output dir: %v", err))
	}

	promiscInt := 1
	if !promisc {
		promiscInt = 0
	}

	// Run capture in background with timeout
	type captureResult struct {
		err error
	}
	done := make(chan captureResult, 1)

	go func() {
		err := pkg.CaptureToFile(ifaceName, filter, packetCount, promiscInt, 100, outputPath)
		done <- captureResult{err: err}
	}()

	// Wait for completion or timeout
	select {
	case res := <-done:
		if res.err != nil {
			return errorResult(res.err)
		}
	case <-time.After(time.Duration(duration) * time.Second):
		// Timeout: stop capture
		_ = pkg.StopLivePacketCapture(ifaceName)
		// Wait a bit for cleanup
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	// Get file info
	info, err := os.Stat(outputPath)
	if err != nil {
		return errorResult(fmt.Errorf("capture completed but cannot stat output: %v", err))
	}

	result := map[string]interface{}{
		"interface":  ifaceName,
		"filter":     filter,
		"outputPath": outputPath,
		"fileSize":   info.Size(),
		"status":     "saved",
		"hint":       "Use dissect_frames/protocol_stats/extract_files with this pcap file for analysis",
	}
	jsonBytes, _ := json.Marshal(result)
	return textResult(string(jsonBytes))
}

// getCaptureOutputDir returns the directory for saving capture output files.
func getCaptureOutputDir() string {
	dir := pkg.ExtractFileDir
	if dir == "" {
		dir = "."
	}
	captureDir := filepath.Join(dir, "captures")
	os.MkdirAll(captureDir, 0o755)
	return captureDir
}

// checkCapturePermission verifies that the process can open BPF devices for capture.
func checkCapturePermission() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil
	}
	if runtime.GOOS == "darwin" {
		for i := 0; i < 4; i++ {
			path := fmt.Sprintf("/dev/bpf%d", i)
			f, err := os.OpenFile(path, os.O_RDWR, 0)
			if err == nil {
				f.Close()
				return nil
			}
			if os.IsPermission(err) {
				return fmt.Errorf("no permission to capture packets (cannot open %s). "+
					"Fix: run 'sudo ./install_bpf_permissions.sh' or 'sudo chmod g+rw /dev/bpf*'", path)
			}
		}
	}
	return nil
}
