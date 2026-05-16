package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
	"github.com/randolphcyg/gowireshark/pkg"
)

func main() {
	r := gin.Default()

	// Health check (no auth, for K8s/Docker probes)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Auth middleware
	authToken := os.Getenv("AUTH_TOKEN")
	if authToken != "" {
		r.Use(authMiddleware(authToken))
		slog.Info("Token authentication enabled")
	} else {
		slog.Warn("AUTH_TOKEN not set, running without authentication")
	}

	// Path restriction: only allow files under PCAP_BASE_DIR
	// Default: ./pcaps relative to working directory (use /app/pcaps in Docker via env)
	pcapBaseDir := os.Getenv("PCAP_BASE_DIR")
	if pcapBaseDir == "" {
		pcapBaseDir = "./pcaps"
	}
	// Resolve relative path
	if !filepath.IsAbs(pcapBaseDir) {
		abs, _ := filepath.Abs(pcapBaseDir)
		pcapBaseDir = abs
	}
	r.Use(pathGuard(pcapBaseDir))

	// File extraction output directory
	extractDir := os.Getenv("EXTRACT_DIR")
	if extractDir == "" {
		extractDir = os.Getenv("EXTRACT_FILE_DIR")
	}
	if extractDir == "" {
		extractDir = "./extracted_files"
	}
	if !filepath.IsAbs(extractDir) {
		abs, _ := filepath.Abs(extractDir)
		extractDir = abs
	}
	pkg.ExtractFileDir = extractDir

	// Request timeout
	timeoutStr := os.Getenv("REQUEST_TIMEOUT")
	timeout := 120 * time.Second
	if d, err := time.ParseDuration(timeoutStr); err == nil && d > 0 {
		timeout = d
	}
	r.Use(timeoutMiddleware(timeout))

	api := r.Group("/api/v1")
	{
		// System
		api.GET("/version", getWiresharkVersion)
		api.GET("/interfaces", getInterfaces)
		api.POST("/filter/validate", validateFilter)

		// Frame Dissection (offline pcap analysis)
		api.POST("/dissect/frames", getAllFrames)
		api.POST("/dissect/frames/stream", streamAllFrames)
		api.POST("/dissect/frames/page", getFramesByPage)
		api.POST("/dissect/frames/idxs", getFramesByIdxs)
		api.POST("/dissect/frames/count", getFrameCount)
		api.POST("/dissect/frames/hex", getFrameHex)

		// Stream Follow (TCP/UDP stream reassembly)
		api.POST("/dissect/follow", getStreamData)

		// Statistics
		api.POST("/dissect/stats", getProtocolStats)

		// File Extraction
		api.POST("/extract/files", extractFiles)
		api.DELETE("/extract/files", cleanExtractedFiles)

		// Export
		api.POST("/export/frames", exportFramesToFile)

		// PCAP Upload
		api.POST("/upload", uploadPcap)

		// Live Capture (online)
		api.POST("/capture/start", startCapture)
		api.POST("/capture/stop", stopCapture)
		api.POST("/capture/to-pcap", captureToFile)
		api.GET("/capture/stream/:interface", streamCapture)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	slog.Info("Server started", "port", port, "pcapBaseDir", pcapBaseDir, "extractDir", extractDir)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}
	slog.Info("Server exited")
}

// --- Request DTOs ---

type baseRequest struct {
	Filepath  string `json:"filepath" binding:"required"`
	IsDebug   bool   `json:"isDebug"`
	IgnoreErr bool   `json:"ignoreErr"`
	Filter    string `json:"filter"`
}

type pageRequest struct {
	baseRequest
	Page int `json:"page"`
	Size int `json:"size"`
}

type idxsRequest struct {
	baseRequest
	FrameIdxs []int `json:"frameIdxs" binding:"required"`
}

type hexRequest struct {
	baseRequest
	FrameIdx int `json:"frameIdx" binding:"required"`
}

type followRequest struct {
	baseRequest
	Protocol string `json:"protocol" binding:"required"` // "tcp" or "udp"
}

type filterValidateRequest struct {
	Filter string `json:"filter" binding:"required"`
}

type extractRequest struct {
	baseRequest
	CleanBefore bool `json:"cleanBefore"`
}

type exportRequest struct {
	baseRequest
	Format     string `json:"format" binding:"required"` // "json" or "csv"
	OutputPath string `json:"outputPath"`                // optional, auto-generated if empty
}

type captureToFileRequest struct {
	Interface   string `json:"interface" binding:"required"`
	Filter      string `json:"filter"`
	PacketCount int    `json:"packetCount"` // default: 100
	Duration    int    `json:"duration"`    // max seconds, default: 10
	Promisc     *bool  `json:"promisc"`     // default: true
	OutputPath  string `json:"outputPath"`  // optional, auto-generated if empty
}

// --- Response DTOs ---

type StandardResponse struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

type ListData struct {
	List  any `json:"list"`
	Total int `json:"total"`
}

type PageData struct {
	List    any  `json:"list"`
	Total   int  `json:"total"`
	HasMore bool `json:"hasMore"`
	Page    int  `json:"page"`
	Size    int  `json:"size"`
}

// --- System Handlers ---

func getWiresharkVersion(c *gin.Context) {
	Success(c, gin.H{"version": pkg.EpanVersion()})
}

func getInterfaces(c *gin.Context) {
	iFaces, err := pkg.GetIFaces()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "failed to get network interfaces", err)
		return
	}
	Success(c, ListData{List: iFaces, Total: len(iFaces)})
}

func validateFilter(c *gin.Context) {
	var req filterValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	if err := pkg.ValidateFilter(req.Filter); err != nil {
		Success(c, gin.H{"valid": false, "error": err.Error()})
		return
	}

	Success(c, gin.H{"valid": true})
}

// --- Frame Dissection Handlers ---

func getFrameCount(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	count, err := pkg.CountFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "count frames failed", err)
		return
	}

	Success(c, gin.H{"count": count})
}

func getAllFrames(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	// If client accepts NDJSON, use streaming path directly
	if c.GetHeader("Accept") == "application/x-ndjson" {
		c.Header("Content-Type", "application/x-ndjson")
		c.Status(200)
		count, err := pkg.StreamAllFrames(req.Filepath, c.Writer,
			pkg.WithDebug(req.IsDebug),
			pkg.IgnoreError(req.IgnoreErr),
			pkg.WithBpfFilter(req.Filter),
		)
		if err != nil {
			slog.Error("stream interrupted", "error", err, "frames_sent", count)
		}
		return
	}

	frames, err := pkg.GetAllFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse failed", err)
		return
	}

	// Auto-switch to NDJSON for large results
	if len(frames) > 1000 {
		c.Header("Content-Type", "application/x-ndjson")
		c.Header("X-Total-Count", fmt.Sprintf("%d", len(frames)))
		c.Status(200)
		for _, frame := range frames {
			data, _ := sonic.Marshal(frame)
			c.Writer.Write(data)
			c.Writer.Write([]byte("\n"))
		}
		c.Writer.Flush()
		return
	}

	Success(c, ListData{List: frames, Total: len(frames)})
}

func streamAllFrames(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	c.Header("Content-Type", "application/x-ndjson")
	c.Status(200)

	count, err := pkg.StreamAllFrames(req.Filepath, c.Writer,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		slog.Error("stream interrupted", "error", err, "frames_sent", count)
	}
}

const maxPageSize = 500

func getFramesByPage(c *gin.Context) {
	var req pageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.Size < 1 {
		req.Size = 20
	}
	if req.Size > maxPageSize {
		req.Size = maxPageSize
		c.Header("X-Page-Size-Capped", fmt.Sprintf("requested size exceeded max %d, capped", maxPageSize))
	}

	// Zero-copy streaming path when client requests NDJSON
	if c.GetHeader("Accept") == "application/x-ndjson" {
		c.Header("Content-Type", "application/x-ndjson")
		c.Status(200)
		count, hasMore, err := pkg.StreamFramesByPage(req.Filepath, req.Page, req.Size, c.Writer,
			pkg.WithDebug(req.IsDebug),
			pkg.IgnoreError(req.IgnoreErr),
			pkg.WithBpfFilter(req.Filter),
		)
		if err != nil {
			slog.Error("stream page failed", "error", err, "frames_sent", count)
		}
		trailer := fmt.Sprintf("{\"_meta\":{\"page\":%d,\"size\":%d,\"count\":%d,\"hasMore\":%v}}\n",
			req.Page, req.Size, count, hasMore)
		c.Writer.Write([]byte(trailer))
		c.Writer.Flush()
		return
	}

	frames, hasMore, err := pkg.GetFramesByPage(req.Filepath, req.Page, req.Size,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse failed", err)
		return
	}

	Success(c, PageData{
		List:    frames,
		Total:   len(frames),
		HasMore: hasMore,
		Page:    req.Page,
		Size:    req.Size,
	})
}

func getFramesByIdxs(c *gin.Context) {
	var req idxsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	if len(req.FrameIdxs) > 1000 {
		HandleError(c, http.StatusBadRequest, "too many frame indices", fmt.Errorf("max 1000, got %d", len(req.FrameIdxs)))
		return
	}

	frames, err := pkg.GetFramesByIdxs(req.Filepath, req.FrameIdxs,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse failed", err)
		return
	}

	Success(c, ListData{List: frames, Total: len(frames)})
}

func getFrameHex(c *gin.Context) {
	var req hexRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	hexData, err := pkg.GetHexDataByIdx(req.Filepath, req.FrameIdx,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse hex failed", err)
		return
	}

	Success(c, hexData)
}

// --- Stream Follow Handler ---

func getStreamData(c *gin.Context) {
	var req followRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	res, err := pkg.GetStreamData(req.Filepath, req.Filter, req.Protocol,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "follow stream failed", err)
		return
	}

	Success(c, res)
}

// --- File Extraction Handler ---

func extractFiles(c *gin.Context) {
	var req extractRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	// Clean before extraction if requested
	if req.CleanBefore {
		if err := cleanExtractDirectory(); err != nil {
			HandleError(c, http.StatusInternalServerError, "clean failed", err)
			return
		}
	}

	frames, err := pkg.GetAllFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(true),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse frames failed", err)
		return
	}

	extracted, err := pkg.ExtractFiles(frames)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "extraction failed", err)
		return
	}

	Success(c, gin.H{
		"files":     extracted,
		"count":     len(extracted),
		"outputDir": pkg.ExtractFileDir,
	})
}

func cleanExtractedFiles(c *gin.Context) {
	removed, totalSize, err := cleanExtractDirectoryWithStats()
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "clean failed", err)
		return
	}
	Success(c, gin.H{
		"outputDir":    pkg.ExtractFileDir,
		"filesRemoved": removed,
		"bytesFreed":   totalSize,
	})
}

// --- Export Handler ---

func exportFramesToFile(c *gin.Context) {
	var req exportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	if req.Format != "json" && req.Format != "csv" {
		HandleError(c, http.StatusBadRequest, "invalid format", fmt.Errorf("format must be 'json' or 'csv'"))
		return
	}

	// Determine output path
	outputPath := req.OutputPath
	if outputPath == "" {
		base := filepath.Base(req.Filepath)
		base = base[:len(base)-len(filepath.Ext(base))]
		outputPath = filepath.Join(pkg.ExtractFileDir, base+"."+req.Format)
	}

	frames, err := pkg.GetAllFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(true),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse frames failed", err)
		return
	}

	os.MkdirAll(filepath.Dir(outputPath), 0o755)

	var writeErr error
	switch req.Format {
	case "json":
		writeErr = writeExportJSON(outputPath, frames)
	case "csv":
		writeErr = writeExportCSV(outputPath, frames)
	}
	if writeErr != nil {
		HandleError(c, http.StatusInternalServerError, "export failed", writeErr)
		return
	}

	info, _ := os.Stat(outputPath)
	var fileSize int64
	if info != nil {
		fileSize = info.Size()
	}

	Success(c, gin.H{
		"sourcePcap":  req.Filepath,
		"outputPath":  outputPath,
		"format":      req.Format,
		"framesCount": len(frames),
		"fileSize":    fileSize,
	})
}

// --- Capture to PCAP File Handler ---

func captureToFile(c *gin.Context) {
	var req captureToFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	// Defaults
	if req.PacketCount <= 0 {
		req.PacketCount = 100
	}
	if req.PacketCount > 100000 {
		req.PacketCount = 100000
	}
	if req.Duration <= 0 {
		req.Duration = 10
	}
	if req.Duration > 300 {
		req.Duration = 300
	}
	promisc := 1
	if req.Promisc != nil && !*req.Promisc {
		promisc = 0
	}

	// Determine output path
	outputPath := req.OutputPath
	if outputPath == "" {
		captureDir := filepath.Join(pkg.ExtractFileDir, "captures")
		os.MkdirAll(captureDir, 0o755)
		outputPath = filepath.Join(captureDir, fmt.Sprintf("capture_%s_%s.pcap",
			req.Interface, time.Now().Format("20060102_150405")))
	}
	os.MkdirAll(filepath.Dir(outputPath), 0o755)

	// Run capture with timeout
	type result struct{ err error }
	done := make(chan result, 1)

	go func() {
		err := pkg.CaptureToFile(req.Interface, req.Filter, req.PacketCount, promisc, 100, outputPath)
		done <- result{err: err}
	}()

	select {
	case res := <-done:
		if res.err != nil {
			HandleError(c, http.StatusInternalServerError, "capture failed", res.err)
			return
		}
	case <-time.After(time.Duration(req.Duration) * time.Second):
		_ = pkg.StopLivePacketCapture(req.Interface)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "capture completed but file not found", err)
		return
	}

	Success(c, gin.H{
		"interface":  req.Interface,
		"filter":     req.Filter,
		"outputPath": outputPath,
		"fileSize":   info.Size(),
	})
}

// --- Protocol Statistics Handler ---

func getProtocolStats(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	frames, err := pkg.GetAllFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(true),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, http.StatusInternalServerError, "parse frames failed", err)
		return
	}

	type ProtoStat struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
		Bytes    int    `json:"bytes"`
	}

	protoMap := make(map[string]*ProtoStat)
	var totalBytes int

	for _, frame := range frames {
		proto := "unknown"
		frameLen := 0

		if frame.BaseLayers.WsCol != nil && frame.BaseLayers.WsCol.Protocol != "" {
			proto = frame.BaseLayers.WsCol.Protocol
		}
		if frame.BaseLayers.Frame != nil {
			frameLen = frame.BaseLayers.Frame.Len
		}

		totalBytes += frameLen

		if stat, ok := protoMap[proto]; ok {
			stat.Count++
			stat.Bytes += frameLen
		} else {
			protoMap[proto] = &ProtoStat{Protocol: proto, Count: 1, Bytes: frameLen}
		}
	}

	stats := make([]ProtoStat, 0, len(protoMap))
	for _, stat := range protoMap {
		stats = append(stats, *stat)
	}

	Success(c, gin.H{
		"totalFrames":    len(frames),
		"totalBytes":     totalBytes,
		"protocolCount":  len(stats),
		"protocols":      stats,
	})
}

// --- PCAP Upload Handler ---

func uploadPcap(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		HandleError(c, http.StatusBadRequest, "file required", err)
		return
	}

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		HandleError(c, http.StatusBadRequest, "invalid file type",
			fmt.Errorf("only .pcap, .pcapng, .cap files are accepted, got %s", ext))
		return
	}

	// Limit file size (default 500MB)
	maxSize := int64(500 * 1024 * 1024)
	if file.Size > maxSize {
		HandleError(c, http.StatusBadRequest, "file too large",
			fmt.Errorf("max size %dMB, got %dMB", maxSize/(1024*1024), file.Size/(1024*1024)))
		return
	}

	// Save to PCAP_BASE_DIR
	pcapBaseDir := os.Getenv("PCAP_BASE_DIR")
	if pcapBaseDir == "" {
		pcapBaseDir = "./pcaps"
	}

	// Sanitize filename
	safeName := filepath.Base(file.Filename)
	safeName = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, safeName)

	destPath := filepath.Join(pcapBaseDir, safeName)

	// Avoid overwriting existing files
	if pkg.FileExists(destPath) {
		base := strings.TrimSuffix(safeName, ext)
		safeName = fmt.Sprintf("%s_%d%s", base, time.Now().UnixMilli(), ext)
		destPath = filepath.Join(pcapBaseDir, safeName)
	}

	if err := c.SaveUploadedFile(file, destPath); err != nil {
		HandleError(c, http.StatusInternalServerError, "save file failed", err)
		return
	}

	Success(c, gin.H{
		"filename": safeName,
		"filepath": destPath,
		"size":     file.Size,
	})
}

// --- Live Capture Handlers ---

type captureRequest struct {
	Interface   string `json:"interface" binding:"required"`
	Filter      string `json:"filter"`      // BPF filter (e.g. "tcp port 80")
	PacketCount int    `json:"packetCount"` // -1 for infinite, default: -1
	Promisc     *bool  `json:"promisc"`     // Promiscuous mode, default: true (use pointer to detect absence)
	Timeout     int    `json:"timeout"`     // Read timeout in ms, default: 100
}

type stopCaptureRequest struct {
	Interface string `json:"interface" binding:"required"`
}

// startCapture begins live packet capture on the specified interface.
func startCapture(c *gin.Context) {
	var req captureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	// Defaults
	if req.PacketCount == 0 {
		req.PacketCount = -1
	}
	if req.Timeout == 0 {
		req.Timeout = 100
	}
	promisc := 1
	if req.Promisc != nil && !*req.Promisc {
		promisc = 0
	}

	// Start capture in background goroutine
	go func() {
		err := pkg.StartLivePacketCapture(req.Interface, req.Filter, req.PacketCount, promisc, req.Timeout)
		if err != nil {
			slog.Error("Live capture ended with error", "interface", req.Interface, "error", err)
		}
	}()

	// Wait for channel to be created (retry with backoff)
	var ch <-chan pkg.FrameData
	for i := 0; i < 10; i++ {
		time.Sleep(200 * time.Millisecond)
		ch = pkg.GetIfaceChannel(req.Interface)
		if ch != nil {
			break
		}
	}

	if ch == nil {
		HandleError(c, http.StatusInternalServerError, "failed to start capture",
			fmt.Errorf("channel not initialized for %s (may need root/sudo permissions)", req.Interface))
		return
	}

	Success(c, gin.H{
		"interface": req.Interface,
		"status":    "capturing",
		"stream":    fmt.Sprintf("/api/v1/capture/stream/%s", req.Interface),
	})
}

// stopCapture stops live packet capture on the specified interface.
func stopCapture(c *gin.Context) {
	var req stopCaptureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, http.StatusBadRequest, "invalid param", err)
		return
	}

	if err := pkg.StopLivePacketCapture(req.Interface); err != nil {
		HandleError(c, http.StatusInternalServerError, "stop capture failed", err)
		return
	}

	Success(c, gin.H{
		"interface": req.Interface,
		"status":    "stopped",
	})
}

// streamCapture streams captured packets as NDJSON (long-lived connection).
func streamCapture(c *gin.Context) {
	ifaceName := c.Param("interface")
	if ifaceName == "" {
		HandleError(c, http.StatusBadRequest, "interface name required", fmt.Errorf("empty interface"))
		return
	}

	ch := pkg.GetIfaceChannel(ifaceName)
	if ch == nil {
		HandleError(c, http.StatusNotFound, "no active capture",
			fmt.Errorf("no capture running on %s", ifaceName))
		return
	}

	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Status(200)

	flusher := c.Writer
	clientGone := c.Request.Context().Done()

	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				return
			}
			data, err := sonic.Marshal(frame)
			if err != nil {
				continue
			}
			flusher.Write(data)
			flusher.Write([]byte("\n"))
			flusher.Flush()

		case <-clientGone:
			return
		}
	}
}

// --- Helpers ---

func HandleError(c *gin.Context, httpCode int, msg string, err error) {
	slog.Error(msg, slog.Any("error", err))
	c.JSON(httpCode, StandardResponse{Code: httpCode, Msg: msg, Error: err.Error()})
}

func Success(c *gin.Context, data any) {
	c.JSON(200, StandardResponse{Code: 0, Msg: "ok", Data: data})
}

// --- Middleware ---

// authMiddleware validates Bearer token from Authorization header.
func authMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				StandardResponse{Code: 401, Msg: "missing authorization header"})
			return
		}

		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				StandardResponse{Code: 401, Msg: "invalid authorization format"})
			return
		}

		if auth[len(prefix):] != token {
			c.AbortWithStatusJSON(http.StatusForbidden,
				StandardResponse{Code: 403, Msg: "invalid token"})
			return
		}

		c.Next()
	}
}

// pathGuard restricts filepath parameters to a specific base directory.
func pathGuard(baseDir string) gin.HandlerFunc {
	absBase, _ := filepath.Abs(baseDir)
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		body, err := c.GetRawData()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest,
				StandardResponse{Code: 400, Msg: "cannot read body"})
			return
		}
		c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

		var peek struct {
			Filepath string `json:"filepath"`
		}
		if sonic.Unmarshal(body, &peek) == nil && peek.Filepath != "" {
			absPath, _ := filepath.Abs(peek.Filepath)
			if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
				c.AbortWithStatusJSON(http.StatusForbidden, StandardResponse{
					Code: 403,
					Msg:  fmt.Sprintf("filepath must be under %s", absBase),
				})
				return
			}
		}

		c.Next()
	}
}

// timeoutMiddleware aborts requests that exceed the configured duration.
func timeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip timeout for streaming endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/api/v1/capture/stream/") {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// --- File Utility Functions ---

func cleanExtractDirectory() error {
	if pkg.ExtractFileDir == "" {
		return fmt.Errorf("extract file dir not configured")
	}
	entries, err := os.ReadDir(pkg.ExtractFileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		os.RemoveAll(filepath.Join(pkg.ExtractFileDir, entry.Name()))
	}
	return nil
}

func cleanExtractDirectoryWithStats() (int, int64, error) {
	if pkg.ExtractFileDir == "" {
		return 0, 0, fmt.Errorf("extract file dir not configured")
	}
	entries, err := os.ReadDir(pkg.ExtractFileDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	var removed int
	var totalSize int64
	for _, entry := range entries {
		path := filepath.Join(pkg.ExtractFileDir, entry.Name())
		if info, err := entry.Info(); err == nil {
			totalSize += info.Size()
		}
		os.RemoveAll(path)
		removed++
	}
	return removed, totalSize, nil
}

func writeExportJSON(path string, frames []*pkg.FrameData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := sonic.MarshalIndent(frames, "", "  ")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

func writeExportCSV(path string, frames []*pkg.FrameData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("No.,Time,Source,Destination,Protocol,Length,Info\n")
	for _, frame := range frames {
		no, ts, src, dst, proto, length, info := 0, "", "", "", "", 0, ""
		if frame.BaseLayers.Frame != nil {
			no = frame.BaseLayers.Frame.Number
			length = frame.BaseLayers.Frame.Len
			ts = frame.BaseLayers.Frame.TimeRelative
		}
		if frame.BaseLayers.WsCol != nil {
			proto = frame.BaseLayers.WsCol.Protocol
			info = frame.BaseLayers.WsCol.Info
			if frame.BaseLayers.Ip == nil {
				src = frame.BaseLayers.WsCol.DefSrc
				dst = frame.BaseLayers.WsCol.DefDst
			}
		}
		if frame.BaseLayers.Ip != nil {
			src = frame.BaseLayers.Ip.Src
			dst = frame.BaseLayers.Ip.Dst
		}
		// Escape CSV fields with commas/quotes
		line := fmt.Sprintf("%d,%s,%s,%s,%s,%d,%s\n",
			no, csvEscapeField(ts), csvEscapeField(src), csvEscapeField(dst),
			csvEscapeField(proto), length, csvEscapeField(info))
		f.WriteString(line)
	}
	return nil
}

func csvEscapeField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
