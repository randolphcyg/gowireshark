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

	// Path restriction: only allow files under PCAP_BASE_DIR (default: /app/pcaps)
	pcapBaseDir := os.Getenv("PCAP_BASE_DIR")
	if pcapBaseDir == "" {
		pcapBaseDir = "/app/pcaps"
	}
	r.Use(pathGuard(pcapBaseDir))

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
		api.GET("/version/wireshark", getWiresharkVersion)
		api.GET("/interfaces", getInterfaces)

		// Frame Parsing (offline)
		api.POST("/frames/all", getAllFrames)
		api.POST("/frames/stream/all", streamAllFrames)
		api.POST("/frames/page", getFramesByPage)
		api.POST("/frames/idxs", getFramesByIdxs)
		api.POST("/frames/count", getFrameCount)
		api.POST("/frames/hex", getFrameHex)
		api.POST("/frames/stream", getStreamData)

		// Live Capture (online)
		api.POST("/capture/start", startCapture)
		api.POST("/capture/stop", stopCapture)
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

	slog.Info("Server started", "port", port)

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

type streamRequest struct {
	baseRequest
	Protocol string `json:"protocol" binding:"required"`
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

// --- Handlers ---

func getWiresharkVersion(c *gin.Context) {
	Success(c, gin.H{"version": pkg.EpanVersion()})
}

func getInterfaces(c *gin.Context) {
	iFaces, err := pkg.GetIFaces()
	if err != nil {
		HandleError(c, 500, "failed to get network interfaces", err)
		return
	}
	Success(c, ListData{List: iFaces, Total: len(iFaces)})
}

func getFrameCount(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	count, err := pkg.CountFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, 500, "count frames failed", err)
		return
	}

	Success(c, gin.H{"count": count})
}

func getAllFrames(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	frames, err := pkg.GetAllFrames(req.Filepath,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
		pkg.WithBpfFilter(req.Filter),
	)
	if err != nil {
		HandleError(c, 500, "parse failed", err)
		return
	}

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
	} else {
		Success(c, ListData{List: frames, Total: len(frames)})
	}
}

func streamAllFrames(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
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

func getFramesByPage(c *gin.Context) {
	var req pageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.Size < 1 {
		req.Size = 20
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
		HandleError(c, 500, "parse failed", err)
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
		HandleError(c, 400, "invalid param", err)
		return
	}

	frames, err := pkg.GetFramesByIdxs(req.Filepath, req.FrameIdxs,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "parse failed", err)
		return
	}

	Success(c, ListData{List: frames, Total: len(frames)})
}

func getFrameHex(c *gin.Context) {
	var req hexRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	hexData, err := pkg.GetHexDataByIdx(req.Filepath, req.FrameIdx,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "parse hex failed", err)
		return
	}

	Success(c, hexData)
}

func getStreamData(c *gin.Context) {
	var req streamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	res, err := pkg.GetStreamData(req.Filepath, req.Filter, req.Protocol,
		pkg.WithDebug(req.IsDebug),
		pkg.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "stream parse failed", err)
		return
	}

	Success(c, res)
}

// --- Live Capture Handlers ---

type captureRequest struct {
	Interface   string `json:"interface" binding:"required"`
	Filter      string `json:"filter"`                        // BPF filter (e.g. "tcp port 80")
	PacketCount int    `json:"packetCount"`                   // -1 for infinite, default: -1
	Promisc     bool   `json:"promisc"`                       // Promiscuous mode, default: true
	Timeout     int    `json:"timeout"`                       // Read timeout in ms, default: 100
}

type stopCaptureRequest struct {
	Interface string `json:"interface" binding:"required"`
}

// startCapture begins live packet capture on the specified interface.
// Capture runs in the background; use /capture/stream/:interface to consume packets.
func startCapture(c *gin.Context) {
	var req captureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
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
	if !req.Promisc {
		promisc = 0
	}

	// Start capture in background goroutine
	go func() {
		err := pkg.StartLivePacketCapture(req.Interface, req.Filter, req.PacketCount, promisc, req.Timeout)
		if err != nil {
			slog.Error("Live capture ended with error", "interface", req.Interface, "error", err)
		}
	}()

	// Wait briefly for channel to be created
	time.Sleep(200 * time.Millisecond)

	if pkg.GetIfaceChannel(req.Interface) == nil {
		HandleError(c, 500, "failed to start capture", fmt.Errorf("channel not initialized for %s", req.Interface))
		return
	}

	Success(c, gin.H{
		"interface": req.Interface,
		"status":    "capturing",
		"message":   fmt.Sprintf("Use GET /api/v1/capture/stream/%s to receive packets (SSE/NDJSON)", req.Interface),
	})
}

// stopCapture stops live packet capture on the specified interface.
func stopCapture(c *gin.Context) {
	var req stopCaptureRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	if err := pkg.StopLivePacketCapture(req.Interface); err != nil {
		HandleError(c, 500, "stop capture failed", err)
		return
	}

	Success(c, gin.H{
		"interface": req.Interface,
		"status":    "stopped",
	})
}

// streamCapture streams captured packets as NDJSON via Server-Sent Events (long-lived connection).
// Client connects and receives one JSON frame per line until capture stops or client disconnects.
func streamCapture(c *gin.Context) {
	ifaceName := c.Param("interface")
	if ifaceName == "" {
		HandleError(c, 400, "interface name required", fmt.Errorf("empty interface"))
		return
	}

	ch := pkg.GetIfaceChannel(ifaceName)
	if ch == nil {
		HandleError(c, 404, "no active capture", fmt.Errorf("no capture running on %s", ifaceName))
		return
	}

	c.Header("Content-Type", "application/x-ndjson")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Status(200)

	flusher := c.Writer
	clientGone := c.Request.Context().Done()

	for {
		select {
		case frame, ok := <-ch:
			if !ok {
				// Channel closed (capture stopped)
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
			// Client disconnected
			return
		}
	}
}

// --- Helpers ---

func HandleError(c *gin.Context, code int, msg string, err error) {
	slog.Error(msg, slog.Any("error", err))
	c.JSON(200, StandardResponse{Code: code, Msg: msg, Error: err.Error()})
}

func Success(c *gin.Context, data any) {
	c.JSON(200, StandardResponse{Code: 0, Msg: "ok", Data: data})
}

// --- Middleware ---

// authMiddleware validates Bearer token from Authorization header.
func authMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip auth for health check
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(401, StandardResponse{Code: 401, Msg: "missing authorization header"})
			return
		}

		const prefix = "Bearer "
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			c.AbortWithStatusJSON(401, StandardResponse{Code: 401, Msg: "invalid authorization format"})
			return
		}

		if auth[len(prefix):] != token {
			c.AbortWithStatusJSON(403, StandardResponse{Code: 403, Msg: "invalid token"})
			return
		}

		c.Next()
	}
}

// pathGuard restricts filepath parameters to a specific base directory.
// Prevents path traversal attacks (e.g. filepath: "/etc/passwd").
func pathGuard(baseDir string) gin.HandlerFunc {
	absBase, _ := filepath.Abs(baseDir)
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost {
			c.Next()
			return
		}

		// Read body, validate, then restore for downstream handlers
		body, err := c.GetRawData()
		if err != nil {
			c.AbortWithStatusJSON(400, StandardResponse{Code: 400, Msg: "cannot read body"})
			return
		}
		// Restore body
		c.Request.Body = io.NopCloser(strings.NewReader(string(body)))

		// Extract and validate filepath field
		var peek struct {
			Filepath string `json:"filepath"`
		}
		if sonic.Unmarshal(body, &peek) == nil && peek.Filepath != "" {
			absPath, _ := filepath.Abs(peek.Filepath)
			if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
				c.AbortWithStatusJSON(403, StandardResponse{
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
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
