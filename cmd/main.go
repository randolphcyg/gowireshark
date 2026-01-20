package main

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/randolphcyg/gowireshark"
)

func main() {
	// Initialize the Gin engine with default middleware (logger and recovery)
	r := gin.Default()

	// Define API version grouping
	api := r.Group("/api/v1")
	{
		// System & Metadata Endpoints
		api.GET("/version/wireshark", getWiresharkVersion)

		// Packet Parsing Endpoints
		// 1. Full Scan: Parses the entire file. Warning: High memory usage for large files.
		api.POST("/frames/all", getAllFrames)

		// 2. Pagination: Optimized single-pass I/O. Highly recommended for large PCAP files.
		api.POST("/frames/page", getFramesByPage)

		// 3. Random Access: Fetches specific frames by their Frame Number.
		api.POST("/frames/idxs", getFramesByIdxs)
	}

	// Start the HTTP server on port 8090
	if err := r.Run(":8090"); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}

// --- Request DTOs (Data Transfer Objects) ---

// baseRequest contains common parameters required for parsing logic.
type baseRequest struct {
	Filepath  string `json:"filepath" binding:"required"` // Absolute path to the .pcap/.pcapng file inside the container
	IsDebug   bool   `json:"isDebug"`                     // If true, enables verbose C-level logging
	IgnoreErr bool   `json:"ignoreErr"`                   // If true, parsing continues even if a single frame is malformed
}

// getByPageRequest handles pagination parameters.
type getByPageRequest struct {
	baseRequest
	Page int `json:"page"` // Page number (1-based, default: 1)
	Size int `json:"size"` // Frames per page (default: 10)
}

// getByIdxsRequest handles specific frame retrieval.
type getByIdxsRequest struct {
	baseRequest
	FrameIdxs []int `json:"frameIdxs" binding:"required"` // List of specific frame numbers (e.g., [1, 5, 100])
}

// --- Route Handlers ---

// getAllFrames parses the entire file and returns all frames.
func getAllFrames(c *gin.Context) {
	var req baseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	frames, err := gowireshark.GetAllFrames(req.Filepath,
		gowireshark.WithDebug(req.IsDebug),
		gowireshark.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "wireshark parse err", err)
		return
	}

	Success(c, gin.H{
		"list":  frames,
		"total": len(frames),
	})
}

// getFramesByPage performs an optimized paginated query.
// It uses a single I/O pass to skip unwanted frames efficiently.
func getFramesByPage(c *gin.Context) {
	var req getByPageRequest
	// Set default values if not provided
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Size < 1 {
		req.Size = 10
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	// Call the optimized library function
	// totalCount represents the total number of records, NOT pages.
	frames, totalCount, err := gowireshark.GetFramesByPage(req.Filepath, req.Page, req.Size,
		gowireshark.WithDebug(req.IsDebug),
		gowireshark.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "wireshark parse err", err)
		return
	}

	// Return standard pagination response structure
	Success(c, gin.H{
		"list":  frames,
		"total": totalCount, // Frontend calculates pages via: ceil(total / size)
		"page":  req.Page,
		"size":  req.Size,
	})
}

// getFramesByIdxs retrieves specific frames efficiently.
func getFramesByIdxs(c *gin.Context) {
	var req getByIdxsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, 400, "invalid param", err)
		return
	}

	frames, err := gowireshark.GetFramesByIdxs(req.Filepath, req.FrameIdxs,
		gowireshark.WithDebug(req.IsDebug),
		gowireshark.IgnoreError(req.IgnoreErr),
	)
	if err != nil {
		HandleError(c, 500, "wireshark parse err", err)
		return
	}

	Success(c, gin.H{
		"list":  frames,
		"total": len(frames),
	})
}

// --- Helper Functions ---

type wiresharkVersionResp struct {
	Version string `json:"version"`
}

func getWiresharkVersion(c *gin.Context) {
	var resp wiresharkVersionResp
	resp.Version = gowireshark.EpanVersion()
	Success(c, resp)
}

// HandleError returns a standardized error response.
func HandleError(ctx *gin.Context, code int, message string, err error) {
	if err != nil {
		slog.Error(message, slog.Any("error", err))
	}
	// Using 200 OK for business logic errors is a common convention,
	// though 4xx/5xx is also valid depending on your API style guide.
	ctx.JSON(200, gin.H{
		"code":  code,
		"msg":   message,
		"error": err.Error(), // Include detailed error for debugging
	})
}

// Success returns a standardized success response.
func Success(ctx *gin.Context, data any) {
	ctx.JSON(200, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}
