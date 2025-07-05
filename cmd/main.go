package main

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/randolphcyg/gowireshark"
)

func main() {
	r := gin.Default()

	api := r.Group("/api/v1")
	{
		api.GET("/version/wireshark", getWiresharkVersion) // wireshark version
		api.POST("/getAllFrames", getAllFrames)            // get pcap all frames
	}

	if err := r.Run(":8090"); err != nil {
		slog.Error("Failed to start server", "error", err)
		os.Exit(1)
	}
}

type wiresharkVersionResp struct {
	Version string `json:"version"`
}

func getWiresharkVersion(c *gin.Context) {
	var resp wiresharkVersionResp
	resp.Version = gowireshark.EpanVersion()
	Success(c, resp)
}

func HandleError(ctx *gin.Context, code int, message string, err error) {
	if err != nil {
		slog.Error(message, slog.Any("error", err))
	}
	ctx.JSON(200, gin.H{
		"code": code,
		"msg":  message,
	})
}

func Success(ctx *gin.Context, data any) {
	ctx.JSON(200, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

type getAllFramesRequest struct {
	Filepath  string `json:"filepath" binding:"required"`
	IsDebug   bool   `json:"isDebug,omitempty"`
	IgnoreErr bool   `json:"ignoreErr,omitempty"`
}

func getAllFrames(c *gin.Context) {
	var req getAllFramesRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		HandleError(c, -1, "invalid param", err)
		return
	}

	frames, err := gowireshark.GetAllFrames(req.Filepath,
		gowireshark.WithDebug(req.IsDebug),
		gowireshark.IgnoreError(req.IgnoreErr))
	if err != nil {
		HandleError(c, -2, "wireshark parse err", err)
		return
	}

	Success(c, frames)
}
