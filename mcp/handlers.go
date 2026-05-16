package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/randolphcyg/gowireshark/pkg"
)

// === System Handlers ===

func getVersionHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	result := map[string]interface{}{
		"epanVersion":      pkg.EpanVersion(),
		"pluginsSupported": pkg.EpanPluginsSupported(),
	}
	return jsonResult(result)
}

func listInterfacesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	iFaces, err := pkg.GetIFaces()
	if err != nil {
		return errorResult(fmt.Errorf("failed to get interfaces: %v", err))
	}
	return jsonResult(map[string]interface{}{"interfaces": iFaces, "count": len(iFaces)})
}

func validateFilterHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	filter, err := getRequiredStringArg(request, "filter")
	if err != nil {
		return errorResult(err)
	}
	if validErr := pkg.ValidateFilter(filter); validErr != nil {
		return jsonResult(map[string]interface{}{"valid": false, "error": validErr.Error()})
	}
	return jsonResult(map[string]interface{}{"valid": true, "filter": filter})
}

// === Frame Dissection Handlers ===

func countFramesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	var opts []pkg.Option
	if filter, _ := getStringArg(request, "filter"); filter != "" {
		opts = append(opts, pkg.WithBpfFilter(filter))
	}
	count, err := pkg.CountFrames(fp, opts...)
	if err != nil {
		return errorResult(err)
	}
	return jsonResult(map[string]interface{}{"filepath": fp, "frameCount": count})
}

func dissectFramesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}

	page := int(getFloatArg(request, "page", 1))
	if page < 1 {
		page = 1
	}
	size := int(getFloatArg(request, "size", float64(defaultPageSize)))
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}

	filter, _ := getStringArg(request, "filter")
	var opts []pkg.Option
	opts = append(opts, pkg.IgnoreError(true))
	if filter != "" {
		opts = append(opts, pkg.WithBpfFilter(filter))
	}

	frames, hasMore, err := pkg.GetFramesByPage(fp, page, size, opts...)
	if err != nil {
		return errorResult(err)
	}

	summary := make([]map[string]interface{}, 0, len(frames))
	for _, f := range frames {
		item := buildFrameSummary(f)
		summary = append(summary, item)
	}

	return jsonResult(map[string]interface{}{
		"frames": summary, "hasMore": hasMore,
		"page": page, "pageSize": size, "count": len(summary),
	})
}

func getFrameDetailHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	indicesStr, err := getRequiredStringArg(request, "frame_indices")
	if err != nil {
		return errorResult(err)
	}
	indices, err := parseIntList(indicesStr)
	if err != nil {
		return errorResult(fmt.Errorf("invalid frame_indices: %v", err))
	}
	if len(indices) == 0 {
		return errorResult(fmt.Errorf("frame_indices cannot be empty"))
	}
	if len(indices) > maxFrameDetail {
		return errorResult(fmt.Errorf("too many indices (max %d, got %d)", maxFrameDetail, len(indices)))
	}

	frames, err := pkg.GetFramesByIdxs(fp, indices, pkg.IgnoreError(true))
	if err != nil {
		return errorResult(err)
	}
	return jsonResult(map[string]interface{}{"frames": frames, "count": len(frames)})
}

func getFrameHexHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	frameIdx := int(getFloatArg(request, "frame_index", 0))
	if frameIdx < 1 {
		return errorResult(fmt.Errorf("frame_index must be >= 1"))
	}
	hexData, err := pkg.GetHexDataByIdx(fp, frameIdx)
	if err != nil {
		return errorResult(err)
	}
	return jsonResult(map[string]interface{}{"frameIndex": frameIdx, "hexDump": hexData})
}

// === Stream Handlers ===

func followStreamHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	protocol, err := getRequiredStringArg(request, "protocol")
	if err != nil {
		return errorResult(err)
	}
	if protocol != "tcp" && protocol != "udp" {
		return errorResult(fmt.Errorf("protocol must be 'tcp' or 'udp'"))
	}
	filter, _ := getStringArg(request, "filter")
	streamResult, err := pkg.GetStreamData(fp, filter, protocol)
	if err != nil {
		return errorResult(err)
	}
	return jsonResult(streamResult)
}

// === Statistics Handlers ===

func protocolStatsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	var opts []pkg.Option
	opts = append(opts, pkg.IgnoreError(true))
	if filter, _ := getStringArg(request, "filter"); filter != "" {
		opts = append(opts, pkg.WithBpfFilter(filter))
	}

	frames, err := pkg.GetAllFrames(fp, opts...)
	if err != nil {
		return errorResult(err)
	}

	type protoStat struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
		Bytes    int    `json:"bytes"`
	}
	protoMap := make(map[string]*protoStat)
	totalBytes := 0

	for _, f := range frames {
		proto := "unknown"
		length := 0
		if f.BaseLayers.WsCol != nil && f.BaseLayers.WsCol.Protocol != "" {
			proto = f.BaseLayers.WsCol.Protocol
		}
		if f.BaseLayers.Frame != nil {
			length = f.BaseLayers.Frame.Len
		}
		totalBytes += length
		if stat, ok := protoMap[proto]; ok {
			stat.Count++
			stat.Bytes += length
		} else {
			protoMap[proto] = &protoStat{Protocol: proto, Count: 1, Bytes: length}
		}
	}

	stats := make([]protoStat, 0, len(protoMap))
	for _, stat := range protoMap {
		stats = append(stats, *stat)
	}

	return jsonResult(map[string]interface{}{
		"totalFrames": len(frames), "totalBytes": totalBytes,
		"protocolCount": len(stats), "protocols": stats,
	})
}

// === File Extraction Handlers ===

func extractFilesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	if getBoolArg(request, "clean_before", false) {
		if err := cleanExtractDir(); err != nil {
			return errorResult(fmt.Errorf("clean failed: %v", err))
		}
	}

	var opts []pkg.Option
	opts = append(opts, pkg.IgnoreError(true))
	if filter, _ := getStringArg(request, "filter"); filter != "" {
		opts = append(opts, pkg.WithBpfFilter(filter))
	}
	frames, err := pkg.GetAllFrames(fp, opts...)
	if err != nil {
		return errorResult(err)
	}
	extracted, err := pkg.ExtractFiles(frames)
	if err != nil {
		return errorResult(err)
	}

	files := make([]map[string]interface{}, 0, len(extracted))
	for _, ef := range extracted {
		files = append(files, map[string]interface{}{
			"filename": ef.Filename, "protocol": ef.Protocol,
			"size": ef.Size, "srcAddress": ef.SrcAddr,
			"dstAddress": ef.DstAddr, "outputPath": ef.Path,
		})
	}
	return jsonResult(map[string]interface{}{
		"files": files, "count": len(files), "outputDir": pkg.ExtractFileDir,
	})
}

func cleanExtractedFilesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	removed, totalSize, err := cleanExtractDirWithStats()
	if err != nil {
		return errorResult(err)
	}
	return jsonResult(map[string]interface{}{
		"outputDir": pkg.ExtractFileDir, "filesRemoved": removed,
		"bytesFreed": totalSize, "status": "cleaned",
	})
}

// === Export Handler ===

func exportFramesHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	fp, err := validateFilepath(request)
	if err != nil {
		return errorResult(err)
	}
	format, _ := getStringArg(request, "format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return errorResult(fmt.Errorf("format must be 'json' or 'csv'"))
	}
	outputPath, _ := getStringArg(request, "output_path")
	if outputPath == "" {
		base := filepath.Base(fp)
		base = base[:len(base)-len(filepath.Ext(base))]
		dir := pkg.ExtractFileDir
		if dir == "" {
			dir = filepath.Dir(fp)
		}
		outputPath = filepath.Join(dir, base+"."+format)
	}
	filter, _ := getStringArg(request, "filter")
	var opts []pkg.Option
	opts = append(opts, pkg.IgnoreError(true))
	if filter != "" {
		opts = append(opts, pkg.WithBpfFilter(filter))
	}
	frames, err := pkg.GetAllFrames(fp, opts...)
	if err != nil {
		return errorResult(err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return errorResult(fmt.Errorf("create output dir: %v", err))
	}
	deref := make([]pkg.FrameData, 0, len(frames))
	for _, f := range frames {
		if f != nil {
			deref = append(deref, *f)
		}
	}
	var writeErr error
	switch format {
	case "json":
		writeErr = writeFramesJSON(outputPath, deref)
	case "csv":
		writeErr = writeFramesCSV(outputPath, deref)
	}
	if writeErr != nil {
		return errorResult(fmt.Errorf("export failed: %v", writeErr))
	}
	info, _ := os.Stat(outputPath)
	var fileSize int64
	if info != nil {
		fileSize = info.Size()
	}
	return jsonResult(map[string]interface{}{
		"sourcePcap": fp, "outputPath": outputPath, "format": format,
		"framesCount": len(deref), "fileSize": fileSize,
	})
}

// === Shared Helpers ===

// jsonResult marshals any value to JSON and returns as text result.
func jsonResult(v interface{}) (*mcp.CallToolResult, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return errorResult(fmt.Errorf("serialize error: %v", err))
	}
	return textResult(string(jsonBytes))
}

// buildFrameSummary creates a compact summary map from a FrameData.
func buildFrameSummary(f *pkg.FrameData) map[string]interface{} {
	item := map[string]interface{}{
		"no": 0, "time": "", "src": "", "dst": "",
		"protocol": "", "length": 0, "info": "",
	}
	if f.BaseLayers.Frame != nil {
		item["no"] = f.BaseLayers.Frame.Number
		item["length"] = f.BaseLayers.Frame.Len
		item["time"] = f.BaseLayers.Frame.TimeRelative
	}
	if f.BaseLayers.WsCol != nil {
		item["protocol"] = f.BaseLayers.WsCol.Protocol
		item["info"] = f.BaseLayers.WsCol.Info
		if f.BaseLayers.Ip == nil {
			item["src"] = f.BaseLayers.WsCol.DefSrc
			item["dst"] = f.BaseLayers.WsCol.DefDst
		}
	}
	if f.BaseLayers.Ip != nil {
		item["src"] = f.BaseLayers.Ip.Src
		item["dst"] = f.BaseLayers.Ip.Dst
	}
	return item
}

// cleanExtractDir removes all files in the extract directory.
func cleanExtractDir() error {
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

// cleanExtractDirWithStats removes all files and returns stats.
func cleanExtractDirWithStats() (int, int64, error) {
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
			if entry.IsDir() {
				totalSize += dirSize(path)
			} else {
				totalSize += info.Size()
			}
		}
		os.RemoveAll(path)
		removed++
	}
	return removed, totalSize, nil
}

// dirSize calculates total size of a directory recursively.
func dirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// --- File Writers ---

func writeFramesJSON(path string, frames []pkg.FrameData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(frames)
}

func writeFramesCSV(path string, frames []pkg.FrameData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("No.,Time,Source,Destination,Protocol,Length,Info\n")
	for _, frame := range frames {
		item := buildFrameSummary(&frame)
		f.WriteString(fmt.Sprintf("%v,%s,%s,%s,%s,%v,%s\n",
			item["no"], csvEscape(fmt.Sprint(item["time"])),
			csvEscape(fmt.Sprint(item["src"])), csvEscape(fmt.Sprint(item["dst"])),
			csvEscape(fmt.Sprint(item["protocol"])), item["length"],
			csvEscape(fmt.Sprint(item["info"]))))
	}
	return nil
}

func csvEscape(s string) string {
	if s == "" {
		return ""
	}
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			return "\"" + escapeQuotes(s) + "\""
		}
	}
	return s
}

func escapeQuotes(s string) string {
	var b []byte
	for _, c := range []byte(s) {
		if c == '"' {
			b = append(b, '"')
		}
		b = append(b, c)
	}
	return string(b)
}
