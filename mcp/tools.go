package mcp

import (
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Maximum response size constants to avoid overwhelming AI context windows.
const (
	maxPageSize       = 100 // max frames per page for dissect_frames
	maxFrameDetail    = 20  // max frames for get_frame_detail
	maxCapturedPage   = 200 // max packets per page for get_captured_packets
	defaultPageSize   = 20
	defaultCapturePkt = 100
	defaultDuration   = 10
)

// registerAllTools registers all gowireshark analysis tools with the MCP server.
func registerAllTools(s *server.MCPServer) {
	// === System / Info Tools (read-only, no file access) ===

	s.AddTool(mcp.NewTool("get_version",
		mcp.WithDescription("Get Wireshark EPAN library version and plugin support status."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Get Version",
			ReadOnlyHint: boolPtr(true),
		}),
	), getVersionHandler)

	s.AddTool(mcp.NewTool("list_interfaces",
		mcp.WithDescription("List all available network interfaces with their addresses and flags."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "List Interfaces",
			ReadOnlyHint: boolPtr(true),
		}),
	), listInterfacesHandler)

	s.AddTool(mcp.NewTool("validate_filter",
		mcp.WithDescription("Check if a Wireshark display filter expression is syntactically valid."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Validate Filter",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filter", mcp.Required(),
			mcp.Description("Display filter to validate (e.g. 'tcp.port == 80', 'http.request')"),
		),
	), validateFilterHandler)

	// === Offline Analysis Tools (read-only, file access) ===

	s.AddTool(mcp.NewTool("count_frames",
		mcp.WithDescription("Count total frames in a pcap file. Fast operation without full dissection."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Count Frames",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithString("filter", mcp.Description("Display filter to count only matching frames")),
	), countFramesHandler)

	s.AddTool(mcp.NewTool("dissect_frames",
		mcp.WithDescription("Dissect pcap frames with pagination. Returns summary: frame number, time, protocol, src/dst, length, info. Start with page=1 and use hasMore to paginate."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Dissect Frames",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithNumber("page", mcp.Description("Page number (default: 1)")),
		mcp.WithNumber("size", mcp.Description(fmt.Sprintf("Frames per page (default: %d, max: %d)", defaultPageSize, maxPageSize))),
		mcp.WithString("filter", mcp.Description("Wireshark display filter (e.g. 'http', 'tcp.port == 443', 'dns')")),
	), dissectFramesHandler)

	s.AddTool(mcp.NewTool("get_frame_detail",
		mcp.WithDescription("Get full protocol dissection of specific frames. Returns all layer fields. Use sparingly — output can be large."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Get Frame Detail",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithString("frame_indices", mcp.Required(),
			mcp.Description(fmt.Sprintf("Comma-separated 1-based indices (max %d), e.g. '1,5,10'", maxFrameDetail))),
	), getFrameDetailHandler)

	s.AddTool(mcp.NewTool("get_frame_hex",
		mcp.WithDescription("Get hex dump (offset, hex bytes, ASCII) of a single frame."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Get Frame Hex",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithNumber("frame_index", mcp.Required(), mcp.Description("Frame index (1-based)")),
	), getFrameHexHandler)

	s.AddTool(mcp.NewTool("follow_stream",
		mcp.WithDescription("Reassemble a TCP or UDP stream. Returns bidirectional payload with client/server identification."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Follow Stream",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithString("protocol", mcp.Required(), mcp.Description("'tcp' or 'udp'"), mcp.Enum("tcp", "udp")),
		mcp.WithString("filter", mcp.Description("Filter to select stream (e.g. 'tcp.stream eq 0')")),
	), followStreamHandler)

	s.AddTool(mcp.NewTool("protocol_stats",
		mcp.WithDescription("Get protocol distribution: per-protocol frame count and byte totals."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Protocol Statistics",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithString("filter", mcp.Description("Display filter to scope statistics")),
	), protocolStatsHandler)

	// === File Extraction Tools (writes to disk) ===

	s.AddTool(mcp.NewTool("extract_files",
		mcp.WithDescription("Extract transferred files from pcap traffic. Supports HTTP, FTP-DATA, TFTP, SMB/SMB2, and email (IMF). Writes files to the configured output directory."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:           "Extract Files",
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(false),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Path to pcap/pcapng file")),
		mcp.WithString("filter", mcp.Description("Display filter to limit extraction scope")),
		mcp.WithBoolean("clean_before", mcp.Description("Clean output directory before extraction (default: false)")),
	), extractFilesHandler)

	s.AddTool(mcp.NewTool("clean_extracted_files",
		mcp.WithDescription("Remove all files from the extraction output directory (including captures/). Frees disk space."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:           "Clean Extracted Files",
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(true),
		}),
	), cleanExtractedFilesHandler)

	// === Live Capture Tools ===

	s.AddTool(mcp.NewTool("start_capture",
		mcp.WithDescription("Start live packet capture on a network interface. Buffers packets in memory for later retrieval. Requires capture permissions (see --help)."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Start Capture",
			ReadOnlyHint: boolPtr(false),
		}),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Interface name (use list_interfaces to discover)")),
		mcp.WithString("filter", mcp.Description("BPF filter (e.g. 'tcp port 80', 'host 10.0.0.1')")),
		mcp.WithNumber("packet_count", mcp.Description(fmt.Sprintf("Max packets (default: %d, max: 10000)", defaultCapturePkt))),
		mcp.WithNumber("duration", mcp.Description(fmt.Sprintf("Max seconds (default: %d, max: 300)", defaultDuration))),
		mcp.WithBoolean("promisc", mcp.Description("Promiscuous mode (default: true)")),
	), startCaptureHandler)

	s.AddTool(mcp.NewTool("stop_capture",
		mcp.WithDescription("Stop an active live capture session."),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Interface to stop")),
	), stopCaptureHandler)

	s.AddTool(mcp.NewTool("get_capture_status",
		mcp.WithDescription("Check status of capture sessions: running state, packet count, elapsed time."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Capture Status",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("interface", mcp.Description("Specific interface (omit for all sessions)")),
	), getCaptureStatusHandler)

	s.AddTool(mcp.NewTool("get_captured_packets",
		mcp.WithDescription("Retrieve buffered packets from a capture session (paginated summaries)."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Get Captured Packets",
			ReadOnlyHint: boolPtr(true),
		}),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Interface to read from")),
		mcp.WithNumber("page", mcp.Description("Page number (default: 1)")),
		mcp.WithNumber("size", mcp.Description(fmt.Sprintf("Page size (default: 50, max: %d)", maxCapturedPage))),
	), getCapturedPacketsHandler)

	s.AddTool(mcp.NewTool("clear_capture",
		mcp.WithDescription("Free memory used by stopped capture sessions."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:           "Clear Capture",
			ReadOnlyHint:    boolPtr(false),
			DestructiveHint: boolPtr(true),
		}),
		mcp.WithString("interface", mcp.Description("Interface to clear (omit for all stopped)")),
	), clearCaptureHandler)

	s.AddTool(mcp.NewTool("save_capture",
		mcp.WithDescription("Export buffered capture data as JSON or CSV file. For pcap format use capture_to_pcap."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Save Capture",
			ReadOnlyHint: boolPtr(false),
		}),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Interface whose data to save")),
		mcp.WithString("output_path", mcp.Description("Output path (.json/.csv). Default: auto-generated.")),
	), saveCaptureHandler)

	s.AddTool(mcp.NewTool("capture_to_pcap",
		mcp.WithDescription("Capture live traffic directly to a valid pcap file using libpcap. Produces files that open correctly in Wireshark. Recommended for saving captures."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Capture to PCAP",
			ReadOnlyHint: boolPtr(false),
		}),
		mcp.WithString("interface", mcp.Required(), mcp.Description("Interface name")),
		mcp.WithString("filter", mcp.Description("BPF filter")),
		mcp.WithNumber("packet_count", mcp.Description("Max packets (default: 100, max: 100000)")),
		mcp.WithNumber("duration", mcp.Description("Max seconds (default: 10, max: 300)")),
		mcp.WithBoolean("promisc", mcp.Description("Promiscuous mode (default: true)")),
		mcp.WithString("output_path", mcp.Description("Output .pcap path. Default: auto-generated.")),
	), captureToPcapHandler)

	// === Export Tools ===

	s.AddTool(mcp.NewTool("export_frames",
		mcp.WithDescription("Export pcap frames to JSON or CSV file for external analysis."),
		mcp.WithToolAnnotation(mcp.ToolAnnotation{
			Title:        "Export Frames",
			ReadOnlyHint: boolPtr(false),
		}),
		mcp.WithString("filepath", mcp.Required(), mcp.Description("Source pcap/pcapng file")),
		mcp.WithString("format", mcp.Required(), mcp.Description("'json' or 'csv'"), mcp.Enum("json", "csv")),
		mcp.WithString("output_path", mcp.Description("Output path. Default: auto-generated.")),
		mcp.WithString("filter", mcp.Description("Display filter to limit exported frames")),
	), exportFramesHandler)
}

// boolPtr is a helper for annotation fields.
func boolPtr(b bool) *bool { return &b }
