# Gowireshark MCP Server

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that brings Wireshark-level packet analysis capabilities to AI assistants. Powered by libwireshark for deep protocol dissection.

基于 [MCP 协议](https://modelcontextprotocol.io/) 的网络流量分析工具，让 AI 助手具备 Wireshark 级别的抓包和协议解析能力。

---

## Features

- 🔍 **Deep Protocol Dissection** — Full Wireshark EPAN engine, 3000+ protocols
- 📊 **Traffic Statistics** — Protocol distribution, conversation analysis
- 📦 **File Extraction** — Extract files from HTTP, FTP, SMB, TFTP, email
- 🌊 **Stream Reassembly** — Follow TCP/UDP streams with bidirectional data
- 🎯 **Display Filters** — Full Wireshark display filter syntax support
- 📡 **Live Capture** — Real-time packet capture with BPF filters
- 💾 **Export** — Save captures as pcap, export analysis as JSON/CSV

---

## Quick Start

### Option 1: Pre-built Binary (Recommended)

Download from [GitHub Releases](https://github.com/randolphcyg/gowireshark/releases):

```bash
# macOS (Apple Silicon)
curl -L https://github.com/randolphcyg/gowireshark/releases/latest/download/gowireshark-mcp-darwin-arm64.tar.gz | tar xz

# macOS (Intel)
curl -L https://github.com/randolphcyg/gowireshark/releases/latest/download/gowireshark-mcp-darwin-amd64.tar.gz | tar xz

# Linux (amd64)
curl -L https://github.com/randolphcyg/gowireshark/releases/latest/download/gowireshark-mcp-linux-amd64.tar.gz | tar xz
```

### Option 2: Docker

```bash
docker pull randolphcyg/gowireshark-mcp:latest
```

### Option 3: Build from Source

```bash
git clone https://github.com/randolphcyg/gowireshark.git
cd gowireshark
./build.sh -m
```

Requires: Go 1.22+, libwireshark-dev, libpcap-dev, libglib2.0-dev

---

## MCP Client Configuration

### Claude Desktop / Kiro / Cursor / Windsurf

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "gowireshark": {
      "command": "/path/to/gowireshark-mcp",
      "args": [],
      "env": {
        "GOWIRESHARK_BASE_DIR": "/path/to/working/directory"
      }
    }
  }
}
```

### Docker Mode (no local dependencies)

```json
{
  "mcpServers": {
    "gowireshark": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--cap-add=NET_RAW",
        "-v", "/path/to/pcaps:/data/pcaps",
        "-v", "/path/to/output:/data/output",
        "-e", "PCAP_BASE_DIR=/data/pcaps",
        "-e", "EXTRACT_FILE_DIR=/data/output",
        "randolphcyg/gowireshark-mcp:latest"
      ]
    }
  }
}
```

### Configuration File Locations

| Client | Config Path |
|--------|-------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Kiro | `.kiro/settings/mcp.json` or `~/.kiro/settings/mcp.json` |
| Cursor | Settings → MCP → Add Server |
| Windsurf | `~/.windsurf/mcp.json` |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GOWIRESHARK_BASE_DIR` | Base directory for resolving relative paths | Executable's directory |
| `PCAP_BASE_DIR` | Restrict pcap file access to this directory (security) | Empty (no restriction) |
| `EXTRACT_FILE_DIR` | Output directory for extracted files and captures | `<base_dir>/extracted_files` |

---

## Available Tools (19)

### System

| Tool | Description |
|------|-------------|
| `get_version` | Get Wireshark EPAN library version |
| `list_interfaces` | List available network interfaces |
| `validate_filter` | Validate display filter syntax |

### Offline Analysis

| Tool | Description |
|------|-------------|
| `count_frames` | Fast frame count (no full dissection) |
| `dissect_frames` | Paginated frame dissection with filtering |
| `get_frame_detail` | Full protocol detail for specific frames |
| `get_frame_hex` | Hex dump of a specific frame |
| `follow_stream` | TCP/UDP stream reassembly |
| `protocol_stats` | Protocol distribution statistics |

### File Extraction

| Tool | Description |
|------|-------------|
| `extract_files` | Extract files from HTTP/FTP/SMB/TFTP/email |
| `clean_extracted_files` | Clean the extraction output directory |

### Live Capture

| Tool | Description |
|------|-------------|
| `start_capture` | Start live capture (buffered in memory) |
| `stop_capture` | Stop an active capture |
| `get_capture_status` | Check capture session status |
| `get_captured_packets` | Retrieve captured packets (paginated) |
| `clear_capture` | Free capture memory |
| `save_capture` | Save captured data as JSON/CSV |
| `capture_to_pcap` | Capture directly to pcap file (libpcap native) |

### Export

| Tool | Description |
|------|-------------|
| `export_frames` | Export pcap frames to JSON or CSV |

---

## Permissions (Live Capture)

Live capture requires access to network devices:

### macOS

```bash
# One-time setup (requires admin password)
sudo ./install_bpf_permissions.sh
```

### Linux

```bash
# Option 1: setcap (recommended)
sudo setcap cap_net_raw,cap_net_admin+ep /path/to/gowireshark-mcp

# Option 2: run as root (not recommended)
sudo /path/to/gowireshark-mcp
```

### Docker

Add `--cap-add=NET_RAW` to the docker run command (already included in the config example above).

> **Note**: Live capture permissions are only needed for `start_capture` and `capture_to_pcap`. All offline analysis tools (dissect, extract, stats, etc.) work without any special permissions.

---

## Example Conversations

**User**: Analyze the traffic in /data/sample.pcap

**AI**:
1. `count_frames` → 12,345 frames
2. `protocol_stats` → TCP 72%, UDP 17%, DNS 5%, HTTP 4%
3. `dissect_frames` → Shows first 20 frames with summary
4. `get_frame_detail` → Deep dive into interesting frames

**User**: Extract all files from this pcap

**AI**:
1. `extract_files` with `clean_before: true`
2. Returns: 3 files extracted (logo.png via HTTP, config.bin via FTP, report.pdf via SMB2)

**User**: Capture HTTP traffic on en0 for 30 seconds

**AI**:
1. `capture_to_pcap` with interface="en0", filter="tcp port 80", duration=30
2. Returns: saved to captures/capture_en0_20240101_120000.pcap (125KB)
3. `protocol_stats` on the new pcap → Shows captured traffic breakdown

---

## Architecture

```
gowireshark/
├── cmd/
│   ├── main.go                # HTTP REST API server
│   └── mcp-server/main.go    # MCP stdio server (this tool)
├── mcp/
│   ├── server.go              # MCP server setup + helpers
│   ├── tools.go               # Tool definitions + handlers
│   └── capture.go             # Live capture + export handlers
├── pkg/                       # Core library (C bindings to libwireshark)
│   ├── online.c/h             # Live capture via libpcap
│   ├── offline.c/h            # Offline pcap dissection
│   ├── layers.go              # Protocol layer parsing
│   └── extract.go             # File extraction
├── version/                   # Version info (injected at build time)
├── build.sh                   # Build script
├── Dockerfile                 # Multi-stage Docker build
└── install_bpf_permissions.sh # macOS BPF permission setup
```

Built with:
- [libwireshark](https://www.wireshark.org/) — Protocol dissection engine
- [libpcap](https://www.tcpdump.org/) — Packet capture library
- [mcp-go](https://github.com/mark3labs/mcp-go) — MCP protocol SDK

---

## Security Considerations

- **Path restriction**: Set `PCAP_BASE_DIR` to limit file access to a specific directory
- **No network egress**: The MCP server never makes outbound network connections
- **Read-only by default**: Only `extract_files`, `save_capture`, `capture_to_pcap`, and `export_frames` write to disk
- **Capture isolation**: Live capture requires explicit permission setup; offline analysis is fully sandboxed

---

## License

MIT
