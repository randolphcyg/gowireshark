# Gowireshark

README: [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md) | [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md)

- Provide the same packet processing capabilities as Wireshark for Go
- Support offline and online (live capture) packet parsing
- Multi-protocol file extraction (HTTP, FTP, TFTP, SMB, IMF)
- TCP stream reassembly with real-time callbacks
- Custom protocol parser extension via registry
- Based on [Wireshark](https://www.wireshark.org/#download) and [libpcap](https://www.tcpdump.org/release/) shared libraries

---

## Contents

- [1. Installation](#1-installation)
  - [1.1. Quick Start (Docker)](#11-quick-start-docker)
  - [1.2. Local Development (macOS)](#12-local-development-macos)
  - [1.3. Local Development (Windows)](#13-local-development-windows)
  - [1.4. Local Development (Linux)](#14-local-development-linux)
- [2. Usage](#2-usage)
  - [2.1. Frame Dissection](#21-frame-dissection)
  - [2.2. Live Capture](#22-live-capture)
  - [2.3. TCP Stream Reassembly](#23-tcp-stream-reassembly)
  - [2.4. File Extraction](#24-file-extraction)
  - [2.5. Custom Protocol Parsing](#25-custom-protocol-parsing)
- [3. Testing](#3-testing)
- [4. Project Structure](#4-project-structure)
- [5. Architecture](#5-architecture)
- [6. Deployment](#6-deployment)
- [7. API Reference](#7-api-reference)
- [8. Roadmap](#8-roadmap)

---

## 1. Installation

### 1.1. Quick Start (Docker)

The recommended way to run gowireshark as a service. No local dependencies required.

```shell
# Build the image
docker build -t gowireshark:latest . --platform linux/amd64

# Run the service (mount your pcap directory)
docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  gowireshark:latest
```

**API Examples:**

```shell
# Get Wireshark version
curl http://localhost:18090/api/v1/version

# Paginated frame query (recommended for large files)
curl -X POST http://localhost:18090/api/v1/dissect/frames/page \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap", "page": 1, "size": 20}'

# Extract files from pcap (HTTP, FTP, SMB, etc.)
curl -X POST http://localhost:18090/api/v1/extract/files \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap"}'

# Validate a display filter
curl -X POST http://localhost:18090/api/v1/filter/validate \
  -H "Content-Type: application/json" \
  -d '{"filter": "tcp.port == 80"}'
```

### 1.2. Local Development (macOS)

```shell
# One-time setup: installs deps, builds Wireshark/libpcap, generates CGO config
./init_mac_dev.sh

# Load runtime environment
source ./dev_env.sh

# Run tests
go test -v ./pkg/
```

Prerequisites: [Homebrew](https://brew.sh). The script handles everything else.

### 1.3. Local Development (Windows)

```powershell
# One-time setup (run in PowerShell as Administrator)
.\init_win_dev.ps1

# Load runtime environment
. .\dev_env.ps1

# Run tests
go test -v ./pkg/
```

Prerequisites: [MSYS2](https://www.msys2.org/) installed at `C:\msys64`, and [Npcap](https://npcap.com/#download) runtime driver.

### 1.4. Local Development (Linux)

```shell
# Install dependencies (Ubuntu/Debian)
sudo apt install -y libglib2.0-dev libpcap-dev

# Use as a Go library
go get github.com/randolphcyg/gowireshark
```

On Linux, `#cgo pkg-config: glib-2.0` is used automatically. For full local builds (compiling Wireshark from source), refer to the Dockerfile.

---

## 2. Usage

### 2.1. Frame Dissection

```go
package main

import (
    "fmt"
    "github.com/randolphcyg/gowireshark/pkg"
)

func main() {
    filepath := "/path/to/capture.pcap"

    // Paginated access (recommended for large files)
    frames, hasMore, err := pkg.GetFramesByPage(filepath, 1, 20)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Has more: %v\n", hasMore)
    for _, frame := range frames {
        fmt.Printf("Frame %d: %s → %s [%s]\n",
            frame.BaseLayers.Frame.Number,
            frame.BaseLayers.Ip.Src,
            frame.BaseLayers.Ip.Dst,
            frame.BaseLayers.WsCol.Protocol)
    }
}
```

### 2.2. Live Capture

```go
func capturePackets() {
    ifaceName := "en0"

    go pkg.StartLivePacketCapture(ifaceName, "tcp port 80", -1, 1, 100)

    time.Sleep(100 * time.Millisecond)
    ch := pkg.GetIfaceChannel(ifaceName)

    for frame := range ch {
        fmt.Printf("[%s] %s → %s\n",
            frame.BaseLayers.WsCol.Protocol,
            frame.BaseLayers.Ip.Src,
            frame.BaseLayers.Ip.Dst)
    }
}
```

### 2.3. TCP Stream Reassembly

```go
func reassembleTcpStreams() {
    reassembler := pkg.NewTCPReassembler(
        pkg.WithOnData(func(p pkg.Packet) {
            fmt.Printf("Stream %d: %d bytes from %s\n",
                p.StreamID, len(p.RawData), p.Src)
        }),
    )
    handle := reassembler.RegisterCallback()
    defer reassembler.UnregisterCallback(handle)

    // Parse with TCP stream tap enabled
    pkg.GetAllFrames("/path/to/file.pcap", pkg.PrintTcpStreams(true))

    // Access reassembled streams
    for streamID, packets := range reassembler.GetAllStreams() {
        payload := pkg.ReassembleStreamPayload(packets)
        duration := pkg.StreamDuration(packets)
        fmt.Printf("Stream %d: %d bytes, %v duration\n",
            streamID, len(payload), duration)
    }
}
```

### 2.4. File Extraction

```go
func extractFiles() {
    pkg.ExtractFileDir = "/tmp/extracted"

    frames, _ := pkg.GetAllFrames("/path/to/file.pcap", pkg.IgnoreError(true))

    // Multi-protocol extraction (HTTP, FTP, TFTP, SMB, IMF)
    extracted, err := pkg.ExtractFiles(frames)
    if err != nil {
        panic(err)
    }

    for _, ef := range extracted {
        fmt.Printf("[%s] %s (%d bytes) %s→%s\n",
            ef.Protocol, ef.Filename, ef.Size, ef.SrcAddr, ef.DstAddr)
    }
}
```

### 2.5. Custom Protocol Parsing

```go
// Define a parser for your protocol
type MySQLLayer struct {
    PacketLength string `json:"mysql.packet_length"`
    User         string `json:"mysql.user"`
}

func (p *MySQLLayer) Parse(layers pkg.Layers) (any, error) {
    src, ok := layers["mysql"]
    if !ok {
        return nil, pkg.ErrLayerNotFound
    }
    // Parse from raw map...
    return p, nil
}

func init() {
    // Register once at startup — automatically applied to all frame parsing
    pkg.DefaultRegistry.Register("mysql", &MySQLLayer{})
}

// After registration, frame.CustomLayers["mysql"] will contain parsed results
```

See `pkg/*_test.go` for more examples including TLS decryption and display filter validation.

---

## 3. Testing

Tests auto-discover pcap files. Place any `.pcap` or `.pcapng` file in the `./pcaps/` directory:

```shell
# Place a test file
cp ~/Downloads/sample.pcap ./pcaps/

# Run all tests (skip network-dependent tests if no traffic)
source ./dev_env.sh
go test ./pkg/ -timeout=60s -count=1

# Run specific test groups
go test ./pkg/ -run TestGetAllFrames -v
go test ./pkg/ -run TestExtractFiles -v
go test ./pkg/ -run TestFollowTcpStream -v
go test ./pkg/ -run TestLiveCapture -v

# Benchmarks
go test ./pkg/ -bench=BenchmarkParseFrameData -benchmem
go test ./pkg/ -bench=BenchmarkGetAllFrames -benchmem
```

Alternatively, specify a file via environment variable:

```shell
export GOWIRESHARK_TEST_PCAP=/path/to/any.pcap
go test ./pkg/ -v
```

Tests that require specific protocols (MySQL, HTTPS, etc.) or network traffic will skip gracefully.

---

## 4. Project Structure

```
gowireshark/
├── cmd/main.go              # HTTP service entry point (Gin)
├── pkg/                     # Core library
│   ├── lib.c/h              # C bridge: initialization, utilities
│   ├── offline.c/go         # Offline pcap parsing (dissection, pagination, streaming)
│   ├── online.c/go          # Live packet capture
│   ├── reassembly.c/go      # TCP stream reassembly with tap callbacks
│   ├── layers.go            # Protocol layer parsers (zero-copy from map)
│   ├── registry.go          # Custom protocol parser registration (thread-safe)
│   ├── extract.go           # Multi-protocol file extraction
│   ├── config.go            # Options pattern (TLS, BPF filter, debug)
│   ├── mime_types.txt       # 200+ MIME type mappings for file extraction
│   ├── cgo_linux.go         # CGO flags for Linux
│   └── *_test.go            # Comprehensive test suite
├── init_mac_dev.sh          # macOS dev environment setup
├── init_win_dev.ps1         # Windows dev environment setup
├── Dockerfile               # Multi-stage production build
├── docker-compose.yml       # Multi-replica deployment with Nginx
└── pcaps/                   # Test pcap files (gitignored)
```

---

## 5. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  cmd/main.go (HTTP API - Gin)                               │
├─────────────────────────────────────────────────────────────┤
│  pkg/offline.go    │  pkg/online.go    │  pkg/reassembly.go │
│  (Offline Analysis)│  (Live Capture)   │  (TCP Reassembly)  │
├─────────────────────────────────────────────────────────────┤
│  pkg/layers.go (Protocol Parsing)  │  pkg/extract.go       │
│  pkg/registry.go (Extensions)      │  (File Extraction)    │
├─────────────────────────────────────────────────────────────┤
│  CGO Bridge (callbacks, channels)                           │
├─────────────────────────────────────────────────────────────┤
│  offline.c         │  online.c         │  reassembly.c      │
│  (libwireshark)    │  (libpcap+epan)   │  (tcp_follow tap)  │
├─────────────────────────────────────────────────────────────┤
│  lib.c (Shared: init_env, hex_data, tls_prefs)              │
└─────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- `EpanMutex` serializes all libwireshark operations (epan is single-threaded by design)
- C callbacks push JSON to Go channels; Go workers parse in parallel
- `ParseFrameData` reads directly from `map[string]any` — no intermediate Marshal/Unmarshal
- `DefaultRegistry` automatically applies custom parsers during frame dissection
- File extraction is protocol-agnostic: each protocol extractor checks its layer key

---

## 6. Deployment

### Single Instance

```shell
docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -e AUTH_TOKEN=your-secret \
  -e PCAP_BASE_DIR=/app/pcaps \
  -e EXTRACT_DIR=/app/extracted \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  -v $(pwd)/extracted/:/app/extracted/ \
  gowireshark:latest
```

### Multi-Instance (Docker Compose + Nginx)

```shell
AUTH_TOKEN=your-secret docker compose up -d --scale gowireshark=3
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TOKEN` | _(empty, auth disabled)_ | Bearer token for API authentication |
| `PCAP_BASE_DIR` | `/app/pcaps` | Restrict filepath access to this directory |
| `EXTRACT_DIR` | `/app/extracted` | Output directory for extracted files |
| `PORT` | `8090` | HTTP listen port |
| `REQUEST_TIMEOUT` | `120s` | Maximum request processing time |

---

## 7. API Reference

All endpoints require `Authorization: Bearer <token>` header when `AUTH_TOKEN` is set.

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/api/v1/version` | Wireshark version info |
| GET | `/api/v1/interfaces` | Available network interfaces |
| POST | `/api/v1/filter/validate` | Validate display filter syntax |

### Frame Dissection (Offline)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/dissect/frames` | All frames (auto NDJSON for >1000) |
| POST | `/api/v1/dissect/frames/stream` | All frames, NDJSON streaming (zero-copy) |
| POST | `/api/v1/dissect/frames/page` | Paginated frames (max 500/page) |
| POST | `/api/v1/dissect/frames/idxs` | Random access by frame numbers (max 1000) |
| POST | `/api/v1/dissect/frames/count` | Frame count (fast, no dissection) |
| POST | `/api/v1/dissect/frames/hex` | Hex dump of a single frame |

### Stream Follow

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/dissect/follow` | TCP/UDP stream reassembly |

### File Extraction

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/extract/files` | Extract files from all supported protocols |

### Upload

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/upload` | Upload a pcap file (multipart/form-data, field: `file`) |

### Statistics

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/dissect/stats` | Protocol distribution statistics |

### Live Capture

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/capture/start` | Start live capture on interface |
| POST | `/api/v1/capture/stop` | Stop live capture |
| GET | `/api/v1/capture/stream/:interface` | Stream packets (NDJSON, long-lived) |

### Request Body (Common Fields)

```json
{
  "filepath": "/app/pcaps/sample.pcap",
  "filter": "tcp.port == 80",
  "page": 1,
  "size": 20,
  "isDebug": false,
  "ignoreErr": true
}
```

### Response Format

```json
{
  "code": 0,
  "msg": "ok",
  "data": { ... }
}
```

Error responses use appropriate HTTP status codes (400, 403, 404, 500) with:

```json
{
  "code": 500,
  "msg": "parse failed",
  "error": "detailed error message"
}
```

### Streaming (NDJSON)

Add `Accept: application/x-ndjson` header to `/dissect/frames` or `/dissect/frames/page` for zero-copy streaming. Each line is a complete JSON frame object.

### File Extraction Response

```json
{
  "code": 0,
  "msg": "ok",
  "data": {
    "list": [
      {
        "path": "/app/extracted/report.pdf",
        "filename": "report.pdf",
        "protocol": "http",
        "size": 84790,
        "srcAddr": "192.168.1.100",
        "dstAddr": "10.0.0.1"
      }
    ],
    "total": 1
  }
}
```

Supported extraction protocols: `http`, `ftp-data`, `tftp`, `smb`, `smb2`, `imf`

### Upload Example

```shell
curl -X POST http://localhost:18090/api/v1/upload \
  -F "file=@/path/to/capture.pcap"
```

Response:
```json
{
  "code": 0,
  "msg": "ok",
  "data": {
    "filename": "capture.pcap",
    "filepath": "/app/pcaps/capture.pcap",
    "size": 1048576
  }
}
```

### Statistics Response

```shell
curl -X POST http://localhost:18090/api/v1/dissect/stats \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap"}'
```

```json
{
  "code": 0,
  "msg": "ok",
  "data": {
    "totalFrames": 24632,
    "totalBytes": 51283456,
    "protocolCount": 12,
    "protocols": [
      {"protocol": "TCP", "count": 18200, "bytes": 48000000},
      {"protocol": "UDP", "count": 5100, "bytes": 2800000},
      {"protocol": "DNS", "count": 332, "bytes": 48000}
    ]
  }
}
```

### TLS Decryption

Supports both RSA private key (TLS 1.2) and SSLKEYLOGFILE (TLS 1.3):

```shell
# With RSA key
curl -X POST http://localhost:18090/api/v1/dissect/frames/page \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/https.pcap",
    "page": 1, "size": 20,
    "tls": {
      "desegmentSslRecords": true,
      "keysList": [{"port": 443, "keyFile": "/app/keys/server.key"}]
    }
  }'

# With SSLKEYLOGFILE (TLS 1.3 / ECDHE)
curl -X POST http://localhost:18090/api/v1/dissect/frames/page \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/tls13.pcap",
    "page": 1, "size": 20,
    "tls": {
      "keylogFile": "/app/keys/sslkeylog.txt"
    }
  }'
```

---

## 8. Roadmap

- [x] Offline pcap file parsing with JSON output
- [x] Hex data extraction from frames
- [x] Live interface capture with real-time dissection
- [x] Multi-device capture with per-device stop control
- [x] TLS decryption with RSA keys (offline and live)
- [x] Functional options pattern for API configuration
- [x] Custom protocol parser registration (thread-safe, auto-integrated)
- [x] Multi-protocol file extraction (HTTP, FTP, TFTP, SMB, IMF)
- [x] TCP stream reassembly with real-time callbacks
- [x] Zero-copy NDJSON streaming for large pcap files
- [x] Display filter validation API
- [x] Pagination with configurable limits
- [x] Path traversal protection and filename sanitization
- [x] Docker multi-replica deployment with Nginx load balancing
- [x] PCAP file upload endpoint
- [x] TLS keylog file support (SSLKEYLOGFILE for TLS 1.3 + ECDHE decryption)
- [x] Protocol distribution statistics endpoint
