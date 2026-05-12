# Gowireshark

README: [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md) | [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md)

- Provide the same packet processing capabilities as Wireshark for Go
- Support offline and online (live capture) packet parsing
- Based on [Wireshark](https://www.wireshark.org/#download) and [libpcap](https://www.tcpdump.org/release/) shared libraries

---

## Contents

- [1. Installation](#1-installation)
  - [1.1. Quick Start (Docker)](#11-quick-start-docker)
  - [1.2. Local Development (macOS)](#12-local-development-macos)
  - [1.3. Local Development (Windows)](#13-local-development-windows)
  - [1.4. Local Development (Linux)](#14-local-development-linux)
- [2. Usage](#2-usage)
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
curl http://localhost:18090/api/v1/version/wireshark

# Paginated frame query (recommended for large files)
curl -X POST http://localhost:18090/api/v1/frames/page \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap", "page": 1, "size": 20}'

# Random access by frame indices
curl -X POST http://localhost:18090/api/v1/frames/idxs \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap", "frameIdxs": [1, 5, 10, 32]}'
```

### 1.2. Local Development (macOS)

For running tests and developing directly on macOS:

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

For running tests and developing on Windows:

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

On Linux, `#cgo pkg-config: glib-2.0` is used automatically. For full local builds (compiling Wireshark from source), refer to the Dockerfile for the exact steps.

---

## 2. Usage

```go
package main

import (
    "fmt"

    "github.com/randolphcyg/gowireshark/pkg"
)

func main() {
    filepath := "/path/to/your/capture.pcap"
    page := 1
    size := 20

    frames, hasMore, err := pkg.GetFramesByPage(filepath, page, size)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Has more frames: %v\n", hasMore)
    for _, frame := range frames {
        fmt.Printf("Frame %d: %s\n",
            frame.BaseLayers.Frame.Number,
            frame.BaseLayers.WsCol.Protocol)
    }
}
```

See `pkg/*_test.go` for more examples including live capture, TLS decryption, TCP stream reassembly, and custom protocol parsing.

---

## 3. Testing

Tests auto-discover pcap files. Place any `.pcap` or `.pcapng` file in the `./pcaps/` directory:

```shell
# Place a test file
cp ~/Downloads/sample.pcap ./pcaps/

# Run all tests
source ./dev_env.sh
go test -v ./pkg/
```

Alternatively, specify a file via environment variable:

```shell
export GOWIRESHARK_TEST_PCAP=/path/to/any.pcap
go test -v ./pkg/
```

Tests that require specific protocols (MySQL, HTTPS, etc.) will skip gracefully if the corresponding traffic is not present in the test file.

---

## 4. Project Structure

```
gowireshark/
├── cmd/main.go              # HTTP service entry point (Gin)
├── pkg/                     # Core library
│   ├── lib.c/h              # C bridge: initialization, utilities
│   ├── offline.c/go         # Offline pcap parsing
│   ├── online.c/go          # Live packet capture
│   ├── reassembly.c/go      # TCP stream reassembly
│   ├── layers.go            # Protocol layer parsers
│   ├── registry.go          # Custom protocol parser registration
│   ├── extract.go           # HTTP file extraction
│   ├── cgo_linux.go         # CGO flags for Linux (pkg-config)
│   └── testutil_test.go     # Test helpers (pcap auto-discovery)
├── init_mac_dev.sh          # macOS dev environment setup
├── init_win_dev.ps1         # Windows dev environment setup
├── Dockerfile               # Multi-stage production build
└── pcaps/                   # Test pcap files (gitignored)
```

| File | Description |
|------|-------------|
| `lib.c, offline.c, online.c, reassembly.c` | C code wrapping libpcap and Wireshark native APIs |
| `layers.go` | Common network protocol layer parser (Go) |
| `registry.go` | User-facing custom protocol parser registration |
| `online.go, offline.go` | Final Go API layer for end users |
| `cgo_linux.go` | Platform-specific CGO flags (Linux uses pkg-config) |
| `cgo_darwin.go` / `cgo_windows.go` | Generated by init scripts (gitignored, contain local paths) |

---

## 5. Architecture

```
Go application
    │
    ├── cgo ──► C bridge layer (lib.c, offline.c, online.c, reassembly.c)
    │               │
    │               ├──► libwireshark (epan: protocol dissection)
    │               ├──► libwiretap   (file format handling)
    │               ├──► libwsutil    (utility functions)
    │               └──► libpcap      (live packet capture)
    │
    └── Go layer (offline.go, online.go, layers.go, registry.go)
```

---

## 6. Deployment

### Single Instance

```shell
docker build -t gowireshark:latest . --platform linux/amd64

docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -e AUTH_TOKEN=your-secret \
  -e PCAP_BASE_DIR=/app/pcaps \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  gowireshark:latest
```

### Multi-Instance (Docker Compose + Nginx Load Balancer)

For higher throughput, scale horizontally with multiple replicas behind Nginx:

```
                         ┌─── gowireshark-1:8090
Client → Nginx:18090  ───┼─── gowireshark-2:8090
                         └─── gowireshark-3:8090
                         
         Shared volume: ./pcaps → /app/pcaps (read-only)
```

```shell
# Start with 3 replicas
AUTH_TOKEN=your-secret docker compose up -d

# Scale to 5 replicas
docker compose up -d --scale gowireshark=5

# Check status
docker compose ps

# Stop
docker compose down
```

The service is stateless — each replica independently processes requests. Nginx distributes requests via round-robin. All replicas share the same pcap directory (read-only mount).

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TOKEN` | _(empty, auth disabled)_ | Bearer token for API authentication |
| `PCAP_BASE_DIR` | `/app/pcaps` | Restrict filepath access to this directory |
| `PORT` | `8090` | HTTP listen port |
| `REQUEST_TIMEOUT` | `120s` | Maximum request processing time |

---

## 7. API Reference

All endpoints require `Authorization: Bearer <token>` header when `AUTH_TOKEN` is set.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth required) |
| GET | `/api/v1/version/wireshark` | Wireshark version |
| GET | `/api/v1/interfaces` | Network interfaces |
| POST | `/api/v1/frames/count` | Total frame count (fast, no dissection) |
| POST | `/api/v1/frames/all` | All frames (auto NDJSON for >1000 frames) |
| POST | `/api/v1/frames/stream/all` | All frames, NDJSON streaming (zero-copy, O(1) memory) |
| POST | `/api/v1/frames/page` | Paginated frames (recommended) |
| POST | `/api/v1/frames/idxs` | Random access by frame numbers |
| POST | `/api/v1/frames/hex` | Hex dump of a single frame |
| POST | `/api/v1/frames/stream` | TCP/UDP stream reassembly |

**Request body (common fields):**

```json
{
  "filepath": "/app/pcaps/sample.pcap",
  "filter": "tcp",
  "page": 1,
  "size": 20,
  "isDebug": false,
  "ignoreErr": true
}
```

**Streaming (NDJSON):** Add `Accept: application/x-ndjson` header to `/frames/page` for zero-copy streaming response. Each line is a complete JSON frame object.

---

## 8. Roadmap

- [x] Offline pcap file parsing and printing
- [x] Offline parsing with JSON output
- [x] Hex data extraction from frames
- [x] Live interface capture
- [x] Real-time dissection results via Go channels
- [x] Multi-device capture with per-device stop control
- [x] Descriptive field values in parse results
- [x] TLS decryption with RSA keys (offline and live)
- [x] Functional options pattern for API configuration
- [x] Custom protocol parser registration
- [x] HTTP file extraction
- [x] TCP stream reassembly
