# Gowireshark

`gowireshark` is a Go SDK around `libwireshark`. It owns packet dissection only: packet acquisition belongs in `gocapture`, HTTP composition in `gowireshark-server`, and user-facing entrypoints in CLI or agent tooling.

## Capabilities

- Offline pcap / pcapng dissection with paginated access for large files
- Frame, layer, hex, display-filter, and stream-follow helpers
- Raw-packet dissection for callers that already own packet acquisition
- Explicit custom-protocol registries for typed layer parsing
- Optional `extract` and `reassembly` subpackages for higher-level helpers

## Project family

| Repository | Responsibility |
| --- | --- |
| `gowireshark` | libwireshark-backed dissection SDK |
| `gocapture` | packet acquisition backends such as libpcap and DPDK |
| `gowireshark-server` | HTTP composition layer |
| `gowireshark-cli` | command-line frontend |
| `gowireshark-agent-kit` | agent-facing usage materials |

## Install

```bash
go get github.com/randolphcyg/gowireshark
```

`gowireshark` links against `libwireshark` through CGO, so a local Wireshark development environment is still required.

## Quick start

```go
package main

import (
    "fmt"

    "github.com/randolphcyg/gowireshark"
)

func main() {
    frames, hasMore, err := gowireshark.FramesPage("capture.pcap", 1, 20)
    if err != nil {
        panic(err)
    }
    fmt.Println(len(frames), hasMore)
}
```

### Session

`Session` reuses one dissection configuration and frame index across multiple queries. Sequential scans reset the underlying reader between operations. Session methods are not safe for concurrent goroutines, and because libwireshark keeps process-global capture state, only one active `Session` may exist in a process at a time.

```go
s, err := gowireshark.OpenSession("capture.pcap")
if err != nil {
    panic(err)
}
defer s.Close()

count, _ := s.FrameCount(gowireshark.Query{Filter: "tcp"})
fmt.Println("TCP frames:", count)

frames, hasMore, _ := s.FramesPage(gowireshark.Query{Filter: "tcp"}, 1, 10)
fmt.Println(len(frames), hasMore)

err = s.WalkFrames(gowireshark.Query{Filter: "http"}, func(f *gowireshark.FrameData) error {
    fmt.Println(f.BaseLayers.Frame.Number)
    return nil
})

result, _ := s.FollowStream(gowireshark.Query{Filter: "tcp.stream eq 0"}, "tcp")
fmt.Println("packets:", result.PacketCount, "client bytes:", result.ClientBytes)
```

- `FrameCount` and `FramesPage` results are cached per session by `(filter, page, size)`. Calling `Close()` clears the cache.
- `WalkFrames` and `FollowStream` are not cached.

The existing free functions (`FrameCount`, `FramesPage`, `WalkFrames`, `FollowStream`) remain available and create a temporary `Session` internally. They are convenient for one-shot calls; prefer `Session` when you plan multiple queries against the same pcap. Do not call those helpers while another `Session` is still active.

### WalkFrames

`WalkFrames` streams parsed frames through a callback instead of collecting them in memory. The `*FrameData` is only valid during the callback; do not retain it.

```go
var frameNumbers []int
err := gowireshark.WalkFrames("capture.pcap", func(f *gowireshark.FrameData) error {
    if f.BaseLayers.Frame != nil {
        frameNumbers = append(frameNumbers, f.BaseLayers.Frame.Number)
    }
    return nil // return an error to stop early
})
```

### FollowStream

`FollowStream` extracts TCP or UDP payloads matching a display filter. Each `FollowPayload` includes a decoded `Bytes` field alongside the raw hex string.

```go
result, err := gowireshark.FollowStream("capture.pcap", "tcp.stream eq 0", "tcp")
if err != nil {
    panic(err)
}
for _, p := range result.Payloads {
    fmt.Printf("[%s] %d bytes\n", p.Dir, len(p.Bytes))
}
```

### CLI / Agent evidence helpers

`gowireshark` exposes stable primitives for CLI and agent tooling that need precise, reproducible evidence:

```go
frame, _ := gowireshark.FrameByIndex("capture.pcap", 42)
frames, _ := gowireshark.FramesByIndices("capture.pcap", []int{42, 43})
hex, _ := gowireshark.HexDataByIndex("capture.pcap", 42)

streams, _ := gowireshark.Streams("capture.pcap")
conversations, _ := gowireshark.Conversations("capture.pcap")
timeline, _ := gowireshark.Timeline("capture.pcap")
files, _ := gowireshark.Files("capture.pcap")
_ = frame; _ = frames; _ = hex; _ = streams; _ = conversations; _ = timeline; _ = files

selector := gowireshark.FrameSelector{Filter: "tcp.stream == 3"}
_, _ = gowireshark.WritePcapSlice("capture.pcap", out, selector)
bundle, _ := gowireshark.BuildEvidenceBundle("capture.pcap", selector)
_ = bundle
```

Writer-style APIs support CLI-friendly output shaping:

```go
_, _ = gowireshark.WriteFramesJSONL("capture.pcap", out,
    gowireshark.WithDisplayFilter("tcp"),
    gowireshark.WithOutputFields([]string{"frame.number", "ip.src", "ip.dst", "tcp.stream"}),
)
```

### Analysis

The `analysis` subpackage computes protocol and endpoint statistics. `WalkAnalyze` walks a pcap without holding all frames in memory.

```go
import "github.com/randolphcyg/gowireshark/analysis"

summary, err := analysis.WalkAnalyze("capture.pcap")
if err != nil {
    panic(err)
}
fmt.Printf("%d frames, %d bytes, %s duration\n",
    summary.FrameCount, summary.ByteCount, summary.Duration)
for _, proto := range summary.Protocols {
    fmt.Printf("%s: %d (%.1f%%)\n", proto.Protocol, proto.FrameCount, proto.Percentage)
}
```

You can also pass analysis over already-collected frames:

```go
frames, _ := gowireshark.Frames("capture.pcap")
summary := analysis.Analyze(frames)
```

## Raw packet dissection

```go
frame, err := gowireshark.DissectPacket(gowireshark.RawPacket{
    Data:           ethernetFrame,
    CaptureLength:  len(ethernetFrame),
    OriginalLength: len(ethernetFrame),
    LinkType:       gowireshark.LinkTypeEthernet,
})
```

`LinkType` uses libpcap LINKTYPE / DLT numeric values; the SDK converts them to Wireshark encapsulations internally.

## Wireshark metadata, Expert Info, and Decode As

```go
_ = gowireshark.ValidateField("tcp.stream")
field, _ := gowireshark.FieldInfo("http.request.uri")
protocols, _ := gowireshark.Protocols()
fields, _ := gowireshark.Fields()
experts, _ := gowireshark.ExpertInfos("capture.pcap")
```

Force a dissector for traffic on a non-standard port:

```go
frames, err := gowireshark.Frames("capture.pcap",
    gowireshark.WithDecodeAs([]gowireshark.DecodeAsRule{
        {Table: "tcp.port", Selector: "8080", Protocol: "http"},
    }),
)
```

## Optional helpers

Use `github.com/randolphcyg/gowireshark/extract` when you want explicit file extraction into a caller-owned directory, and `github.com/randolphcyg/gowireshark/reassembly` when you want a TCP follow collector layered over the core dissection APIs.

## Local development

### macOS

```bash
./init_mac_dev.sh
source ./dev_env.sh
go test ./...
```

### Windows

```powershell
.\init_win_dev.ps1
. .\dev_env.ps1
go test ./...
```

### Linux

Install Wireshark and GLib development packages for your distribution, then run:

```bash
go test ./...
```

## Tests

Integration tests auto-discover `.pcap` / `.pcapng` fixtures under `./pcaps/`, or you can point at an exact file:

```bash
GOWIRESHARK_TEST_PCAP=/path/to/capture.pcap go test ./...
```

## License

This project links against `libwireshark` and is distributed under the GNU General Public License v2. See `LICENSE`.
