# Gowireshark

`gowireshark` is a Go SDK around `libwireshark`. It owns packet dissection only: packet acquisition belongs in `gocapture`, HTTP composition in `gowireshark-server`, and CLI, MCP, and agent-facing documentation live in `gowireshark-cli`.

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
| `gowireshark-cli` | command-line frontend, MCP server, and agent-facing docs |

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

## Core API quick index

- Session lifecycle: `OpenSessionContext`, `Session.Close`; a context controls waiting for the single process-wide libwireshark session gate.
- Context helpers: every one-shot SDK helper has a `*Context` variant, including `FramesContext`, `WriteFramesContext`, `FollowStreamContext`, `StreamsContext`, `ExportObjectsContext`, and `IOStatsContext`.
- Field extraction: `FieldsRows` with `WithFieldOccurrence(OccurrenceFirst|OccurrenceLast)` for scalar rows, `FieldsRowsValues` for all occurrences.
- Frame index: frame numbers are always Wireshark 1-based numbers. Use `FrameByNumberContext`, `FramesByNumbersContext`, `HexDataByFrameNumberContext`, `Session.Frame`, `Session.Frames`, and `Session.HexData`.
- Iterators: `IterFrames`, `IterFieldsRows`, `IterFrameJSON` for large captures and streaming consumers.
- Output formats: `WriteDissection` with JSON, raw JSON, fields, PDML, PSML, and text SDK-compatible writers.
- Pcap slicing: `WritePcapSlice` for best-effort output, `WritePcapSliceWithOptions` with `PcapOutputPcap`, `PcapOutputPcapNG`, or `PcapOutputSame` for native wiretap output.
- Capability discovery: `RuntimeVersion`, `RuntimeProtocols`, `RuntimeFields`, `RuntimeSuggestFields`, `RuntimePreferences`, `RuntimeProfiles`, `RuntimeDecodeAsTables`, `RuntimeDecodeAsChoices`, `RuntimeTapTypes`, `RuntimeExportObjectProtocols` — all are context-first with cancellation support. Thin wrappers that use `context.Background()` are available for simpler call sites.
- Error handling: branch with sentinel errors through `errors.Is`; use structured errors such as `DisplayFilterError`, `FieldError`, `DecodeAsError`, `OutputFormatError`, and `WiretapError` through `errors.As`.

### Session

`Session` reuses one dissection configuration and frame index across multiple queries. Sequential scans reset the underlying reader between operations. Session methods are not safe for concurrent goroutines, and because libwireshark keeps process-global capture state, only one active `Session` may exist in a process at a time.

```go
s, err := gowireshark.OpenSessionContext(context.Background(), "capture.pcap")
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

- `FrameCount`, `FramesPage`, `Streams`, `ExpertInfos`, and `FollowStream` results are cached per session by `(filter)` or `(filter, proto)`. Calling `Close()` clears all caches.
- `WalkFrames` is not cached.

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
s, _ := gowireshark.OpenSessionContext(context.Background(), "capture.pcap")
defer s.Close()
frame, _ := s.Frame(42)
frames, _ := gowireshark.FramesByNumbersContext(context.Background(), "capture.pcap", []int{42, 43})
hex, _ := gowireshark.HexDataByFrameNumberContext(context.Background(), "capture.pcap", 42)

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
_, _ = gowireshark.WriteFramesContext(context.Background(), "capture.pcap", out,
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
protocols, _ := gowireshark.RuntimeProtocols(context.Background())
fields, _ := gowireshark.RuntimeFields(context.Background())
suggestions, _ := gowireshark.RuntimeSuggestFields(context.Background(), "tcp", 10)
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

## Capability boundaries

Several APIs depend on runtime libwireshark registration tables. Do not assume full protocol coverage equivalent to Wireshark GUI.

### Session concurrency

libwireshark keeps process-global capture state guarded by two package-level primitives:

- **`sessionGate`** ensures only one active `Session` may exist in a process at a time. Any attempt to open a second `Session` (including internally by free functions) blocks until the first is `Close()`d or the context is cancelled.
- **`epanMu`** serialises all C-level calls (dissection, scanning, tap operations) within the process, so that C global state is never touched concurrently.

Session methods are **not safe for concurrent goroutines** beyond the serialisation that `epanMu` provides. If you need concurrent dissection, serialise all calls into a single goroutine or use separate processes.

### Output formats (PDML / PSML / Text)

`WriteDissection` supports `OutputJSON`, `OutputJSONRaw`, `OutputFields`, `OutputPDML`, `OutputPSML`, and `OutputText`.

- **`OutputText`** and **`OutputPSML`** use C-level streaming writers that extract only summary columns (frame number, protocol, source, destination, info) without generating full frame JSON. These are the recommended text output paths for performance.
- **`OutputPDML`** is an SDK-compatible renderer built from parsed `FrameData`; it is a high-cost full-tree output. Prefer field-only or text/PSML paths for bulk output. PDML native streaming is planned for a future release.
- **`OutputFields`** and **`WriteFieldsRows`** use C-level field-only extraction and are the fastest output paths.
- All formats are valid structured output for Go callers, but are not byte-for-byte equivalent to `tshark -T pdml`, `tshark -T psml`, or `tshark -V`.

### PcapNG metadata preserve

`WritePcapSlice` uses a best-effort `pcapgo` path by default. `WritePcapSliceWithOptions` switches to native wiretap when `PreserveComments`, `PreserveInterfaces`, or an explicit `OutputFormat` is set, preserving pcapng interface metadata, packet comments, timestamp precision, and link-layer metadata where supported by the linked Wireshark/wiretap runtime.

```go
count, err := gowireshark.WritePcapSliceWithOptions(pcap, &buf, selector,
    gowireshark.PcapSliceOptions{
        PreserveInterfaces: true,
        OutputFormat: gowireshark.PcapOutputPcapNG,
    })
_ = count
_ = err
```

### Export Objects

`ExportObjects` / `WriteExportObject` / `WriteExportObjects` use Wireshark's export-object tap. Supported protocol names are exposed by `ExportObjectProtocols` and currently include HTTP, SMB, TFTP, FTP-DATA, IMF, and DICOM when available in the linked runtime:

```go
gowireshark.SupportsExportObjects("http") // true
gowireshark.SupportsExportObjects("smb")  // true
```

Calling with an unsupported protocol returns `ErrUnsupportedProtocol`. Use `SupportsExportObjects` to check before calling to avoid trial-and-error patterns.

### Tap conversations / endpoints

Tap `conversations` and `endpoints` cover the protocol types returned by `TapTypes`. Support depends on the linked Wireshark runtime and the C tap implementation; unsupported types return `ErrUnsupportedProtocol`.

### Service Response Times (SRT)

`ServiceResponseTimes` uses libwireshark runtime SRT tables. Support depends on which tables are registered in the linked Wireshark build; there is no hardcoded protocol list:

```go
gowireshark.SupportsServiceResponseTimes("smb")  // depends on runtime
gowireshark.SupportsServiceResponseTimes("dns")  // depends on runtime
```

If no SRT table is registered for a protocol, `ServiceResponseTimes` returns `ErrUnsupportedProtocol`. Use `SupportsServiceResponseTimes` to probe at runtime.

### Field extraction performance

- `FieldsRows`, `IterFieldsRows` (includes `Values() []string` fast path), and `WriteFieldsRows` are the fastest field extraction APIs. They use C-level field-only callback and the `Values()` method returns values in field order without map allocation. Multi-value fields return the first occurrence by default; pass `WithFieldOccurrence(OccurrenceLast)` to return the last scalar occurrence. `FieldsRowsValues` returns all occurrences as structured slices. Scalar field APIs intentionally reject `OccurrenceAll`; use `FieldsRowsValues` for structured multi-value output.

**Lightweight iterator / writer paths:**

- `Session.IterFrameJSON(q)` streams raw frame JSON bytes without `ParseFrameData` overhead. For callers that need original JSON, this is significantly cheaper than `IterFrames()`.
- `Session.WriteFrameJSON(q, w)` writes raw frame JSON directly to an `io.Writer` using the same streaming fast path.
- `IterFrames()` returns full `FrameData` objects (higher cost); prefer `IterFrameJSON()` when you only need raw JSON.

**Large-file recommendation (in order of preference):**

1. `IterFrameJSON` / `IterFieldsRows` — stream frames one at a time without parsing or materialising full frame trees
2. `WriteFrameJSON` / `WriteFieldsRows` / `WriteDissection(OutputFields|OutputText|OutputPSML)` — write directly to `io.Writer`
3. `FieldsRows` with narrow display filter — field-only extraction for targeted queries
4. `Session` cache with `FramesPage` — paginated access reuses cached results
5. Use `Frames()` / `IterFrames()` / `OutputPDML` cautiously — they build full `FrameData` trees and are the most expensive paths

**Frame lookup performance:**

`Session.Frame(n)`, `Session.Frames(nums)`, and `Session.HexData(n)` use a frame index built during the first scan. Mid-position and end-of-file lookups use sequential `wtap_read` to skip intermediate frames (metadata only, no dissection) and only fully dissect the target frame. This is faster than a full sequential scan but does not use random-access seek; a native `wtap_seek_read` fallback is documented for future work.

The `Session` tracks a conservative read-position dirty flag: the first sequential scan skips the C-level reset, and subsequent scans reset only when the position has been moved. This speeds up repeated same-pcap queries when the filter does not change.

### Stream identification

`StreamSummary.StreamID` returns the real Wireshark protocol stream ID (`tcp.stream` / `udp.stream`) suitable for use in display filters like `"tcp.stream eq N"`. `StreamID == -1` indicates that the stream ID could not be resolved (e.g. IPv6 link-local addresses in `FieldsRows` output). Only values where `StreamID >= 0` should be used in display filters. `ConversationID` is an internal hash of the sorted 5-tuple, provided for correlation across tap results. Previous versions used the hash as StreamID; this is now fixed so that the stream-list → follow-stream evidence chain is correct.

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
