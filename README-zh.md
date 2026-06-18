# Gowireshark

`gowireshark` 是基于 `libwireshark` 的 Go SDK，只负责协议解析。抓包放在 `gocapture`，HTTP 组合放在 `gowireshark-server`，命令行、MCP 与 Agent 使用文档放在 `epan`。

## 能力

- 离线 pcap / pcapng 解析，并支持大文件分页访问
- frame、layer、hex、display filter、follow 等核心解析能力
- 面向外部采集组件的原始包解析入口
- 显式 registry 驱动的自定义协议解析
- 可选的 `extract` 与 `reassembly` 子包

## 项目家族

| 仓库 | 职责 |
| --- | --- |
| `gowireshark` | 基于 libwireshark 的解析 SDK |
| `gocapture` | libpcap、DPDK 等抓包后端 |
| `gowireshark-server` | HTTP 组合层 |
| `epan` | 命令行入口、MCP 服务与 Agent 使用文档 |

## 安装

```bash
go get github.com/randolphcyg/gowireshark
```

由于底层通过 CGO 链接 `libwireshark`，本地仍需准备 Wireshark 开发环境。

## 快速开始

```go
import "github.com/randolphcyg/gowireshark"

frames, hasMore, err := gowireshark.FramesPage("capture.pcap", 1, 20)
```

## 核心 API 快速索引

- Session 生命周期：`OpenSessionContext`、`Session.Close`；context 控制等待单进程全局 libwireshark session gate。
- Context helper：所有一次性 SDK helper 都提供 `*Context` 版本，包括 `FramesContext`、`WriteFramesContext`、`FollowStreamContext`、`StreamsContext`、`ExportObjectsContext`、`IOStatsContext`。
- 字段提取：`FieldsRows` 配合 `WithFieldOccurrence(OccurrenceFirst|OccurrenceLast)` 返回标量行，`FieldsRowsValues` 返回全部 occurrence。
- 帧索引：frame number 永远是 Wireshark 1-based 编号。推荐 `FrameByNumberContext`、`FramesByNumbersContext`、`HexDataByFrameNumberContext`、`Session.Frame`、`Session.Frames`、`Session.HexData`。
- Iterator：`IterFrames`、`IterFieldsRows`、`IterFrameJSON` 面向大文件和流式消费。
- 输出格式：`WriteDissection` 支持 JSON、raw JSON、fields、PDML、PSML、text SDK 兼容 writer。
- pcap 切片：`WritePcapSlice` 默认尽力而为；`WritePcapSliceWithOptions` 配合 `PcapOutputPcap`、`PcapOutputPcapNG`、`PcapOutputSame` 走 native wiretap。
- 能力发现：`RuntimeVersion`、`RuntimeProtocols`、`RuntimeFields`、`RuntimeSuggestFields`、`RuntimePreferences`、`RuntimeProfiles`、`RuntimeDecodeAsTables`、`RuntimeDecodeAsChoices`、`RuntimeTapTypes`、`RuntimeExportObjectProtocols` — 全部是 context-first 设计并支持取消。对简单场景，也提供 `context.Background()` 薄包装。
- 错误处理：用 `errors.Is` 判断 sentinel error；用 `errors.As` 获取 `DisplayFilterError`、`FieldError`、`DecodeAsError`、`OutputFormatError`、`WiretapError`。

### Session

`Session` 在多次查询间复用同一套解析配置和帧索引；顺序扫描会在每次操作前重置底层 reader。单个 `Session` 的方法不支持多 goroutine 并发；由于 libwireshark 保留进程级全局状态，同一进程同一时间也只允许一个活跃 `Session`。

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

- `FrameCount`、`FramesPage`、`Streams`、`ExpertInfos`、`FollowStream` 结果按 `(filter)` 或 `(filter, proto)` 缓存。`Close()` 会清空所有缓存。
- `WalkFrames` 不做缓存。

旧版 free function（`FrameCount`、`FramesPage`、`WalkFrames`、`FollowStream`）保持可用，内部创建临时 `Session`。一次性调用时很方便；多次查询同一个 pcap 建议用 `Session`。已有外部 `Session` 尚未关闭时，不要再调用这些 helper。

### WalkFrames

`WalkFrames` 通过回调流式处理帧，不会把所有帧加载到内存。`*FrameData` 仅在回调中有效，不要保存引用。

```go
err := gowireshark.WalkFrames("capture.pcap", func(f *gowireshark.FrameData) error {
    fmt.Println(f.BaseLayers.Frame.Number)
    return nil // 返回 error 可提前停止
})
```

### FollowStream

`FollowStream` 提取匹配 display filter 的 TCP 或 UDP 负载。`FollowPayload` 除了原始 hex 字符串外还包含解析好的 `Bytes` 字段。

```go
result, err := gowireshark.FollowStream("capture.pcap", "tcp.stream eq 0", "tcp")
for _, p := range result.Payloads {
    fmt.Printf("[%s] %d bytes\n", p.Dir, len(p.Bytes))
}
```

### CLI / Agent 取证辅助

`gowireshark` 提供面向 CLI 和 Agent 的稳定原始接口，用于精确、可复现的取证提取：

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

Writer 风格 API 支持 CLI 友好的输出格式控制：

```go
_, _ = gowireshark.WriteFramesContext(context.Background(), "capture.pcap", out,
    gowireshark.WithDisplayFilter("tcp"),
    gowireshark.WithOutputFields([]string{"frame.number", "ip.src", "ip.dst", "tcp.stream"}),
)
```

### Analysis

`analysis` 子包计算协议统计和端点统计。`WalkAnalyze` 在不持有全部帧的前提下边读边算。

```go
import "github.com/randolphcyg/gowireshark/analysis"

summary, err := analysis.WalkAnalyze("capture.pcap")
fmt.Printf("%d frames, %d bytes, %s duration\n",
    summary.FrameCount, summary.ByteCount, summary.Duration)
for _, proto := range summary.Protocols {
    fmt.Printf("%s: %d (%.1f%%)\n", proto.Protocol, proto.FrameCount, proto.Percentage)
}
```

也可对已采集帧做分析：

```go
frames, _ := gowireshark.Frames("capture.pcap")
summary := analysis.Analyze(frames)
```

## 原始包解析

```go
frame, err := gowireshark.DissectPacket(gowireshark.RawPacket{
    Data:           ethernetFrame,
    CaptureLength:  len(ethernetFrame),
    OriginalLength: len(ethernetFrame),
    LinkType:       gowireshark.LinkTypeEthernet,
})
```

`LinkType` 使用 libpcap LINKTYPE / DLT 数值，SDK 会在内部转换为 Wireshark 封装类型。

## Wireshark 元数据、Expert Info 与 Decode As

```go
_ = gowireshark.ValidateField("tcp.stream")
field, _ := gowireshark.FieldInfo("http.request.uri")
protocols, _ := gowireshark.RuntimeProtocols(context.Background())
fields, _ := gowireshark.RuntimeFields(context.Background())
suggestions, _ := gowireshark.RuntimeSuggestFields(context.Background(), "tcp", 10)
experts, _ := gowireshark.ExpertInfos("capture.pcap")
```

对非标准端口的流量强制指定解析器：

```go
frames, err := gowireshark.Frames("capture.pcap",
    gowireshark.WithDecodeAs([]gowireshark.DecodeAsRule{
        {Table: "tcp.port", Selector: "8080", Protocol: "http"},
    }),
)
```

## 能力边界

部分 API 依赖运行时 libwireshark 注册表，不要假定具备与 Wireshark GUI 同等的协议覆盖范围。

### Session 并发

libwireshark 保留进程级全局抓包状态，由两个包级原语保护：

- **`sessionGate`** 确保同一进程同一时间只允许**一个活跃 `Session`**。在首个 `Session` `Close()` 或 context 取消之前，任何打开第二个 `Session` 的尝试（包括 free function 内部）都会阻塞。
- **`epanMu`** 序列化进程内所有 C 层调用（解析、扫描、tap 操作），确保 C 层全局状态不被并发访问。

Session 方法在 `epanMu` 提供的序列化之外，**不支持多 goroutine 并发**。如需并发解析，请将所有调用序列化到单个 goroutine，或使用独立进程。

### 输出格式（PDML / PSML / Text）

`WriteDissection` 支持 `OutputJSON`、`OutputJSONRaw`、`OutputFields`、`OutputPDML`、`OutputPSML` 和 `OutputText`。

- **`OutputText`** 和 **`OutputPSML`** 使用 C 层 streaming writer，只提取摘要列（帧号、协议、源、目标、info），不生成完整帧 JSON。这是推荐的性能文本输出路径。
- **`OutputPDML`** 当前是基于解析后的 `FrameData` 生成的 SDK 兼容输出，是**高成本 full-tree 输出**。批量输出建议优先使用 field-only 或 Text/PSML 路径。PDML native streaming 计划在后续版本实现。
- **`OutputFields`** 和 **`WriteFieldsRows`** 使用 C 层 field-only 提取，是最快的输出路径。
- 所有格式都是适合 Go 调用方消费的有效结构化输出，但不保证与 `tshark -T pdml`、`tshark -T psml` 或 `tshark -V` 字节级/结构完全一致。

### PcapNG 元数据保留

`WritePcapSlice` 默认走 `pcapgo` 的尽力而为路径。`WritePcapSliceWithOptions` 在启用 `PreserveComments`、`PreserveInterfaces` 或显式指定 `OutputFormat` 时会切换到原生 wiretap 写出，在链接的 Wireshark/wiretap 运行时支持范围内保留 pcapng 接口元数据、packet comment、时间戳精度和链路层元数据。

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

`ExportObjects` / `WriteExportObject` / `WriteExportObjects` 使用 Wireshark 的导出对象 tap。支持协议由 `ExportObjectProtocols` 暴露，当前包括 HTTP、SMB、TFTP、FTP-DATA、IMF 和 DICOM，实际可用性取决于链接的运行时：

```go
gowireshark.SupportsExportObjects("http") // true
gowireshark.SupportsExportObjects("smb")  // true
```

使用不支持的协议会返回 `ErrUnsupportedProtocol`。建议调用前使用 `SupportsExportObjects` 检查，避免试错模式。

### Tap Conversations / Endpoints

Tap `conversations` 和 `endpoints` 覆盖 `TapTypes` 返回的协议类型。支持情况取决于链接的 Wireshark 运行时和当前 C 层 tap 实现；不支持的类型返回 `ErrUnsupportedProtocol`。

### Service Response Times（SRT）

`ServiceResponseTimes` 使用 libwireshark 运行时 SRT 表。支持情况取决于链接的 Wireshark 构建中注册了哪些表；没有硬编码的协议列表：

```go
gowireshark.SupportsServiceResponseTimes("smb")  // 取决于运行时
gowireshark.SupportsServiceResponseTimes("dns")  // 取决于运行时
```

如果某协议没有注册 SRT 表，`ServiceResponseTimes` 返回 `ErrUnsupportedProtocol`。使用 `SupportsServiceResponseTimes` 运行时探测。

### 字段提取性能

`FieldsRows`、`IterFieldsRows`（包含 `Values() []string` 快速路径）和 `WriteFieldsRows` 是最快的字段提取 API。它们使用 C 层 field-only 回调，`Values()` 方法按字段顺序返回值，无需 map 分配。多值字段默认返回第一个 occurrence；传入 `WithFieldOccurrence(OccurrenceLast)` 可返回最后一个标量 occurrence。`FieldsRowsValues` 以结构化切片返回全部 occurrence。标量字段 API 都会拒绝 `OccurrenceAll`，需要多值结构化输出时请使用 `FieldsRowsValues`。

**轻量 iterator / writer 路径：**

- `Session.IterFrameJSON(q)` 流式返回原始帧 JSON bytes，避免 `ParseFrameData` 开销。调用者只需原始 JSON 时，比 `IterFrames()` 显著更高效。
- `Session.WriteFrames(q, w)` 使用相同的 streaming fast path 直接写入 `io.Writer`。
- `IterFrames()` 返回完整 `FrameData` 对象（较高成本）；只需原始 JSON 时优先使用 `IterFrameJSON()`。

**大文件推荐路径（按优先级排序）：**

1. `IterFrameJSON` / `IterFieldsRows` — 逐帧流式消费，不解析或物化完整帧树
2. `WriteFrames` / `WriteFieldsRows` / `WriteDissection(OutputFields|OutputText|OutputPSML)` — 直接写入 `io.Writer`
3. `FieldsRows` 配合窄 display filter — 面向精确查询的 field-only 提取
4. `Session` 缓存配合 `FramesPage` — 分页访问复用已缓存结果
5. 谨慎使用 `Frames()` / `IterFrames()` / `OutputPDML` — 它们构建完整 `FrameData` 树，是成本最高的路径

**帧查找性能：**

`Session.Frame(n)`、`Session.Frames(nums)` 和 `Session.HexData(n)` 使用首次扫描时构建的帧索引。中间位置和末尾查找使用顺序 `wtap_read` 跳过中间帧（仅元数据读取，不解包），仅对目标帧完整解包。这比完整顺序扫描更快，但不使用随机访问 seek；native `wtap_seek_read` 回退路径留待后续工作。

`Session` 维护保守的 read-position dirty 标记：首次顺序扫描跳过 C 层位置重置，后续扫描仅在位置被移动时重置。这加速了对同一 pcap 的重复查询（filter 不变时）。

### Stream 标识

`StreamSummary.StreamID` 返回真实的 Wireshark 协议流 ID（`tcp.stream` / `udp.stream`），可用于 display filter 如 `"tcp.stream eq N"`。`StreamID == -1` 表示流 ID 未能解析（例如 IPv6 链路本地地址在 `FieldsRows` 输出中无法匹配）。仅当 `StreamID >= 0` 时才可用于 display filter。`ConversationID` 是排序后五元组的内部哈希值，用于跨 tap 结果关联。早期版本曾将哈希值作为 StreamID；现已修正，确保 stream-list → follow-stream 取证链正确。

## 可选能力

文件提取使用 `github.com/randolphcyg/gowireshark/extract`；TCP follow 收集使用 `github.com/randolphcyg/gowireshark/reassembly`。两者都建立在核心解析 API 之上，不污染主包边界。

## 本地开发

```bash
./init_mac_dev.sh
source ./dev_env.sh
go test ./...
```

Windows 使用 `init_win_dev.ps1`；Linux 安装系统对应的 Wireshark 与 GLib 开发包后直接执行测试即可。

## 测试

集成测试会自动查找 `./pcaps/` 下的 `.pcap` / `.pcapng` 文件，也可显式指定：

```bash
GOWIRESHARK_TEST_PCAP=/path/to/capture.pcap go test ./...
```

## 许可证

本项目链接 `libwireshark`，按 GNU General Public License v2 发布，详见 `LICENSE`。
