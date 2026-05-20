# Gowireshark

`gowireshark` 是基于 `libwireshark` 的 Go SDK，只负责协议解析。抓包放在 `gocapture`，HTTP 组合放在 `gowireshark-server`，面向人或 Agent 的入口交给 CLI / agent-kit。

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
| `gowireshark-cli` | 命令行入口 |
| `gowireshark-agent-kit` | Agent 使用资料 |

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

### Session

`Session` 在多次查询间复用同一套解析配置和帧索引；顺序扫描会在每次操作前重置底层 reader。单个 `Session` 的方法不支持多 goroutine 并发；由于 libwireshark 保留进程级全局状态，同一进程同一时间也只允许一个活跃 `Session`。

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

Writer 风格 API 支持 CLI 友好的输出格式控制：

```go
_, _ = gowireshark.WriteFramesJSONL("capture.pcap", out,
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
protocols, _ := gowireshark.Protocols()
fields, _ := gowireshark.Fields()
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

libwireshark 保留进程级全局抓包状态。同一进程同一时间只允许**一个活跃 `Session`**。Session 方法**不支持多 goroutine 并发**。

对于需要并发解析的 agent/server 场景：
- 将所有解析序列化到单个 goroutine 或队列中
- 或运行多个 worker 进程（每个进程一个 Session）
- 不要尝试在单个进程内并发使用多个 `Session` 实例

这是 Wireshark 的根本限制，而非 Go 设计选择。

### 输出格式（PDML / PSML / Text）

`WriteDissection` 使用 `OutputPDML`、`OutputPSML` 或 `OutputText` 时**尚未实现**，会返回错误。仅支持 `OutputJSON`、`OutputJSONRaw` 和 `OutputFields`。这些格式可能在将来有需要原生 Wireshark XML/文本输出路径的场景时加入。

### PcapNG 元数据保留

`WritePcapSlice` / `WritePcapSliceWithOptions` 通过 `pcapgo` 生成尽力而为的 pcap/pcapng 文件。原生 wiretap 保留元数据的 pcapng 切片（保留注释、接口描述、自定义块）**尚未实现**。

```go
_, err := gowireshark.WritePcapSliceWithOptions(pcap, &buf, selector,
    gowireshark.PcapSliceOptions{PreserveInterfaces: true})
// errors.Is(err, gowireshark.ErrPreserveNotSupported) == true
```

### Export Objects

`ExportObjects` / `WriteExportObject` / `WriteExportObjects` 使用 Wireshark 的导出对象 tap。当前仅支持 HTTP：

```go
gowireshark.SupportsExportObjects("http") // true
gowireshark.SupportsExportObjects("smb")  // false
```

使用不支持的协议会返回 `ErrUnsupportedProtocol`。建议调用前使用 `SupportsExportObjects` 检查，避免试错模式。

### Tap Conversations / Endpoints

Tap `conversations` 和 `endpoints` 当前覆盖 `eth`、`ip`、`tcp`、`udp`。其他协议类型（如 `wlan`、`fc`）C 层未实现。

### Service Response Times（SRT）

`ServiceResponseTimes` 使用 libwireshark 运行时 SRT 表。支持情况取决于链接的 Wireshark 构建中注册了哪些表；没有硬编码的协议列表：

```go
gowireshark.SupportsServiceResponseTimes("smb")  // 取决于运行时
gowireshark.SupportsServiceResponseTimes("dns")  // 取决于运行时
```

如果某协议没有注册 SRT 表，`ServiceResponseTimes` 返回 `ErrUnsupportedProtocol`。使用 `SupportsServiceResponseTimes` 运行时探测。

### 字段提取性能

`FieldsRows` 和 `WriteDissection(OutputFields)`（包括 `WithFieldOutput`）在 C 层为每帧生成完整 JSON 后再在 Go 侧进行字段筛选。这**不是** tshark 原生 `-T fields` 快路径（C 层直接只输出请求的字段）。对于 WalkFrames 聚合成为瓶颈的场景（stream_list、timeline），建议使用 `FieldsRows` API 而非 WalkFrames，以避免 BaseLayers 构建开销。纯 C 层字段输出是计划中的未来优化。

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
