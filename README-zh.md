# Gowireshark

`gowireshark` 是基于 `libwireshark` 的 Go SDK，只负责协议解析。抓包放在 `gocapture`，HTTP 组合放在 `gowireshark-server`，面向人或 Agent 的入口交给 CLI / agent-kit。

## 能力边界

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

- `FrameCount` 和 `FramesPage` 结果按 `(filter, page, size)` 缓存。`Close()` 会清空缓存。
- `WalkFrames` 和 `FollowStream` 不做缓存。

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
