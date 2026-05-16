# Gowireshark

README: [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md) | [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md)

- 为 Go 提供与 Wireshark 相同的数据包处理能力
- 支持离线、在线（实时抓包）数据包解析
- 多协议文件提取（HTTP、FTP、TFTP、SMB、IMF）
- TCP 流重组，支持实时回调
- 自定义协议解析器扩展注册
- 基于 [Wireshark](https://www.wireshark.org/#download) 和 [libpcap](https://www.tcpdump.org/release/) 动态链接库

---

## 目录

- [1. 安装](#1-安装)
- [2. 使用示例](#2-使用示例)
- [3. 测试](#3-测试)
- [4. 项目结构](#4-项目结构)
- [5. 架构](#5-架构)
- [6. 部署](#6-部署)
- [7. API 接口](#7-api-接口)
- [8. 路线图](#8-路线图)

---

## 1. 安装

### Docker（推荐）

```shell
docker build -t gowireshark:latest . --platform linux/amd64

docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  -v $(pwd)/extracted/:/app/extracted/ \
  gowireshark:latest
```

### macOS 本地开发

```shell
./init_mac_dev.sh && source ./dev_env.sh
go test ./pkg/ -timeout=60s
```

### Linux 本地开发

```shell
sudo apt install -y libglib2.0-dev libpcap-dev
go get github.com/randolphcyg/gowireshark
```

---

## 2. 使用示例

### 帧解析

```go
frames, hasMore, _ := pkg.GetFramesByPage("/path/to/file.pcap", 1, 20)
for _, f := range frames {
    fmt.Printf("Frame %d: %s → %s [%s]\n",
        f.BaseLayers.Frame.Number,
        f.BaseLayers.Ip.Src, f.BaseLayers.Ip.Dst,
        f.BaseLayers.WsCol.Protocol)
}
```

### 实时抓包

```go
go pkg.StartLivePacketCapture("en0", "tcp port 80", -1, 1, 100)
for frame := range pkg.GetIfaceChannel("en0") {
    fmt.Println(frame.BaseLayers.WsCol.Protocol)
}
```

### TCP 流重组

```go
reassembler := pkg.NewTCPReassembler(pkg.WithOnData(func(p pkg.Packet) {
    fmt.Printf("Stream %d: %d bytes\n", p.StreamID, len(p.RawData))
}))
handle := reassembler.RegisterCallback()
defer reassembler.UnregisterCallback(handle)

pkg.GetAllFrames("/path/to/file.pcap", pkg.PrintTcpStreams(true))

for id, packets := range reassembler.GetAllStreams() {
    payload := pkg.ReassembleStreamPayload(packets)
    fmt.Printf("Stream %d: %d bytes, %v\n", id, len(payload), pkg.StreamDuration(packets))
}
```

### 多协议文件提取

```go
pkg.ExtractFileDir = "/tmp/extracted"
frames, _ := pkg.GetAllFrames("/path/to/file.pcap", pkg.IgnoreError(true))
extracted, _ := pkg.ExtractFiles(frames)
for _, ef := range extracted {
    fmt.Printf("[%s] %s (%d bytes)\n", ef.Protocol, ef.Filename, ef.Size)
}
```

### 自定义协议解析

```go
// 实现 ProtocolParser 接口并注册到 DefaultRegistry
pkg.DefaultRegistry.Register("mysql", &MySQLParser{})
// 之后所有帧解析自动包含 frame.CustomLayers["mysql"]
```

---

## 3. 测试

```shell
cp ~/Downloads/sample.pcap ./pcaps/
source ./dev_env.sh
go test ./pkg/ -timeout=60s -count=1

# 指定测试文件
export GOWIRESHARK_TEST_PCAP=/path/to/any.pcap
go test ./pkg/ -v
```

---

## 4. 项目结构

```
gowireshark/
├── cmd/main.go              # HTTP 服务入口 (Gin)
├── pkg/
│   ├── lib.c/h              # C 桥接：初始化、工具函数
│   ├── offline.c/go         # 离线解析（解剖、分页、流式输出）
│   ├── online.c/go          # 实时抓包
│   ├── reassembly.c/go      # TCP 流重组（tap 回调）
│   ├── layers.go            # 协议层解析（零拷贝 map 直接提取）
│   ├── registry.go          # 自定义协议注册（线程安全）
│   ├── extract.go           # 多协议文件提取
│   ├── config.go            # 选项模式（TLS、BPF、调试）
│   └── mime_types.txt       # 200+ MIME 类型映射
├── Dockerfile               # 多阶段生产构建
├── docker-compose.yml       # 多副本 + Nginx 负载均衡
└── pcaps/                   # 测试 pcap 文件
```

---

## 5. 架构

```
┌─────────────────────────────────────────────────────────────┐
│  cmd/main.go (HTTP API - Gin)                               │
├─────────────────────────────────────────────────────────────┤
│  offline.go        │  online.go        │  reassembly.go     │
│  (离线分析)         │  (实时抓包)        │  (TCP 重组)        │
├─────────────────────────────────────────────────────────────┤
│  layers.go (协议解析)  │  extract.go (文件提取)               │
│  registry.go (扩展)    │  config.go (配置)                   │
├─────────────────────────────────────────────────────────────┤
│  CGO 桥接 (回调、通道)                                        │
├─────────────────────────────────────────────────────────────┤
│  offline.c │ online.c │ reassembly.c │ lib.c                │
│  libwireshark + libpcap + libwiretap                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. 部署

```shell
# 单实例
docker run -d -p 18090:8090 \
  -e AUTH_TOKEN=secret -e EXTRACT_DIR=/app/extracted \
  -v ./pcaps:/app/pcaps -v ./extracted:/app/extracted \
  gowireshark:latest

# 多副本
AUTH_TOKEN=secret docker compose up -d --scale gowireshark=3
```

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `AUTH_TOKEN` | _(空)_ | Bearer token 认证 |
| `PCAP_BASE_DIR` | `/app/pcaps` | 文件路径限制目录 |
| `EXTRACT_DIR` | `/app/extracted` | 文件提取输出目录 |
| `PORT` | `8090` | 监听端口 |
| `REQUEST_TIMEOUT` | `120s` | 请求超时 |

---

## 7. API 接口

### 系统

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/api/v1/version` | Wireshark 版本 |
| GET | `/api/v1/interfaces` | 网络接口列表 |
| POST | `/api/v1/filter/validate` | 校验 display filter 语法 |

### 帧解析（离线）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/dissect/frames` | 全量帧（>1000 自动 NDJSON） |
| POST | `/api/v1/dissect/frames/stream` | 流式输出（零拷贝） |
| POST | `/api/v1/dissect/frames/page` | 分页（最大 500/页） |
| POST | `/api/v1/dissect/frames/idxs` | 按帧号访问（最大 1000 条） |
| POST | `/api/v1/dissect/frames/count` | 帧计数（快速） |
| POST | `/api/v1/dissect/frames/hex` | 单帧 hex dump |

### 流追踪

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/dissect/follow` | TCP/UDP 流重组 |

### 文件提取

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/extract/files` | 多协议文件提取 |

支持协议：`http`、`ftp-data`、`tftp`、`smb`、`smb2`、`imf`

### 上传

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/upload` | 上传 pcap 文件（multipart/form-data，字段：`file`） |

### 统计

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/dissect/stats` | 协议分布统计 |

### 实时抓包

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/capture/start` | 开始抓包 |
| POST | `/api/v1/capture/stop` | 停止抓包 |
| GET | `/api/v1/capture/stream/:interface` | 流式推送（NDJSON） |

---

## 8. 路线图

- [x] 离线 pcap 解析（JSON 输出、分页、流式）
- [x] 实时抓包与解析
- [x] TLS 解密（RSA key）
- [x] 自定义协议解析器注册（线程安全、自动集成）
- [x] 多协议文件提取（HTTP、FTP、TFTP、SMB、IMF）
- [x] TCP 流重组（实时回调、payload 拼接）
- [x] 零拷贝 NDJSON 流式输出
- [x] Display filter 校验 API
- [x] 分页限制与路径遍历防护
- [x] Docker 多副本 + Nginx 负载均衡
- [x] PCAP 文件上传接口
- [x] TLS keylog 文件支持（SSLKEYLOGFILE，解密 TLS 1.3 + ECDHE）
- [x] 协议分布统计接口
