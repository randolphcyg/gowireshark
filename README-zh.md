# Gowireshark

README: [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md) | [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md)

- 为 Go 提供与 Wireshark 相同的数据包处理能力
- 支持离线、在线（实时抓包）数据包解析
- 基于 [Wireshark](https://www.wireshark.org/#download) 和 [libpcap](https://www.tcpdump.org/release/) 动态链接库

---

## 目录

- [1. 安装](#1-安装)
  - [1.1. 快速开始 (Docker)](#11-快速开始-docker)
  - [1.2. 本地开发 (macOS)](#12-本地开发-macos)
  - [1.3. 本地开发 (Windows)](#13-本地开发-windows)
  - [1.4. 本地开发 (Linux)](#14-本地开发-linux)
- [2. 使用示例](#2-使用示例)
- [3. 测试](#3-测试)
- [4. 项目结构](#4-项目结构)
- [5. 架构](#5-架构)
- [6. 路线图](#6-路线图)

---

## 1. 安装

### 1.1. 快速开始 (Docker)

推荐的服务运行方式，无需本地安装任何依赖。

```shell
# 构建镜像
docker build -t gowireshark:latest . --platform linux/amd64

# 启动服务（将本地 pcaps 目录映射到容器内）
docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  gowireshark:latest
```

**API 示例：**

```shell
# 获取 Wireshark 版本
curl http://localhost:18090/api/v1/version/wireshark

# 分页查询（推荐，适合大文件）
curl -X POST http://localhost:18090/api/v1/frames/page \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap", "page": 1, "size": 20}'

# 按帧号随机访问
curl -X POST http://localhost:18090/api/v1/frames/idxs \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/app/pcaps/sample.pcap", "frameIdxs": [1, 5, 10, 32]}'
```

### 1.2. 本地开发 (macOS)

在 macOS 上直接运行测试和开发：

```shell
# 一键初始化：安装依赖、编译 Wireshark/libpcap、生成 CGO 配置
./init_mac_dev.sh

# 加载运行时环境变量
source ./dev_env.sh

# 运行测试
go test -v ./pkg/
```

前置条件：[Homebrew](https://brew.sh)。脚本会自动处理其他所有依赖。

### 1.3. 本地开发 (Windows)

在 Windows 上运行测试和开发：

```powershell
# 一键初始化（以管理员身份运行 PowerShell）
.\init_win_dev.ps1

# 加载运行时环境变量
. .\dev_env.ps1

# 运行测试
go test -v ./pkg/
```

前置条件：[MSYS2](https://www.msys2.org/) 安装在 `C:\msys64`，以及 [Npcap](https://npcap.com/#download) 运行时驱动。

### 1.4. 本地开发 (Linux)

```shell
# 安装依赖 (Ubuntu/Debian)
sudo apt install -y libglib2.0-dev libpcap-dev

# 作为 Go 库使用
go get github.com/randolphcyg/gowireshark
```

Linux 上自动使用 `#cgo pkg-config: glib-2.0`。如需从源码完整编译 Wireshark，请参考 Dockerfile 中的步骤。

---

## 2. 使用示例

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

    fmt.Printf("是否有更多帧: %v\n", hasMore)
    for _, frame := range frames {
        fmt.Printf("Frame %d: %s\n",
            frame.BaseLayers.Frame.Number,
            frame.BaseLayers.WsCol.Protocol)
    }
}
```

更多示例请参考 `pkg/*_test.go`，包括实时抓包、TLS 解密、TCP 流重组、自定义协议解析等。

---

## 3. 测试

测试会自动发现 pcap 文件。将任意 `.pcap` 或 `.pcapng` 文件放入 `./pcaps/` 目录即可：

```shell
# 放入测试文件
cp ~/Downloads/sample.pcap ./pcaps/

# 运行所有测试
source ./dev_env.sh
go test -v ./pkg/
```

也可以通过环境变量指定文件：

```shell
export GOWIRESHARK_TEST_PCAP=/path/to/any.pcap
go test -v ./pkg/
```

需要特定协议流量的测试（如 MySQL、HTTPS）在找不到对应协议时会自动跳过，不会报错。

---

## 4. 项目结构

```
gowireshark/
├── cmd/main.go              # HTTP 服务入口 (Gin)
├── pkg/                     # 核心库
│   ├── lib.c/h              # C 桥接层：初始化、工具函数
│   ├── offline.c/go         # 离线 pcap 解析
│   ├── online.c/go          # 实时抓包
│   ├── reassembly.c/go      # TCP 流重组
│   ├── layers.go            # 协议层解析器
│   ├── registry.go          # 自定义协议解析器注册
│   ├── extract.go           # HTTP 文件提取
│   ├── cgo_linux.go         # Linux CGO 参数 (pkg-config)
│   └── testutil_test.go     # 测试辅助（pcap 自动发现）
├── init_mac_dev.sh          # macOS 开发环境初始化脚本
├── init_win_dev.ps1         # Windows 开发环境初始化脚本
├── Dockerfile               # 多阶段生产构建
└── pcaps/                   # 测试用 pcap 文件（已 gitignore）
```

| 文件 | 说明 |
|------|------|
| `lib.c, offline.c, online.c, reassembly.c` | C 代码，封装 libpcap 和 Wireshark 原生 API |
| `layers.go` | 通用网络协议层解析器 (Go) |
| `registry.go` | 用户自定义协议解析器注册接口 |
| `online.go, offline.go` | 最终 Go API 层，供用户直接调用 |
| `cgo_linux.go` | 平台特定 CGO 参数（Linux 使用 pkg-config） |
| `cgo_darwin.go` / `cgo_windows.go` | 由初始化脚本生成（已 gitignore，包含本机绝对路径） |

---

## 5. 架构

```
Go 应用
    │
    ├── cgo ──► C 桥接层 (lib.c, offline.c, online.c, reassembly.c)
    │               │
    │               ├──► libwireshark (epan: 协议解析)
    │               ├──► libwiretap   (文件格式处理)
    │               ├──► libwsutil    (工具函数)
    │               └──► libpcap      (实时抓包)
    │
    └── Go 层 (offline.go, online.go, layers.go, registry.go)
```

---

## 6. 部署

### 单实例

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

### 多实例部署（Docker Compose + Nginx 负载均衡）

通过多副本水平扩展提升吞吐量：

```
                         ┌─── gowireshark-1:8090
Client → Nginx:18090  ───┼─── gowireshark-2:8090
                         └─── gowireshark-3:8090
                         
         共享卷: ./pcaps → /app/pcaps (只读挂载)
```

```shell
# 启动 3 副本
AUTH_TOKEN=your-secret docker compose up -d

# 扩容到 5 副本
docker compose up -d --scale gowireshark=5

# 查看状态
docker compose ps

# 停止
docker compose down
```

服务是无状态的——每个副本独立处理请求。Nginx 通过 round-robin 分发请求。所有副本共享同一个 pcaps 目录（只读挂载），无需 Redis 等中间件。

**环境变量：**

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AUTH_TOKEN` | _(空，不启用认证)_ | API 认证 Bearer token |
| `PCAP_BASE_DIR` | `/app/pcaps` | 限制 filepath 访问范围 |
| `PORT` | `8090` | HTTP 监听端口 |
| `REQUEST_TIMEOUT` | `120s` | 最大请求处理时间 |

---

## 7. API 接口

设置 `AUTH_TOKEN` 后，所有接口需携带 `Authorization: Bearer <token>` 请求头。

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查（无需认证） |
| GET | `/api/v1/version/wireshark` | Wireshark 版本 |
| GET | `/api/v1/interfaces` | 网络接口列表 |
| POST | `/api/v1/frames/count` | 帧总数（快速，不做协议解析） |
| POST | `/api/v1/frames/all` | 全量帧（>1000 帧自动切换 NDJSON） |
| POST | `/api/v1/frames/stream/all` | 全量帧流式输出（零拷贝，O(1) 内存） |
| POST | `/api/v1/frames/page` | 分页查询（推荐） |
| POST | `/api/v1/frames/idxs` | 按帧号随机访问 |
| POST | `/api/v1/frames/hex` | 单帧十六进制数据 |
| POST | `/api/v1/frames/stream` | TCP/UDP 流重组 |

**请求体（通用字段）：**

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

**流式响应（NDJSON）：** 在 `/frames/page` 请求中添加 `Accept: application/x-ndjson` 头可获得零拷贝流式响应，每行一个完整的 JSON 帧对象。

---

## 8. 路线图

- [x] 离线数据包文件解析打印
- [x] 离线数据包文件解析并输出 JSON 格式结果
- [x] 离线数据包解析获取十六进制相关数据
- [x] 实时监听接口并捕获数据包
- [x] 通过 Go channel 传递实时解析结果
- [x] 支持多设备抓包，按设备名停止
- [x] 解析结果支持描述性值
- [x] 支持设置 RSA key 解析 TLS 协议（离线和实时）
- [x] 支持可选参数（Functional Options 模式）
- [x] 支持注册自定义协议解析器
- [x] 支持从 HTTP 协议中提取文件
- [x] 支持 TCP 流重组
