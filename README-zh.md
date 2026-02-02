# Gowireshark

README: [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md) | [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md)

- 为Go提供与wireshark相同的数据包处理能力
- 支持离线、在线数据包解析
- 基于[wireshark](https://www.wireshark.org/#download)、[libpcap](https://www.tcpdump.org/release/)动态链接库

---

# Contents

- [Gowireshark](#gowireshark)
- [Contents](#contents)
    - [1. 安装](#1-安装)
        - [1.1. 前置条件](#11-前置条件)
        - [1.2. 用法](#12-用法)
        - [1.3. 快速开始 (Docker 方式)](#13-快速开始-Docker-方式)
    - [2. 详细说明](#2-详细说明)
        - [2.1. 项目目录](#21-项目目录)
        - [2.2. 调用链](#22-调用链)
        - [2.3. 解析结果格式说明](#24-解析结果格式说明)
    - [3. 路线图](#3-路线图)
    - [5. 联系](#5-联系)

---

## 1. 安装

---

### 1.1. 前置条件
- glib-2.0

```shell
# install glib-2.0
sudo apt install libglib2.0-dev -y
```

### 1.2. 用法

```shell
go get "github.com/randolphcyg/gowireshark"
```

如何测试:

```shell
go test -v -run TestEpanVersion
```

1. 分页解析 pcap 数据包文件

```go
package main

import (
	"fmt"

	"github.com/randolphcyg/gowireshark/pkg"
)

func main() {
	filepath := "./pcaps/mysql.pcapng"
	page := 4
	size := 20

	// 在业务层计算总页数
	frames, totalCount, err := pkg.GetFramesByPage(filepath, page, size)
	if err != nil {
		panic(err)
	}

	// 在业务层计算总页数
	totalPages := (totalCount + size - 1) / size

	fmt.Printf("总记录数: %d\n", totalCount)
	fmt.Printf("总页数: %d\n", totalPages)
	fmt.Printf("当前页号: %d\n", page)

	for _, frame := range frames {
		fmt.Printf("Frame %d: %s\n", frame.BaseLayers.Frame.Number, frame.BaseLayers.WsCol.Protocol)
	}
}
```

其他示例可以参考`*_test.go`。

### 1.3. 快速开始 (Docker 方式)

无需本地安装复杂的 glib/libpcap 依赖，直接构建 Docker 镜像即可启动 HTTP 解析服务。

**打包 & 启动:**

```shell
# 构建镜像 (使用阿里云源加速)
docker build -t gowireshark:latest . --platform linux/amd64

# 启动服务
# 将本地 pcaps 目录映射到容器内
docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  gowireshark:latest
```

**API 测试:**

```shell
# 1. 获取 Wireshark 版本
curl -X GET http://localhost:18090/api/v1/version/wireshark

# 2. 全量解析(慎用，适用于小文件)
curl -X POST \
  http://localhost:18090/api/v1/frames/all \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/mysql.pcapng",
    "isDebug": true,
    "ignoreErr": false
}'

# 3. 分页查询(推荐，高性能)
curl -X POST \
  http://localhost:18090/api/v1/frames/page \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/mysql.pcapng",
    "page": 1,
    "size": 20,
    "isDebug": true
}'

# 4. 指定帧号查询(随机访问)
curl -X POST \
  http://localhost:18090/api/v1/frames/idxs \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/mysql.pcapng",
    "frameIdxs": [1, 5, 10, 32],
    "isDebug": false
}'
```

## 2. 详细说明

---

### 2.1. 项目目录
```
gowireshark
├── cmd/                # 示例 HTTP 服务入口
├── pkg/                # 核心库代码 (不再有二级 gowireshark 目录)
│   ├── lib.c/h         # C 桥接层
│   ├── online.go       # 在线抓包接口
│   └── offline.go      # 离线解析接口
└── Dockerfile          # 三阶段全自动化构建文件
```
### 项目目录结构的详细说明：

| 文件                                                 | 说明                                                    |
|----------------------------------------------------|-------------------------------------------------------|
| `lib.c, offline.c, online.c, reassembly.c`         | 用C封装和加强libpcap和wireshark功能的代码                         |
| `layers.go`                                        | 通用协议层解析器                                              |
| `registry.go`                                      | 用户注册自定义协议解析器                                          |
| `online.go, offline.go 等`                          | 用go封装最终的接口，用户go程序可直接使用                                |

### 2.2. 调用链

```
Golang =cgo=> Clang ==> Wireshark/libpcap DLL
```

### 2.3. 解析结果格式说明

1. 16进制相关字段与协议解析结果分开：
    - offset 偏移量
    - hex 16进制数据
    - ascii ascii字符

2. 描述性值逻辑
    - 原生的打印协议树接口`proto_tree_print`包含描述性值,而协议json输出接口`write_json_proto_tree`不包含描述性值,通过借鉴前者的实现逻辑`proto_tree_print_node`可以完善这个功能;
    - 主要参考`proto.h`函数的`proto_item_fill_label`函数:
        ```c
        /** Fill given label_str with a simple string representation of field.
        @param finfo the item to get the info from
        @param label_str the string to fill
        @param value_offset offset to the value in label_str
        @todo think about changing the parameter profile */
        WS_DLL_PUBLIC void
        proto_item_fill_label(const field_info *finfo, char *label_str, size_t *value_offset);
        ```

## 3. 路线图

---

- [x] 离线数据包文件解析打印
- [x] 离线数据包文件解析并输出 JSON 格式结果
- [x] 离线数据包解析获取16进制相关数据
- [x] 实时监听接口并捕获数据包
- [x] 封装 go 调用实时解析的逻辑——通过回调函数将实时解析结果传输到 golang
- [x] 封装 go 对收到的 Golang 调用实时数据包解析结果的处理
- [x] 优化代码并解决内存泄漏问题，使实时接口可以长时间运行
- [x] 支持多个设备的数据包捕获，并根据设备名称停止实时接口
- [x] 解析结果支持描述性值
- [x] 支持离线和实时设置rsa key用来解析TLS协议
- [x] 支持可选参数
- [x] 支持注册自定义协议解析器
- [x] 支持从HTTP协议中提取文件
- [x] 支持TCP流重组

## 5. 联系

QQ群: **301969140**