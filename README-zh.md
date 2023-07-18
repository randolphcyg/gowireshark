# Gowireshark

README: [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md) | [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md)

- Gowireshark 是一个 Golang 库，它允许我们的 Golang 程序具有 wireshark 的协议解析功能，它可以离线解析 pcap 数据包文件或实时监听设备并获得协议解析结果。
- Gowireshark基于[libpcap 1.10.4](https://www.tcpdump.org/release/)与[wireshark 4.0.7](https://www.wireshark.org/#download)编译后的动态链接库开发。

---

# Contents

- [1. 安装](#1-安装)
    - [1.1. 前置条件](#11-前置条件)
    - [1.2. 用法](#12-用法)
- [2. 详细说明](#2-详细说明)
    - [2.1. 项目目录](#21-项目目录)
    - [2.2. 调用链](#22-调用链)
    - [2.3. 编译dll](#23-编译dll)
- [3. 开发](#3-开发)
- [4. 路线图](#4-路线图)
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
cd tests/
go test -v -run TestDissectPrintFirstFrame
```

如何在我们的 golang 程序中解析 pcap 数据包文件：

```go
package main
   
import (
    "fmt"

    "github.com/randolphcyg/gowireshark"
)

func main() {
    filepath := "pcaps/s7comm_clean.pcap"
    err := gowireshark.DissectPrintFirstFrame(filepath)
    if err != nil {
        fmt.Println(err)
    }
}
```
其他示例可以参考[测试文件](https://github.com/randolphcyg/gowireshark/blob/main/tests/gowireshark_test.go)。

## 2. 详细说明

---

### 2.1. 项目目录
```
gowireshark/
├── README-zh.md
├── README.md
├── cJSON.c
├── frame_tvbuff.c
├── go.mod
├── go.sum
├── gowireshark.go
├── include/
│   ├── cJSON.h
│   ├── frame_tvbuff.h
│   ├── lib.h
│   ├── libpcap/
│   ├── offline.h
│   ├── online.h
│   ├── uthash.h
│   └── wireshark/
├── lib.c
├── libs/
│   ├── libpcap.so.1
│   ├── libwireshark.so -> libwireshark.so.16*
│   ├── libwireshark.so.16 -> libwireshark.so.16.0.7*
│   ├── libwireshark.so.16.0.7*
│   ├── libwiretap.so -> libwiretap.so.13*
│   ├── libwiretap.so.13 -> libwiretap.so.13.0.7*
│   ├── libwiretap.so.13.0.7*
│   ├── libwsutil.so -> libwsutil.so.14*
│   ├── libwsutil.so.14 -> libwsutil.so.14.0.0*
│   └── libwsutil.so.14.0.0*
├── offline.c
├── online.c
├── pcaps/
│   ├── s7comm_clean.pcap
│   └── wincc_s400_production.pcap
└── tests/
    └── gowireshark_test.go
```
项目目录结构的详细说明：

| 文件                                        | 说明                                                    |
|-------------------------------------------|-------------------------------------------------------|
| `include/wireshark/`                      | wireshark 编译后源码                                       |
| `include/libpcap/`                        | libpcap 未编译源码                                         |
| `frame_tvbuff.c`、`include/frame_tvbuff.h` | wireshark的源码文件、拷贝出来的、必须放在此处                           |
| `libs/`                                   | wireshark、libpcap最新动态链接库文件                            |
| `pcaps/`                                  | 用于测试的 pcap 数据包文件                                      |
| `tests/`                                  | 测试文件夹                                                 |
| `uthash.h`                                | 第三方 [uthash](https://github.com/troydhanson/uthash) 库 |
| `cJSON.c、cJSON.h`                         | 第三方[cJSON](https://github.com/DaveGamble/cJSON)库      |
| `lib.c、offline.c、online.c`                | 用C封装和加强libpcap和wireshark功能的代码                         |
| `include/lib.h、offline.h、online.h`        | 暴露给go的一些c接口                                           |
| `gowireshark.go`                          | 用go封装最终的接口，用户go程序可直接使用                                |

### 2.2. 调用链

```mermaid
graph LR
    A(golang)==cgo==>B(clang)
    B(clang)-.->C[wireshark dll]
    B(clang)-.->D[libpcap dll]
    style A fill:#FFCCCC
    style B fill:#99CCCC
    style C fill:#FFCC99,stroke:#FFCCCC,stroke-width:2px,stroke-dasharray: 5, 5
    style D fill:#FFCC99,stroke:#FFCCCC,stroke-width:2px,stroke-dasharray: 5, 5
```


### 2.3. 编译dll

如何编译wireshark, libpcap动态链接库?

如果编译的 wireshark 和 libpcap 动态链接库与当前项目支持的版本不同，请同时覆盖 `include/wireshark/` 和 `include/libpcap/` 目录;

注意，如果 wireshark 版本变化很大，本项目中的某些接口可能无效，但可以研究和修复;

<details>
<summary>1.编译wireshark动态链接库</summary>

```shell
# 确定最新发行版本并设置环境变量
export WIRESHARKV=4.0.7
# 到/opt目录下操作
cd /opt/
# 下载源码
wget https://1.as.dl.wireshark.org/src/wireshark-$WIRESHARKV.tar.xz
# 解压缩并修改文件夹名称
tar -xvf wireshark-$WIRESHARKV.tar.xz
mv wireshark-$WIRESHARKV wireshark
# 到/opt/wireshark目录操作
cd /opt/wireshark/

--------[首次编译需要检查下] 如何检查编译所需的依赖项-------------
# 根据输出的红色错误日志解决依赖项问题，直到发生 qt5 错误时忽略这些问题
cmake -LH ./

# 如果您没有 cmake3.20，请先安装它
wget https://cmake.org/files/LatestRelease/cmake-3.24.2.tar.gz
sudo tar -xzf cmake-3.24.2.tar.gz
cd cmake-3.24.2/
sudo ./bootstrap
sudo apt install build-essential -y

# 如果未安装 openSSL，请执行
sudo apt install libssl-dev  -y
sudo make
sudo make install
cmake --version

# 可能需要安装的依赖项
apt install libgcrypt-dev -y
apt install libc-ares-dev -y
apt install flex -y
apt install libglib2.0-dev -y
apt install libssl-dev -y
apt install ninja-build -y
apt install pcaputils -y
apt install libpcap-dev -y
# 我们不使用与 Qt5 相关的依赖项，可以忽略
apt install qtbase5-dev -y
apt install qttools5-dev-tools -y
apt install qttools5-dev -y
apt install qtmultimedia5-dev -y

# 根据问题解决完成情况，删除测试生成的文件
rm CMakeCache.txt
rm -rf CMakeFiles/
-------------------------------------------------------------------------------

# 在 /opt/wireshark/ 目录下创建一个用来构建的目录
mkdir build && cd build
# 构建[生产用]
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..
# 编译[时长略久]
ninja

# 编译成功后，进入build/run/目录查看编译后的动态链接库
cd run/ && ls -lh
# 覆盖替换原始的 9 个 wireshark 动态链接库文件
cd /opt/gowireshark/libs/
cp /opt/wireshark/build/run/lib*so* .
# 首先执行 步骤 [修正源码导入错误]
👇
👇
👇
# 覆盖 wireshark 源文件夹（先删除无用的 build/ 目录）
rm -rf /opt/wireshark/build/
# 将源码拷贝到项目前可以将原 /opt/gowireshark/include/wireshark/ 目录备份
cp -r /opt/wireshark/ /opt/gowireshark/include/wireshark/

# 查看项目目录结构 [项目目录父目录执行]
tree -L 2 -F gowireshark
```


[修正源码导入错误]
可以使用IDE批量修改
```shell
#include <ws_version.h>
#include <config.h>
// 在build后, 将生成文件 `ws_version.h` 和 `config.h`, 将它俩复制到wireshark根目录,最后在将`wireshark/`覆盖到项目`include/wireshark/`目录
cp /opt/wireshark/build/ws_version.h /opt/wireshark/ws_version.h
cp /opt/wireshark/build/config.h /opt/wireshark/config.h

#include "ws_symbol_export.h"
==>
#include "include/ws_symbol_export.h"

#include <ws_symbol_export.h>
==>
#include <include/ws_symbol_export.h>

#include <ws_attributes.h>
==>
#include <include/ws_attributes.h>

#include <ws_diag_control.h>
==>
#include <include/ws_diag_control.h>

#include <wireshark.h>
==>
#include <include/wireshark.h>
 
#include "ws_compiler_tests.h"
==>
#include "include/ws_compiler_tests.h"

#include <ws_compiler_tests.h>
==>
#include <include/ws_compiler_tests.h>

#include <ws_posix_compat.h>
==>
#include <include/ws_posix_compat.h>

#include <ws_log_defs.h>
==>
#include <include/ws_log_defs.h>

#include "ws_attributes.h"
==>
#include "include/ws_attributes.h"
```
</details>

<details>
<summary>2.编译libpcap动态链接库</summary>

```
# 确定最新发行版本并设置环境变量
export PCAPV=1.10.4
# 在/opt目录下操作
cd /opt
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
./configure --host=aarch64-linux --with-pcap=linux
# 编译
make

# 成功编译后，重命名动态链接库文件
mv libpcap.so.$PCAPV libpcap.so.1
# 最后替换原动态链接库文件
mv /opt/libpcap-$PCAPV/libpcap.so.1 /opt/gowireshark/libs/libpcap.so.1

---[非必须]---
# 如果没有flex、bison库，请先安装
apt install flex
apt install bison
------
```
</details>

## 3. 开发

---

1. 可以在 `lib.c、offline.c、online.c` 中或在根目录中创建一个新的C文件并添加自定义功能的接口;
2. 接口完成后需要在`include/`目录下同名H头文件增加声明，若`gowireshark.go`中也用到该接口，则需要在此文件的cgo序文中增加相同的声明；
3. 在`gowireshark.go`中封装该接口;
4. 在`tests/`目录下增加测试案例;
5. 使用 clang 格式工具格式化自定义的 C 代码和头文件：
   例如：`clang-format -i lib.c`，参数`-i`表示此命令直接格式化指定的文件，删除`-i`进行预览。
   修改根目录中的所有 .c 文件和 `include/` 目录中的所有 .h 头文件(注意用grep去掉第三方库文件例如cJSON)
  （只有当前目录是级别 1，不要向下遍历查找，即不格式化`include/wireshark/`与`include/libpcap/`下的源码文件）：

   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | grep -v 'frame_tvbuff.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'frame_tvbuff.h' | grep -v 'uthash.h' | xargs  clang-format -i
   ```
6. 如何测试(cd tests/):

    可以在`tests/`目录下编写测试函数，直接测试：
   ```shell
   # Parse and output the first frame
   go test -v -run TestDissectPrintFirstFrame
   # Parse and output a frame in JSON format
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # Parses and outputs a frame of HEX data
   go test -v -run TestGetSpecificFrameHexData
   # Parse packets in real time
   go test -v -run TestDissectPktLive
   # Real-time packet capture Read a certain number and parse it
   go test -v -run TestDissectPktLiveSpecificNum
   ```
   或者通过调用此库的方式测试。

7. `gowireshark.go`的原理:

    在序文中存在一些C语法的声明和导入，也有一些cgo参数，这样使用`go build`编译此go项目时，会自动将内部的C项目也编译进去：
    ```cgo
    # 可以在 Go 代码中调用动态链接库，需要的操作是：
    
    // 导入 libpcap 库将在 libs 目录中找到一个名为 libpcap.so.1 的动态链接库
    #cgo LDFLAGS: -L${SRCDIR}/libs -lpcap
    #cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
    // 这允许程序找到与libpcap动态链接库对应的源代码
    #cgo CFLAGS: -I${SRCDIR}/include/libpcap
    // 注释掉 c99 标准（如果有的话），否则调用 libpcap 时将无法识别u_int、u_short等类型
    //#cgo CFLAGS: -std=c99
    ```

## 4. 路线图

---

- [x] 离线数据包文件解析打印
- [x] 离线数据包文件解析并输出 JSON 格式结果
- [x] 离线数据包解析获取16进制相关数据
- [x] 实时监听接口并捕获数据包
- [x] 封装 go 调用实时解析的逻辑——通过 Unix 域套接字(AF_UNIX)将实时解析结果传输到 golang
- [x] 封装 go 对收到的 Golang 调用实时数据包解析结果的处理
- [x] 优化代码并解决内存泄漏问题，使实时接口可以长时间运行
- [x] 支持停止实时接口
- [ ] :punch: 支持多个设备的数据包捕获，并根据设备名称停止实时接口 (TODO bug待修复)
 

## 5. 格式说明

无论是直接读取文件还是抓包输出为json格式，原始json键值格式如下：

原生wireshark中的字段加了如下三个字段：
offset 偏移量
hex 16进制数据
ascii ascii字符

```shell
{
	"_index": "packets-2017-06-09",
	"_type": "doc",
	"_score": {},
	"offset": ["0000", "0010", "0020", "0030", "0040", "0050"],
	"hex": ["00 1c 06 1c 69 e4 20 47 47 87 d4 96 08 00 45 00", "00 47 74 d0 40 00 80 06 04 79 c0 a8 00 15 c0 a8", "00 02 ff 5b 00 66 50 19 95 08 00 03 b3 4d 50 18", "f7 f3 f4 01 00 00 03 00 00 1f 02 f0 80 32 01 00", "00 32 06 00 0e 00 00 04 01 12 0a 10 02 00 01 00", "00 82 00 00 00                                 "],
	"ascii": ["....i. GG.....E.", ".Gt.@....y......", "...[.fP......MP.", ".............2..", ".2..............", "....."],
	"_source": {
		"layers": {
			"frame": {
				"frame.encap_type": "1",
				"frame.time": "Jun  9, 2017 15:58:06.698040000 CST",
				"frame.offset_shift": "0.000000000",
				"frame.time_epoch": "1496995086.698040000",
				"frame.time_delta": "0.000931000",
				"frame.time_delta_displayed": "0.000931000",
				"frame.time_relative": "0.000000000",
				"frame.number": "3",
				"frame.len": "85",
				"frame.cap_len": "85",
				"frame.marked": "0",
				"frame.ignored": "0",
				"frame.protocols": "eth:ethertype:ip:tcp:tpkt:cotp:s7comm"
			},
			"eth": {
				"eth.dst": "00:1c:06:1c:69:e4",
				"eth.dst_tree": {
					"eth.dst_resolved": "SiemensN_1c:69:e4",
					"eth.dst.oui": "7174",
					"eth.dst.oui_resolved": "Siemens Numerical Control Ltd., Nanjing",
					"eth.addr": "00:1c:06:1c:69:e4",
					"eth.addr_resolved": "SiemensN_1c:69:e4",
					"eth.addr.oui": "7174",
					"eth.addr.oui_resolved": "Siemens Numerical Control Ltd., Nanjing",
					"eth.dst.lg": "0",
					"eth.lg": "0",
					"eth.dst.ig": "0",
					"eth.ig": "0"
				},
				"eth.src": "20:47:47:87:d4:96",
				"eth.src_tree": {
					"eth.src_resolved": "Dell_87:d4:96",
					"eth.src.oui": "2115399",
					"eth.src.oui_resolved": "Dell Inc.",
					"eth.addr": "20:47:47:87:d4:96",
					"eth.addr_resolved": "Dell_87:d4:96",
					"eth.addr.oui": "2115399",
					"eth.addr.oui_resolved": "Dell Inc.",
					"eth.src.lg": "0",
					"eth.lg": "0",
					"eth.src.ig": "0",
					"eth.ig": "0"
				},
				"eth.type": "0x0800"
			},
			"ip": {
				"ip.version": "4",
				"ip.hdr_len": "20",
				"ip.dsfield": "0x00",
				"ip.dsfield_tree": {
					"ip.dsfield.dscp": "0",
					"ip.dsfield.ecn": "0"
				},
				"ip.len": "71",
				"ip.id": "0x74d0",
				"ip.flags": "0x02",
				"ip.flags_tree": {
					"ip.flags.rb": "0",
					"ip.flags.df": "1",
					"ip.flags.mf": "0"
				},
				"ip.frag_offset": "0",
				"ip.ttl": "128",
				"ip.proto": "6",
				"ip.checksum": "0x0479",
				"ip.checksum.status": "2",
				"ip.src": "192.168.0.21",
				"ip.addr": "192.168.0.21",
				"ip.src_host": "192.168.0.21",
				"ip.host": "192.168.0.21",
				"ip.dst": "192.168.0.2",
				"ip.dst_host": "192.168.0.2"
			},
			"tcp": {
				"tcp.srcport": "65371",
				"tcp.dstport": "102",
				"tcp.port": "65371",
				"tcp.stream": "0",
				"tcp.completeness": "8",
				"tcp.len": "31",
				"tcp.seq": "32",
				"tcp.seq_raw": "1343853832",
				"tcp.nxtseq": "63",
				"tcp.ack": "27",
				"tcp.ack_raw": "242509",
				"tcp.hdr_len": "20",
				"tcp.flags": "0x0018",
				"tcp.flags_tree": {
					"tcp.flags.res": "0",
					"tcp.flags.ae": "0",
					"tcp.flags.cwr": "0",
					"tcp.flags.ece": "0",
					"tcp.flags.urg": "0",
					"tcp.flags.ack": "1",
					"tcp.flags.push": "1",
					"tcp.flags.reset": "0",
					"tcp.flags.syn": "0",
					"tcp.flags.fin": "0",
					"tcp.flags.str": "·······AP···"
				},
				"tcp.window_size_value": "63475",
				"tcp.window_size": "63475",
				"tcp.window_size_scalefactor": "-1",
				"tcp.checksum": "0xf401",
				"tcp.checksum.status": "2",
				"tcp.urgent_pointer": "0",
				"Timestamps": {
					"tcp.time_relative": "0.002279000",
					"tcp.time_delta": "0.000931000"
				},
				"tcp.analysis": {
					"tcp.analysis.acks_frame": "2",
					"tcp.analysis.ack_rtt": "0.000931000",
					"tcp.analysis.bytes_in_flight": "31",
					"tcp.analysis.push_bytes_sent": "31"
				},
				"tcp.payload": "03:00:00:1f:02:f0:80:32:01:00:00:32:06:00:0e:00:00:04:01:12:0a:10:02:00:01:00:00:82:00:00:00"
			},
			"tpkt": {
				"tpkt.version": "3",
				"tpkt.reserved": "0",
				"tpkt.length": "31"
			},
			"cotp": {
				"cotp.li": "2",
				"cotp.type": "0x0f",
				"cotp.destref": "0x0000",
				"cotp.tpdu-number": "0x00",
				"cotp.eot": "1"
			},
			"s7comm": {
				"s7comm.header": {
					"s7comm.header.protid": "0x32",
					"s7comm.header.rosctr": "1",
					"s7comm.header.redid": "0x0000",
					"s7comm.header.pduref": "12806",
					"s7comm.header.parlg": "14",
					"s7comm.header.datlg": "0"
				},
				"s7comm.param": {
					"s7comm.param.func": "0x04",
					"s7comm.param.itemcount": "1",
					"s7comm.param.item": {
						"s7comm.param.item.varspec": "0x12",
						"s7comm.param.item.varspec_length": "10",
						"s7comm.param.item.syntaxid": "0x10",
						"s7comm.param.item.transp_size": "2",
						"s7comm.param.item.length": "1",
						"s7comm.param.item.db": "0",
						"s7comm.param.item.area": "0x82",
						"s7comm.param.item.address": "0x000000",
						"s7comm.param.item.address_tree": {
							"s7comm.param.item.address.byte": "0",
							"s7comm.param.item.address.bit": "0"
						}
					}
				}
			}
		}
	}
}
```

## 6. 联系

有任何想讨论的，可以加QQ群:

- **301969140**

**内存泄露问题还未解决**