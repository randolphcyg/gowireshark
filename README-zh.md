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
    - [2. 详细说明](#2-详细说明)
        - [2.1. 项目目录](#21-项目目录)
        - [2.2. 调用链](#22-调用链)
        - [2.3. 编译dll](#23-编译dll)
        - [2.4. 解析结果格式说明](#24-解析结果格式说明)
    - [3. 开发测试](#3-开发测试)
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
go test -v -run TestDissectPrintAllFrame
```

如何解析 pcap 数据包文件的某一帧：

```go
package main

import (
	"fmt"

	"github.com/randolphcyg/gowireshark"
)

func main() {
	inputFilepath := "pcaps/mysql.pcapng"
	frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(inputFilepath, 65, true, true)
	if err != nil {
		fmt.Println(err)
	}

	colSrc := frameData.WsSource.Layers["_ws.col"]
	col, err := gowireshark.UnmarshalWsCol(colSrc)
	if err != nil {
		fmt.Println(err)
	}

	frameSrc := frameData.WsSource.Layers["frame"]
	frame, err := gowireshark.UnmarshalFrame(frameSrc)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("# Frame index:", col.Num)
	fmt.Println("## WsIndex:", frameData.WsIndex)
	fmt.Println("## Offset:", frameData.Offset)
	fmt.Println("## Hex:", frameData.Hex)
	fmt.Println("## Ascii:", frameData.Ascii)

	fmt.Println("【layer _ws.col】:", col)
	fmt.Println("【layer frame】:", frame)
}
```
其他示例可以参考[测试文件](https://github.com/randolphcyg/gowireshark/blob/main/gowireshark_test.go)。

## 2. 详细说明

---

### 2.1. 项目目录
```
gowireshark
├── LICENSE
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
│   ├── libwireshark.so
│   ├── libwireshark.so.18
│   ├── libwireshark.so.18.0.0
│   ├── libwiretap.so
│   ├── libwiretap.so.15
│   ├── libwiretap.so.15.0.0
│   ├── libwsutil.so
│   ├── libwsutil.so.16
│   └── libwsutil.so.16.0.0
├── offline.c
├── online.c
├── pcaps/
│   └── mysql.pcapng
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
| `gowireshark_test.go`                     | 测试文件                                                  |
| `uthash.h`                                | 第三方 [uthash](https://github.com/troydhanson/uthash) 库 |
| `cJSON.c、cJSON.h`                         | 第三方[cJSON](https://github.com/DaveGamble/cJSON)库      |
| `lib.c、offline.c、online.c`                | 用C封装和加强libpcap和wireshark功能的代码                         |
| `include/lib.h、offline.h、online.h`        | 暴露给go的一些c接口                                           |
| `gowireshark.go`                          | 用go封装最终的接口，用户go程序可直接使用                                |

### 2.2. 调用链

```
Golang =cgo=> Clang ==> Wireshark/libpcap DLL
```

### 2.3. 编译dll

如何编译wireshark, libpcap动态链接库?

如果编译的 wireshark 和 libpcap 动态链接库与当前项目支持的版本不同，请同时覆盖 `include/wireshark/` 和 `include/libpcap/` 目录;

注意，如果 wireshark 版本变化很大，本项目中的某些接口可能无效，但可以研究和修复;

<details>
<summary>1.编译wireshark动态链接库</summary>

```shell
# 确定最新发行版本并设置环境变量
export WIRESHARKV=4.4.0
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

# 如果没有 cmake，请先安装它
export CMAKEV=3.29.3
sudo wget https://cmake.org/files/LatestRelease/cmake-$CMAKEV.tar.gz
tar -xzf cmake-$CMAKEV.tar.gz
mv cmake-$CMAKEV cmake
cd /opt/cmake
sudo ./bootstrap
sudo make
sudo make install
cmake --version

# 可能需要安装的依赖项
sudo apt install build-essential -y
sudo apt install libgcrypt-dev -y
sudo apt install libc-ares-dev -y
sudo apt install flex -y
sudo apt install libglib2.0-dev -y
sudo apt install libssl-dev -y
sudo apt install ninja-build -y
sudo apt install pcaputils -y
sudo apt install libpcap-dev -y
# ubuntu
sudo apt install libxslt1-dev
sudo apt install doxygen
sudo apt install libspeexdsp-dev
# mac m1
sudo brew install libxslt1
sudo brew install doxygen
sudo brew install libspeexdsp-dev

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

#include <wireshark.h>
==>
#include <include/wireshark.h>

#include "ws_symbol_export.h"
==>
#include "include/ws_symbol_export.h"

#include <ws_symbol_export.h>
==>
#include <include/ws_symbol_export.h>

#include <ws_attributes.h>
==>
#include <include/ws_attributes.h>

#include <ws_log_defs.h>
==>
#include <include/ws_log_defs.h>

#include <ws_posix_compat.h>
==>
#include <include/ws_posix_compat.h>

#include <ws_diag_control.h>
==>
#include <include/ws_diag_control.h>

#include <ws_codepoints.h>
==>
#include <include/ws_codepoints.h>

#include "ws_attributes.h"
==>
#include "include/ws_attributes.h"

#include "ws_compiler_tests.h"
==>
#include "include/ws_compiler_tests.h"

#include <ws_compiler_tests.h>
==>
#include <include/ws_compiler_tests.h>
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

### 2.4. 解析结果格式说明

1. 增加的字段,在原生wireshark解析结果基础上增加了三个字段：
    - offset 偏移量
    - hex 16进制数据
    - ascii ascii字符

2. 描述性值逻辑来源
    - 原生的打印协议树接口`proto_tree_print`包含描述性值,而协议json输出接口`write_json_proto_tree`不包含描述性值,通过借鉴前者的实现逻辑`proto_tree_print_node`可以完善这个功能;
    - 修改后接口`GetSpecificFrameProtoTreeInJson`参数`isDescriptive`,对应c接口`proto_tree_in_json`的`descriptive`参数;设置为`false`则字段不带描述性值,设置为`true`则字段带描述性值;
    - 主要参考`proto.h`函数的`proto_item_fill_label`函数:
        ```c
        /** Fill given label_str with a simple string representation of field.
         @param finfo the item to get the info from
         @param label_str the string to fill
         @todo think about changing the parameter profile */
        WS_DLL_PUBLIC void
        proto_item_fill_label(field_info *finfo, gchar *label_str);
        ```

    <details>
    <summary>1.字段不带描述性值</summary>

    ```shell
    {
        "_index": "packets-2023-12-12",
        "_type": "doc",
        "_score": {},
        "offset": ["0000", "0010", "0020", "0030", "0040", "0050", "0060", "0070", "0080", "0090"],
        "hex": ["00 e0 4c 94 13 13 00 1c 42 b5 ef cf 08 00 45 00", "00 8d 2b 5f 40 00 40 06 76 97 c0 a8 0b d1 c0 a8", "0b 53 da 92 0c ea ed 32 0f 36 b0 a2 a1 de 80 18", "01 f6 75 85 00 00 01 01 08 0a 0a 2b 2d 19 cf 39", "56 d8 55 00 00 01 8d a2 0a 00 00 00 00 00 2d 00", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "00 00 00 00 00 00 72 6f 6f 74 00 14 36 f7 ff 52", "c6 43 b2 88 21 2d 6b 52 be 48 85 e7 c9 16 73 b2", "64 65 6d 6f 00 6d 79 73 71 6c 5f 6e 61 74 69 76", "65 5f 70 61 73 73 77 6f 72 64 00               "],
        "ascii": ["..L.....B.....E.", "..+_@.@.v.......", ".S.....2.6......", "..u........+-..9", "V.U...........-.", "................", "......root..6..R", ".C..!-kR.H....s.", "demo.mysql_nativ", "e_password."],
        "_source": {
            "layers": {
                "frame": {
                    "frame.section_number": "1",
                    "frame.interface_id": "0",
                    "frame.encap_type": "1",
                    "frame.time": "Dec 12, 2023 14:25:23.682836000 CST",
                    "frame.time_utc": "Dec 12, 2023 06:25:23.682836000 UTC",
                    "frame.time_epoch": "1702362323.682836000",
                    "frame.offset_shift": "0.000000000",
                    "frame.time_delta": "0.000028000",
                    "frame.time_delta_displayed": "0.000028000",
                    "frame.time_relative": "0.000000000",
                    "frame.number": "65",
                    "frame.len": "155",
                    "frame.cap_len": "155",
                    "frame.marked": "0",
                    "frame.ignored": "0",
                    "frame.protocols": "eth:ethertype:ip:tcp:mysql"
                },
                "eth": {
                    "eth.dst": "00:e0:4c:94:13:13",
                    "eth.dst_tree": {
                        "eth.dst_resolved": "RealtekSemic_94:13:13",
                        "eth.dst.oui": "57420",
                        "eth.dst.oui_resolved": "Realtek Semiconductor Corp.",
                        "eth.addr": "00:e0:4c:94:13:13",
                        "eth.addr_resolved": "RealtekSemic_94:13:13",
                        "eth.addr.oui": "57420",
                        "eth.addr.oui_resolved": "Realtek Semiconductor Corp.",
                        "eth.dst.lg": "0",
                        "eth.lg": "0",
                        "eth.dst.ig": "0",
                        "eth.ig": "0"
                    },
                    "eth.src": "00:1c:42:b5:ef:cf",
                    "eth.src_tree": {
                        "eth.src_resolved": "Parallels_b5:ef:cf",
                        "eth.src.oui": "7234",
                        "eth.src.oui_resolved": "Parallels, Inc.",
                        "eth.addr": "00:1c:42:b5:ef:cf",
                        "eth.addr_resolved": "Parallels_b5:ef:cf",
                        "eth.addr.oui": "7234",
                        "eth.addr.oui_resolved": "Parallels, Inc.",
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
                    "ip.len": "141",
                    "ip.id": "0x2b5f",
                    "ip.flags": "0x02",
                    "ip.flags_tree": {
                        "ip.flags.rb": "0",
                        "ip.flags.df": "1",
                        "ip.flags.mf": "0"
                    },
                    "ip.frag_offset": "0",
                    "ip.ttl": "64",
                    "ip.proto": "6",
                    "ip.checksum": "0x7697",
                    "ip.checksum.status": "2",
                    "ip.src": "192.168.11.209",
                    "ip.addr": "192.168.11.209",
                    "ip.src_host": "192.168.11.209",
                    "ip.host": "192.168.11.209",
                    "ip.dst": "192.168.11.83",
                    "ip.dst_host": "192.168.11.83"
                },
                "tcp": {
                    "tcp.srcport": "55954",
                    "tcp.dstport": "3306",
                    "tcp.port": "55954",
                    "tcp.stream": "1",
                    "tcp.completeness": "15",
                    "tcp.completeness_tree": {
                        "tcp.completeness.rst": "0",
                        "tcp.completeness.fin": "0",
                        "tcp.completeness.data": "1",
                        "tcp.completeness.ack": "1",
                        "tcp.completeness.syn-ack": "1",
                        "tcp.completeness.syn": "1",
                        "tcp.completeness.str": "··DASS"
                    },
                    "tcp.len": "89",
                    "tcp.seq": "1",
                    "tcp.seq_raw": "3979480886",
                    "tcp.nxtseq": "90",
                    "tcp.ack": "79",
                    "tcp.ack_raw": "2963448286",
                    "tcp.hdr_len": "32",
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
                    "tcp.window_size_value": "502",
                    "tcp.window_size": "64256",
                    "tcp.window_size_scalefactor": "128",
                    "tcp.checksum": "0x7585",
                    "tcp.checksum.status": "2",
                    "tcp.urgent_pointer": "0",
                    "tcp.options": "01:01:08:0a:0a:2b:2d:19:cf:39:56:d8",
                    "tcp.options_tree": {
                        "tcp.options.nop": "01",
                        "tcp.options.nop_tree": {
                            "tcp.option_kind": "1"
                        },
                        "tcp.options.timestamp": "08:0a:0a:2b:2d:19:cf:39:56:d8",
                        "tcp.options.timestamp_tree": {
                            "tcp.option_kind": "8",
                            "tcp.option_len": "10",
                            "tcp.options.timestamp.tsval": "170601753",
                            "tcp.options.timestamp.tsecr": "3476641496"
                        }
                    },
                    "Timestamps": {
                        "tcp.time_relative": "0.022846000",
                        "tcp.time_delta": "0.000028000"
                    },
                    "tcp.analysis": {
                        "tcp.analysis.initial_rtt": "0.000419000",
                        "tcp.analysis.bytes_in_flight": "89",
                        "tcp.analysis.push_bytes_sent": "89"
                    },
                    "tcp.payload": "55:00:00:01:8d:a2:0a:00:00:00:00:00:2d:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:72:6f:6f:74:00:14:36:f7:ff:52:c6:43:b2:88:21:2d:6b:52:be:48:85:e7:c9:16:73:b2:64:65:6d:6f:00:6d:79:73:71:6c:5f:6e:61:74:69:76:65:5f:70:61:73:73:77:6f:72:64:00",
                    "tcp.pdu.size": "89"
                },
                "mysql": {
                    "mysql.packet_length": "85",
                    "mysql.packet_number": "1",
                    "mysql.login_request": {
                        "mysql.caps.client": "0xa28d",
                        "mysql.caps.client_tree": {
                            "mysql.caps.lp": "1",
                            "mysql.caps.fr": "0",
                            "mysql.caps.lf": "1",
                            "mysql.caps.cd": "1",
                            "mysql.caps.ns": "0",
                            "mysql.caps.cp": "0",
                            "mysql.caps.ob": "0",
                            "mysql.caps.li": "1",
                            "mysql.caps.is": "0",
                            "mysql.caps.cu": "1",
                            "mysql.caps.ia": "0",
                            "mysql.caps.sl": "0",
                            "mysql.caps.ii": "0",
                            "mysql.caps.ta": "1",
                            "mysql.caps.rs": "0",
                            "mysql.caps.sc": "1"
                        },
                        "mysql.extcaps.client": "0x000a",
                        "mysql.extcaps.client_tree": {
                            "mysql.caps.ms": "0",
                            "mysql.caps.mr": "1",
                            "mysql.caps.pm": "0",
                            "mysql.caps.pa": "1",
                            "mysql.caps.ca": "0",
                            "mysql.caps.ep": "0",
                            "mysql.caps.session_track": "0",
                            "mysql.caps.deprecate_eof": "0",
                            "mysql.caps.optional_metadata": "0",
                            "mysql.caps.compress_zsd": "0",
                            "mysql.caps.query_attrs": "0",
                            "mysql.caps.mf_auth": "0",
                            "mysql.caps.cap_ext": "0",
                            "mysql.caps.vc": "0",
                            "mysql.caps.unused": "0x0000"
                        },
                        "mysql.max_packet": "0",
                        "mysql.charset": "45",
                        "mysql.unused": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
                        "mysql.user": "root",
                        "mysql.passwd": "36:f7:ff:52:c6:43:b2:88:21:2d:6b:52:be:48:85:e7:c9:16:73:b2",
                        "mysql.schema": "demo",
                        "mysql.client_auth_plugin": "mysql_native_password"
                    }
                },
                "_ws.col": {
                    "_ws.col.number": "65",
                    "_ws.col.cls_time": "0.000000",
                    "_ws.col.def_src": "192.168.11.209",
                    "_ws.col.def_dst": "192.168.11.83",
                    "_ws.col.protocol": "MySQL",
                    "_ws.col.packet_length": "155",
                    "_ws.col.info": "Login Request user=root db=demo "
                }
            }
        }
    }
    ```
    </details>

    <details>
    <summary>2.字段带描述性值</summary>

    ```shell
    {
        "_index": "packets-2023-12-12",
        "_type": "doc",
        "_score": {},
        "offset": ["0000", "0010", "0020", "0030", "0040", "0050", "0060", "0070", "0080", "0090"],
        "hex": ["00 e0 4c 94 13 13 00 1c 42 b5 ef cf 08 00 45 00", "00 8d 2b 5f 40 00 40 06 76 97 c0 a8 0b d1 c0 a8", "0b 53 da 92 0c ea ed 32 0f 36 b0 a2 a1 de 80 18", "01 f6 75 85 00 00 01 01 08 0a 0a 2b 2d 19 cf 39", "56 d8 55 00 00 01 8d a2 0a 00 00 00 00 00 2d 00", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", "00 00 00 00 00 00 72 6f 6f 74 00 14 36 f7 ff 52", "c6 43 b2 88 21 2d 6b 52 be 48 85 e7 c9 16 73 b2", "64 65 6d 6f 00 6d 79 73 71 6c 5f 6e 61 74 69 76", "65 5f 70 61 73 73 77 6f 72 64 00               "],
        "ascii": ["..L.....B.....E.", "..+_@.@.v.......", ".S.....2.6......", "..u........+-..9", "V.U...........-.", "................", "......root..6..R", ".C..!-kR.H....s.", "demo.mysql_nativ", "e_password."],
        "_source": {
            "layers": {
                "frame": {
                    "frame.section_number": "1",
                    "frame.interface_id": "0",
                    "frame.encap_type": "Ethernet (1)",
                    "frame.time": "Dec 12, 2023 14:25:23.682836000 CST",
                    "frame.time_utc": "Dec 12, 2023 06:25:23.682836000 UTC",
                    "frame.time_epoch": "1702362323.682836000",
                    "frame.offset_shift": "0.000000000 seconds",
                    "frame.time_delta": "0.000028000 seconds",
                    "frame.time_delta_displayed": "0.000028000 seconds",
                    "frame.time_relative": "0.000000000 seconds",
                    "frame.number": "65",
                    "frame.len": "155",
                    "frame.cap_len": "155",
                    "frame.marked": "False",
                    "frame.ignored": "False",
                    "frame.protocols": "eth:ethertype:ip:tcp:mysql"
                },
                "eth": {
                    "eth.dst": "RealtekSemic_94:13:13 (00:e0:4c:94:13:13)",
                    "eth.dst_tree": {
                        "eth.dst_resolved": "RealtekSemic_94:13:13",
                        "eth.dst.oui": "00:e0:4c (Realtek Semiconductor",
                        "eth.dst.oui_resolved": "Realtek Semiconductor Corp.",
                        "eth.addr": "RealtekSemic_94:13:13 (00:e0:4c:94:13:13)",
                        "eth.addr_resolved": "RealtekSemic_94:13:13",
                        "eth.addr.oui": "00:e0:4c (Realtek Semiconductor",
                        "eth.addr.oui_resolved": "Realtek Semiconductor Corp.",
                        "eth.dst.lg": "Globally unique address (factory default)",
                        "eth.lg": "Globally unique address (factory default)",
                        "eth.dst.ig": "Individual address (unicast)",
                        "eth.ig": "Individual address (unicast)"
                    },
                    "eth.src": "Parallels_b5:ef:cf (00:1c:42:b5:ef:cf)",
                    "eth.src_tree": {
                        "eth.src_resolved": "Parallels_b5:ef:cf",
                        "eth.src.oui": "00:1c:42 (Parallels, Inc.)",
                        "eth.src.oui_resolved": "Parallels, Inc.",
                        "eth.addr": "Parallels_b5:ef:cf (00:1c:42:b5:ef:cf)",
                        "eth.addr_resolved": "Parallels_b5:ef:cf",
                        "eth.addr.oui": "00:1c:42 (Parallels, Inc.)",
                        "eth.addr.oui_resolved": "Parallels, Inc.",
                        "eth.src.lg": "Globally unique address (factory default)",
                        "eth.lg": "Globally unique address (factory default)",
                        "eth.src.ig": "Individual address (unicast)",
                        "eth.ig": "Individual address (unicast)"
                    },
                    "eth.type": "IPv4 (0x0800)"
                },
                "ip": {
                    "ip.version": "4",
                    "ip.hdr_len": "20",
                    "ip.dsfield": "0x00",
                    "ip.dsfield_tree": {
                        "ip.dsfield.dscp": "Default (0)",
                        "ip.dsfield.ecn": "Not ECN-Capable Transport (0)"
                    },
                    "ip.len": "141",
                    "ip.id": "0x2b5f (11103)",
                    "ip.flags": "0x02",
                    "ip.flags_tree": {
                        "ip.flags.rb": "Not set",
                        "ip.flags.df": "Set",
                        "ip.flags.mf": "Not set"
                    },
                    "ip.frag_offset": "0",
                    "ip.ttl": "64",
                    "ip.proto": "TCP (6)",
                    "ip.checksum": "0x7697",
                    "ip.checksum.status": "Unverified",
                    "ip.src": "192.168.11.209",
                    "ip.addr": "192.168.11.209",
                    "ip.src_host": "192.168.11.209",
                    "ip.host": "192.168.11.209",
                    "ip.dst": "192.168.11.83",
                    "ip.dst_host": "192.168.11.83"
                },
                "tcp": {
                    "tcp.srcport": "55954",
                    "tcp.dstport": "3306",
                    "tcp.port": "55954",
                    "tcp.stream": "1",
                    "tcp.completeness": "Incomplete, DATA (15)",
                    "tcp.completeness_tree": {
                        "tcp.completeness.rst": "Absent",
                        "tcp.completeness.fin": "Absent",
                        "tcp.completeness.data": "Present",
                        "tcp.completeness.ack": "Present",
                        "tcp.completeness.syn-ack": "Present",
                        "tcp.completeness.syn": "Present",
                        "tcp.completeness.str": "··DASS"
                    },
                    "tcp.len": "89",
                    "tcp.seq": "1",
                    "tcp.seq_raw": "3979480886",
                    "tcp.nxtseq": "90",
                    "tcp.ack": "79",
                    "tcp.ack_raw": "2963448286",
                    "tcp.hdr_len": "32",
                    "tcp.flags": "0x0018",
                    "tcp.flags_tree": {
                        "tcp.flags.res": "Not set",
                        "tcp.flags.ae": "Not set",
                        "tcp.flags.cwr": "Not set",
                        "tcp.flags.ece": "Not set",
                        "tcp.flags.urg": "Not set",
                        "tcp.flags.ack": "Set",
                        "tcp.flags.push": "Set",
                        "tcp.flags.reset": "Not set",
                        "tcp.flags.syn": "Not set",
                        "tcp.flags.fin": "Not set",
                        "tcp.flags.str": "·······AP···"
                    },
                    "tcp.window_size_value": "502",
                    "tcp.window_size": "64256",
                    "tcp.window_size_scalefactor": "128",
                    "tcp.checksum": "0x7585",
                    "tcp.checksum.status": "Unverified",
                    "tcp.urgent_pointer": "0",
                    "tcp.options": "01:01:08:0a:0a:2b:2d:19:cf:39:56:d8",
                    "tcp.options_tree": {
                        "tcp.options.nop": "01",
                        "tcp.options.nop_tree": {
                            "tcp.option_kind": "No-Operation (1)"
                        },
                        "tcp.options.timestamp": "08:0a:0a:2b:2d:19:cf:39:56:d8",
                        "tcp.options.timestamp_tree": {
                            "tcp.option_kind": "Time Stamp Option (8)",
                            "tcp.option_len": "10",
                            "tcp.options.timestamp.tsval": "170601753",
                            "tcp.options.timestamp.tsecr": "3476641496"
                        }
                    },
                    "Timestamps": {
                        "tcp.time_relative": "0.022846000 seconds",
                        "tcp.time_delta": "0.000028000 seconds"
                    },
                    "tcp.analysis": {
                        "tcp.analysis.initial_rtt": "0.000419000 seconds",
                        "tcp.analysis.bytes_in_flight": "89",
                        "tcp.analysis.push_bytes_sent": "89"
                    },
                    "tcp.payload": "55:00:00:01:8d:a2:0a:00:00:00:00:00:2d:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:72:6f:6f:74:00:14:36:f7:ff:52:c6:43:b2:88:21:2d:6b:52:be:48:85:e7:c9:16:73:b2:64:65:6d:6f:00:6d:79:73:71:6c:5f:6e:61:74:69:76:65:5f:70:61:73:73:77:6f:72:64:00",
                    "tcp.pdu.size": "89"
                },
                "mysql": {
                    "mysql.packet_length": "85",
                    "mysql.packet_number": "1",
                    "mysql.login_request": {
                        "mysql.caps.client": "0xa28d",
                        "mysql.caps.client_tree": {
                            "mysql.caps.lp": "Set",
                            "mysql.caps.fr": "Not set",
                            "mysql.caps.lf": "Set",
                            "mysql.caps.cd": "Set",
                            "mysql.caps.ns": "Not set",
                            "mysql.caps.cp": "Not set",
                            "mysql.caps.ob": "Not set",
                            "mysql.caps.li": "Set",
                            "mysql.caps.is": "Not set",
                            "mysql.caps.cu": "Set",
                            "mysql.caps.ia": "Not set",
                            "mysql.caps.sl": "Not set",
                            "mysql.caps.ii": "Not set",
                            "mysql.caps.ta": "Set",
                            "mysql.caps.rs": "Not set",
                            "mysql.caps.sc": "Set"
                        },
                        "mysql.extcaps.client": "0x000a",
                        "mysql.extcaps.client_tree": {
                            "mysql.caps.ms": "Not set",
                            "mysql.caps.mr": "Set",
                            "mysql.caps.pm": "Not set",
                            "mysql.caps.pa": "Set",
                            "mysql.caps.ca": "Not set",
                            "mysql.caps.ep": "Not set",
                            "mysql.caps.session_track": "Not set",
                            "mysql.caps.deprecate_eof": "Not set",
                            "mysql.caps.optional_metadata": "Not set",
                            "mysql.caps.compress_zsd": "Not set",
                            "mysql.caps.query_attrs": "Not set",
                            "mysql.caps.mf_auth": "Not set",
                            "mysql.caps.cap_ext": "Not set",
                            "mysql.caps.vc": "Not set",
                            "mysql.caps.unused": "0x0"
                        },
                        "mysql.max_packet": "0",
                        "mysql.charset": "utf8mb4 COLLATE utf8mb4_general_ci (45)",
                        "mysql.unused": "0000000000000000000000000000000000000000000000",
                        "mysql.user": "root",
                        "mysql.passwd": "36f7ff52c643b288212d6b52be4885e7c91673b2",
                        "mysql.schema": "demo",
                        "mysql.client_auth_plugin": "mysql_native_password"
                    }
                },
                "_ws.col": {
                    "_ws.col.number": "65",
                    "_ws.col.cls_time": "0.000000",
                    "_ws.col.def_src": "192.168.11.209",
                    "_ws.col.def_dst": "192.168.11.83",
                    "_ws.col.protocol": "MySQL",
                    "_ws.col.packet_length": "155",
                    "_ws.col.info": "Login Request user=root db=demo "
                }
            }
        }
    }
    ```
    </details>

## 3. 开发测试

---

1. 可以在 `lib.c、offline.c、online.c` 中或在根目录中创建一个新的C文件并添加自定义功能的接口;
2. 接口完成后需要在`include/`目录下同名H头文件增加声明，若`gowireshark.go`中也用到该接口，则需要在此文件的cgo序文中增加相同的声明；
3. 在`gowireshark.go`中封装该接口;
4. 在`gowireshark_test.go`文件中增加测试案例;
5. 使用 clang 格式工具格式化自定义的 C 代码和头文件：
   例如：`clang-format -i lib.c`，参数`-i`表示此命令直接格式化指定的文件，删除`-i`进行预览。
   修改根目录中的所有 .c 文件和 `include/` 目录中的所有 .h 头文件(注意用grep去掉第三方库文件例如cJSON)
   （只有当前目录是级别 1，不要向下遍历查找，即不格式化`include/wireshark/`与`include/libpcap/`下的源码文件）：

   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | grep -v 'frame_tvbuff.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'frame_tvbuff.h' | grep -v 'uthash.h' | xargs  clang-format -i
   ```
6. 测试:

   可以在`gowireshark_test.go`文件中编写测试函数，直接测试：
   ```shell
   # 解析并输出一个流量包文件所有帧
   go test -v -run TestDissectPrintAllFrame
   # 解析并输出一个流量包文件特定帧,并以json格式呈现
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # 解析并输出一个流量包文件多个选定帧,并以json格式呈现
   go test -v -run TestGetSeveralFrameProtoTreeInJson
   # 解析并输出一个流量包文件所有帧,并以json格式呈现
   go test -v -run TestGetAllFrameProtoTreeInJson
   # 解析并输出一个流量包文件特定帧的16进制数据,并以json格式呈现
   go test -v -run TestGetSpecificFrameHexData
   # 实时抓包解析
   go test -v -run TestDissectPktLive
   # 实时抓取一定数目包并解析
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
- [x] 封装 go 调用实时解析的逻辑——通过回调函数将实时解析结果传输到 golang
- [x] 封装 go 对收到的 Golang 调用实时数据包解析结果的处理
- [x] 优化代码并解决内存泄漏问题，使实时接口可以长时间运行[TODO]
- [x] 支持多个设备的数据包捕获，并根据设备名称停止实时接口
- [x] 解析结果支持描述性值

## 5. 联系

QQ群: **301969140**