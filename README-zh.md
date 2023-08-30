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
	filepath := "pcaps/f1ap.pcapng"
	specificFrameDissectRes, err := gowireshark.GetSpecificFrameProtoTreeInJson(filepath, 5, true, true)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(specificFrameDissectRes)
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
│   ├── libwireshark.so*
│   ├── libwireshark.so.16*
│   ├── libwireshark.so.16.0.8*
│   ├── libwiretap.so*
│   ├── libwiretap.so.13*
│   ├── libwiretap.so.13.0.8*
│   ├── libwsutil.so*
│   ├── libwsutil.so.14*
│   └── libwsutil.so.14.0.0*
├── offline.c
├── online.c
├── pcaps/
│   ├── f1ap.pcapng
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
export WIRESHARKV=4.0.8
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
      "_index": "packets-2020-12-14",
      "offset": [
        "0000",
        "0010",
        "0020",
        "0030",
        "0040",
        "0050",
        "0060"
      ],
      "hex": [
        "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 02",
        "00 58 00 01 40 00 40 84 3c 1d 7f 00 00 01 7f 00",
        "00 01 98 3a 96 48 a6 25 c3 63 00 00 00 00 00 03",
        "00 38 e3 0b 04 a7 00 00 00 00 00 00 00 3e 40 01",
        "00 0e 00 00 02 00 4e 00 02 00 14 00 00 00 01 00",
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 d0 55",
        "79 4b 65 55 00 00                              "
      ],
      "ascii": [
        "..............E.",
        ".X..@.@.\u003c.......",
        "...:.H.%.c......",
        ".8...........\u003e@.",
        "......N.........",
        "...............U",
        "yKeU.."
      ],
      "_source": {
        "layers": {
          "eth": {
            "eth.dst": "00:00:00:00:00:00",
            "eth.dst_tree": {
              "eth.addr": "00:00:00:00:00:00",
              "eth.addr.oui": "0",
              "eth.addr_resolved": "00:00:00:00:00:00",
              "eth.dst.ig": "0",
              "eth.dst.lg": "0",
              "eth.dst.oui": "0",
              "eth.dst_resolved": "00:00:00:00:00:00",
              "eth.ig": "0",
              "eth.lg": "0"
            },
            "eth.src": "00:00:00:00:00:00",
            "eth.src_tree": {
              "eth.addr": "00:00:00:00:00:00",
              "eth.addr.oui": "0",
              "eth.addr_resolved": "00:00:00:00:00:00",
              "eth.ig": "0",
              "eth.lg": "0",
              "eth.src.ig": "0",
              "eth.src.lg": "0",
              "eth.src.oui": "0",
              "eth.src_resolved": "00:00:00:00:00:00"
            },
            "eth.type": "0x0800"
          },
          "f1ap": {
            "f1ap.F1AP_PDU": "1",
            "f1ap.F1AP_PDU_tree": {
              "f1ap.successfulOutcome_element": {
                "f1ap.criticality": "0",
                "f1ap.procedureCode": "1",
                "f1ap.value_element": {
                  "f1ap.F1SetupResponse_element": {
                    "f1ap.protocolIEs": "2",
                    "f1ap.protocolIEs_tree": {
                      "Item 0: id-TransactionID": {
                        "f1ap.ProtocolIE_Field_element": {
                          "f1ap.criticality": "0",
                          "f1ap.id": "78",
                          "f1ap.value_element": {
                            "f1ap.TransactionID": "20",
                            "per.extension_present_bit": "0"
                          },
                          "per.enum_index": "0",
                          "per.open_type_length": "2"
                        }
                      },
                      "Item 1: id-Cause": {
                        "f1ap.ProtocolIE_Field_element": {
                          "f1ap.criticality": "0",
                          "f1ap.id": "0",
                          "f1ap.value_element": {
                            "f1ap.Cause": "0",
                            "f1ap.Cause_tree": {
                              "f1ap.radioNetwork": "0",
                              "per.enum_index": "0",
                              "per.extension_present_bit": "0"
                            },
                            "per.choice_index": "0"
                          },
                          "per.enum_index": "0",
                          "per.open_type_length": "1"
                        }
                      }
                    },
                    "per.extension_bit": "0",
                    "per.sequence_of_length": "2"
                  }
                },
                "per.enum_index": "0",
                "per.open_type_length": "14"
              }
            },
            "per.choice_index": "1"
          },
          "frame": {
            "frame.cap_len": "102",
            "frame.encap_type": "1",
            "frame.ignored": "0",
            "frame.interface_id": "0",
            "frame.len": "102",
            "frame.marked": "0",
            "frame.number": "5",
            "frame.offset_shift": "0.000000000",
            "frame.protocols": "eth:ethertype:ip:sctp:f1ap",
            "frame.section_number": "1",
            "frame.time": "Dec 14, 2020 16:01:11.974420814 UTC",
            "frame.time_delta": "0.000021538",
            "frame.time_delta_displayed": "0.000021538",
            "frame.time_epoch": "1607961671.974420814",
            "frame.time_relative": "0.000000000"
          },
          "ip": {
            "ip.addr": "127.0.0.1",
            "ip.checksum": "0x3c1d",
            "ip.checksum.status": "2",
            "ip.dsfield": "0x02",
            "ip.dsfield_tree": {
              "ip.dsfield.dscp": "0",
              "ip.dsfield.ecn": "2"
            },
            "ip.dst": "127.0.0.1",
            "ip.dst_host": "127.0.0.1",
            "ip.flags": "0x02",
            "ip.flags_tree": {
              "ip.flags.df": "1",
              "ip.flags.mf": "0",
              "ip.flags.rb": "0"
            },
            "ip.frag_offset": "0",
            "ip.hdr_len": "20",
            "ip.host": "127.0.0.1",
            "ip.id": "0x0001",
            "ip.len": "88",
            "ip.proto": "132",
            "ip.src": "127.0.0.1",
            "ip.src_host": "127.0.0.1",
            "ip.ttl": "64",
            "ip.version": "4"
          },
          "sctp": {
            "DATA chunk (ordered, complete segment, TSN: 0, SID: 0, SSN: 0, PPID: 62, payload length: 40 bytes)": {
              "sctp.chunk_flags": "0x03",
              "sctp.chunk_flags_tree": {
                "sctp.data_b_bit": "1",
                "sctp.data_e_bit": "1",
                "sctp.data_i_bit": "0",
                "sctp.data_u_bit": "0"
              },
              "sctp.chunk_length": "56",
              "sctp.chunk_type": "0",
              "sctp.chunk_type_tree": {
                "sctp.chunk_bit_1": "0",
                "sctp.chunk_bit_2": "0"
              },
              "sctp.data_payload_proto_id": "62",
              "sctp.data_sid": "0x0000",
              "sctp.data_ssn": "0",
              "sctp.data_tsn": "0",
              "sctp.data_tsn_raw": "3809150119"
            },
            "sctp.assoc_index": "65535",
            "sctp.checksum": "0x00000000",
            "sctp.checksum.status": "2",
            "sctp.dstport": "38472",
            "sctp.port": "38970",
            "sctp.srcport": "38970",
            "sctp.verification_tag": "0xa625c363"
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
        "_index": "packets-2020-12-14",
        "_type": "doc",
        "_score": {},
        "offset": ["0000", "0010", "0020", "0030", "0040", "0050", "0060"],
        "hex": ["00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 02", "00 58 00 01 40 00 40 84 3c 1d 7f 00 00 01 7f 00", "00 01 98 3a 96 48 a6 25 c3 63 00 00 00 00 00 03", "00 38 e3 0b 04 a7 00 00 00 00 00 00 00 3e 40 01", "00 0e 00 00 02 00 4e 00 02 00 14 00 00 00 01 00", "00 00 00 00 00 00 00 00 00 00 00 00 00 00 d0 55", "79 4b 65 55 00 00                              "],
        "ascii": ["..............E.", ".X..@.@.<.......", "...:.H.%.c......", ".8...........>@.", "......N.........", "...............U", "yKeU.."],
        "_source": {
            "layers": {
                "frame": {
                    "frame.section_number": "1",
                    "frame.interface_id": "0",
                    "frame.encap_type": "Ethernet (1)",
                    "frame.time": "Dec 14, 2020 16:01:11.974420814 UTC",
                    "frame.offset_shift": "0.000000000 seconds",
                    "frame.time_epoch": "1607961671.974420814 seconds",
                    "frame.time_delta": "0.000021538 seconds",
                    "frame.time_delta_displayed": "0.000021538 seconds",
                    "frame.time_relative": "0.000000000 seconds",
                    "frame.number": "5",
                    "frame.len": "102",
                    "frame.cap_len": "102",
                    "frame.marked": "False",
                    "frame.ignored": "False",
                    "frame.protocols": "eth:ethertype:ip:sctp:f1ap"
                },
                "eth": {
                    "eth.dst": "00:00:00:00:00:00 (00:00:00:00:00:00)",
                    "eth.dst_tree": {
                        "eth.dst_resolved": "00:00:00:00:00:00",
                        "eth.dst.oui": "00:00:00",
                        "eth.addr": "00:00:00:00:00:00 (00:00:00:00:00:00)",
                        "eth.addr_resolved": "00:00:00:00:00:00",
                        "eth.addr.oui": "00:00:00",
                        "eth.dst.lg": "Globally unique address (factory default)",
                        "eth.lg": "Globally unique address (factory default)",
                        "eth.dst.ig": "Individual address (unicast)",
                        "eth.ig": "Individual address (unicast)"
                    },
                    "eth.src": "00:00:00:00:00:00 (00:00:00:00:00:00)",
                    "eth.src_tree": {
                        "eth.src_resolved": "00:00:00:00:00:00",
                        "eth.src.oui": "00:00:00",
                        "eth.addr": "00:00:00:00:00:00 (00:00:00:00:00:00)",
                        "eth.addr_resolved": "00:00:00:00:00:00",
                        "eth.addr.oui": "00:00:00",
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
                    "ip.dsfield": "0x02",
                    "ip.dsfield_tree": {
                        "ip.dsfield.dscp": "Default (0)",
                        "ip.dsfield.ecn": "ECN-Capable Transport codepoint '10' (2)"
                    },
                    "ip.len": "88",
                    "ip.id": "0x0001 (1)",
                    "ip.flags": "0x02",
                    "ip.flags_tree": {
                        "ip.flags.rb": "Not set",
                        "ip.flags.df": "Set",
                        "ip.flags.mf": "Not set"
                    },
                    "ip.frag_offset": "0",
                    "ip.ttl": "64",
                    "ip.proto": "SCTP (132)",
                    "ip.checksum": "0x3c1d",
                    "ip.checksum.status": "Unverified",
                    "ip.src": "127.0.0.1",
                    "ip.addr": "127.0.0.1",
                    "ip.src_host": "127.0.0.1",
                    "ip.host": "127.0.0.1",
                    "ip.dst": "127.0.0.1",
                    "ip.dst_host": "127.0.0.1"
                },
                "sctp": {
                    "sctp.srcport": "38970",
                    "sctp.dstport": "38472",
                    "sctp.verification_tag": "0xa625c363",
                    "sctp.assoc_index": "65535",
                    "sctp.port": "38970",
                    "sctp.checksum": "0x00000000",
                    "sctp.checksum.status": "Unverified",
                    "DATA chunk (ordered, complete segment, TSN: 0, SID: 0, SSN: 0, PPID: 62, payload length: 40 bytes)": {
                        "sctp.chunk_type": "DATA (0)",
                        "sctp.chunk_type_tree": {
                            "sctp.chunk_bit_1": "Stop processing of the packet",
                            "sctp.chunk_bit_2": "Do not report"
                        },
                        "sctp.chunk_flags": "0x03",
                        "sctp.chunk_flags_tree": {
                            "sctp.data_i_bit": "Possibly delay SACK",
                            "sctp.data_u_bit": "Ordered delivery",
                            "sctp.data_b_bit": "First segment",
                            "sctp.data_e_bit": "Last segment"
                        },
                        "sctp.chunk_length": "56",
                        "sctp.data_tsn": "0",
                        "sctp.data_tsn_raw": "3809150119",
                        "sctp.data_sid": "0x0000",
                        "sctp.data_ssn": "0",
                        "sctp.data_payload_proto_id": "F1 AP (62)"
                    }
                },
                "f1ap": {
                    "per.choice_index": "1",
                    "f1ap.F1AP_PDU": "successfulOutcome (1)",
                    "f1ap.F1AP_PDU_tree": {
                        "f1ap.successfulOutcome_element": {
                            "f1ap.procedureCode": "id-F1Setup (1)",
                            "per.enum_index": "0",
                            "f1ap.criticality": "reject (0)",
                            "per.open_type_length": "14",
                            "f1ap.value_element": {
                                "f1ap.F1SetupResponse_element": {
                                    "per.extension_bit": "0",
                                    "per.sequence_of_length": "2",
                                    "f1ap.protocolIEs": "2",
                                    "f1ap.protocolIEs_tree": {
                                        "Item 0: id-TransactionID": {
                                            "f1ap.ProtocolIE_Field_element": {
                                                "f1ap.id": "id-TransactionID (78)",
                                                "per.enum_index": "0",
                                                "f1ap.criticality": "reject (0)",
                                                "per.open_type_length": "2",
                                                "f1ap.value_element": {
                                                    "per.extension_present_bit": "0",
                                                    "f1ap.TransactionID": "20"
                                                }
                                            }
                                        },
                                        "Item 1: id-Cause": {
                                            "f1ap.ProtocolIE_Field_element": {
                                                "f1ap.id": "id-Cause (0)",
                                                "per.enum_index": "0",
                                                "f1ap.criticality": "reject (0)",
                                                "per.open_type_length": "1",
                                                "f1ap.value_element": {
                                                    "per.choice_index": "0",
                                                    "f1ap.Cause": "radioNetwork (0)",
                                                    "f1ap.Cause_tree": {
                                                        "per.extension_present_bit": "0",
                                                        "per.enum_index": "0",
                                                        "f1ap.radioNetwork": "unspecified (0)"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
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
- [x] 解析结果支持描述性值

## 5. 联系

有任何想讨论的，可以加QQ群:

- **301969140**

**内存泄露问题还未解决**