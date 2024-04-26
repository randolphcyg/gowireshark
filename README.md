# Gowireshark

README: [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md) | [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md)

- Provide the same packet processing capabilities as wireshark for Go
- Support offline or online parsing of data packets
- Based on [wireshark](https://www.wireshark.org/#download)、[libpcap](https://www.tcpdump.org/release/) dynamic link library

---

# Contents

- [Gowireshark](#gowireshark)
- [Contents](#contents)
    - [1. Installation](#1-installation)
        - [1.1. Requirements](#11-requirements)
        - [1.2. Usage](#12-usage)
    - [2. Detailed description](#2-detailed-description)
        - [2.1. Project directory](#21-project-directory)
        - [2.2. Call chain](#22-call-chain)
        - [2.3. Compile dll](#23-compile-dll)
        - [2.4. Parsing result format description](#24-parsing-result-format-description)
    - [3. Develop&Test](#3-developtest)
    - [4. Roadmap](#4-roadmap)
    - [5. Contact](#5-contact)

---

## 1. Installation

---

### 1.1. Requirements
- glib-2.0

```shell
# install glib-2.0
sudo apt install libglib2.0-dev -y
```

### 1.2. Usage

```shell
go get "github.com/randolphcyg/gowireshark"
```

how to test:

```shell
cd tests/
go test -v -run TestDissectPrintFirstFrame
```

how to dissect specific frame of a pcap file:

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

Other examples can refer to the [test file](https://github.com/randolphcyg/gowireshark/blob/main/tests/gowireshark_test.go).

## 2. Detailed description

---

### 2.1. Project directory
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
│   ├── libwireshark.so.17
│   ├── libwireshark.so.17.0.4
│   ├── libwiretap.so
│   ├── libwiretap.so.14
│   ├── libwiretap.so.14.1.4
│   ├── libwsutil.so
│   ├── libwsutil.so.15
│   └── libwsutil.so.15.0.0
├── offline.c
├── online.c
├── pcaps/
│   └── mysql.pcapng
└── tests/
    └── gowireshark_test.go
```
Detailed description of the project directory structure：

| file                                      | description                                                                                 |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| `include/wireshark/`                      | wireshark compiled source code                                                              |
| `include/libpcap/`                        | libpcap uncompiled source code                                                              |
| `frame_tvbuff.c`、`include/frame_tvbuff.h` | The wireshark source files, copied out, must be placed here                                 |
| `libs/`                                   | wireshark、libpcap latest dll files                                                          |
| `pcaps/`                                  | Pcap packet files used for testing                                                          |
| `tests/`                                  | Test files                                                                                  |
| `uthash.h`                                | Third-party [uthash](https://github.com/troydhanson/uthash) library                         |
| `cJSON.c、cJSON.h`                         | Third-party [cJSON](https://github.com/DaveGamble/cJSON) library                            |
| `lib.c、offline.c、online.c`                | Code that encapsulates and enhances libpcap and wireshark functionality in C                |
| `include/lib.h、offline.h、online.h`        | Some c interfaces exposed to go                                                             |
| `gowireshark.go`                          | The final interface is encapsulated with Go, and the user's Go program can be used directly |


- **lib.c、offline.c、online.c** 
- **include/lib.h、offline.h、online.h** The declaration of the wireshark interface is encapsulated in C and finally called by the Go encapsulation.
- **gowireshark.go** All external interfaces are encapsulated by Go.

### 2.2. Call chain

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


### 2.3. Compile dll

How to compile wireshark, libpcap dynamic link libraries?

If the compiled wireshark and libpcap dynamic link libraries are different from the supported versions of the current project, please cover the `include/wireshark/` and `include/libpcap/` directories simultaneously;

Note that some interfaces in this project may not be valid if the wireshark version changes a lot, but can be researched and fixed;

<details>
<summary>1.Compile the wireshark dynamic link library</summary>

```shell
# Determine the latest release version and set environment variables
export WIRESHARKV=4.2.4
# Operate in the /opt directory
cd /opt/
# Download the source code
wget https://1.as.dl.wireshark.org/src/wireshark-$WIRESHARKV.tar.xz
# Unzip and modify the folder name
tar -xvf wireshark-$WIRESHARKV.tar.xz
mv wireshark-$WIRESHARKV wireshark
# Operate in the /opt/wireshark directory
cd /opt/wireshark/

--------[The first compilation needs to be checked] How to check the dependencies required for compilation-------------
# Resolve dependency issues according to the output red error log until they are ignored when a qt5 error occurs
cmake -LH ./

# If you do not have cmake, please install it first
export CMAKEV=3.28.3
sudo wget https://cmake.org/files/LatestRelease/cmake-$CMAKEV.tar.gz
tar -xzf cmake-$CMAKEV.tar.gz
mv cmake-$CMAKEV cmake
cd /opt/cmake
sudo ./bootstrap
sudo make
sudo make install
cmake --version

# Dependencies that may need to be installed
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

# Dependent on the problem resolution complete, delete the files generated by the test
rm CMakeCache.txt
rm -rf CMakeFiles/
-------------------------------------------------------------------------------

# Create a build-specific directory under the /opt/wireshark/ directory
mkdir build && cd build
# Build [For production]
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..
# Compile[slightly longer]
ninja

# After successful compilation, enter the run directory to view the compiled dynamic link library
cd run/ && ls -lh
# Overwrites replaces the original 9 wireshark dynamic link library files
cd /opt/gowireshark/libs/
cp -r /opt/wireshark/build/run/lib*so* .
# first do step [modify source code import error]
👇
👇
👇
# Overwrite the wireshark source folder(Remove the useless build/ directory first)
rm -rf /opt/wireshark/build/
# Before copying the source code to the project, you can back up the original /opt/gowireshark/include/wireshark/ directory
cp -r /opt/wireshark/ /opt/gowireshark/include/wireshark/

# View project directory structure [project directory parent directory execution]
tree -L 2 -F gowireshark
```

[modify source code import error]
```shell
#include <ws_version.h>
#include <config.h>
after build, it genarate file `ws_version.h` and `config.h`
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
<summary>2.Compile the libpcap dynamic link library</summary>

```
# Determine the latest release version and set environment variables
export PCAPV=1.10.4
# Operate in the /opt directory
cd /opt
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
./configure --host=aarch64-linux --with-pcap=linux
# Compile
make

# After successful compilation, rename the dll file
mv libpcap.so.$PCAPV libpcap.so.1
# Finally, replace the original dll file
mv /opt/libpcap-$PCAPV/libpcap.so.1 /opt/gowireshark/libs/libpcap.so.1

---[unessential]---
# If there is no flex、bison library, please install first
apt install flex
apt install bison
------
```
</details>

### 2.4. Parsing result format description

1. New fields,Three fields have been added to the native wireshark parsing result：
   - offset
   - hex
   - ascii

2. Descriptive values
   - The native printing protocol tree interface`proto_tree_print`contains descriptive values, while the protocol JSON output interface`write_json_proto_tree`does not contain descriptive values,
     which can be improved by borrowing the implementation logic`proto_tree_print_node`of the former;
   - The modified interface`GetSpecificFrameProtoTreeInJson`parameter`isDescriptive`,corresponds to the`descriptive`parameter of the c interface`proto_tree_in_json`;
     Set to `false` to have no descriptive value for the field, and set to `true` for the field with a descriptive value;
   - Refer to`proto_item_fill_label`in`proto.h`:
       ```c
       /** Fill given label_str with a simple string representation of field.
        @param finfo the item to get the info from
        @param label_str the string to fill
        @todo think about changing the parameter profile */
       WS_DLL_PUBLIC void
       proto_item_fill_label(field_info *finfo, gchar *label_str);
       ```

    <details>
    <summary>1.output fields are original</summary>

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
    <summary>2.output fields are descriptive</summary>

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


## 3. Develop&Test

---

1. You can create a new C file in `lib.c, offline.c, online.c`'` or in the root directory and add interfaces for custom functions;
2. After the interface is completed, you need to add a declaration in the H header file with the same name in the `include/` directory, and if the interface is also used in `gowireshark.go`, you need to add the same declaration in the cgo preamble of this file;
3. encapsulate the interface in `gowireshark.go`;
4. Add test cases under `tests/` directory;
5. Use the clang-format tool to format custom C code and header files:
   E.g：`clang-format -i lib.c`，With the parameter '-i' indicates that this command directly formats the specified file, remove '-i' to preview.
   Modify all .c files in the root directory and all .h header files in the `include/` directory (note that third-party library files such as cJSON are removed with grep)
   (Only the current directory is level 1, do not traverse down the lookup, i.e. do not format the source files under `include/wireshark/` and `include/libpcap/`):
   
   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | grep -v 'frame_tvbuff.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'frame_tvbuff.h' | xargs  clang-format -i
   ```
6. how to test(cd tests/):
   ```shell
   # Parse and output the first frame
   go test -v -run TestDissectPrintFirstFrame
   # Parse and output a frame in JSON format
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # Parse and output all frame in JSON format
   go test -v -run TestGetAllFrameProtoTreeInJson
   # Parses and outputs a frame of HEX data
   go test -v -run TestGetSpecificFrameHexData
   # Parse packets in real time
   go test -v -run TestDissectPktLive
   # Real-time packet capture Read a certain number and parse it
   go test -v -run TestDissectPktLiveSpecificNum
   ```
   Or test by calling this library.

7. How `gowireshark.go` works:

   There are some C syntax declarations and imports in the preface, as well as some cgo parameters, so that when compiling this go project with `go build`, the internal C project will be automatically compiled into it:
    ```cgo
    # After the compilation is completed, modify 【libpcap.so.1.x.x】 to 【libpcap.so.1】, 
    # you can call the dynamic link library in the go code, and the required operations are:
    
    // Importing the libpcap library will find a dynamic link library named libpcap.so.1 in the libs directory
    #cgo LDFLAGS: -L${SRCDIR}/libs -lpcap
    #cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
    // This allows the program to find the source code corresponding to the libpcap dynamic link library
    #cgo CFLAGS: -I${SRCDIR}/include/libpcap
    // Comment out the c99 standard(if any), otherwise you will not recognize the u_int, u_short and other types when calling libpcap
    //#cgo CFLAGS: -std=c99
    ```

## 4. Roadmap

---

- [x] Offline packet file parsing printing
- [x] Offline packet files parse and output JSON format
- [x] Offline packet parsing to obtain base-16 related data
- [x] Listen to interfaces in real time and capture packets
- [x] Encapsulates the logic for go to invoke real-time parsing - transmits real-time parsing results to golang
- [x] Encapsulates Golang's processing of the received real-time packet parsing results for Golang calling
- [x] Optimize memory leakage and improve the performance of real-time packet capture and parsing interfaces[TODO]
- [x] Supports packet capture for multiple devices and stops packet capture based on device name
- [x] parser result support descriptive values