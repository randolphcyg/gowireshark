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

how to dissect a pcap file in our golang program:

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

Other examples can refer to the [test file](https://github.com/randolphcyg/gowireshark/blob/main/tests/gowireshark_test.go).

## 2. Detailed description

---

### 2.1. Project directory
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
export WIRESHARKV=4.0.8
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

# If you do not have cmake3.20, please install it first
wget https://cmake.org/files/LatestRelease/cmake-3.24.2.tar.gz
sudo tar -xzf cmake-3.24.2.tar.gz
cd cmake-3.24.2/
sudo ./bootstrap
sudo apt install build-essential -y

# If openSSL is not installed, execute it
sudo apt install libssl-dev  -y
sudo make
sudo make install
cmake --version

# Dependencies that may need to be installed
apt install libgcrypt-dev -y
apt install libc-ares-dev -y
apt install flex -y
apt install libglib2.0-dev -y
apt install libssl-dev -y
apt install ninja-build -y
apt install pcaputils -y
apt install libpcap-dev -y
# Qt5-related dependencies are not used and can be ignored
apt install qtbase5-dev -y
apt install qttools5-dev-tools -y
apt install qttools5-dev -y
apt install qtmultimedia5-dev -y

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
   - The modified interface`GetSpecificFrameProtoTreeInJson`parameter`isDescriptive`,corresponds to the`descriptive`parameter of the c interface`proto_tree_in_json`参数;
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
    <summary>2.output fields are descriptive</summary>

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
    # After the compilation is completed, modify 【libpcap.so.1.10.4】 to 【libpcap.so.1】, 
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
- [x] Encapsulates the logic for go to invoke real-time parsing - transmits real-time parsing results to golang via Unix domain sockets (AF_UNIX)
- [x] Encapsulates Golang's processing of the received real-time packet parsing results for Golang calling
- [x] Optimize code to resolve memory leaks
- [x] Stop real-time packet capture parsing
- [x] Optimize memory leakage and improve the performance of real-time packet capture and parsing interfaces
- [ ] :punch: Supports packet capture for multiple devices and stops packet capture based on device name (TODO Bugs to be fixed)
- [ ] handle_packet func: memory leakage
- [x] parser result support descriptive values


## 5. Contact

If you have anything you want to communicate, please join the QQ group: 

- **301969140**