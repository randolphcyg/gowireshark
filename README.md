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
        - [1.3. Quick Start (Docker)](#13-Quick-Start-Docker)
    - [2. Detailed description](#2-detailed-description)
        - [2.1. Project directory](#21-project-directory)
        - [2.2. Call chain](#22-call-chain)
        - [2.3. Parsing result format description](#24-parsing-result-format-description)
    - [3. Roadmap](#3-roadmap)

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
go test -v -run TestEpanVersion
```

1. Fetches a specific page of frames using pagination.

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

	// Optimized Pagination: Returns frames for the page and the TOTAL record count
	frames, totalCount, err := pkg.GetFramesByPage(filepath, page, size)
	if err != nil {
		panic(err)
	}

	// Calculate total pages on the client side
	totalPages := (totalCount + size - 1) / size

	fmt.Printf("Total Records: %d\n", totalCount)
	fmt.Printf("Total Pages: %d\n", totalPages)
	fmt.Printf("Current Page: %d\n", page)

	for _, frame := range frames {
		fmt.Printf("Frame %d: %s\n", frame.BaseLayers.Frame.Number, frame.BaseLayers.WsCol.Protocol)
	}
}
```

Other examples can refer to the `*_test.go`.


### 1.3. Quick Start (Docker)

The easiest way to use gowireshark is via Docker, which provides a pre-compiled environment with Wireshark and all dependencies.

**Build & Run:**

```shell
# 1. Build the image
docker build -t gowireshark:latest . --platform linux/amd64

# 2. Run the service (Map your pcap directory to /gowireshark/pcaps)
docker run -d \
  --name gowireshark \
  -p 18090:8090 \
  -v $(pwd)/pcaps/:/app/pcaps/ \
  gowireshark:latest
```

**API Examples:**
```shell
# 1. Get Wireshark Version
curl -X GET http://localhost:18090/api/v1/version/wireshark

# 2. Pagination Query (High Performance)
curl -X POST \
  http://localhost:18090/api/v1/frames/page \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/mysql.pcapng",
    "page": 1,
    "size": 20,
    "isDebug": true
}'

# 3. Random Access by Frame IDs
curl -X POST \
  http://localhost:18090/api/v1/frames/idxs \
  -H "Content-Type: application/json" \
  -d '{
    "filepath": "/app/pcaps/mysql.pcapng",
    "frameIdxs": [1, 5, 10, 32],
    "isDebug": false
}'
```

## 2. Detailed description

---

### 2.1. Project directory
```
gowireshark
├── cmd/  
├── pkg/          
│   ├── lib.c/h     
│   ├── online.go   
│   └── offline.go               
└── Dockerfile          
```
Detailed description of the project directory structure：

| file                                               | description                                                                               |
|----------------------------------------------------|-------------------------------------------------------------------------------------------|
| `lib.c, offline.c, online.c, reassembly.c`         | C language code that encapsulates and extends libpcap and Wireshark native functionality. |
| `layers.go`                                        | Common network protocol layer parser (Go implementation).                                 |
| `registry.go`                                      | Provide custom protocol parser registration for users.                                    |
| `online.go, offline.go, etc.`                      | Final Go encapsulation layer, provide out-of-the-box APIs for user's Go program.          |


### 2.2. Call chain

```
Golang =cgo=> Clang ==> Wireshark/libpcap DLL
```

### 2.3. Parsing result format description

1. Hexadecimal related fields are separated from the protocol parsing results：
   - offset
   - hex
   - ascii

2. Descriptive values
   - The native printing protocol tree interface`proto_tree_print`contains descriptive values, while the protocol JSON output interface`write_json_proto_tree`does not contain descriptive values,
     which can be improved by borrowing the implementation logic`proto_tree_print_node`of the former;
   - Refer to`proto_item_fill_label`in`proto.h`:
       ```c
       /** Fill given label_str with a simple string representation of field.
       @param finfo the item to get the info from
       @param label_str the string to fill
       @param value_offset offset to the value in label_str
       @todo think about changing the parameter profile */
       WS_DLL_PUBLIC void
       proto_item_fill_label(const field_info *finfo, char *label_str, size_t *value_offset);
       ```
     
## 3. Roadmap

---

- [x] Offline packet file parsing printing
- [x] Offline packet files parse and output JSON format
- [x] Offline packet parsing to obtain base-16 related data
- [x] Listen to interfaces in real time and capture packets
- [x] Encapsulates the logic for go to invoke real-time parsing - transmits real-time parsing results to golang
- [x] Encapsulates Golang's processing of the received real-time packet parsing results for Golang calling
- [x] Optimize memory leakage and improve the performance of real-time packet capture and parsing interfaces
- [x] Supports packet capture for multiple devices and stops packet capture based on device name
- [x] parser result support descriptive values
- [x] Support Set rsa keys to parse the TLS protocol, offline and real-time
- [x] Support for optional parameters
- [x] Users can register custom protocol parsers
- [x] Supports extracting files from the HTTP protocol
- [x] Supports follow TCP streams