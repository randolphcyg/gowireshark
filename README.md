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
go test -v -run TestDissectPrintAllFrame
```

1. Dissect all frame of a pcap file

```go
package main

import (
	"fmt"

	"github.com/randolphcyg/gowireshark"
)

func main() {
	inputFilepath := "pcaps/mysql.pcapng"
	res, err := gowireshark.GetAllFrameProtoTreeInJson(inputFilepath,
		gowireshark.WithDescriptive(true), gowireshark.WithDebug(false))
	if err != nil {
		panic(err)
	}

	for _, frameRes := range res {
		fmt.Println("# Frame index:", frameRes.BaseLayers.WsCol.Num, "===========================")
		fmt.Println("## Hex:", frameRes.Hex)
		fmt.Println("## Ascii:", frameRes.Ascii)

		if frameRes.BaseLayers.Ip != nil {
			fmt.Println("## ip.src:", frameRes.BaseLayers.Ip.Src)
			fmt.Println("## ip.dst:", frameRes.BaseLayers.Ip.Dst)
		}
		if frameRes.BaseLayers.Http != nil {
			fmt.Println("## http.request.uri:", frameRes.BaseLayers.Http.RequestUri)
		}
		if frameRes.BaseLayers.Dns != nil {
			fmt.Println("## dns:", frameRes.BaseLayers.Dns)
		}
	}
}
```

2. parse custom protocol

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
	"github.com/randolphcyg/gowireshark"
)

type MySQLCapsTree struct {
	CD string `json:"mysql.caps.cd"` // Capability: CLIENT_DEPRECATED
	CP string `json:"mysql.caps.cp"` // Capability: CLIENT_PROTOCOL
	CU string `json:"mysql.caps.cu"` // Capability: CLIENT_USER
	FR string `json:"mysql.caps.fr"` // Capability: CLIENT_FOUND_ROWS
	IA string `json:"mysql.caps.ia"` // Capability: CLIENT_IGNORE_SPACE
	II string `json:"mysql.caps.ii"` // Capability: CLIENT_INTERACTIVE
	IS string `json:"mysql.caps.is"` // Capability: CLIENT_IGNORE_SIGPIPE
	LF string `json:"mysql.caps.lf"` // Capability: CLIENT_LONG_FLAG
	LI string `json:"mysql.caps.li"` // Capability: CLIENT_LONG_PASSWORD
	LP string `json:"mysql.caps.lp"` // Capability: CLIENT_LOCAL_FILES
	NS string `json:"mysql.caps.ns"` // Capability: CLIENT_NO_SCHEMA
	OB string `json:"mysql.caps.ob"` // Capability: CLIENT_ODBC
	RS string `json:"mysql.caps.rs"` // Capability: CLIENT_RESERVED
	SC string `json:"mysql.caps.sc"` // Capability: CLIENT_SSL_COMPRESS
	SL string `json:"mysql.caps.sl"` // Capability: CLIENT_SSL
	TA string `json:"mysql.caps.ta"` // Capability: CLIENT_TRANSACTIONS
}

type MySQLExtCapsTree struct {
	CA               string `json:"mysql.caps.ca"`                // Extended Capability: CLIENT_AUTH
	CapExt           string `json:"mysql.caps.cap_ext"`           // Extended Capability
	CD               string `json:"mysql.caps.cd"`                // Extended Capability: CLIENT_DEPRECATED
	CompressZSD      string `json:"mysql.caps.compress_zsd"`      // Extended Capability
	DeprecateEOF     string `json:"mysql.caps.deprecate_eof"`     // Extended Capability: CLIENT_DEPRECATE_EOF
	EP               string `json:"mysql.caps.ep"`                // Extended Capability
	MFAuth           string `json:"mysql.caps.mf_auth"`           // Extended Capability: Multi-factor Authentication
	MR               string `json:"mysql.caps.mr"`                // Extended Capability: Multi-Resultsets
	MS               string `json:"mysql.caps.ms"`                // Extended Capability: Multi-Statements
	OptionalMetadata string `json:"mysql.caps.optional_metadata"` // Optional Metadata
	PA               string `json:"mysql.caps.pa"`                // Plugin Authentication
	PM               string `json:"mysql.caps.pm"`                // Prepares Metadata
	QueryAttrs       string `json:"mysql.caps.query_attrs"`       // Query Attributes
	SessionTrack     string `json:"mysql.caps.session_track"`     // Session Tracking
	Unused           string `json:"mysql.caps.unused"`            // Unused
	VC               string `json:"mysql.caps.vc"`                // Version Check
}

type MySQLLoginRequest struct {
	CapsClient        string           `json:"mysql.caps.client"`         // Client Capabilities
	CapsClientTree    MySQLCapsTree    `json:"mysql.caps.client_tree"`    // Client Capabilities Tree
	ExtCapsClient     string           `json:"mysql.extcaps.client"`      // Extended Capabilities
	ExtCapsClientTree MySQLExtCapsTree `json:"mysql.extcaps.client_tree"` // Extended Capabilities Tree
	MaxPacket         string           `json:"mysql.max_packet"`          // Maximum Packet Size
	Collation         string           `json:"mysql.collation"`           // Collation Setting
	User              string           `json:"mysql.user"`                // Username
	Password          string           `json:"mysql.passwd"`              // Encrypted Password
	Schema            string           `json:"mysql.schema"`              // Default Schema
	Unused            string           `json:"mysql.unused"`              // Unused Field
	ClientAuthPlugin  string           `json:"mysql.client_auth_plugin"`  // Authentication Plugin
}

type MySQLLayer struct {
	PacketLength string            `json:"mysql.packet_length"` // Length of the packet
	PacketNumber string            `json:"mysql.packet_number"` // Sequence number of the packet
	LoginRequest MySQLLoginRequest `json:"mysql.login_request"` // Login request details
}

// Parse implements the ProtocolParser interface for MySQL.
func (p *MySQLLayer) Parse(layers gowireshark.Layers) (any, error) {
	src, ok := layers["mysql"]
	if !ok {
		return nil, errors.Wrap(gowireshark.ErrLayerNotFound, "mysql")
	}

	jsonData, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &p)
	if err != nil {
		return nil, gowireshark.ErrParseFrame
	}

	return p, nil
}

func ParseCustomProtocol(inputFilepath string) (mysqlLayer *MySQLLayer, err error) {
	frameRes, err := gowireshark.GetSpecificFrameProtoTreeInJson(inputFilepath, 65,
		gowireshark.WithDescriptive(true), gowireshark.WithDebug(false))
	if err != nil {
		return nil, err
	}

	// init ParserRegistry
	registry := gowireshark.NewParserRegistry()
	// register MySQL protocol Parser
	registry.Register("mysql", &MySQLLayer{})

	parsedLayer, err := registry.ParseProtocol("mysql", frameRes.WsSource.Layers)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing MySQL protocol")
	}

	mysqlLayer, ok := parsedLayer.(*MySQLLayer)
	if !ok {
		return nil, errors.Wrap(err, "Error parsing MySQL protocol")
	}

	return mysqlLayer, nil
}

func main() {
	inputFilepath := "pcaps/mysql.pcapng"
	mysqlLayer, err := ParseCustomProtocol(inputFilepath)
	if err != nil {
		return
	}
	fmt.Println("Parsed MySQL layer, mysql.passwd:", mysqlLayer.LoginRequest.Password)
}
```

Other examples can refer to the [test file](https://github.com/randolphcyg/gowireshark/blob/main/gowireshark_test.go).

## 2. Detailed description

---

### 2.1. Project directory
```
gowireshark
├── LICENSE
├── README-zh.md
├── README.md
├── cJSON.c
├── config.go
├── frame_tvbuff.c
├── go.mod
├── go.sum
├── gowireshark.go
├── gowireshark_test.go
├── include/
│   ├── cJSON.h
│   ├── frame_tvbuff.h
│   ├── lib.h
│   ├── libpcap/
│   ├── offline.h
│   ├── online.h
│   ├── uthash.h
│   └── wireshark/
├── layers.go
├── lib.c
├── libs/
│   ├── libpcap.so.1
│   ├── libwireshark.so
│   ├── libwireshark.so.18
│   ├── libwireshark.so.18.0.2
│   ├── libwiretap.so
│   ├── libwiretap.so.15
│   ├── libwiretap.so.15.0.2
│   ├── libwsutil.so
│   ├── libwsutil.so.16
│   └── libwsutil.so.16.0.0
├── offline.c
├── online.c
├── online.go
│   ├── https.key
│   ├── https.pcapng
│   ├── mysql.pcapng
│   ├── server.key
│   └── testInvalid.key
└── registry.go
```
Detailed description of the project directory structure：

| file                                      | description                                                                                   |
|-------------------------------------------|-----------------------------------------------------------------------------------------------|
| `include/wireshark/`                      | wireshark compiled source code                                                                |
| `include/libpcap/`                        | libpcap uncompiled source code                                                                |
| `frame_tvbuff.c`、`include/frame_tvbuff.h` | The wireshark source files, copied out, must be placed here                                   |
| `libs/`                                   | wireshark、libpcap latest dll files                                                            |
| `pcaps/`                                  | Pcap packet files used for testing                                                            |
| `gowireshark_test.go`                     | Test files                                                                                    |
| `uthash.h`                                | Third-party [uthash](https://github.com/troydhanson/uthash) library                           |
| `cJSON.c、cJSON.h`                         | Third-party [cJSON](https://github.com/DaveGamble/cJSON) library                              |
| `lib.c、offline.c、online.c`                | Code that encapsulates and enhances libpcap and wireshark functionality in C                  |
| `include/lib.h、offline.h、online.h`        | Some c interfaces exposed to go                                                               |
| `layers.go`                               | common layers parser                                                                          |
| `registry.go`                             | user register custom protocol parser                                                          |
| `online.go、gowireshark.go`                | The final interface is encapsulated with Go, and the user's Go program can be used directly   |


- **lib.c、offline.c、online.c** 
- **include/lib.h、offline.h、online.h** The declaration of the wireshark interface is encapsulated in C and finally called by the Go encapsulation.
- **gowireshark.go** All external interfaces are encapsulated by Go.

### 2.2. Call chain

```
Golang =cgo=> Clang ==> Wireshark/libpcap DLL
```


### 2.3. Compile dll

How to compile wireshark, libpcap dynamic link libraries?

If the compiled wireshark and libpcap dynamic link libraries are different from the supported versions of the current project, please cover the `include/wireshark/` and `include/libpcap/` directories simultaneously;

Note that some interfaces in this project may not be valid if the wireshark version changes a lot, but can be researched and fixed;

<details>
<summary>1.Compile the wireshark dynamic link library</summary>

```shell
# Determine the latest release version and set environment variables
export WIRESHARKV=4.4.2
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
export CMAKEV=3.31.1
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
# after build, it genarate file `ws_version.h` and `config.h`
cp /opt/wireshark/build/ws_version.h /opt/wireshark/ws_version.h
cp /opt/wireshark/build/config.h /opt/wireshark/config.h
sudo mv /opt/wireshark/include/* /opt/wireshark/
```
</details>

<details>
<summary>2.Compile the libpcap dynamic link library</summary>

```
# Determine the latest release version and set environment variables
export PCAPV=1.10.5
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
     Set to `WithDescriptive(false)` to have no descriptive value for the field, and set to `WithDescriptive(true)` for the field with a descriptive value;
   - Refer to`proto_item_fill_label`in`proto.h`:
       ```c
       /** Fill given label_str with a simple string representation of field.
        @param finfo the item to get the info from
        @param label_str the string to fill
        @todo think about changing the parameter profile */
       WS_DLL_PUBLIC void
       proto_item_fill_label(field_info *finfo, gchar *label_str);
       ```

## 3. Develop&Test

---

1. You can create a new C file in `lib.c, offline.c, online.c`'` or in the root directory and add interfaces for custom functions;
2. After the interface is completed, you need to add a declaration in the H header file with the same name in the `include/` directory, and if the interface is also used in `gowireshark.go`, you need to add the same declaration in the cgo preamble of this file;
3. encapsulate the interface in `gowireshark.go`;
4. Add test cases in file `gowireshark_test.go`;
5. Use the clang-format tool to format custom C code and header files:
   E.g：`clang-format -i lib.c`，With the parameter '-i' indicates that this command directly formats the specified file, remove '-i' to preview.
   Modify all .c files in the root directory and all .h header files in the `include/` directory (note that third-party library files such as cJSON are removed with grep)
   (Only the current directory is level 1, do not traverse down the lookup, i.e. do not format the source files under `include/wireshark/` and `include/libpcap/`):
   
   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | grep -v 'frame_tvbuff.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'frame_tvbuff.h' | grep -v 'uthash.h' | xargs  clang-format -i
   ```
6. how to test:
   ```shell
   # Parse and output all the frame of a pcap file
   go test -v -run TestDissectPrintAllFrame
   # Parse and output a frame in JSON format
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # Parse and output several frame in JSON format
   go test -v -run TestGetSeveralFrameProtoTreeInJson
   # Parse and output all frame in JSON format
   go test -v -run TestGetAllFrameProtoTreeInJson
   # Parses and outputs a frame of HEX data
   go test -v -run TestGetSpecificFrameHexData
   # Parse packets in real time
   go test -v -run TestDissectPktLive
   # Real-time packet capture Read a certain number and parse it
   go test -v -run TestDissectPktLiveSpecificNum
   # Set rsa key to parse TLSv1.2
   go test -v -run TestParseHttps
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
- [x] Optimize memory leakage and improve the performance of real-time packet capture and parsing interfaces
- [x] Supports packet capture for multiple devices and stops packet capture based on device name
- [x] parser result support descriptive values
- [x] Support Set rsa keys to parse the TLS protocol, offline and real-time
- [x] Support for optional parameters
- [x] Users can register custom protocol parsers