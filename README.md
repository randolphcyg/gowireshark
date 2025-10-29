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
        - [1.3. Invoke and Package the Service as an Image](#13-Invoke-and-Package-the-Service-as-an-Image)
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
	frames, err := gowireshark.GetAllFrames(inputFilepath,
		gowireshark.WithDebug(false))
	if err != nil {
		panic(err)
	}

	for _, frame := range frames {
		fmt.Println("# Frame index:", frame.BaseLayers.WsCol.Num, "===========================")

		if frame.BaseLayers.Ip != nil {
			fmt.Println("## ip.src:", frame.BaseLayers.Ip.Src)
			fmt.Println("## ip.dst:", frame.BaseLayers.Ip.Dst)
		}
		if frame.BaseLayers.Http != nil {
			fmt.Println("## http.request.uri:", frame.BaseLayers.Http[0].RequestUri)
		}
		if frame.BaseLayers.Dns != nil {
			fmt.Println("## dns:", frame.BaseLayers.Dns)
		}
	}
}
```

Other examples can refer to the [test file](https://github.com/randolphcyg/gowireshark/blob/main/gowireshark_test.go).


### 1.3. Invoke and Package the Service as an Image

```shell
docker build -t gowireshark:2.5.0 . --platform linux/amd64

docker run -d \
  --name gowireshark \
  -p 8090:8090 \
  -v /xxx/pcaps/:/gowireshark/pcaps/ \
  gowireshark:2.5.0
  
# Get libwireshark version
curl -X GET http://localhost:8090/api/v1/version/wireshark
# {"code":0,"data":{"version":"4.4.9"},"msg":"ok"}%
# Test
curl -X POST \
  http://localhost:8090/api/v1/getAllFrames \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/gowireshark/pcaps/mysql.pcapng", "isDebug": false, "ignoreErr": false}'
```

## 2. Detailed description

---

### 2.1. Project directory
```
gowireshark
├── cJSON.c
├── config.go
├── go.mod
├── go.sum
├── gowireshark_test.go
├── include/
│   ├── cJSON.h
│   ├── lib.h
│   ├── libpcap/
│   ├── offline.h
│   ├── online.h
│   ├── reassembly.h
│   ├── uthash.h
│   └── wireshark/
├── layers.go
├── lib.c
├── libs/
│   ├── libpcap.so.1
│   ├── libwireshark.so.19
│   ├── libwiretap.so.16
│   └── libwsutil.so.17
├── offline.c
├── offline.go
├── online.c
├── online.go
├── pcaps/
├── reassembly.c
└── registry.go
```
Detailed description of the project directory structure：

| file                                            | description                                                                                 |
|-------------------------------------------------|---------------------------------------------------------------------------------------------|
| `include/wireshark/`                            | wireshark compiled source code                                                              |
| `include/libpcap/`                              | libpcap uncompiled source code                                                              |
| `libs/`                                         | wireshark、libpcap latest dll files                                                          |
| `pcaps/`                                        | Pcap packet files used for testing                                                          |
| `gowireshark_test.go`                           | Test files                                                                                  |
| `uthash.h`                                      | Third-party [uthash](https://github.com/troydhanson/uthash) library                         |
| `cJSON.c、cJSON.h`                               | Third-party [cJSON](https://github.com/DaveGamble/cJSON) library                            |
| `lib.c、offline.c、online.c、reassembly.c`         | Code that encapsulates and enhances libpcap and wireshark functionality in C                |
| `include/lib.h、offline.h、online.h、reassembly.h` | Some c interfaces exposed to go                                                             |
| `layers.go`                                     | common layers parser                                                                        |
| `registry.go`                                   | user register custom protocol parser                                                        |
| `online.go、gowireshark.go`                      | The final interface is encapsulated with Go, and the user's Go program can be used directly |


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
export WIRESHARKV=4.6.0
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
export CMAKEV=4.1.2
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

## gnutls < nettle < Libhogweed
apt install libgmp-dev  -y
apt install libunbound-dev  -y
apt install libp11-kit-dev  -y

## nettle
wget https://ftp.gnu.org/gnu/nettle/nettle-3.9.1.tar.gz
tar -xvf nettle-3.9.1.tar.gz
cd nettle-3.9.1
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
## fetch nettle.pc dir > /usr/local/lib64/pkgconfig/
sudo find /usr -name "nettle.pc"
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig/
pkg-config --modversion nettle

# Solve the problem of libgnutls dll dependency error nettle dll
sudo find /usr -name libnettle.so
cp /usr/local/lib64/libnettle.so /usr/local/lib/
# Make sure /usr/local/lib has a higher priority
sudo vim /etc/ld.so.conf.d/local.conf
# add content
/usr/local/lib
# reload the dll cache
sudo ldconfig

## gnutls
wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.8.tar.xz
tar -xvf gnutls-3.8.8.tar.xz
cd gnutls-3.8.8
./configure --prefix=/usr/local --with-included-libtasn1 --with-included-unistring
make -j$(nproc)
sudo make install
sudo ldconfig
gnutls-cli --version

## when finish compiling wireshark, run wireshark/build/run/tshark -v, confirm Compiled with GnuTLS
Compiled xxx with GnuTLS

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
# Compile
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

## 3. Develop&Test

---

1. You can create a new C file in `lib.c, offline.c, online.c`'` or in the root directory and add interfaces for custom functions;
2. After the interface is completed, you need to add a declaration in the H header file with the same name in the `include/` directory, and if the interface is also used in cgo file, you need to add the same declaration in the cgo preamble of this file;
3. encapsulate the interface in cgo file;
4. Add test cases in file `gowireshark_test.go`;
5. Use the clang-format tool to format custom C code and header files:
   E.g：`clang-format -i lib.c`，With the parameter '-i' indicates that this command directly formats the specified file, remove '-i' to preview.
   Modify all .c files in the root directory and all .h header files in the `include/` directory (note that third-party library files such as cJSON are removed with grep)
   (Only the current directory is level 1, do not traverse down the lookup, i.e. do not format the source files under `include/wireshark/` and `include/libpcap/`):
   
   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'uthash.h' | xargs  clang-format -i
   ```
6. how to test:
   ```shell
   # Print all the frame of a pcap file
   go test -v -run TestPrintAllFrames
   # Parse and output a frame in JSON format
   go test -v -run TestGetFrameByIdx
   # Parse and output several frame in JSON format
   go test -v -run TestGetFramesByIdxs
   # Parse and output all frame in JSON format
   go test -v -run TestGetAllFrames
   # Parses and outputs a frame of HEX data
   go test -v -run TestGetHexDataByIdx
   # Parse packets in real time
   go test -v -run TestStartAndStopLivePacketCaptureInfinite
   # Real-time packet capture Read a certain number and parse it
   go test -v -run TestStartAndStopLivePacketCaptureLimited
   # Set rsa key to parse TLSv1.2
   go test -v -run TestParseHttps
   ```
   Or test by calling this library.

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
- [x] Supports extracting files from the HTTP protocol
- [x] Supports follow TCP streams