# Gowireshark

README: [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md) | [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md)

- Gowireshark is a Golang library that allows our Golang program to have wireshark's protocol parsing function, which can parse pcap packet files offline or listen to the device in real time and obtain protocol parsing results.
- Gowireshark is developed based on the dynamic link library compiled by [libpcap 1.10.4](https://www.tcpdump.org/release/)、[wireshark 4.0.5](https://www.wireshark.org/#download).

---

# Contents

- [1. Installation](#1-installation)
   - [1.1. Requirements](#11-requirements)
   - [1.2. Usage](#12-usage)
- [2. Detailed description](#2-detailed-description)
   - [2.1. Project directory structure](#21-project-directory)
   - [2.2. Call chain](#22-call-chain)
   - [2.3. Compile dll](#23-compile-dll)
- [3. Develop](#3-develop)
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
    filepath := "pcaps/s7comm_clean.pcap"
    err := gowireshark.DissectPrintFirstFrame(filepath)
    if err != nil {
        fmt.Println(err)
    }
}
```
Other examples can refer to the [test file](https://github.com/randolphcyg/gowireshark/blob/main/tests/gowireshark_test.go).

## 2. Detailed description

---

### 2.1. Project directory
```
gowireshark
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
│   ├── libwireshark.so.16
│   ├── libwireshark.so.16.0.3
│   ├── libwiretap.so
│   ├── libwiretap.so.13
│   ├── libwiretap.so.13.0.3
│   ├── libwsutil.so
│   ├── libwsutil.so.14
│   └── libwsutil.so.14.0.0
├── offline.c
├── online.c
├── pcaps/
│   ├── s7comm_clean.pcap
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
export WIRESHARKV=4.0.5
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
mkdir build
cd build
# Build [For production]
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..
# Compile[slightly longer]
ninja

# After successful compilation, enter the run directory to view the compiled dynamic link library
cd run/
ls -lh
# Overwrites replaces the original 9 wireshark dynamic link library files
cd /opt/gowireshark/libs/
cp -r /opt/wireshark/build/run/lib*so* .
# Overwrite the wireshark source folder(Remove the useless build/ directory first)
rm -rf /opt/wireshark/build/
# Before copying the source code to the project, you can back up the original /opt/gowireshark/include/wireshark/ directory
cp /opt/wireshark/ /opt/gowireshark/include/wireshark/

# View project directory structure [project directory parent directory execution]
tree -L 2 -F gowireshark
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

## 3. Develop

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


## 5. Contact

If you have anything you want to communicate, please join the QQ group: 

- **301969140**