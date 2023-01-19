# Gowireshark

README: [中文](https://github.com/randolphcyg/gowireshark/blob/main/README-zh.md) | [English](https://github.com/randolphcyg/gowireshark/blob/main/README.md)

- Gowireshark 是一个 Golang 库，它允许我们的 Golang 程序具有 wireshark 的协议解析功能，它可以离线解析 pcap 数据包文件或实时监听设备并获得协议解析结果。
- Gowireshark基于[libpcap 1.10.3](https://www.tcpdump.org/release/)与[wireshark 4.0.3](https://www.wireshark.org/#download)编译后的动态链接库开发。

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
# 到/opt目录下操作
cd /opt/
export WIRESHARKV=4.0.3

# 下载源码
wget https://1.as.dl.wireshark.org/src/wireshark-$WIRESHARKV.tar.xz

# 解压缩并修改文件夹名称
tar -xvf wireshark-$WIRESHARKV.tar.xz
mv wireshark-$WIRESHARKV wireshark

# 进入wireshark目录
cd /opt/wireshark/

--------[首次操作] 如何检查编译所需的依赖项-------------
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

# 在 wireshark/ 目录下创建一个用来构建的目录
mkdir build
cd build

# 构建[生产用]
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..

# 编译[时长略久]
ninja

# 编译成功后，进入build/run/目录查看编译后的动态链接库
cd run/
ls -lh

# 覆盖替换原始的 9 个 wireshark 动态链接库文件
cd /opt/gowireshark/libs/
cp /opt/wireshark/build/run/lib*so* .

# 覆盖 wireshark 源文件夹（先删除无用的 build/ 目录）
rm -rf /opt/wireshark/build/
# 将源码拷贝到项目前可以将原 /opt/gowireshark/include/wireshark/ 目录备份
cp -r /opt/wireshark/ /opt/gowireshark/include/wireshark/

# 查看项目目录结构 [项目目录父目录执行]
tree -L 2 -F gowireshark
```
</details>

<details>
<summary>2.编译libpcap动态链接库</summary>

```
cd /opt
export PCAPV=1.10.3
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz
tar -zxvf libpcap-$PCAPV.tar.gz
cd libpcap-$PCAPV
export CC=aarch64-linux-gnu-gcc
./configure --host=aarch64-linux --with-pcap=linux
# 记得安装 flex、bison 库并删除额外的清单和 syso 文件
make

------
# 如果没有 bison 库，请安装它
apt install bison
------

# 编译完成后，将 【libpcap.so.1.10.3】 修改为 【libpcap.so.1】，
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
 


## 5. 联系

有任何想讨论的，可以加QQ群:

- **301969140**