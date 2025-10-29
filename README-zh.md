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
        - [1.3. 调用并打包服务为镜像](#13-调用并打包服务为镜像)
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

1. 如何解析 pcap 数据包文件所有帧

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

其他示例可以参考[测试文件](https://github.com/randolphcyg/gowireshark/blob/main/gowireshark_test.go)。

### 1.3. 调用并打包服务为镜像

```shell
docker build -t gowireshark:2.5.0 . --platform linux/amd64

docker run -d \
  --name gowireshark \
  -p 8090:8090 \
  -v /xxx/pcaps/:/gowireshark/pcaps/ \
  gowireshark:2.5.0
  
# 获取libwireshark版本
curl -X GET http://localhost:8090/api/v1/version/wireshark
# {"code":0,"data":{"version":"4.4.9"},"msg":"ok"}%
# 测试
curl -X POST \
  http://localhost:8090/api/v1/getAllFrames \
  -H "Content-Type: application/json" \
  -d '{"filepath": "/gowireshark/pcaps/mysql.pcapng", "isDebug": false, "ignoreErr": false}'
```

## 2. 详细说明

---

### 2.1. 项目目录
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
项目目录结构的详细说明：

| 文件                                              | 说明                                                    |
|-------------------------------------------------|-------------------------------------------------------|
| `include/wireshark/`                            | wireshark 编译后源码                                       |
| `include/libpcap/`                              | libpcap 未编译源码                                         |
| `libs/`                                         | wireshark、libpcap最新动态链接库文件                            |
| `pcaps/`                                        | 用于测试的 pcap 数据包文件                                      |
| `gowireshark_test.go`                           | 测试文件                                                  |
| `uthash.h`                                      | 第三方 [uthash](https://github.com/troydhanson/uthash) 库 |
| `cJSON.c、cJSON.h`                               | 第三方[cJSON](https://github.com/DaveGamble/cJSON)库      |
| `lib.c、offline.c、online.c、reassembly.c`         | 用C封装和加强libpcap和wireshark功能的代码                         |
| `include/lib.h、offline.h、online.h、reassembly.h` | 暴露给go的一些c接口                                           |
| `layers.go`                                     | 通用协议层解析器                                              |
| `registry.go`                                   | 用户注册自定义协议解析器                                          |
| `online.go、offline.go`                          | 用go封装最终的接口，用户go程序可直接使用                                |

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
export WIRESHARKV=4.6.0
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
export CMAKEV=4.1.2
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
sudo apt install libxslt1-dev  -y
sudo apt install doxygen  -y
sudo apt install libspeexdsp-dev  -y

## ubuntu安装gnutls库所需依赖nettle的依赖Libhogweed
apt install libgmp-dev  -y
apt install libunbound-dev  -y
apt install libp11-kit-dev  -y

## 安装nettle
wget https://ftp.gnu.org/gnu/nettle/nettle-3.9.1.tar.gz
tar -xvf nettle-3.9.1.tar.gz
cd nettle-3.9.1
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
## 查询nettle.pc所在文件夹/usr/local/lib64/pkgconfig/
sudo find /usr -name "nettle.pc"
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig/
pkg-config --modversion nettle
# 解决 libgnutls dll 依赖错误的 nettle dll 问题
sudo find /usr -name libnettle.so
cp /usr/local/lib64/libnettle.so /usr/local/lib/
# 确保 /usr/local/lib 优先级更高
sudo vim /etc/ld.so.conf.d/local.conf
# 添加内容
/usr/local/lib
# 重新加载动态链接库缓存
sudo ldconfig

## 安装gnutls库
wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.8.tar.xz
tar -xvf gnutls-3.8.8.tar.xz
cd gnutls-3.8.8
./configure --prefix=/usr/local --with-included-libtasn1 --with-included-unistring
make -j$(nproc)  # 使用多核编译
sudo make install
sudo ldconfig
gnutls-cli --version

## 编译安装完wireshark可以利用wireshark/build/run/tshark -v 看下是否编译时带上了GnuTLS
Compiled xxx with GnuTLS


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
# 编译
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
```shell
#include <ws_version.h>
#include <config.h>
// 在build后, 将生成文件 `ws_version.h` 和 `config.h`, 将它俩复制到wireshark根目录,最后在将`wireshark/`覆盖到项目`include/wireshark/`目录
cp /opt/wireshark/build/ws_version.h /opt/wireshark/ws_version.h
cp /opt/wireshark/build/config.h /opt/wireshark/config.h
sudo mv /opt/wireshark/include/* /opt/wireshark/
```
</details>

<details>
<summary>2.编译libpcap动态链接库</summary>

```
# 确定最新发行版本并设置环境变量
export PCAPV=1.10.5
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

1. 16进制相关字段与协议解析结果分开：
    - offset 偏移量
    - hex 16进制数据
    - ascii ascii字符

2. 描述性值逻辑
    - 原生的打印协议树接口`proto_tree_print`包含描述性值,而协议json输出接口`write_json_proto_tree`不包含描述性值,通过借鉴前者的实现逻辑`proto_tree_print_node`可以完善这个功能;
    - 主要参考`proto.h`函数的`proto_item_fill_label`函数:
        ```c
        /** Fill given label_str with a simple string representation of field.
        @param finfo the item to get the info from
        @param label_str the string to fill
        @param value_offset offset to the value in label_str
        @todo think about changing the parameter profile */
        WS_DLL_PUBLIC void
        proto_item_fill_label(const field_info *finfo, char *label_str, size_t *value_offset);
        ```

## 3. 开发测试

---

1. 可以在 `lib.c、offline.c、online.c` 中或在根目录中创建一个新的C文件并添加自定义功能的接口;
2. 接口完成后需要在`include/`目录下同名H头文件增加声明，若 cgo 中也用到该接口，则需要在此文件的cgo序文中增加相同的声明；
3. 在 cgo 文件中封装该接口;
4. 在`gowireshark_test.go`文件中增加测试案例;
5. 使用 clang 格式工具格式化自定义的 C 代码和头文件：
   例如：`clang-format -i lib.c`，参数`-i`表示此命令直接格式化指定的文件，删除`-i`进行预览。
   修改根目录中的所有 .c 文件和 `include/` 目录中的所有 .h 头文件(注意用grep去掉第三方库文件例如cJSON)
   （只有当前目录是级别 1，不要向下遍历查找，即不格式化`include/wireshark/`与`include/libpcap/`下的源码文件）：

   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | xargs clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | grep -v 'uthash.h' | xargs  clang-format -i
   ```
6. 测试:

   可以在`gowireshark_test.go`文件中编写测试函数，直接测试：
   ```shell
   # 打印一个流量包文件所有帧
   go test -v -run TestPrintAllFrames
   # 解析并输出一个流量包文件特定帧,并以json格式呈现
   go test -v -run TestGetFrameByIdx
   # 解析并输出一个流量包文件多个选定帧,并以json格式呈现
   go test -v -run TestGetFramesByIdxs
   # 解析并输出一个流量包文件所有帧,并以json格式呈现
   go test -v -run TestGetAllFrames
   # 解析并输出一个流量包文件特定帧的16进制数据,并以json格式呈现
   go test -v -run TestGetHexDataByIdx
   # 实时抓包解析
   go test -v -run TestStartAndStopLivePacketCaptureInfinite
   # 实时抓取一定数目包并解析
   go test -v -run TestStartAndStopLivePacketCaptureLimited
   # 使用rsa key解析tls1.2
   go test -v -run TestParseHttps
   ```
   或者通过调用此库的方式测试。

## 4. 路线图

---

- [x] 离线数据包文件解析打印
- [x] 离线数据包文件解析并输出 JSON 格式结果
- [x] 离线数据包解析获取16进制相关数据
- [x] 实时监听接口并捕获数据包
- [x] 封装 go 调用实时解析的逻辑——通过回调函数将实时解析结果传输到 golang
- [x] 封装 go 对收到的 Golang 调用实时数据包解析结果的处理
- [x] 优化代码并解决内存泄漏问题，使实时接口可以长时间运行
- [x] 支持多个设备的数据包捕获，并根据设备名称停止实时接口
- [x] 解析结果支持描述性值
- [x] 支持离线和实时设置rsa key用来解析TLS协议
- [x] 支持可选参数
- [x] 支持注册自定义协议解析器
- [x] 支持从HTTP协议中提取文件
- [x] 支持TCP流重组

## 5. 联系

QQ群: **301969140**