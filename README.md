# gowireshark

> gowireshark 是一个提供 wireshark 协议解析功能的golang包

- 暂仅支持linux平台，此库在ubuntu22.04中开发测试
- 基于 wireshark4.0.0、libpcap1.10.1
- 用c和go封装 wireshark，是一个golang包
---
## 1.项目结构说明

### 1.1. 依赖组件：
- 内置：lwiretap、lwsutil、lwireshark、lpcap
- 系统需要安装：glib-2.0

### 1.2. 项目结构

- include/ wireshark源码及lib.h 封装的对go提供的接口
- libs/ wireshark动态链接库，在linux中编译
- pcaps/ pcap文件 用来测试
- tests/ 测试文件夹
- cJSON.c、cJSON.h c的json库[勿动]
- lib.c、offline.c、online.c 修复和使用的wireshark、libpcap库源码
- include/lib.h、offline.h、online.h 封装wireshark接口的声明，提供给gowireshark.go调用
- include/wireshark wireshark源码[勿动]
- include/libpcap libpcap源码[勿动]
- gowireshark.go go封装最终对外的接口

树结构:
```
gowireshark
├── README.md
├── cJSON.c
├── go.mod
├── go.sum
├── gowireshark.go
├── include/
│   ├── cJSON.h
│   ├── lib.h
│   ├── libpcap/
│   ├── offline.h
│   ├── online.h
│   └── wireshark/
├── lib.c
├── libs/
│   ├── libpcap.so.1
│   ├── libwireshark.so
│   ├── libwireshark.so.16
│   ├── libwireshark.so.16.0.0
│   ├── libwiretap.so
│   ├── libwiretap.so.13
│   ├── libwiretap.so.13.0.0
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

## 2. 项目设计思路

## 2.1. 设计思路

1. 根据wireshark源码编译libwireshark.so等动态链接库
2. 用c封装功能并用go封装对外接口

## 2.2. 调用关系

gowireshark.go >> lib.h + lib.c >> wireshark 动态链接库 + wireshark 源码 

```mermaid
graph LR
    A(gowireshark.go)==cgo==>B(lib.h + lib.c)-.->C[wireshark 动态链接库 + wireshark 源码]
    style A fill:#FFCCCC
    style B fill:#99CCCC
    style C fill:#FFCC99,stroke:#FFCCCC,stroke-width:2px,stroke-dasharray: 5, 5
```

## 3. How To Use

> 环境要求: x86-64, 安装glib2.0

```shell
# 安装glib-2.0
sudo apt install libglib2.0-dev -y
```

### 3.1. 安装

```shell
go get github.com/randolphcyg/gowireshark
```

### 3.2. 根据系统选择动态链接库

因为github有大文件限制，因此so文件上传不了：

阿里云盘下载：「gowireshark-libs」https://www.aliyundrive.com/s/j3aVfoFtHgp

根据系统选择，wireshark版本选择最新版本，否则将和代码不兼容。

将9个wireshark动态链接库文件和1个libpcap动态链接库文件放到/libs目录下即可。

### 3.3. 测试代码：

1. tests文件夹下用go test命令直接测试
   ```shell
   go test -v -run TestDissectFirstFrame
   ```
   若没有出现报错即可。

2. 项目外
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

## 4. 如何更新及规范说明

### 4.1. 更新wireshark源码及编译动态链接库

在linux下编译动态链接库,若更新动态链接库，include/wireshark/目录需要同步更新，同时测试各接口是否发生变动。

<details>
<summary>编译wireshark动态链接库</summary>

```
在/opt目录下操作
cd /opt/

下载
wget https://2.na.dl.wireshark.org/src/wireshark-4.0.0.tar.xz

解压并修改文件夹名
tar -xvf wireshark-4.0.0.tar.xz
mv wireshark-4.0.0 wireshark

到wireshark目录下
cd wireshark/

-------------环境中编译所需的依赖-----------------------------------

[仅测试] 输出日志有爆红则解决依赖问题，到qt5时忽略报错，删除CMakeCache.txt、CMakeFiles/
cmake -LH ./

若没有cmake3.20以上版本请安装
wget https://cmake.org/files/LatestRelease/cmake-3.24.2.tar.gz
sudo tar -xzf cmake-3.24.2.tar.gz
cd cmake-3.24.2/
sudo ./bootstrap
sudo apt install build-essential -y

若显示openssl未安装则执行
sudo apt install libssl-dev  -y
sudo make
sudo make install
cmake --version

需要安装的依赖
apt install libgcrypt-dev -y
apt install libc-ares-dev -y
apt install flex -y
apt install qtbase5-dev -y
apt install qttools5-dev-tools -y
apt install qttools5-dev -y
apt install qtmultimedia5-dev -y

看到qt5报错时候 其实没必要安装 直接走下一步就可以了 Qt5Multimedia 的错误不用管
其他可能的依赖
apt install libglib2.0-dev -y
apt install libssl-dev -y
apt install ninja-build -y
apt install pcaputils -y
apt install libpcap-dev -y

-------------环境中编译所需的依赖-----------------------------------

解决完依赖问题，删除之前测试用生成的文件
rm ../CMakeCache.txt
rm -rf ../CMakeFiles/

创建目录
mkdir build
cd build

构建[生产用]
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..

编译(时间较长)
ninja

编译成功进入run目录下查看编译好的动态链接库
cd run/

查看，出现so后缀的动态链接库即可
ls -lh

将动态链接库移动到libs目录下 一共是9个(如果之前有旧版本的记得将旧版本的删除)
cd 项目根目录/libs/
cp/opt/wireshark/build/run/lib*so* .

先删除因为编译被污染的文件夹
rm -rf /opt/wireshark/build/

将源码替换到include/wireshark
cp /opt/wireshark/ 项目根目录/include/wireshark/

查看项目目录结构(项目跟目录上一层执行)
tree -L 2 -F gowireshark
```
</details>

### 4.2. 开发新功能注意点
   
1. 先编写新功能c代码，可在lib.c中或根目录新建c文件；
2. 同步将函数声明更新到同名头文件lib.h或新建头文件， 同样在go代码序文中增加相同的声明；
3. 在go代码中封装对外接口；
4. 测试统一写到tests文件夹中;
5. 用 clang-format 工具格式化c代码及头文件：
    
   例：`clang-format -i lib.c`，带参数-i表示此命令直接格式化指定文件，去掉-i即可预览；

   修改根目录下所有.c文件、include/目录下所有.h头文件(仅当前目录1层，不向下遍历查找)：
   ```shell
   find . -maxdepth 1 -name '*.c' | grep -v 'cJSON.c' | xargs  clang-format -i
   find ./include -maxdepth 1 -name '*.h' | grep -v 'cJSON.h' | xargs  clang-format -i
   ```
6. 在linux环境测试tests/目录下测试
   非特殊情况请进行指定函数测试，例如:
   ```shell
   # 解析并输出第一帧
   go test -v -run TestDissectPrintFirstFrame
   # 解析并以Json格式输出某一帧
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # 解析并输出某一帧的hex等数据
   go test -v -run TestGetSpecificFrameHexData
   # 实时解析数据包
   go test -v -run TestDissectPktLive
   ```

## 5. TODO

1. ~~离线数据包文件解析打印~~
2. ~~离线数据包文件解析并输出json格式~~
3. ~~16进制数据获取~~
4. ~~实时监听接口并抓包~~
5. 实时解析从接口抓到的数据包
