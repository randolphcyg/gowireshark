# gowireshark

> gowireshark 是一个提供 wireshark 协议解析功能的golang包

- 暂仅支持linux平台，此库在ubuntu22.04中开发测试
- 基于 wireshark3.6.8、libpcap1.10.1
- 用c和go封装 wireshark，是一个golang包
---
## 1.项目结构说明

### 1.1. 依赖组件：
- 内置：lwiretap、lwsutil、lwireshark
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
│   ├── libwireshark.so.15
│   ├── libwireshark.so.15.0.8
│   ├── libwiretap.so
│   ├── libwiretap.so.12
│   ├── libwiretap.so.12.0.8
│   ├── libwsutil.so
│   ├── libwsutil.so.13
│   └── libwsutil.so.13.1.0
├── offline.c
├── online.c
├── pcaps/
│   └── s7comm_clean.pcap
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

将9个文件放到/libs目录下即可。

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

### 4.1. 如果要更新wireshark源码及动态链接库，请遵循以下步骤(更详细可参考另一片文档)

   在linux下编译动态链接库，同时注意**尽量将另一份未操作过的源码解压修改名字放到 include/wireshark 目录，保持不修改源码**
   
```shell
#下载
wget https://2.na.dl.wireshark.org/src/wireshark-3.6.8.tar.xz
# 解压并修改文件夹名
tar -xvf wireshark-3.6.8.tar.xz
mv wireshark-3.6.8 wireshark
# 到正确文件夹目录下
cd wireshark/

# 测试 若有报红参考依赖解决步骤；直到往上翻阅日志没有依赖报错，才往下走
cmake -LH ./

## 若没有cmake3.20以上版本请安装
wget https://cmake.org/files/LatestRelease/cmake-3.24.2.tar.gz
sudo tar -xzf cmake-3.24.2.tar.gz
cd cmake-3.24.2/
sudo ./bootstrap
sudo apt install build-essential -y
### 若显示openssl未安装则执行
sudo apt install libssl-dev  -y
sudo make
sudo make install
cmake --version

# 需要安装的依赖
apt install libgcrypt-dev -y
apt install libc-ares-dev -y
apt install flex -y
apt install qtbase5-dev -y
apt install qttools5-dev-tools -y
apt install qttools5-dev -y
apt install qtmultimedia5-dev -y
# 看到qt5报错时候 其实没必要安装 直接走下一步就可以了 Qt5Multimedia 的错误不用管
# 其他可能的依赖
apt install libglib2.0-dev -y
apt install libssl-dev -y
apt install ninja-build -y
apt install pcaputils -y
apt install libpcap-dev -y

# 创建目录
mkdir build
cd build

# 删除之前测试用生成的文件 一定要删除
rm ../CMakeCache.txt
rm -rf ../CMakeFiles/


# 构建 生成的文件将在build中
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_wireshark=off -DENABLE_LUA=off ..

# 生产用这一个
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=off -DENABLE_LUA=off ..
# 编译 时间略长一些
ninja

# 编译成功进入run目录下查看编译好的动态链接库
cd run/
# 查看
ls -lh 


# 将动态链接库移动到libs目录下 一共是9个，如果之前有旧版本的记得将旧版本的删除
cd ../../../../libs/
cp ../include/wireshark/build/run/lib*so* .

# 最后删除编译用到的文件夹及源码包
# 先删除因为编译被污染的文件夹
rm -rf wireshark/
# 然后拿着源码包在解压
tar -xvf wireshark-3.6.8.tar.xz
mv wireshark-3.6.8 wireshark
# 删除源码包
rm wireshark-3.6.8.tar.xz

# 查看项目目录结构 到项目跟目录的上一层执行
tree -L 2 -F gowireshark
```

### 4.2. 开发新功能注意点
   
1. 先修改 lib.c，增加/修改函数；
2. 若修改了函数声明/增加了函数，需要在 include/lib.h 修改/增加对应声明，
同样在 gowireshark.go 导入c的序文中修改/增加同样的对应声明。
3. 测试请统一写到tests文件夹中，通用工具类写在common中
4. 用 clang-format 工具格式化c代码：
   ```shell
   # 带参数-i表示此命令直接格式化指定文件，去掉-i即可预览
   clang-format -i lib.c
   clang-format -i include/lib.h
   ```
5. 在linux环境测试
   非特殊情况请进行指定函数测试，例如:
   ```shell
   # 解析并输出第一帧
   go test -v -run TestDissectPrintFirstFrame
   # 解析并以Json格式输出某一帧
   go test -v -run TestGetSpecificFrameProtoTreeInJson
   # 解析并输出某一帧的hex等数据
   go test -v -run TestGetSpecificFrameHexData
   ```

## 5. TODO

1. ~~修复解析数据包过程错误截断问题~~
2. ~~增加输出json格式解析结果~~
3. ~~增加输出16进制数据~~
4. 增加实时监听解析功能
