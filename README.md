# gowireshark

> gowireshark 是一个提供 wireshark 协议解析功能的golang包

- 暂仅支持linux平台，此库在ubuntu22.04中开发测试
- 基于 wireshark3.6.8
- 用c和go封装 wireshark，是一个golang包
---
## 1.项目结构说明

### 1.1. 依赖组件：
   - lwiretap、lwsutil、lwireshark
   - glib-2.0
   - github.com/pkg/errors
   - github.com/sirupsen/logrus

### 1.2. 项目结构

- common 通用工具类，日志模块等
- include wireshark源码及lib.h 封装的对go提供的接口
- libs wireshark动态链接库，在linux中编译
- pcaps pcap文件 用来测试
- tests 测试文件夹
- gowireshark.go go封装最终对外的接口
- lib.c c封装wireshark接口，提供给gowireshark.go调用

树结构:
```
gowireshark/
├── README.md
├── common/
│   ├── middleware/
│   └── tool/
├── go.mod
├── go.sum
├── gowireshark.go
├── include/
│   ├── lib.h
│   └── wireshark/
├── lib.c
├── libs/
│   ├── libwireshark.so*
│   ├── libwireshark.so.15*
│   ├── libwireshark.so.15.0.8*
│   ├── libwiretap.so*
│   ├── libwiretap.so.12*
│   ├── libwiretap.so.12.0.8*
│   ├── libwsutil.so*
│   ├── libwsutil.so.13*
│   └── libwsutil.so.13.1.0*
├── pcaps/
│   └── s7comm_clean.pcap
└── tests/
    ├── gowireshark.log
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

### 3.1. 安装

```shell
go get github.com/randolphcyg/gowireshark
```

### 3.2. 测试代码：

```go
package main

import (
    "fmt"

    "github.com/randolphcyg/gowireshark"
)

func main() {
    filepath := "pcaps/s7comm_clean.pcap"
    err := gowireshark.DissectFirstFrame(filepath)
    if err != nil {
        fmt.Println(err)
    }
}
```

## 4. 如何更新及规范说明

### 4.1. 如果要更新wireshark源码及动态链接库，请遵循以下步骤(更详细可参考另一片文档)

   在linux下编译动态链接库，同时注意**尽量将另一份未操作过的源码解压修改名字放到 include/wireshark 目录，保持不修改源码**
   
```shell
wget https://2.na.dl.wireshark.org/src/wireshark-3.6.8.tar.xz

# 解压并修改文件夹名
tar -xvf wireshark-3.6.8.tar.xz
mv wireshark-3.6.8 wireshark
# 到正确文件夹目录下
cd wireshark/

# 测试 若有报红参考依赖解决步骤；直到往上翻阅日志没有依赖报错，才往下走
cmake -LH ./

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
# 复制之前先删掉之前的动态链接库
cp ../include/wireshark/build/run/lib*so* .

# 最后删除编译用到的文件夹及源码包
# 先删除因为编译被污染的文件夹
cd ../include/
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
   go test -v -run TestDissectFirstFrame
   ```

## 5. TODO

1. ~~修复解析数据包过程错误截断问题~~
2. 增加修正为输出解析后的json数据
3. 增加实时监听解析功能
