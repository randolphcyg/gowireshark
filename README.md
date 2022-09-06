# gowireshark

> gowireshark是一个提供wireshark协议解析功能的golang包

- 暂仅支持linux平台，此库在ubuntu22.04中开发测试
- 基于 wireshark3.6.7
- 用c和go封装wireshark，是一个golang包
---
## 1.项目结构说明

1. 依赖组件：
   - lwiretap、lwsutil、lwireshark
   - glib-2.0
   - github.com/pkg/errors
   - github.com/sirupsen/logrus

2. 项目结构

   ```shell
   gowireshark
   ├── README.md
   ├── common/                       // 项目依赖的基础包
   │   ├── middleware/               // 中间件 日志logrus
   │   └── tool/                     // 工具类
   ├── go.mod
   ├── go.sum
   ├── gowireshark.go
   ├── include/
   │   ├── lib.h                     // 经过封装暴露出的wireshark接口
   │   └── wireshark/                // wireshark源码
   ├── lib.c                         // 封装的流程
   ├── libs/                         // 基于 wireshark3.6.7 源码编译的 libwireshark.so 等动态链接库文件
   │   ├── libwireshark.so
   │   ├── libwireshark.so.15
   │   ├── libwireshark.so.15.0.7
   │   ├── libwiretap.so
   │   ├── libwiretap.so.12
   │   ├── libwiretap.so.12.0.7
   │   ├── libwsutil.so
   │   ├── libwsutil.so.13
   │   └── libwsutil.so.13.1.0
   ├── pcaps/                         // pcap测试文件
   │   └── s7comm_clean.pcap
   └── tests/                         // 测试文件夹
       └── gowireshark_test.go
   ```

## 2. 项目思路

1. 根据wireshark源码编译libwireshark.so等动态链接库
2. 用c封装功能并用go封装对外接口

## 3. How To Use

1. 环境要求：  x86-64, 安装了glib2.0

2. 安装

   ```shell
   go get github.com/randolphcyg/gowireshark
   ```

3. 测试代码：

   ```go
   package main
   
   import (
       "fmt"
   
       "github.com/randolphcyg/gowireshark"
   )
   
   func main() {
       fmt.Println("测试数据包文件第一个包解析")
       filepath := "pcaps/s7comm_clean.pcap"
       err := gowireshark.DissectFirstPkt(filepath)
       if err != nil {
           fmt.Println(err)
       }
   }
   ```

## 4. TODO

1. 修复解析数据包过程错误问题
2. 增加修正为输出解析后的json数据
3. 增加实时监听解析功能




