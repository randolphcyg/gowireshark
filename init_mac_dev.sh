#!/bin/bash

# --- 1. 路径与版本配置 ---
PROJECT_ROOT=$(pwd)
DEPS_DIR="$PROJECT_ROOT/local_deps"
PKG_DIR="$PROJECT_ROOT/pkg"

WIRESHARK_VER="4.6.3"
PCAP_VER="1.10.6"
CJSON_VER="1.7.19"
CHASH_VER="2.3.0"

echo "==== 正在初始化 macOS 本地开发环境 ===="
mkdir -p "$DEPS_DIR/libs" "$DEPS_DIR/include/wireshark" "$DEPS_DIR/include/libpcap" "$PKG_DIR"

# --- 2. 编译 Wireshark ---
if [ ! -f "$DEPS_DIR/libs/libwireshark.dylib" ]; then
    echo ">> 正在构建 Wireshark..."
    cd "$DEPS_DIR"
    wget -N https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VER}.tar.xz -O wireshark.tar.xz
    tar -xf wireshark.tar.xz && mv wireshark-${WIRESHARK_VER} wireshark_src
    mkdir -p wireshark_src/build && cd wireshark_src/build
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_wireshark=OFF -DENABLE_LUA=OFF -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" ..
    ninja

    # 拷贝并修复 rpath (抹除绝对路径)
    cp run/lib*.dylib "$DEPS_DIR/libs/"
    for lib in "$DEPS_DIR/libs"/*.dylib; do
        install_name_tool -id "@rpath/$(basename "$lib")" "$lib"
    done

    # 完整拷贝头文件目录以支持 dissectors 引用
    cp -r ../epan ../wiretap ../wsutil "$DEPS_DIR/include/wireshark/"
    cp ../include/*.h "$DEPS_DIR/include/wireshark/" 2>/dev/null
    cp ./*.h "$DEPS_DIR/include/wireshark/" 2>/dev/null

    cd "$DEPS_DIR" && rm -rf wireshark_src wireshark.tar.xz
    cd "$PROJECT_ROOT"
fi

# --- 3. 编译 libpcap (参考 Dockerfile 逻辑) ---
if [ ! -f "$DEPS_DIR/libs/libpcap.1.dylib" ]; then
    echo ">> 构建 libpcap..."
    cd "$DEPS_DIR"
    wget -N http://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz -O pcap.tar.gz
    tar -zxvf pcap.tar.gz && mv libpcap-${PCAP_VER} pcap_src
    cd pcap_src && ./configure && make

    # 获取编译出的文件名并重命名为 .1.dylib (参考 Dockerfile)
    GEN_PCAP=$(ls libpcap.*.dylib | head -n 1)
    cp "$GEN_PCAP" "$DEPS_DIR/libs/libpcap.1.dylib"
    ln -sf libpcap.1.dylib "$DEPS_DIR/libs/libpcap.dylib"

    # 修复 Mach-O ID：将内部 ID 改为 @rpath/libpcap.1.dylib
    # 这样可以解决 Library not loaded: .../libpcap.A.dylib 的报错
    install_name_tool -id "@rpath/libpcap.1.dylib" "$DEPS_DIR/libs/libpcap.1.dylib"

    cp ./*.h "$DEPS_DIR/include/libpcap/"
    cd "$DEPS_DIR" && rm -rf pcap_src pcap.tar.gz
fi

# --- 4. 同步 C 桥接文件 ---
echo ">> 正在同步 C 桥接源码到 pkg/ ..."
cd "$PKG_DIR"
wget -N https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.c
wget -N https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VER}/cJSON.h
wget -N https://raw.githubusercontent.com/troydhanson/uthash/v${CHASH_VER}/src/uthash.h

echo "==== 初始化完成！ ===="

# --- 5. 自动生成环境变量配置 ---
echo ""
echo "==== 环境变量生成中 ===="

# 定义 GoLand 环境配置字符串
GOLAND_ENV="CGO_ENABLED=1;CGO_CFLAGS=-I$DEPS_DIR/include/libpcap -I$DEPS_DIR/include/wireshark -I$PKG_DIR;CGO_LDFLAGS=-L$DEPS_DIR/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0;DYLD_LIBRARY_PATH=$DEPS_DIR/libs"
GOLAND_ARGS="-ldflags=\"-r $DEPS_DIR/libs\""

# 打印到控制台
echo ">>> [GoLand] 请在 Run Configuration -> Environment 中填入:"
echo "$GOLAND_ENV"
echo ""
echo ">>> [GoLand] 请在 Run Configuration -> Go tool arguments 中填入:"
echo "$GOLAND_ARGS"
echo ""

# 自动生成一个本地环境激活文件，方便在 Terminal 使用
cat > "$PROJECT_ROOT/dev_env.sh" <<EOF
export CGO_ENABLED=1
export CGO_CFLAGS="-I$DEPS_DIR/include/libpcap -I$DEPS_DIR/include/wireshark -I$PKG_DIR"
export CGO_LDFLAGS="-L$DEPS_DIR/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0"
export DYLD_LIBRARY_PATH="$DEPS_DIR/libs"
alias gotest='go test -v -ldflags="-r $DEPS_DIR/libs"'
echo "gowireshark 本地开发环境已加载！你可以使用 'gotest' 命令进行测试。"
EOF

chmod +x "$PROJECT_ROOT/dev_env.sh"
echo ">>> [Terminal] 已生成 dev_env.sh。在终端执行 'source ./dev_env.sh' 即可生效。"
echo "==== 初始化成功！ ===="