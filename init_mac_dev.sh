#!/bin/bash

# --- 1. 路径与版本配置 ---
PROJECT_ROOT=$(pwd)
DEPS_DIR="$PROJECT_ROOT/local_deps"
PKG_DIR="$PROJECT_ROOT/pkg"

WIRESHARK_VER="4.6.4"
PCAP_VER="1.10.6"
CJSON_VER="1.7.19"
CHASH_VER="2.3.0"

echo "==== 正在初始化 macOS 本地开发环境 (对齐 Dockerfile 逻辑) ===="
mkdir -p "$DEPS_DIR/libs" "$DEPS_DIR/include/wireshark" "$DEPS_DIR/include/libpcap" "$PKG_DIR"

# --- 2. 编译 Wireshark ---
if [ ! -f "$DEPS_DIR/libs/libwireshark.dylib" ]; then
    echo ">> 正在下载并构建 Wireshark..."
    cd "$DEPS_DIR"
    wget -N https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VER}.tar.xz -O wireshark.tar.xz
    tar -xf wireshark.tar.xz && mv wireshark-${WIRESHARK_VER} wireshark_src

    mkdir -p wireshark_src/build && cd wireshark_src/build
    # 对齐 Dockerfile 的 cmake 参数
    cmake -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_wireshark=OFF \
        -DENABLE_LUA=OFF \
        -DDISABLE_PROTOBUF=ON \
        -DENABLE_DEBUG_INFO=OFF \
        -DENABLE_MAN_PAGES=OFF \
        -DDISABLE_GNUTLS=ON \
        -DENABLE_DOCS=OFF \
        -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" ..
    ninja

    # 拷贝并修复 rpath (对齐 Dockerfile 路径映射)
    cp run/lib*.dylib "$DEPS_DIR/libs/"
    for lib in "$DEPS_DIR/libs"/*.dylib; do
        # 1. 设置自身 id 为 rpath 相对路径
        install_name_tool -id "@rpath/$(basename "$lib")" "$lib"
        # 2. 修复依赖的其他库路径（关键：指向本地 libs 目录）
        otool -L "$lib" | grep -E "(libwireshark|libwsutil|libwiretap|libpcap|libglib-2.0)" | awk '{print $1}' | while read -r dep; do
            if [[ "$dep" != "@rpath/"* && -f "$DEPS_DIR/libs/$(basename "$dep")" ]]; then
                install_name_tool -change "$dep" "@rpath/$(basename "$dep")" "$lib"
            fi
        done
    done

    # --- 资源同步优化：完全对齐 Dockerfile 结构 ---
    echo ">> 同步资源文件 (epan/wiretap/wsutil)..."
    cp ../*.h "$DEPS_DIR/include/wireshark/" 2>/dev/null
    cp ./*.h "$DEPS_DIR/include/wireshark/" 2>/dev/null
    cp -r ../include/* "$DEPS_DIR/include/wireshark/" 2>/dev/null

    # 全量拷贝核心目录，确保 dissectors 和资源文件物理存在以解决 SIGSEGV
    cp -r ../epan "$DEPS_DIR/include/wireshark/"
    cp -r ../wiretap "$DEPS_DIR/include/wireshark/"
    cp -r ../wsutil "$DEPS_DIR/include/wireshark/"

    # 注意：不再执行 rm -rf wireshark_src，确保 CGO 编译时的深度搜索有效
    echo ">> Wireshark 编译完成，保留源码目录以支持深度依赖搜索。"
    cd "$PROJECT_ROOT"
fi

# --- 3. 编译 libpcap ---
if [ ! -f "$DEPS_DIR/libs/libpcap.1.dylib" ]; then
    echo ">> 构建 libpcap..."
    cd "$DEPS_DIR"
    wget -N http://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz -O pcap.tar.gz
    tar -zxvf pcap.tar.gz && mv libpcap-${PCAP_VER} pcap_src
    cd pcap_src && ./configure && make

    # 重命名对齐 Dockerfile 逻辑
    cp libpcap.*.dylib "$DEPS_DIR/libs/libpcap.1.dylib" 2>/dev/null || cp libpcap.dylib "$DEPS_DIR/libs/libpcap.1.dylib"
    ln -sf libpcap.1.dylib "$DEPS_DIR/libs/libpcap.dylib"
    install_name_tool -id "@rpath/libpcap.1.dylib" "$DEPS_DIR/libs/libpcap.1.dylib"
    # 修复 libpcap 依赖的系统库（如果有）
    otool -L "$DEPS_DIR/libs/libpcap.1.dylib" | grep -E "(libSystem|BUNDLE)" | awk '{print $1}' | while read -r dep; do
        if [[ "$dep" != "@rpath/"* && "$dep" != "/usr/lib/"* ]]; then
            install_name_tool -change "$dep" "@rpath/$(basename "$dep")" "$DEPS_DIR/libs/libpcap.1.dylib"
        fi
    done

    cp ./*.h "$DEPS_DIR/include/libpcap/"
    cd "$PROJECT_ROOT"
fi

# --- 4. 同步 C 桥接文件 (加速镜像) ---
echo ">> 同步 C 桥接源码 (cJSON/uthash)..."
GH_PROXY="https://ghproxy.net/https://raw.githubusercontent.com"
cd "$PKG_DIR"
wget -N "$GH_PROXY/DaveGamble/cJSON/v${CJSON_VER}/cJSON.c"
wget -N "$GH_PROXY/DaveGamble/cJSON/v${CJSON_VER}/cJSON.h"
wget -N "$GH_PROXY/troydhanson/uthash/v${CHASH_VER}/src/uthash.h"

# --- 5. 生成对齐 Dockerfile 的环境变量 ---
echo "==== 环境变量生成中 ===="

# 完全对齐 Dockerfile 的 CGO_CFLAGS
CGO_INC="-I$DEPS_DIR/include/libpcap -I$DEPS_DIR/include/wireshark -I$DEPS_DIR/include/wireshark/epan -I$DEPS_DIR/include/wireshark/wiretap -I$DEPS_DIR/include/wireshark/wsutil -I$PKG_DIR"
GOLAND_ENV="CGO_ENABLED=1;CGO_CFLAGS=$CGO_INC;CGO_LDFLAGS=-L$DEPS_DIR/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0;DYLD_LIBRARY_PATH=$DEPS_DIR/libs;WIRESHARK_DATA_DIR=$DEPS_DIR/include/wireshark;WIRESHARK_LIB_DIR=$DEPS_DIR/libs;WIRESHARK_CONF_DIR=/tmp/gowireshark_conf"

echo ">>> [GoLand] 请填入 Environment:"
echo "$GOLAND_ENV"
echo ""
echo ">>> [GoLand] 请填入 Go tool arguments:"
echo "-ldflags=\"-r $DEPS_DIR/libs\""

# --- 在 Wireshark 编译完成后添加 ---
echo ">> 同步 Wireshark 运行时资源文件..."
# 拷贝 share 目录（协议解析、配置等核心资源）
cp -r ../share "$DEPS_DIR/"
# 设置 WIRESHARK_DATA_DIR 包含 share 目录（关键）
WIRESHARK_DATA_DIR="$DEPS_DIR/include/wireshark:$DEPS_DIR/share/wireshark"
# 替换原环境变量中的 WIRESHARK_DATA_DIR
GOLAND_ENV="CGO_ENABLED=1;CGO_CFLAGS=$CGO_INC;CGO_LDFLAGS=-L$DEPS_DIR/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0;DYLD_LIBRARY_PATH=$DEPS_DIR/libs;WIRESHARK_DATA_DIR=$WIRESHARK_DATA_DIR;WIRESHARK_LIB_DIR=$DEPS_DIR/libs;WIRESHARK_CONF_DIR=/tmp/gowireshark_conf"

# 同时更新 dev_env.sh 中的 WIRESHARK_DATA_DIR
cat > "$PROJECT_ROOT/dev_env.sh" <<EOF
export CGO_ENABLED=1
export CGO_CFLAGS="$CGO_INC"
export CGO_LDFLAGS="-L$DEPS_DIR/libs -lwiretap -lwsutil -lwireshark -lpcap -lglib-2.0"
export DYLD_LIBRARY_PATH="$DEPS_DIR/libs"
export WIRESHARK_DATA_DIR="$WIRESHARK_DATA_DIR"  # 替换此行
export WIRESHARK_LIB_DIR="$DEPS_DIR/libs"
export WIRESHARK_CONF_DIR="/tmp/gowireshark_conf"
mkdir -p /tmp/gowireshark_conf
alias gotest='go test -v -ldflags="-r $DEPS_DIR/libs"'
alias goclean='go clean -cache -testcache && rm -rf /Users/randolph/Library/Caches/JetBrains/GoLand*/tmp/GoLand/___*'
EOF

chmod +x "$PROJECT_ROOT/dev_env.sh"
echo "==== 初始化成功！ ===="