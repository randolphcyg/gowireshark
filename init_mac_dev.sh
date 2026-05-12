#!/bin/bash
# ============================================================================
# gowireshark macOS local development environment setup
#
# Steps: check/install deps -> build Wireshark/libpcap -> ninja install
#        -> generate cgo_darwin.go + dev_env.sh
# After completion, tests can be run directly from the IDE.
#
# Usage:
#   ./init_mac_dev.sh
#   source ./dev_env.sh
#   go test -v -run TestEpanVersion ./pkg/
# ============================================================================

set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPS_DIR="$PROJECT_ROOT/local_deps"
INSTALL_DIR="$DEPS_DIR/install"
PKG_DIR="$PROJECT_ROOT/pkg"

WIRESHARK_VER="4.6.5"
PCAP_VER="1.10.6"
CJSON_VER="1.7.19"
CHASH_VER="2.3.0"

JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo "==== gowireshark macOS dev environment setup ===="

# --- 1. Dependency check ---
if ! command -v brew >/dev/null 2>&1; then
    echo "Error: Homebrew is required (https://brew.sh)" && exit 1
fi

BREW_PREFIX="$(brew --prefix)"

# Set PKG_CONFIG_PATH (needed for library detection)
export PKG_CONFIG_PATH="$BREW_PREFIX/lib/pkgconfig:$BREW_PREFIX/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
for keg in libxml2 curl openssl@3 zstd; do
    if [ -d "$BREW_PREFIX/opt/$keg/lib/pkgconfig" ]; then
        export PKG_CONFIG_PATH="$BREW_PREFIX/opt/$keg/lib/pkgconfig:$PKG_CONFIG_PATH"
    fi
done

# Check if commands exist (regardless of source: brew, system, .app, etc.)
missing=()

# CLI tools: command_name:brew_package
for pair in cmake:cmake ninja:ninja pkg-config:pkg-config bison:bison flex:flex; do
    cmd="${pair%%:*}"
    pkg="${pair##*:}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing+=("$pkg")
    fi
done

# Libraries: pkg-config_name:brew_package
for pair in glib-2.0:glib libpcre2-8:pcre2 libgcrypt:libgcrypt libcares:c-ares \
            speexdsp:speexdsp opus:opus libxml-2.0:libxml2 libzstd:zstd \
            liblz4:lz4 libnghttp2:nghttp2 libmaxminddb:libmaxminddb libssh:libssh; do
    pc="${pair%%:*}"
    pkg="${pair##*:}"
    if ! pkg-config --exists "$pc" 2>/dev/null; then
        missing+=("$pkg")
    fi
done

if [ "${#missing[@]}" -gt 0 ]; then
    # Deduplicate
    uniq_missing=($(printf '%s\n' "${missing[@]}" | sort -u))
    echo ">> Installing missing dependencies: ${uniq_missing[*]}"
    brew install "${uniq_missing[@]}"
else
    echo ">> All dependencies are ready."
fi

# bison/flex are keg-only, prepend to PATH
for keg in bison flex; do
    if [ -d "$BREW_PREFIX/opt/$keg/bin" ]; then
        export PATH="$BREW_PREFIX/opt/$keg/bin:$PATH"
    fi
done

fetch() {
    echo ">> Downloading: $1"
    curl -fL --retry 3 --connect-timeout 15 "$1" -o "$2"
}

mkdir -p "$DEPS_DIR" "$INSTALL_DIR" "$PKG_DIR"

# --- 2. Build Wireshark ---
if [ -f "$INSTALL_DIR/lib/libwireshark.dylib" ]; then
    echo ">> Wireshark already built, skipping."
else
    echo ">> Building Wireshark ${WIRESHARK_VER}..."

    if [ ! -d "$DEPS_DIR/wireshark_src" ]; then
        fetch "https://www.wireshark.org/download/src/wireshark-${WIRESHARK_VER}.tar.xz" "$DEPS_DIR/wireshark.tar.xz"
        tar -xf "$DEPS_DIR/wireshark.tar.xz" -C "$DEPS_DIR"
        mv "$DEPS_DIR/wireshark-${WIRESHARK_VER}" "$DEPS_DIR/wireshark_src"
        rm -f "$DEPS_DIR/wireshark.tar.xz"
    fi

    mkdir -p "$DEPS_DIR/wireshark_src/build"

    cmake -G Ninja \
        -S "$DEPS_DIR/wireshark_src" \
        -B "$DEPS_DIR/wireshark_src/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_wireshark=OFF \
        -DENABLE_LUA=OFF \
        -DDISABLE_PROTOBUF=ON \
        -DENABLE_DEBUG_INFO=OFF \
        -DENABLE_MAN_PAGES=OFF \
        -DDISABLE_GNUTLS=ON \
        -DENABLE_DOCS=OFF \
        -DENABLE_APPLICATION_BUNDLE=OFF \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR"

    ninja -C "$DEPS_DIR/wireshark_src/build" -j"$JOBS"
    ninja -C "$DEPS_DIR/wireshark_src/build" install

    echo ">> Wireshark installed."
fi

# --- 3. Build libpcap ---
if [ -f "$INSTALL_DIR/lib/libpcap.1.dylib" ]; then
    echo ">> libpcap already built, skipping."
else
    echo ">> Building libpcap ${PCAP_VER}..."

    if [ ! -d "$DEPS_DIR/pcap_src" ]; then
        fetch "https://www.tcpdump.org/release/libpcap-${PCAP_VER}.tar.gz" "$DEPS_DIR/pcap.tar.gz"
        tar -xzf "$DEPS_DIR/pcap.tar.gz" -C "$DEPS_DIR"
        mv "$DEPS_DIR/libpcap-${PCAP_VER}" "$DEPS_DIR/pcap_src"
        rm -f "$DEPS_DIR/pcap.tar.gz"
    fi

    (
        cd "$DEPS_DIR/pcap_src"
        ./configure --prefix="$INSTALL_DIR"
        make -j"$JOBS"
    )

    mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/include"
    real_lib="$(find "$DEPS_DIR/pcap_src" -maxdepth 1 -name 'libpcap.*.dylib' ! -name 'libpcap.dylib' | head -n1)"
    if [ -z "$real_lib" ]; then
        real_lib="$DEPS_DIR/pcap_src/libpcap.dylib"
    fi
    cp "$real_lib" "$INSTALL_DIR/lib/libpcap.1.dylib"
    ln -sf libpcap.1.dylib "$INSTALL_DIR/lib/libpcap.dylib"
    ln -sf libpcap.1.dylib "$INSTALL_DIR/lib/libpcap.A.dylib"
    cp "$DEPS_DIR/pcap_src"/*.h "$INSTALL_DIR/include/"

    echo ">> libpcap installed."
fi

# --- 4. Sync header files (align with Dockerfile structure) ---
WS_INC="$INSTALL_DIR/include/wireshark"
if [ -d "$WS_INC/epan/dissectors" ]; then
    echo ">> Headers already synced, skipping."
else
    echo ">> Syncing Wireshark headers..."
    mkdir -p "$WS_INC"
    cp "$DEPS_DIR/wireshark_src"/*.h "$WS_INC/" 2>/dev/null || true
    cp "$DEPS_DIR/wireshark_src/build"/*.h "$WS_INC/" 2>/dev/null || true
    cp -r "$DEPS_DIR/wireshark_src/include"/* "$WS_INC/" 2>/dev/null || true
    # Full copy including dissectors subdirectory
    cp -r "$DEPS_DIR/wireshark_src/epan" "$WS_INC/"
    cp -r "$DEPS_DIR/wireshark_src/wiretap" "$WS_INC/"
    cp -r "$DEPS_DIR/wireshark_src/wsutil" "$WS_INC/"
    echo ">> Headers synced."
fi

# --- 5. Sync C bridge source files ---
GH_RAW="https://raw.githubusercontent.com"
if [ -f "$PKG_DIR/cJSON.c" ] && [ -f "$PKG_DIR/cJSON.h" ] && [ -f "$PKG_DIR/uthash.h" ]; then
    echo ">> C bridge sources already present, skipping."
else
    echo ">> Downloading C bridge sources..."
    [ -f "$PKG_DIR/cJSON.c"  ] || fetch "$GH_RAW/DaveGamble/cJSON/v${CJSON_VER}/cJSON.c" "$PKG_DIR/cJSON.c"
    [ -f "$PKG_DIR/cJSON.h"  ] || fetch "$GH_RAW/DaveGamble/cJSON/v${CJSON_VER}/cJSON.h" "$PKG_DIR/cJSON.h"
    [ -f "$PKG_DIR/uthash.h" ] || fetch "$GH_RAW/troydhanson/uthash/v${CHASH_VER}/src/uthash.h" "$PKG_DIR/uthash.h"
fi

# --- 6. Generate pkg/cgo_darwin.go ---
echo ">> Generating pkg/cgo_darwin.go..."
GLIB_CFLAGS="$(pkg-config --cflags glib-2.0)"
GLIB_LIBS="$(pkg-config --libs glib-2.0)"

CGO_CFLAGS="-I$INSTALL_DIR/include -I$WS_INC -I$WS_INC/epan -I$WS_INC/wiretap -I$WS_INC/wsutil $GLIB_CFLAGS"
CGO_LDFLAGS="-L$INSTALL_DIR/lib -Wl,-rpath,$INSTALL_DIR/lib -lwiretap -lwsutil -lwireshark -lpcap $GLIB_LIBS"

cat > "$PKG_DIR/cgo_darwin.go" <<EOF
//go:build darwin

// Code generated by init_mac_dev.sh. DO NOT EDIT.

package pkg

/*
#cgo CFLAGS: $CGO_CFLAGS
#cgo LDFLAGS: $CGO_LDFLAGS
*/
import "C"
EOF

# --- 7. Generate dev_env.sh ---
echo ">> Generating dev_env.sh..."
cat > "$PROJECT_ROOT/dev_env.sh" <<EOF
#!/bin/bash
# Runtime environment variables (generated by init_mac_dev.sh)
# Usage: source ./dev_env.sh

export CGO_ENABLED=1
export DYLD_LIBRARY_PATH="$INSTALL_DIR/lib\${DYLD_LIBRARY_PATH:+:\$DYLD_LIBRARY_PATH}"
export WIRESHARK_LIB_DIR="$INSTALL_DIR/lib"
export WIRESHARK_DATA_DIR="$INSTALL_DIR/share/wireshark"
export WIRESHARK_CONF_DIR="/tmp/gowireshark_conf"
mkdir -p /tmp/gowireshark_conf
EOF
chmod +x "$PROJECT_ROOT/dev_env.sh"

echo ""
echo "==== Setup complete ===="
echo ""
echo "Usage:"
echo "  source ./dev_env.sh"
echo "  go test -v ./pkg/"
echo ""
