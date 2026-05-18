# ============================================================================
# gowireshark Windows local development environment setup (PowerShell)
#
# Prerequisites: MSYS2 installed at C:\msys64 (https://www.msys2.org/)
#
# Steps: check/install MSYS2 deps -> build Wireshark
#        -> generate cgo_windows.go + dev_env.ps1
# After completion, tests can be run directly from the IDE.
#
# Usage (run in PowerShell as Administrator):
#   .\init_win_dev.ps1
#   . .\dev_env.ps1
#   go test -v ./...
# ============================================================================

$ErrorActionPreference = "Stop"

# --- Configuration ---
$WIRESHARK_VER = "4.6.5"
$CJSON_VER = "1.7.19"

$PROJECT_ROOT = $PSScriptRoot
$DEPS_DIR = Join-Path $PROJECT_ROOT "local_deps"
$INSTALL_DIR = Join-Path $DEPS_DIR "install"
$BRIDGE_DIR = $PROJECT_ROOT

# MSYS2 paths
$MSYS2_ROOT = "C:\msys64"
$UCRT64 = Join-Path $MSYS2_ROOT "ucrt64"
$MSYS2_BASH = Join-Path $MSYS2_ROOT "usr\bin\bash.exe"

Write-Host "==== gowireshark Windows dev environment setup ====" -ForegroundColor Green

# --- 1. Check MSYS2 ---
if (-not (Test-Path $MSYS2_BASH)) {
    Write-Host @"
Error: MSYS2 not found at $MSYS2_ROOT
Please install MSYS2 from https://www.msys2.org/
After installation, run this script again.
"@ -ForegroundColor Red
    exit 1
}

Write-Host ">> MSYS2 found at $MSYS2_ROOT"

# Helper: run command in MSYS2 UCRT64 shell
function Invoke-Msys2 {
    param([string]$Command)
    & $MSYS2_BASH --login -c "export MSYSTEM=UCRT64; source /etc/profile; $Command"
    if ($LASTEXITCODE -ne 0) { throw "MSYS2 command failed: $Command" }
}

# --- 2. Install MSYS2 packages ---
Write-Host ">> Checking MSYS2 UCRT64 packages..."

$MSYS2_PACKAGES = @(
    "mingw-w64-ucrt-x86_64-toolchain",
    "mingw-w64-ucrt-x86_64-cmake",
    "mingw-w64-ucrt-x86_64-ninja",
    "mingw-w64-ucrt-x86_64-pkg-config",
    "mingw-w64-ucrt-x86_64-glib2",
    "mingw-w64-ucrt-x86_64-libgcrypt",
    "mingw-w64-ucrt-x86_64-c-ares",
    "mingw-w64-ucrt-x86_64-speexdsp",
    "mingw-w64-ucrt-x86_64-opus",
    "mingw-w64-ucrt-x86_64-libxml2",
    "mingw-w64-ucrt-x86_64-zstd",
    "mingw-w64-ucrt-x86_64-lz4",
    "mingw-w64-ucrt-x86_64-nghttp2",
    "mingw-w64-ucrt-x86_64-libmaxminddb",
    "mingw-w64-ucrt-x86_64-libssh",
    "mingw-w64-ucrt-x86_64-pcre2",
    "bison",
    "flex"
) -join " "

Invoke-Msys2 "pacman -S --needed --noconfirm $MSYS2_PACKAGES"
Write-Host ">> MSYS2 packages ready."

# --- 3. Build Wireshark ---
$WS_DLL = Join-Path $INSTALL_DIR "bin\libwireshark.dll"
if (Test-Path $WS_DLL) {
    Write-Host ">> Wireshark already built, skipping."
} else {
    Write-Host ">> Building Wireshark $WIRESHARK_VER..."

    $WS_SRC = Join-Path $DEPS_DIR "wireshark_src"
    if (-not (Test-Path $WS_SRC)) {
        $tarball = Join-Path $DEPS_DIR "wireshark.tar.xz"
        Write-Host ">> Downloading Wireshark source..."
        Invoke-WebRequest -Uri "https://www.wireshark.org/download/src/wireshark-$WIRESHARK_VER.tar.xz" -OutFile $tarball
        Invoke-Msys2 "cd '$(($DEPS_DIR) -replace '\\','/')' && tar -xf wireshark.tar.xz && mv wireshark-$WIRESHARK_VER wireshark_src"
        Remove-Item $tarball -ErrorAction SilentlyContinue
    }

    # Convert Windows paths to MSYS2 paths
    $MSYS_DEPS = ($DEPS_DIR -replace '\\','/') -replace '^([A-Z]):','/$1'
    $MSYS_INSTALL = ($INSTALL_DIR -replace '\\','/') -replace '^([A-Z]):','/$1'

    Invoke-Msys2 @"
cd '$MSYS_DEPS/wireshark_src' && \
mkdir -p build && cd build && \
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_wireshark=OFF \
    -DENABLE_LUA=OFF \
    -DDISABLE_PROTOBUF=ON \
    -DENABLE_DEBUG_INFO=OFF \
    -DENABLE_MAN_PAGES=OFF \
    -DDISABLE_GNUTLS=ON \
    -DENABLE_DOCS=OFF \
    -DCMAKE_INSTALL_PREFIX='$MSYS_INSTALL' \
    .. && \
ninja -j`nproc` && \
ninja install
"@
    Write-Host ">> Wireshark installed."
}

# --- 4. Sync header files ---
$WS_INC = Join-Path $INSTALL_DIR "include\wireshark"
if (Test-Path (Join-Path $WS_INC "epan\dissectors")) {
    Write-Host ">> Headers already synced, skipping."
} else {
    Write-Host ">> Syncing Wireshark headers..."
    New-Item -ItemType Directory -Path $WS_INC -Force | Out-Null

    $wsSrc = Join-Path $DEPS_DIR "wireshark_src"
    $wsBuild = Join-Path $wsSrc "build"

    # Top-level headers
    Copy-Item -Path (Join-Path $wsSrc "*.h") -Destination $WS_INC -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $wsBuild "*.h") -Destination $WS_INC -ErrorAction SilentlyContinue
    # include/ subdirectory
    if (Test-Path (Join-Path $wsSrc "include")) {
        Copy-Item -Path (Join-Path $wsSrc "include\*") -Destination $WS_INC -Recurse -Force
    }
    # Core directories (full copy with dissectors)
    Copy-Item -Path (Join-Path $wsSrc "epan") -Destination $WS_INC -Recurse -Force
    Copy-Item -Path (Join-Path $wsSrc "wiretap") -Destination $WS_INC -Recurse -Force
    Copy-Item -Path (Join-Path $wsSrc "wsutil") -Destination $WS_INC -Recurse -Force

    Write-Host ">> Headers synced."
}

# --- 5. Download C bridge sources ---
if ((Test-Path (Join-Path $BRIDGE_DIR "cJSON.c")) -and (Test-Path (Join-Path $BRIDGE_DIR "cJSON.h"))) {
    Write-Host ">> C bridge sources already present, skipping."
} else {
    Write-Host ">> Downloading C bridge sources..."
    $GH_RAW = "https://raw.githubusercontent.com"

    if (-not (Test-Path (Join-Path $BRIDGE_DIR "cJSON.c"))) {
        Invoke-WebRequest -Uri "$GH_RAW/DaveGamble/cJSON/v$CJSON_VER/cJSON.c" -OutFile (Join-Path $BRIDGE_DIR "cJSON.c")
    }
    if (-not (Test-Path (Join-Path $BRIDGE_DIR "cJSON.h"))) {
        Invoke-WebRequest -Uri "$GH_RAW/DaveGamble/cJSON/v$CJSON_VER/cJSON.h" -OutFile (Join-Path $BRIDGE_DIR "cJSON.h")
    }
}

# --- 6. Generate cgo_windows.go ---
Write-Host ">> Generating cgo_windows.go..."

# Get glib flags from MSYS2
$GLIB_CFLAGS = (Invoke-Msys2 "pkg-config --cflags glib-2.0" | Out-String).Trim()
$GLIB_LIBS = (Invoke-Msys2 "pkg-config --libs glib-2.0" | Out-String).Trim()

# Convert install dir to forward-slash path for CGO
$CGO_INSTALL = $INSTALL_DIR -replace '\\','/'
$CGO_WS_INC = $WS_INC -replace '\\','/'
$CGO_UCRT64 = $UCRT64 -replace '\\','/'

$cgoContent = @"
//go:build windows

// Code generated by init_win_dev.ps1. DO NOT EDIT.

package gowireshark

/*
#cgo CFLAGS: -I$CGO_INSTALL/include -I$CGO_WS_INC -I$CGO_WS_INC/epan -I$CGO_WS_INC/wiretap -I$CGO_WS_INC/wsutil $GLIB_CFLAGS
#cgo LDFLAGS: -L$CGO_INSTALL/bin -L$CGO_INSTALL/lib -L$CGO_UCRT64/lib -lwiretap -lwsutil -lwireshark $GLIB_LIBS
*/
import "C"
"@

Set-Content -Path (Join-Path $BRIDGE_DIR "cgo_windows.go") -Value $cgoContent -Encoding UTF8

# --- 7. Generate dev_env.ps1 ---
Write-Host ">> Generating dev_env.ps1..."

$devEnvContent = @"
# Runtime environment variables (generated by init_win_dev.ps1)
# Usage: . .\dev_env.ps1

`$env:CGO_ENABLED = "1"
`$env:PATH = "$INSTALL_DIR\bin;$UCRT64\bin;`$env:PATH"
`$env:WIRESHARK_LIB_DIR = "$INSTALL_DIR\bin"
`$env:WIRESHARK_DATA_DIR = "$INSTALL_DIR\share\wireshark"
`$env:WIRESHARK_CONF_DIR = "`$env:TEMP\gowireshark_conf"
New-Item -ItemType Directory -Path `$env:WIRESHARK_CONF_DIR -Force | Out-Null
"@

Set-Content -Path (Join-Path $PROJECT_ROOT "dev_env.ps1") -Value $devEnvContent -Encoding UTF8

Write-Host ""
Write-Host "==== Setup complete ====" -ForegroundColor Green
Write-Host ""
Write-Host "Usage:"
Write-Host "  . .\dev_env.ps1"
Write-Host "  go test -v ./..."
Write-Host ""
Write-Host ""
