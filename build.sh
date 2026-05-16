#!/bin/bash
set -e

# Get git commit hash
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Get current build time
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Default version
DEFAULT_VERSION="1.0"

# Build output directory
OUTPUT_DIR="bin"

# Function to print usage
print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Set version (default: $DEFAULT_VERSION)"
    echo "  -a, --all           Build all targets (HTTP + MCP + Docker)"
    echo "  -s, --server        Build HTTP server only"
    echo "  -m, --mcp           Build MCP server only"
    echo "  -d, --docker        Build Docker image only"
    echo "  -c, --clean         Clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0 -a               Build everything"
    echo "  $0 -m               Build MCP server only"
    echo "  $0 -v 2.0 -s        Build HTTP server with version 2.0"
}

# Parse arguments
BUILD_ALL=false
BUILD_SERVER=false
BUILD_MCP=false
BUILD_DOCKER=false
CLEAN=false
VERSION=$DEFAULT_VERSION

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_usage
            exit 0
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -a|--all)
            BUILD_ALL=true
            shift
            ;;
        -s|--server)
            BUILD_SERVER=true
            shift
            ;;
        -m|--mcp)
            BUILD_MCP=true
            shift
            ;;
        -d|--docker)
            BUILD_DOCKER=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# If no build target specified, show help
if [[ $BUILD_ALL == false && $BUILD_SERVER == false && $BUILD_MCP == false && $BUILD_DOCKER == false && $CLEAN == false ]]; then
    print_usage
    exit 0
fi

# Clean build artifacts
if [[ $CLEAN == true ]]; then
    echo "Cleaning build artifacts..."
    rm -rf "$OUTPUT_DIR"
    rm -f gowireshark.tar.gz
    echo "Clean complete!"
    exit 0
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "========================================"
echo "  GoWireshark Build"
echo "========================================"
echo "Version: $VERSION"
echo "Git Commit: $GIT_COMMIT"
echo "Build Time: $BUILD_TIME"
echo "========================================"

# ldflags for version injection
LDFLAGS="-X github.com/randolphcyg/gowireshark/version.Version=$VERSION -X github.com/randolphcyg/gowireshark/version.GitCommit=$GIT_COMMIT -X github.com/randolphcyg/gowireshark/version.BuildTime=$BUILD_TIME"

# Build HTTP server
if [[ $BUILD_ALL == true || $BUILD_SERVER == true ]]; then
    echo ""
    echo "Building HTTP Server..."
    go build -v -o "$OUTPUT_DIR/gowireshark" \
        -ldflags "$LDFLAGS" \
        ./cmd/main.go
    echo "HTTP Server: $OUTPUT_DIR/gowireshark"
fi

# Build MCP server
if [[ $BUILD_ALL == true || $BUILD_MCP == true ]]; then
    echo ""
    echo "Building MCP Server..."
    go build -v -o "$OUTPUT_DIR/gowireshark-mcp" \
        -ldflags "$LDFLAGS" \
        ./cmd/mcp-server/main.go
    echo "MCP Server: $OUTPUT_DIR/gowireshark-mcp"
fi

# Build Docker image
if [[ $BUILD_ALL == true || $BUILD_DOCKER == true ]]; then
    echo ""
    echo "Building Docker image..."
    docker build \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TIME="$BUILD_TIME" \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        -t gowireshark:"$VERSION" \
        -t gowireshark:latest \
        --platform linux/amd64 \
        .

    echo "Saving image to tarball..."
    docker save gowireshark:latest | gzip > gowireshark.tar.gz
    echo "Docker Image: gowireshark.tar.gz"
fi

echo ""
echo "========================================"
echo "Build complete!"
echo "========================================"
