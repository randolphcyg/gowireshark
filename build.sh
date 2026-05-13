#!/bin/bash
set -e

# Get git commit hash
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Get current build time
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Default version
DEFAULT_VERSION="1.0"

# Read version input
read -p "Enter version (default: $DEFAULT_VERSION): " VERSION
VERSION=${VERSION:-$DEFAULT_VERSION}

echo "========================================"
echo "  GoWireshark Build"
echo "========================================"
echo "Version: $VERSION"
echo "Git Commit: $GIT_COMMIT"
echo "Build Time: $BUILD_TIME"
echo "========================================"

# Build docker image
echo "Building Docker image..."
docker build \
  --build-arg VERSION="$VERSION" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  --build-arg GIT_COMMIT="$GIT_COMMIT" \
  -t gowireshark:"$VERSION" \
  -t gowireshark:latest \
  --platform linux/amd64 \
  .

# Save and compress image
echo "Saving image to tarball..."
docker save gowireshark:latest | gzip > gowireshark.tar.gz

echo "========================================"
echo "Build complete!"
echo "Image file: gowireshark.tar.gz"
echo "========================================"
