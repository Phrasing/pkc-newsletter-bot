#!/bin/bash

# Build script for PKC with embedded API keys
# Usage: ./build.sh [linux|windows|all] (default: windows)

set -e

# Read values directly from .env file
if [ ! -f .env ]; then
    echo "Error: .env file not found"
    exit 1
fi

HYPER_API_KEY=$(grep "^HYPER_API_KEY=" .env | cut -d'=' -f2-)
CAP_KEY=$(grep "^2CAP_KEY=" .env | cut -d'=' -f2-)

# Check required variables
if [ -z "$HYPER_API_KEY" ]; then
    echo "Error: HYPER_API_KEY not set in .env"
    exit 1
fi

if [ -z "$CAP_KEY" ]; then
    echo "Error: 2CAP_KEY not set in .env"
    exit 1
fi

# Ensure bin directory exists
mkdir -p bin

# Build function
build_target() {
    local GOOS=$1
    local GOARCH=$2
    local OUTPUT=$3

    echo "Building for $GOOS/$GOARCH..."

    GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-X main.hyperAPIKey=$HYPER_API_KEY -X main.captchaAPIKey=$CAP_KEY -s -w" \
        -o "bin/$OUTPUT" .

    echo "  -> bin/$OUTPUT ($(du -h "bin/$OUTPUT" | cut -f1))"
}

# Determine target
TARGET="${1:-windows}"

case "$TARGET" in
    windows)
        build_target windows amd64 pkc.exe
        ;;
    linux)
        build_target linux amd64 pkc
        ;;
    all)
        build_target windows amd64 pkc.exe
        build_target linux amd64 pkc
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: ./build.sh [linux|windows|all]"
        exit 1
        ;;
esac

echo ""
echo "Build complete - API keys embedded, no .env required at runtime"
