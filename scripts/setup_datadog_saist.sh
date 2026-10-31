#!/usr/bin/env bash
# ==============================================================================
# Setup Script for Datadog SAIST (AI-native SAST CLI)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
TARGET_BIN="$BIN_DIR/datadog-saist"

mkdir -p "$BIN_DIR"

echo "=========================================================="
echo " Setting up Datadog SAIST CLI in $BIN_DIR"
echo "=========================================================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
  echo "⚠️  'go' compiler not found on this system."
  echo "ℹ️  No problem! Cyber-Forge includes a full native Python 2-Stage SAIST engine"
  echo "   (AST context extraction -> Stage 1 detection -> Stage 2 validation -> SARIF 2.1.0)"
  echo "   that runs automatically via Groq without requiring the Go binary!"
  echo ""
  echo "   If you wish to compile the official Go binary later:"
  echo "   1. Install Go: https://go.dev/doc/install (or 'brew install go')"
  echo "   2. Re-run: ./scripts/setup_datadog_saist.sh"
  exit 0
fi

echo "✅ Go detected: $(go version)"

BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

echo "⬇️  Cloning https://github.com/DataDog/datadog-saist.git..."
git clone --depth 1 https://github.com/DataDog/datadog-saist.git "$BUILD_TMP/datadog-saist"

cd "$BUILD_TMP/datadog-saist"
echo "🔨 Building datadog-saist binary..."
if [ -f Makefile ]; then
  make build || go build -o "$TARGET_BIN" ./cmd/datadog-saist || go build -o "$TARGET_BIN" .
else
  go build -o "$TARGET_BIN" ./cmd/datadog-saist || go build -o "$TARGET_BIN" .
fi

if [ -f "$TARGET_BIN" ]; then
  chmod +x "$TARGET_BIN"
  echo "🎉 Successfully built and installed: $TARGET_BIN"
  "$TARGET_BIN" --help | head -n 5 || true
else
  # Check if binary was built in root or bin/
  FOUND_BIN="$(find "$BUILD_TMP/datadog-saist" -type f -name "datadog-saist" -perm +111 2>/dev/null | head -n 1)"
  if [ -n "$FOUND_BIN" ]; then
    cp "$FOUND_BIN" "$TARGET_BIN"
    chmod +x "$TARGET_BIN"
    echo "🎉 Successfully installed: $TARGET_BIN"
  else
    echo "⚠️  Compilation completed but binary was not found. Using native Python SAIST engine."
  fi
fi
