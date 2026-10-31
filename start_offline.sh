#!/bin/bash
# Start LLM Code Analyser with Ollama (Offline Mode)
# Port: 8001

cd "$(dirname "$0")"

REQUIRED_PYTHON_BIN="${PYTHON_BIN:-python3.12}"

if ! command -v "$REQUIRED_PYTHON_BIN" >/dev/null 2>&1; then
    echo "❌ Python 3.12 is required for this project. Install python3.12 or set PYTHON_BIN to a Python 3.12 interpreter."
    exit 1
fi

if [ ! -d "venv" ] || [ "$(./venv/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo 'missing')" != "3.12" ]; then
    echo "📦 Recreating virtual environment with $REQUIRED_PYTHON_BIN..."
    rm -rf venv
    "$REQUIRED_PYTHON_BIN" -m venv venv
fi

source venv/bin/activate

if [ "$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" != "3.12" ]; then
    echo "❌ This project requires Python 3.12.x. Detected: $(python --version 2>&1)"
    exit 1
fi

export LLM_MODE=ollama
export PORT=8001
export OLLAMA_MODEL=gpt-oss:20b-cloud

# Kill any existing process on port 8001
echo "🔄 Cleaning up old processes on port 8001..."
PIDS_8001=$(lsof -ti:8001 2>/dev/null)

if [ -n "$PIDS_8001" ]; then
    echo "   Killing processes: $PIDS_8001"
    for pid in $PIDS_8001; do
        kill -9 $pid 2>/dev/null
    done
    sleep 1
fi

echo "🔒 Starting LLM Code Analyser - OFFLINE MODE (Ollama)"
echo "📍 URL: http://localhost:8001"
echo "🤖 Model: gpt-oss:20b-cloud"
echo ""

python -m backend.app

