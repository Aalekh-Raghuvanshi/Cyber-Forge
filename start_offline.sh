#!/bin/bash
# Start LLM Code Analyser with Ollama (Offline Mode)
# Port: 8001

cd "$(dirname "$0")"
source venv/bin/activate

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

