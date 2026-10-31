#!/bin/bash
# Start LLM Code Analyser with Gemini (Online Mode)
# Port: 8000

cd "$(dirname "$0")"
source venv/bin/activate

export LLM_MODE=gemini
export PORT=8000

# Kill any existing process on port 8000
echo "🔄 Cleaning up old processes on port 8000..."
PIDS_8000=$(lsof -ti:8000 2>/dev/null)

if [ -n "$PIDS_8000" ]; then
    echo "   Killing processes: $PIDS_8000"
    for pid in $PIDS_8000; do
        kill -9 $pid 2>/dev/null
    done
    sleep 1
fi

echo "🌐 Starting LLM Code Analyser - ONLINE MODE (Gemini)"
echo "📍 URL: http://localhost:8000"
echo "🤖 Model: gemini-2.0-flash"
echo ""

python -m backend.app

