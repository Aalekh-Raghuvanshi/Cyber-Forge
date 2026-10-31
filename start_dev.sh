#!/bin/bash

# Start Development Mode
# Frontend: http://localhost:3000
# Backend: http://localhost:8000

echo "🚀 Starting LLM Code Analyser (Development Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv venv"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Set environment for online mode
export LLM_MODE=gemini
export PORT=8000

# Kill any existing processes on ports 3000 and 8000
echo "🔄 Cleaning up old processes..."
PIDS_3000=$(lsof -ti:3000 2>/dev/null)
PIDS_8000=$(lsof -ti:8000 2>/dev/null)

if [ -n "$PIDS_3000" ]; then
    echo "   Killing processes on port 3000: $PIDS_3000"
    for pid in $PIDS_3000; do
        kill -9 $pid 2>/dev/null
    done
fi

if [ -n "$PIDS_8000" ]; then
    echo "   Killing processes on port 8000: $PIDS_8000"
    for pid in $PIDS_8000; do
        kill -9 $pid 2>/dev/null
    done
fi

sleep 1

# Start backend in background
echo "🔧 Starting backend on port 8000..."
python -m backend.app > /tmp/llm-backend.log 2>&1 &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"

# Wait for backend to start
sleep 3

# Start frontend dev server
echo "🎨 Starting frontend on port 3000..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Development servers started!"
echo ""
echo "🌐 Frontend: http://localhost:3000"
echo "🔧 Backend:  http://localhost:8000"
echo "📖 API Docs: http://localhost:8000/docs"
echo "Press Ctrl+C to stop all servers"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping servers..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    
    # Kill any remaining processes
    PIDS_3000=$(lsof -ti:3000 2>/dev/null)
    PIDS_8000=$(lsof -ti:8000 2>/dev/null)
    
    if [ -n "$PIDS_3000" ]; then
        for pid in $PIDS_3000; do
            kill -9 $pid 2>/dev/null
        done
    fi
    
    if [ -n "$PIDS_8000" ]; then
        for pid in $PIDS_8000; do
            kill -9 $pid 2>/dev/null
        done
    fi
    
    echo "✅ Servers stopped"
    exit 0
}

# Set trap to cleanup on Ctrl+C
trap cleanup INT TERM

# Wait for processes
wait

