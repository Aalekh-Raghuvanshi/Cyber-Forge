# Install and Run Guide

This guide explains how to install and run **LLM Code Analyzer** on a PC or laptop.

It is written for the current repository state and focuses on getting the project running locally on:

- macOS
- Linux
- Windows

## 1. What You Need

Install these tools first:

- **Git**
- **Python 3.12 or later**
- **Node.js 18 or later**
- **npm** (comes with Node.js)
- **One model backend**
  - **Ollama** for offline/local analysis, or
  - **Groq API key** for cloud analysis

## 2. Model Backend Modes

The backend supports two deterministic LLM modes:

- `groq` mode using **Groq** (`llama-3.3-70b-versatile`)
- `ollama` mode using **Ollama** (`codellama`)

This guide therefore documents the setup path that matches the current code.

## 3. Clone the Project

```bash
git clone https://github.com/yourusername/LLM-Code-Analyzer.git
cd LLM-Code-Analyzer
```

If the project is already on your system, open a terminal in the project root folder.

## 4. Backend Setup

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Windows Command Prompt

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## 5. Frontend Setup

```bash
cd frontend
npm install
npm run build
cd ..
```

If you are on Windows, run the same commands in PowerShell or Command Prompt.

## 6. Create the Environment File

Create a `.env` file in the project root.

You can start from the existing template:

### macOS / Linux

```bash
cp .env.example .env
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### Windows Command Prompt

```cmd
copy .env.example .env
```

Then edit `.env` and make sure it contains the values below.

## 7. Required `.env` Configuration

Use this as a practical local setup template:

```env
# App mode
LLM_MODE=ollama

# Groq configuration for cloud mode
GROQ_API_KEY=your-groq-api-key-here
GROQ_MODEL=llama-3.3-70b-versatile

# Ollama configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=codellama

# Server configuration
HOST=0.0.0.0
PORT=8000
DEBUG=true

```

## 8. Accessing the Application

The application has no login or authentication flow. No OAuth credentials, secret key, or redirect URL are needed. The frontend pages and analysis API can be used directly.

## 9. Choose How You Want to Run the Project

You have two practical options:

1. **Offline local mode with Ollama**
2. **Cloud mode with Groq**

If you only want the easiest working local setup, use **Ollama mode**.

## 10. Run Option A: Offline Mode with Ollama

### Step 1: Install Ollama

Download and install Ollama from:

- https://ollama.ai

### Step 2: Pull a Model

Example:

```bash
ollama pull codellama
```

You can also use another code-focused model available in your Ollama environment.

### Step 3: Start Ollama

```bash
ollama serve
```

Keep this terminal running.

### Step 4: Set `.env`

Make sure these values are present:

```env
LLM_MODE=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=codellama
```

### Step 5: Start the App

#### macOS / Linux

You can use the provided offline script:

```bash
./start_offline.sh
```

This starts the backend on:

- `http://localhost:8001`

#### Windows or Any OS Manual Start

Open terminal 1:

```bash
python -m backend.app
```

Make sure `.env` contains:

```env
PORT=8000
LLM_MODE=ollama
```

If these values are already present in `.env`, you do not need to set any extra environment variables before starting the backend.

Open terminal 2:

```bash
cd frontend
npm run dev
```

Then open:

- `http://localhost:3000`

### Recommended Offline Development Setup

For the simplest browser workflow:

- Run backend manually on `8000`
- Run frontend dev server on `3000`

## 11. Run Option B: Cloud Mode with Groq

### Step 1: Set `.env`

Use:

```env
LLM_MODE=groq
GROQ_API_KEY=your-groq-api-key
GROQ_MODEL=llama-3.3-70b-versatile
PORT=8000
```

### Step 2: Start the Backend

#### macOS / Linux

```bash
source venv/bin/activate
export LLM_MODE=groq
export PORT=8000
python -m backend.app
```

#### Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
$env:LLM_MODE="groq"
$env:PORT="8000"
python -m backend.app
```

#### Windows Command Prompt

```cmd
venv\Scripts\activate
set LLM_MODE=groq
set PORT=8000
python -m backend.app
```

### Step 3: Start the Frontend

Open a second terminal:

```bash
cd frontend
npm run dev
```

Then open:

- `http://localhost:3000`

## 12. Run Option C: Use the Provided Development Script on macOS/Linux

The repository includes:

```bash
./start_dev.sh
```

This script:

- starts the backend on port `8000` with `LLM_MODE=groq`
- starts the frontend on port `3000`
- cleans up old processes on those ports

## 13. How to Verify It Is Running

After startup:

- Frontend: `http://localhost:3000`
- Backend API docs: `http://localhost:8000/docs`
- Offline backend script mode: `http://localhost:8001`

You should be able to:

1. Open the landing page or dashboard
2. Paste code or upload files
3. Run analysis
4. Export JSON, Markdown, or PDF reports

## 14. Recommended Development Workflow

For most PCs/laptops, use this flow:

1. Create and activate the Python virtual environment
2. Install Python dependencies
3. Install frontend dependencies
4. Configure `.env`
5. Start backend manually on port `8000`
6. Start frontend with `npm run dev`
7. Open `http://localhost:3000`

This avoids OS-specific script issues and is the most predictable setup.

## 15. Useful Commands

### Frontend

```bash
cd frontend
npm run dev
npm run build
npm run lint
```

### Backend

```bash
python -m backend.app
```

### Backend Syntax Check

```bash
python3 -m py_compile backend/*.py backend/routes/*.py backend/services/*.py backend/models/*.py backend/utils/*.py
```

If your system uses `python` instead of `python3`, replace `python3` with `python`.

### Stop Running Servers

On macOS / Linux:

```bash
lsof -ti:3000 | xargs kill -9 2>/dev/null
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:8001 | xargs kill -9 2>/dev/null
```

On Windows, stop them by:

- pressing `Ctrl + C` in the terminals, or
- closing the terminal windows

## 16. Common Problems

### Problem: Backend starts but analysis fails

Fix:

- If using offline mode, confirm `ollama serve` is running
- If using cloud mode, confirm `GROQ_API_KEY` is valid
- If you used `./start_dev.sh`, try the manual startup path with `LLM_MODE=online`

### Problem: Port already in use

Fix:

- Close old terminal sessions
- Kill the process using the port
- Restart the backend and frontend

## 17. Final Recommended Setup for a Normal Laptop

If you want the simplest path that is likely to work without changing code:

1. Install Python, Node.js, Git, and Ollama
2. Clone the repository
3. Set up `venv`
4. Run `pip install -r requirements.txt`
5. Run `cd frontend && npm install && npm run build`
6. Create `.env` with Ollama settings
7. Run `ollama serve`
8. Run backend manually on port `8000`
9. Run frontend with `npm run dev`
10. Open `http://localhost:3000`

## 18. Files You Should Refer To

- Main project overview: [README.md](/Users/aggimallaabhishek/Documents/LLM-Code-Analyzer/README.md)

## 19. Summary

To run this project on a PC or laptop:

- install Python and Node.js
- install backend and frontend dependencies
- configure `.env`
- start Ollama or configure Groq for online mode
- run backend and frontend locally

For the current repository state, **manual startup is the safest approach**, and **Ollama offline mode is the most reliable local run option**.
