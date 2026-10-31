# 🛡️ Cyber-Forge: SAST + DAST Correlation & Prioritization Engine

> **Next-Generation Application Security Engine:** Deterministically bridges Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) using AST route mapping, multi-scanner deduplication, prioritized risk scoring, and zero-hallucination sandboxed LLM remediation.

![Cyber-Forge](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-green.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688.svg)
![React](https://img.shields.io/badge/React-19-61DAFB.svg)
![Groq](https://img.shields.io/badge/LLM-Groq%20%7C%20Ollama-orange.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

---

## 📌 Table of Contents

- [Overview & The AppSec Problem](#-overview--the-appsec-problem)
- [Key Features & Capabilities](#-key-features--capabilities)
- [Core Architecture & Engine Design](#-core-architecture--engine-design)
- [Zero-Hallucination Philosophy](#-zero-hallucination-philosophy)
- [Supported Canonical CWEs](#-supported-canonical-cwes)
- [Quick Start & Installation](#-quick-start--installation)
- [Configuration Reference (`.env`)](#-configuration-reference-env)
- [REST API Reference & Examples](#-rest-api-reference--examples)
- [Project Structure](#-project-structure)
- [Testing & Verification](#-testing--verification)
- [License & Acknowledgments](#-license--acknowledgments)

---

## ⚡ Overview & The AppSec Problem

Modern AppSec teams suffer from **alert fatigue** caused by the disconnect between static and dynamic analysis:

| Challenge | Static Analysis (SAST) | Dynamic Analysis (DAST) | **Cyber-Forge Solution** |
| :--- | :--- | :--- | :--- |
| **Visibility** | Pinpoints exact files & line numbers | Tests live running HTTP endpoints | **Maps endpoints directly to exact code lines** |
| **Accuracy** | High false positive rate (theoretical bugs) | Proves real-world runtime exploitability | **Correlates SAST + DAST to confirm exploitability** |
| **Remediation** | Lacks runtime request context | Lacks source code line numbers | **Provides code diffs + runtime payload proof** |

**Cyber-Forge** deterministically links SAST findings to DAST alerts via an **AST Route Mapper**. When a dynamic vulnerability on `/api/orders` matches a static vulnerability at `orders.py:88`, Cyber-Forge unifies them into a single **"Confirmed"** issue, ranks it at the top of the remediation queue, and generates a sandboxed code fix.

---

## ✨ Key Features & Capabilities

- **Deterministic SAST Detection (FR-1)**: Scans source code directories using the **Semgrep CLI** (`semgrep scan --config=auto --json`) coupled with a deterministic AST/Regex fallback scanner in Python.
- **DAST Integration & Ingestion (FR-2)**: Supports both **Mode A** (Live OWASP ZAP API daemon integration seeded with AST routes) and **Mode B** (DAST JSON/SARIF report ingestion + offline diagnostic header checks).
- **One Common Finding Format (FR-3)**: Normalizes disparate scanner outputs into a unified `UnifiedFinding` Pydantic model with canonical CWE mappings (`CWE-89`, `CWE-79`, `CWE-22`, etc.) and deterministic SHA-256 fingerprint deduplication.
- **AST Static Route Mapper (FR-4)**: Analyzes source code using Python's built-in `ast` module to map HTTP methods and URL paths directly to handler functions and exact line ranges (`start_line` to `end_line`) for FastAPI, Flask, and Express.js.
- **3-Way Correlation Algorithm (FR-5)**: Matches findings by (1) Canonical CWE, (2) Route-to-code line boundary match, and (3) Parameter name boost.
- **Multi-Scanner Deduplication (FR-6)**: Merges Semgrep SAST, AST Regex SAST, and ZAP DAST alerts into a single `CorrelatedIssue` with full aggregated evidence.
- **Strict 3-State Output Labels (FR-7)**:
  - `Confirmed`: Discovered in code and proven exploitable at runtime (linked via correlation).
  - `Runtime only`: Observed by DAST at runtime without code correlation (e.g., missing defensive HTTP headers).
  - `Code only`: Detected statically without runtime proof (e.g., hardcoded secrets, weak crypto).
- **Prioritized Risk Scoring (FR-9)**: Tiered sorting (`Confirmed` > `Runtime only` > `Code only`) combined with a 0–100 risk score computed from severity weights, confirmation multipliers, and confidence boosts.
- **Persistent SQLite Store & REST API (FR-10)**: Idempotent database storage (`data/scans.db`) with `INSERT OR REPLACE` upsert semantics and rich REST query endpoints.
- **Sandboxed LLM Remediation**: Strict `temperature=0.0` remediation generation powered by **Groq** (`llama-3.3-70b-versatile`) or **Ollama** (`codellama`), backed by deterministic offline templates.

---

## 🏛️ Core Architecture & Engine Design

```
                     ┌───────────────────────────────┐
                     │   Target Source Code Folder   │
                     └───────┬───────────────┬───────┘
                             │               │
                             ▼               ▼
                 ┌───────────────────┐ ┌───────────────┐
                 │  AST Route Mapper │ │ SAST Scanner  │
                 │ (FastAPI / Flask) │ │(Semgrep + AST)│
                 └─────────┬─────────┘ └───────┬───────┘
                           │                   │
                           │   Route Map       │ Static Findings
                           ▼ (Endpoints, Lines)▼ (File, Line, CWE)
┌──────────────┐         ┌─────────────────────────────┐
│  Target URL  │         │   Unified Findings Model    │
│  / DAST JSON ├────────►│  & Canonical CWE Normalizer │
└──────┬───────┘         └──────────────┬──────────────┘
       │                                │
       ▼                                │
┌──────────────┐                        │
│ DAST Scanner ├────────────────────────┘
│ (OWASP ZAP)  │ Runtime Alerts (URL, Param, Evidence)
└──────────────┘
                        │
                        ▼
       ┌─────────────────────────────────────────────────┐
       │         Correlation & Deduplication Engine      │
       │                                                 │
       │  1. Canonical CWE Match                         │
       │  2. Route-to-Code Line Range Match              │
       │  3. Parameter Boost Tie-Breaker                 │
       │  4. SHA-256 Deduplication & Issue Merging       │
       └────────────────────────┬────────────────────────┘
                                │
                                ▼
       ┌─────────────────────────────────────────────────┐
       │            Prioritization Matrix                │
       │                                                 │
       │  Rank 1: Confirmed    (SAST + DAST matched)     │
       │  Rank 2: Runtime only (DAST without code match) │
       │  Rank 3: Code only    (SAST without DAST match) │
       │  Sort:   Risk Score descending (0 - 100)        │
       └────────────────────────┬────────────────────────┘
                                │
                                ▼
       ┌─────────────────────────────────────────────────┐
       │   Sandboxed LLM Remediation (temperature=0.0)   │
       │         Groq (Cloud) / Ollama (Offline)         │
       │      + Deterministic CWE Template Fallback      │
       └────────────────────────┬────────────────────────┘
                                │
                                ▼
       ┌─────────────────────────────────────────────────┐
       │    SQLite Persistence & REST API Endpoints      │
       │   (/api/scans, /api/issues, /api/issues/{id})   │
       └─────────────────────────────────────────────────┘
```

---

## 🎯 Zero-Hallucination Philosophy

Unlike naive LLM wrappers that guess line numbers or invent vulnerabilities:

1. **Zero LLM Detection**: All vulnerabilities are detected strictly and deterministically by Semgrep rules, AST pattern matching, or live OWASP ZAP alerts.
2. **Zero LLM Line Guessing**: Line numbers, bounds, and endpoints are derived directly from Python AST nodes (`node.lineno`, `node.end_lineno`).
3. **Sandboxed LLM Remediation**: The LLM is invoked **only after** an issue is deterministically proven. It runs with `temperature=0.0` strictly to suggest fix instructions and code snippets.
4. **Deterministic Fallback**: If Groq or Ollama is offline or unavailable, Cyber-Forge immediately returns built-in, industry-standard remediation templates without failing.

---

## 🛡️ Supported Canonical CWEs

Cyber-Forge normalizes all scanner-specific rule IDs and child CWEs into canonical parent CWEs:

| Canonical CWE | Vulnerability Name | SAST Detector | DAST Detector |
| :--- | :--- | :--- | :--- |
| **`CWE-89`** | SQL Injection | Semgrep / AST query concatenation | OWASP ZAP Active Scan / Error Injection |
| **`CWE-79`** | Cross-Site Scripting (XSS) | Semgrep / AST unescaped template render | OWASP ZAP Reflected/Stored XSS probes |
| **`CWE-22`** | Path Traversal / LFI | Semgrep / AST `open()` / path join | OWASP ZAP Path Traversal vectors |
| **`CWE-78`** | OS Command Injection | Semgrep / AST `os.system` / `subprocess` | OWASP ZAP Command Injection payloads |
| **`CWE-798`** | Hard-coded Secrets / API Keys | Semgrep / High-entropy regex detector | N/A (Code only) |
| **`CWE-328`** | Weak Hashing / Broken Crypto | Semgrep / AST `hashlib.md5` / `sha1` | N/A (Code only) |
| **`CWE-918`** | Server-Side Request Forgery (SSRF) | Semgrep / AST arbitrary URL requests | OWASP ZAP SSRF / Out-of-band checks |
| **`CWE-601`** | Open Redirect | Semgrep / AST redirect parameters | OWASP ZAP Redirect probes |
| **`CWE-693`** | Missing Defensive Security Headers | AST / Header config audit | OWASP ZAP CSP/HSTS/X-Frame-Options audit |

---

## 🚀 Quick Start & Installation

### Prerequisites

- **Python**: 3.9, 3.10, 3.11, or 3.12
- **Node.js**: 18+ and `npm` (for the React dashboard)
- **Semgrep CLI**: Installed automatically via `requirements.txt`
- **Model Backend**:
  - **Groq API key** for lightning-fast online analysis ([free key at console.groq.com](https://console.groq.com/keys)), **OR**
  - **Ollama** for 100% offline local analysis ([ollama.ai](https://ollama.ai))

### 1. Clone & Set Up Python Environment

```bash
git clone https://github.com/yourusername/LLM-Code-Analyzer.git
cd LLM-Code-Analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Set Up Frontend

```bash
cd frontend
npm install
npm run build
cd ..
```

### 3. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and set your Groq API key:

```env
LLM_MODE=groq
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

### 4. Run the Engine

**Development Mode (Hot-Reload Frontend + Backend):**
```bash
./start_dev.sh
# Frontend: http://localhost:3000
# Backend:  http://localhost:8000
# Docs:     http://localhost:8000/docs
```

**Production Online Mode (Groq):**
```bash
./start_online.sh
# Access: http://localhost:8000
```

**Production Offline Mode (Ollama):**
```bash
./start_offline.sh
# Access: http://localhost:8001
```

---

## 🔧 Configuration Reference (`.env`)

| Variable | Description | Default | Allowed Values |
| :--- | :--- | :--- | :--- |
| `LLM_MODE` | Selected LLM backend provider | `groq` | `groq`, `ollama` |
| `GROQ_API_KEY` | Groq API authorization key | `""` | `gsk_...` |
| `GROQ_MODEL` | Groq chat completion model | `llama-3.3-70b-versatile` | Any Groq chat model |
| `OLLAMA_BASE_URL` | Local Ollama daemon endpoint | `http://localhost:11434` | Any URL |
| `OLLAMA_MODEL` | Local Ollama model name | `codellama` | e.g., `codellama`, `qwen2.5-coder` |
| `HOST` | Server bind host address | `0.0.0.0` | IP string |
| `PORT` | Server listen port | `8000` | Port integer |
| `DEBUG` | Enable debug logging | `false` | `true`, `false` |
| `ANALYSIS_TIMEOUT` | Scanner & analysis timeout (sec) | `120` | Seconds integer |
| `RATE_LIMIT_ANALYSIS_PER_MINUTE` | Maximum analysis requests/min | `60` | Requests integer |

---

## 📖 REST API Reference & Examples

### 1. Run Complete End-to-End Correlation (`POST /api/scans`)

Initiates a combined SAST scan, DAST scan/ingestion, 3-way correlation, multi-scanner deduplication, risk scoring, and SQLite persistence.

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_dir": "data",
    "target_url": "http://localhost:5000",
    "raw_dast_alerts": [
      {
        "alert": "SQL Injection",
        "url": "http://localhost:5000/api/orders?id=1",
        "method": "GET",
        "param": "id",
        "attack": "1 OR 1=1",
        "evidence": "syntax error near SELECT",
        "cweid": "89"
      }
    ]
  }'
```

**Response (`FullScanResponse`):**
```json
{
  "scan_id": "c1f7a462-811c-4e78-9e63-c7ad6e6cb394",
  "status": "completed",
  "summary": {
    "total_issues": 1,
    "confirmed_count": 1,
    "runtime_only_count": 0,
    "code_only_count": 0,
    "critical_count": 1,
    "high_count": 0
  },
  "routes_discovered": 3,
  "issues": [
    {
      "id": "e93a7d...",
      "status_label": "Confirmed",
      "risk_score": 92.5,
      "cwe_id": "CWE-89",
      "vulnerability_type": "SQL Injection",
      "severity": "CRITICAL",
      "file": "data/sample_vulnerable.py",
      "line": 88,
      "url_path": "/api/orders",
      "http_method": "GET",
      "parameter": "id",
      "payload": "1 OR 1=1",
      "evidence": "syntax error near SELECT",
      "code_snippet": "cursor.execute(f'SELECT * FROM orders WHERE id = {order_id}')",
      "fix_suggestion": "Use parameterized queries or ORM abstractions instead of direct string concatenation.",
      "fixed_code": "# Use parameterized query binding\ncursor.execute('SELECT * FROM orders WHERE id = %s', (order_id,))"
    }
  ]
}
```

### 2. Query Prioritized Correlated Issues (`GET /api/issues`)

Retrieve deduplicated issues sorted strictly by priority rank (`Confirmed` first, then `Runtime only`, then `Code only`) and descending risk score:

```bash
# Get all issues
curl http://localhost:8000/api/issues

# Filter by status and minimum severity
curl "http://localhost:8000/api/issues?status_label=Confirmed&severity=CRITICAL"
```

### 3. Get Single Issue Detail with Full Evidence (`GET /api/issues/{issue_id}`)

```bash
curl http://localhost:8000/api/issues/e93a7d...
```

### 4. Extract AST Route Map from Codebase (`GET /api/sast/routes`)

Analyzes target directory source files and returns all registered routes:

```bash
curl "http://localhost:8000/api/sast/routes?target_dir=data"
```

**Response:**
```json
[
  {
    "http_method": "GET",
    "url_path": "/api/orders",
    "file": "data/sample_vulnerable.py",
    "handler_function": "get_orders",
    "start_line": 80,
    "end_line": 95
  }
]
```

### 5. Run SAST-Only Scan (`POST /api/sast/scan`)

```bash
curl -X POST http://localhost:8000/api/sast/scan \
  -H "Content-Type: application/json" \
  -d '{"target_dir": "data"}'
```

---

## 🏗️ Project Structure

```
Cyber-Forge/
├── backend/
│   ├── app.py                     # FastAPI application lifespan & routing
│   ├── config.py                  # Pydantic Settings (Groq, Ollama, server configuration)
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py             # UnifiedFinding, RouteEntry, CorrelatedIssue models
│   ├── routes/
│   │   ├── __init__.py
│   │   └── analyze.py             # REST endpoints (/scans, /issues, /sast, /dast)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── analyzer.py            # Legacy analysis orchestrator
│   │   ├── correlator.py          # 3-way correlation & risk ranking engine (FR-5, FR-9)
│   │   ├── cwe_normalizer.py      # Canonical CWE mapping dictionary (FR-3)
│   │   ├── dast_scanner.py        # OWASP ZAP live scanner & report ingestion (FR-2)
│   │   ├── llm_service.py         # Sandboxed Groq/Ollama remediation generator
│   │   ├── route_mapper.py        # AST static route extractor for Python/Express (FR-4)
│   │   ├── sast_scanner.py        # Semgrep CLI + AST Regex fallback scanner (FR-1)
│   │   ├── static_analyzer.py     # Deterministic static rule fallback
│   │   └── store.py               # SQLite persistence layer with idempotent upsert (FR-10)
│   └── utils/
│       ├── __init__.py
│       ├── logger.py              # Structured JSON logger with correlation IDs
│       ├── prompt_engine.py       # Sandboxed remediation prompt builder
│       └── rate_limit.py          # SlowAPI rate limiting configuration
├── data/                          # Sample vulnerable projects & SQLite DB storage
├── docs/                          # Architecture guides & documentation
├── frontend/                      # React 19 + Vite + Tailwind CSS dashboard
├── .env.example                   # Environment configuration template
├── requirements.txt               # Python production dependencies
├── start_dev.sh                   # Dev mode launcher (hot-reload, ports 3000 & 8000)
├── start_online.sh                # Production Groq launcher (port 8000)
├── start_offline.sh               # Production Ollama launcher (port 8001)
├── test_phase1_fixes.py           # Unit tests for settings, logger, and LLM service
├── test_sast_phase1.py            # Unit tests for FR-1, FR-3, FR-4 (SAST & AST Routes)
├── test_dast_phase2.py            # Unit tests for FR-2, FR-3, FR-6 (DAST & Normalizer)
└── test_correlation_phase3.py     # Unit tests for FR-5, FR-6, FR-7, FR-9, FR-10
```

---

## 🧪 Testing & Verification

Cyber-Forge includes an automated test suite verifying every functional requirement:

### Run Full Pytest Suite

```bash
python3 -m pytest test_phase1_fixes.py test_sast_phase1.py test_dast_phase2.py test_correlation_phase3.py -v
```

**Results (34 / 34 Passed):**
- `test_phase1_fixes.py`: Groq/Ollama mode verification, removed OpenAI/Gemini attributes, logger.
- `test_sast_phase1.py`: Semgrep detection across all 6 core CWEs, AST Route Mapper (FastAPI, Flask, Express), SHA-256 deduplication fingerprints.
- `test_dast_phase2.py`: URL path normalization, ZAP CWE/plugin normalization, Mode A live mock, Mode B diagnostics.
- `test_correlation_phase3.py`: 3-way correlation algorithm, multi-scanner merging, strict 3-state output labels, priority ranking matrix, sandboxed remediation fallback, idempotent SQLite upserts.

### Run Phase Validation Script

```bash
python3 phase1_validation.py
```

---

## 📄 License & Acknowledgments

- **License**: MIT License
- **Frameworks**: [FastAPI](https://fastapi.tiangolo.com/), [React](https://react.dev/), [Vite](https://vitejs.dev/), [Tailwind CSS](https://tailwindcss.com/)
- **Engines**: [Semgrep](https://semgrep.dev/), [OWASP ZAP](https://www.zaproxy.org/)
- **Inference**: [Groq](https://groq.com/) (Llama-3.3-70B) & [Ollama](https://ollama.ai/) (CodeLlama)
