# Cyber-Forge

Cyber-Forge is a web application for static analysis (SAST), dynamic analysis (DAST), and correlation of source-code findings with runtime evidence. It provides a React interface and FastAPI endpoints, uses OWASP ZAP for live DAST, and stores scan results in SQLite.

The normal Docker deployment starts Cyber-Forge alongside PyGoat and ZAP. An optional Docker Compose overlay runs OWASP BenchmarkPython for scanner evaluation.

## Run with Docker

### Requirements

- Docker Desktop or Docker Engine with the Compose plugin.
- PyGoat source available in `data/pygoat`.
- A Groq API key for AI-assisted SAST and remediation. Deterministic SAST can run without a key.

### Configure and start

From the repository root:

```sh
cp .env.example .env
```

Edit `.env` and set `GROQ_API_KEY` to your key. Then build and start the application:

```sh
docker compose -f docker-compose.pygoat.yml up -d --build
```

Open:

- PyGoat: <http://localhost:8000>
- Cyber-Forge UI and API: <http://localhost:8001>
- Interactive API documentation: <http://localhost:8001/docs>

Check service status and logs:

```sh
docker compose -f docker-compose.pygoat.yml ps
docker compose -f docker-compose.pygoat.yml logs -f cyberforge web zap
```

Stop the stack:

```sh
docker compose -f docker-compose.pygoat.yml down
```

The named `cyberforge-data` volume stores application data and is retained by `down`.

## Run a scan

The combined scan endpoint runs SAST, extracts routes, performs DAST, correlates results, and saves them. With the Docker stack above, send this request to scan the mounted PyGoat source and local PyGoat runtime:

```sh
curl -X POST http://localhost:8001/api/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "source_folder": "/pygoat",
    "target_url": "http://127.0.0.1:8000",
    "zap_api_url": "http://127.0.0.1:8090",
    "generate_fixes": false
  }'
```

Use `GET /api/issues` to retrieve findings from the latest scan. The API also provides focused endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /api/sast/scan` | Scan a source folder or supplied files. |
| `GET /api/sast/routes?source_folder=/pygoat` | Extract an AST route map. |
| `POST /api/dast/scan` | Scan a target URL or process supplied ZAP alerts. |
| `POST /api/scans` | Run a combined SAST and DAST scan and correlate findings. |
| `GET /api/issues` | Retrieve latest findings; supports `status_label` and `cwe_id` filters. |
| `GET /docs` | View interactive API documentation and request schemas. |

Paths supplied as `source_folder` must exist inside the Cyber-Forge container. In the provided Compose stack, the PyGoat checkout is mounted at `/pygoat`.

## How scanning works

### SAST

Cyber-Forge extracts route definitions and handler line ranges using AST and framework-aware parsing. It then combines deterministic AST/regex rules, the Python taint engine, and the configured AI-assisted runner. Semgrep CLI runs on smaller folders; for folders containing more than 10 Python files, it is skipped to avoid remote registry latency.

The SAIST runner is enabled by default in Docker Compose and scans Python files for these supported CWE classes:

- CWE-89: SQL injection
- CWE-79: cross-site scripting (XSS)
- CWE-22: path traversal
- CWE-78: OS command injection
- CWE-798: hard-coded credentials
- CWE-328: weak hashing
- CWE-918: server-side request forgery (SSRF)
- CWE-601: open redirect

**Datadog implementation detail:** the current container does not include the official `datadog-saist` executable. When that binary is unavailable, Cyber-Forge uses its native two-stage SAIST-style implementation through the configured Groq model. This is not Datadog's hosted model or official CLI. The native path requires `GROQ_API_KEY`; it filters unsupported or unlabeled CWEs, invalid source lines, and candidates that do not receive HIGH-confidence validation. This precision-oriented filter can reduce false positives and may also reduce recall.

### DAST

Cyber-Forge can run a live OWASP ZAP scan, ingest existing ZAP JSON, Nuclei JSON/JSONL, or SARIF reports, and run limited passive HTTP checks when ZAP is unavailable but the target is reachable. A live scan can use the AST route map as seed URLs. DAST findings retain runtime context such as URL path, HTTP method, parameter, payload, and evidence where available.

Passive checks inspect selected response headers, cookies, server banners, and debug disclosures. They are not a substitute for active scanning. Run active scans only against systems you are authorized to test.

### Correlation and result labels

Findings are normalized to canonical CWEs, deduplicated, and compared using CWE, route/path, source line, and parameter context. Results are labeled:

- **Confirmed:** a source finding correlates with compatible runtime evidence.
- **Runtime only:** DAST reported a finding without a matching source finding.
- **Code only:** SAST reported a finding without matching runtime evidence.

These labels represent the evidence available to the correlation engine; they do not by themselves prove that every finding is exploitable.

## Configuration

Set these values in `.env` before starting or rebuilding the containers:

| Variable | Description | Default |
|---|---|---|
| `GROQ_API_KEY` | API key used by the native SAIST runner and Groq features. | Empty |
| `GROQ_MODEL` | Groq model name. | `llama-3.3-70b-versatile` |
| `LLM_MODE` | LLM provider setting for remediation. | `groq` |
| `ENABLE_DATADOG_SAIST` | Enables the SAIST runner. | `true` |
| `DATADOG_SAIST_BIN` | Path to an installed official SAIST CLI binary, if available. | `./bin/datadog-saist` |
| `OLLAMA_BASE_URL` | Ollama endpoint when using local LLM features. | `http://localhost:11434` |
| `OLLAMA_MODEL` | Ollama model name. | `codellama` |

After changing environment values, apply them with:

```sh
docker compose -f docker-compose.pygoat.yml up -d --build
```

## Optional: Run OWASP BenchmarkPython

The benchmark uses a separate target container and dedicated ZAP instance. The benchmark checkout should be available at `data/benchmarkpython`. From the repository root, start the benchmark services and attach the benchmark source read-only to Cyber-Forge:

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml up -d --build benchmark benchmark-zap cyberforge
```

Run the stratified sample of up to 10 cases per category (140 cases in the recorded run):

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml --profile benchmark run --rm benchmark-runner --cases-per-category 10
```

The harness actively scans only selected case URLs and inputs; it does not spider the full 1,230-case suite. Results are written to `benchmark-results/`. Open the benchmark app at <https://localhost:8443>; its self-signed certificate is expected.

Stop the optional benchmark services:

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml stop benchmark benchmark-zap
```

## Benchmark results

The recorded run used a deterministic, category-balanced sample of 140 cases from the OWASP BenchmarkPython v0.1 suite, with seed `20261101`. The ZAP profile used 11 low-strength rules and completed in 667 seconds (about 11 minutes). Accuracy below is based on exact expected-CWE matching.

| Scanner | Accuracy |
|---|---:|
| Cyber-Forge SAST | 90.0% |
| Cyber-Forge DAST | 59.3% |
| Combined SAST + DAST | 90.0% |

These are sample results, not full-suite performance. The broader SAST any-finding score had five false-positive cases; these did not match the testcases' expected CWE and therefore are not false positives in the exact-CWE table. The recorded SAST benchmark also predates enabling SAIST on large batch scans, so it does not measure the current SAIST-enabled batch configuration. Re-run the benchmark to evaluate that configuration. The DAST result reflects a coverage/runtime tradeoff: an earlier 21-rule profile took about 20 minutes and produced more exact-CWE hits but also more exact-CWE false positives.

For per-metric scores, scanner profile details, and limitations, see [benchmark-results/analysis.md](benchmark-results/analysis.md). The project design and workflow diagrams are in [presentation.md](presentation.md).
