# Cyber-Forge

Cyber-Forge combines Python source scanning, runtime web scanning, and route-to-code correlation. It exposes a FastAPI backend and React UI, normalizes findings into a shared format, labels issues as **Confirmed**, **Runtime only**, or **Code only**, and stores results in SQLite.

## Run the application

### Docker Compose (PyGoat + Cyber-Forge + ZAP)

Requirements: Docker Compose, the PyGoat checkout at `data/pygoat`, and a Groq API key for AI-assisted SAST and remediation.

1. Copy `.env.example` to `.env` and set `GROQ_API_KEY`.
2. From the repository root, run:

```sh
docker compose -f docker-compose.pygoat.yml up -d --build
```

- PyGoat: <http://localhost:8000>
- Cyber-Forge UI and API: <http://localhost:8001>
- API documentation: <http://localhost:8001/docs>

The Cyber-Forge container shares PyGoat's network namespace so it can reach the app and the ZAP daemon. To stop the stack, run `docker compose -f docker-compose.pygoat.yml down`.

### Local backend development

Install Python dependencies with `python3 -m pip install -r requirements.txt`, configure `.env`, then start the backend with:

```sh
PYTHONPATH=. python3 -m backend.app
```

The local frontend is in `frontend/`; use its npm scripts for development or a production build.

## Scan flow

The combined endpoint is `POST /api/scans`. It accepts a source folder and/or uploaded source files, and optionally a runtime URL or previously captured ZAP alerts. For a combined scan, Cyber-Forge:

1. Extracts an AST route map from Python, Flask/FastAPI, and supported Express route declarations.
2. Runs SAST on the source. Small folders may use Semgrep, deterministic AST/regex and Python taint analysis run as the local rules, and enabled SAIST analyzes Python files.
3. Runs DAST against the supplied URL through OWASP ZAP, or normalizes supplied reports. If ZAP is unavailable, the scanner can run limited passive HTTP checks.
4. Normalizes and deduplicates findings, then correlates runtime URLs and CWEs with source routes and lines.
5. Persists the combined issues and returns the route map and findings.

Use `GET /api/issues` to retrieve the latest results. Other useful endpoints include `POST /api/sast/scan`, `POST /api/dast/scan`, and `GET /api/sast/routes`. See `/docs` for request schemas.

## SAST implementation

- **Semgrep:** invoked for smaller folder scans. To keep large scans bounded, Semgrep CLI is skipped when a folder contains more than 10 Python files.
- **Deterministic scanning:** AST/regex rules and the Python taint engine provide local findings and source locations.
- **SAIST path:** enabled by default in the Docker Compose service. The runner scans `.py` files and focuses on CWE-89, CWE-79, CWE-22, CWE-78, CWE-798, CWE-328, CWE-918, and CWE-601. It filters to explicit supported CWE labels, valid source lines, and HIGH-confidence validation responses.
- **Datadog distinction:** the official `datadog-saist` executable is not included in the current container. When it is absent, the runner uses the project's native two-stage SAIST-style implementation and calls the configured Groq model. This is not Datadog's hosted model or official CLI. Configure `DATADOG_SAIST_BIN` if you have installed the official executable.

The default container model is `openai/gpt-oss-120b`; configure `GROQ_MODEL` in `.env` to select another supported Groq model. The native AI path needs a working Groq API key. Without it, deterministic SAST can still run but AI-assisted SAIST is skipped.

## DAST implementation

The DAST endpoint supports a live OWASP ZAP daemon and ingestion of ZAP, Nuclei, or SARIF reports. Live scans can seed routes extracted by SAST, then collect ZAP alerts. The scanner normalizes alert URLs, methods, parameters, payloads, evidence, severity, and CWE values. It also has limited passive HTTP checks for response headers, cookies, server banners, and debug error disclosures when a live ZAP daemon is unavailable. Passive checks do not replace an active scan.

## Finding labels

- **Confirmed:** a source finding is correlated with a compatible runtime finding.
- **Runtime only:** a DAST finding has no matching source finding.
- **Code only:** a SAST finding has no matching runtime finding.

Correlation uses canonical CWEs and route/path, line, and parameter context; matches are deduplicated and ranked. A label is evidence of the correlation logic, not a guarantee that every scanner finding is exploitable.

## OWASP BenchmarkPython results

The recorded benchmark run is documented in [benchmark-results/analysis.md](benchmark-results/analysis.md). It used a deterministic, category-balanced sample of 140 cases from the 1,230-case suite (seed `20261101`) and an 11-rule, low-strength ZAP profile. The benchmark is optional and can be run with `docker-compose.benchmark.yml`; instructions are in [benchmark/README.md](benchmark/README.md).

| Scanner / scoring | TP | FP | TN | FN | Accuracy | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Cyber-Forge SAST, exact expected CWE | 70 | 0 | 70 | 0 | 100.0% | 100.0% | 100.0% |
| Cyber-Forge DAST, exact expected CWE | 13 | 0 | 70 | 57 | 59.3% | 100.0% | 18.6% |
| Combined evidence, exact expected CWE | 70 | 0 | 70 | 0 | 100.0% | 100.0% | 100.0% |

These are **sample results**, not full-suite performance. The run took 667 seconds (about 11 minutes). The broader SAST any-finding score had 5 false-positive cases; those findings did not match the expected CWE and therefore are not exact-CWE false positives in the table. The SAST benchmark was completed before the later change that enabled SAIST for large batches, so it does not measure the current SAIST-enabled batch path. Re-run the benchmark to measure that configuration. A previous 21-rule profile took about 20 minutes and recorded 17 exact-CWE raw ZAP hits and 19 normalized Cyber-Forge DAST hits, including 10 exact-CWE DAST false positives; the faster 11-rule profile found 13 exact-CWE hits with no exact-CWE false positives. The tradeoff is reduced ZAP rule coverage.

## Optional benchmark commands

The benchmark target is a separate container; its source is mounted read-only and is not part of the normal application runtime.

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml up -d --build benchmark benchmark-zap cyberforge
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml --profile benchmark run --rm benchmark-runner --cases-per-category 10
```

The harness writes reports to `benchmark-results/`. It replays and scans only the selected sample; it does not spider the whole suite.

## Configuration

Relevant environment variables (set in `.env`):

| Variable | Purpose | Default |
|---|---|---|
| `GROQ_API_KEY` | Groq API key for SAIST and LLM features | empty |
| `GROQ_MODEL` | Model used for Groq requests | `llama-3.3-70b-versatile` in Docker Compose |
| `LLM_MODE` | Remediation provider | `groq` |
| `ENABLE_DATADOG_SAIST` | Enable the SAIST runner | `true` |
| `DATADOG_SAIST_BIN` | Optional path to the official CLI executable | `./bin/datadog-saist` |
| `OLLAMA_BASE_URL` / `OLLAMA_MODEL` | Local Ollama configuration | `http://localhost:11434` / `codellama` |

## Main components

```text
backend/
  app.py                         FastAPI application
  routes/analyze.py              SAST, DAST, combined scan APIs
  services/sast_scanner.py       SAST orchestration and finding merge
  services/datadog_saist_runner.py Native SAIST-style detection and SARIF parsing
  services/python_taint_engine.py Deterministic Python taint analysis
  services/static_analyzer.py    Deterministic AST/regex rules
  services/route_mapper.py       AST route extraction
  services/dast_scanner.py       ZAP/report DAST normalization
  services/correlator.py         Cross-scanner correlation and ranking
  services/store.py              SQLite persistence
frontend/                        React UI
docker-compose.pygoat.yml        PyGoat, Cyber-Forge, and ZAP stack
docker-compose.benchmark.yml     Optional isolated benchmark overlay
scripts/run_owasp_benchmark.py   Benchmark runner
```
