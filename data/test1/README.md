# SAST-DAST Correlation Advanced Benchmark

A reproducible, intentionally vulnerable two-application benchmark for a 24-hour hackathon SAST-DAST correlation engine.

## What's included

- **App A (known/test app):** 20 planted code/runtime vulnerability pairs and 10 safe decoys.
- **App B (unseen/holdout app):** a separate implementation with 20 planted pairs and 10 safe decoys. Keep it out of tuning until you evaluate generalization.
- **Semgrep rules:** benchmark-specific rules for SQL injection, reflected XSS, path traversal, open redirect, and command injection.
- **ZAP run scripts:** full active scan commands for each app.
- **Runtime smoke probes:** controlled, known-input checks that verify each planted behavior is reachable. These validate the fixture; they do not replace an independent DAST scan.
- **Ground truth:** positive pair map, exact source sink line, route, parameter, CWE, and safe-decoy rationale.
- **Scorer:** calculates the scorecard metrics from normalized JSON emitted by your engine.

## Vulnerability mix per app

| Type | Count | CWE |
|---|---:|---|
| SQL Injection | 6 | CWE-89 |
| Reflected Cross-Site Scripting | 6 | CWE-79 |
| Path Traversal | 4 | CWE-22 |
| Open Redirect | 2 | CWE-601 |
| OS Command Injection | 2 | CWE-78 |
| **Total planted pairs** | **20** | |

Each app also contains 10 safe decoys that resemble risky patterns but apply a valid control (parameterized SQL, allow-listing, output escaping, template autoescaping, path containment, safe file serving, relative redirect validation, or `shell=False`).

## IMPORTANT SAFETY NOTICE

These applications are deliberately vulnerable. The command-injection routes execute only the benign `printf` test payloads in the included probes, but the vulnerability itself can execute shell commands. **Run the apps only with the supplied Docker Compose file. Do not run the Flask apps directly on your host, do not expose ports publicly, and do not deploy them to a cloud host.** The Compose network is internal-only, containers run as a non-root user, have a read-only root filesystem, drop Linux capabilities, and publish only to loopback.

Only scan this supplied local benchmark. Do not point ZAP or active scanners at systems you do not own or have explicit permission to test.

## Start the two benchmark apps

Requirements: Docker Engine and Docker Compose plugin.

```bash
docker compose up --build -d
```

- App A: http://127.0.0.1:5001
- App B: http://127.0.0.1:5002
- Health checks: `http://127.0.0.1:5001/__health` and `http://127.0.0.1:5002/__health`

Stop:

```bash
docker compose down
```

## Run SAST with Semgrep

Install Semgrep in your scanner environment, then from the dataset root:

```bash
bash tools/run_semgrep.sh app_a
bash tools/run_semgrep.sh app_b
```

The script combines Semgrep's Python rules with `semgrep/benchmark-rules.yml` and writes JSON to `outputs/semgrep-app_a.json` / `outputs/semgrep-app_b.json`.

For holdout evaluation, first tune against App A. Do not inspect `ground_truth/` or scan App B until ready to evaluate generalization. App B's probe manifest is also kept in `ground_truth/`.

## Run DAST with OWASP ZAP

The supplied scripts run ZAP's full scan from a container attached to the benchmark's internal-only Docker network:

```bash
bash tools/run_zap_app_a.sh
bash tools/run_zap_app_b.sh
```

Reports are written under `outputs/`. ZAP may not discover every issue automatically; use its spider/active scan settings and inspect alert evidence. The benchmark's runtime probes below are independent fixture checks, not ZAP findings.

## Verify the planted runtime behavior

Install the helper dependency:

```bash
python -m pip install -r requirements-tools.txt
python tools/runtime_probes.py --app app_a --output outputs/probes-app-a.json
python tools/runtime_probes.py --app app_b --output outputs/probes-app-b.json
```

Every probe uses a harmless proof marker. Redirect probes do not follow redirects. Command-injection probes only run `printf` and should only be used against the isolated Docker apps.

## Normalized output expected from your correlation engine

Create a JSON file (example: `outputs/normalized-app-a.json`) using this shape:

```json
{
  "code_findings": [
    {"file": "apps/app_a/app.py", "line": 100, "cwe": "CWE-89", "type": "SQL Injection"}
  ],
  "runtime_findings": [
    {"method": "GET", "path": "/api/catalog/search", "parameter": "term", "cwe": "CWE-89", "type": "SQL Injection", "evidence": "..."}
  ],
  "confirmed_issues": [
    {
      "sast": {"file": "apps/app_a/app.py", "line": 100},
      "dast": {"method": "GET", "path": "/api/catalog/search", "parameter": "term"},
      "status": "confirmed",
      "confidence": 0.95
    }
  ],
  "reported_issues": [
    {"file": "apps/app_a/app.py", "line": 100, "method": "GET", "path": "/api/catalog/search", "parameter": "term", "title": "SQL injection"}
  ],
  "scan_seconds": 180
}
```

Paths must be relative to the dataset root. The scorer matches exact source sink lines and exact `(method, path, parameter)` runtime locations. CWE can be included as an additional consistency check. `reported_issues` should represent all issues your UI/report actually shows; it is used for the safe-decoy false-alarm rate.

## Score your system

```bash
python tools/score_results.py --app app_a --results outputs/normalized-app-a.json
python tools/score_results.py --app app_b --results outputs/normalized-app-b.json
```

App A is your known test app. App B is your unseen app; its `correct_links_pct` is also reported as `unseen_app_pct`.

## Scorecard targets

These are copied from the supplied one-page target sheet:

| Metric | Good | Great |
|---|---:|---:|
| Code detection | >60% | >85% |
| Runtime detection | >50% | >80% |
| Correct links (20 planted pairs) | >50% | >80% |
| Wrong links | <20% | <5% |
| False alarms (safe decoys) | <30% | <10% |
| Unseen app linked pairs | >40% | >65% |
| Scan + correlate + report | <15 min | <5 min |

## Ground-truth handling

`ground_truth/answer_key.json` and `ground_truth/answer_key_pairs.csv` contain exact positive pairs and safe decoys. Treat these as evaluator-only files. For an honest holdout test, tune your engine on App A without reading App B's answer-key entries, then run App B unchanged.

## Limitations

- This is a controlled synthetic benchmark, not a complete production security test suite.
- It focuses on five vulnerability classes and Python/Flask applications.
- ZAP's results depend on spider coverage, active-scan policy, version, and scan duration. A clean ZAP report does not prove the application is safe.
- The supplied custom Semgrep rules are tuned for this fixture's syntax; combine them with broader maintained rules and your own taint/data-flow analysis for real repositories.
- Runtime proof markers demonstrate intentionally planted behavior inside the lab; they are not a universal exploitability verdict for arbitrary applications.
