# OWASP BenchmarkPython harness

This optional overlay runs the official OWASP BenchmarkPython v0.1 app beside the existing PyGoat and Cyber-Forge stack. The benchmark is reachable from the host only at `https://localhost:8443`; its self-signed certificate is expected. Benchmark requests and ZAP active scans are confined to this local benchmark service. It uses a separate `benchmark-zap` container so the existing ZAP service configuration is not changed.

The overlay mounts the benchmark source read-only into Cyber-Forge at `/benchmark-python`. The one-shot runner defaults to a deterministic sample of ten cases per category: five vulnerable and five non-vulnerable where available. It replays only those cases, actively scans their specific URLs and declared GET/POST inputs, submits the ZAP report to Cyber-Forge's DAST ingestion endpoint, and scans the same testcase source files with Cyber-Forge SAST. It does not spider or recursively scan the full 1,230-case site. The active scan uses a focused set of core injection-related ZAP rules at low strength and two request threads per host; expensive persistent, time-based, DOM, and blind rules are excluded. The selected cases, rules, and duration limits are included in the reports. This bounded profile is needed because an unrestricted scan exhausted the available Docker memory and took too long on the full target. Results are written to the ignored `benchmark-results/` directory.

From the repository root, start the benchmark service and add the read-only SAST mount to Cyber-Forge:

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml up -d --build benchmark benchmark-zap cyberforge
```

Run the stratified sample (to increase or reduce the case count, pass `--cases-per-category` after the runner command):

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml --profile benchmark run --rm benchmark-runner
```

For example, run `docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml --profile benchmark run --rm benchmark-runner --cases-per-category 10` to scan up to ten cases in each category. The output explicitly reports that it is a sample and lists the seed and category counts; it is not a full-suite OWASP score.

Open the benchmark app at `https://localhost:8443`. The result files are `summary.md`, `score.json`, `zap-alerts.json`, `cyberforge-dast.json`, and `cyberforge-sast.json` under `benchmark-results/`.

Scoring is testcase-based over the selected sample. A finding must identify a `BenchmarkTestNNNNN` case in its URL or source path. The report provides both case detection and exact expected-CWE detection; findings with no testcase identifier are counted as unmapped and do not inflate true/false positives. The upstream answer key is preliminary v0.1. Its source is mounted read-only and is not patched by this harness.

To stop the optional benchmark and its dedicated scanner:

```sh
docker compose -f docker-compose.pygoat.yml -f docker-compose.benchmark.yml stop benchmark benchmark-zap
```
