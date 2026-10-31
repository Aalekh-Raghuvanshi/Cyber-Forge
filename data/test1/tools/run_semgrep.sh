#!/usr/bin/env bash
set -euo pipefail
APP="${1:-app_a}"
if [[ "$APP" != "app_a" && "$APP" != "app_b" ]]; then echo "Usage: $0 app_a|app_b" >&2; exit 2; fi
mkdir -p outputs
semgrep scan --metrics=off --config p/python --config semgrep/benchmark-rules.yml --json --output "outputs/semgrep-${APP}.json" "apps/${APP}"
echo "Wrote outputs/semgrep-${APP}.json"
