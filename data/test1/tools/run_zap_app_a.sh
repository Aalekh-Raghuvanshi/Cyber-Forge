#!/usr/bin/env bash
set -euo pipefail
mkdir -p outputs
# The Docker network is internal-only; target is the service name, not a public host.
docker run --rm --network sdcbench_benchnet -v "$PWD/outputs:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://app-a:5000 -m 3 -J zap-app_a.json
