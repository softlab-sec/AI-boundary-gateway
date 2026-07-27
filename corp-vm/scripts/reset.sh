#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
curl -s -X POST http://localhost:8090/api/reset >/dev/null && echo "[+] audit cleared"
curl -s -X POST http://10.10.10.10:8080/api/reset >/dev/null && echo "[+] receipts cleared"
curl -s -X POST http://localhost:8090/api/mode/monitor >/dev/null && echo "[+] policy = monitor"
./scripts/steer.sh direct
./scripts/lockdown.sh off >/dev/null 2>&1 || true
