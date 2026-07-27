#!/usr/bin/env bash
# ./steer.sh direct    -> AI hostnames resolve to the edge VM, nothing inspected
# ./steer.sh boundary  -> AI hostnames resolve to the gateway, everything inspected
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  direct)   TARGET="192.168.253.11" ;;
  boundary) TARGET="172.30.0.10" ;;
  *) echo "usage: steer.sh direct|boundary"; exit 1 ;;
esac
sed -i -E "s/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /${TARGET} /" dns/ai-hosts
sed -i "s|^# mode: .*|# mode: ${1}|" dns/ai-hosts
docker compose restart corp-dns >/dev/null
sleep 4
echo "[+] AI destinations now resolve to ${TARGET}  (${1})"
docker compose exec -T workstation getent hosts api.openai.com || true
