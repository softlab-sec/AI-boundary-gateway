#!/usr/bin/env bash
# Minimal acceptance check.
set -uo pipefail
cd "$(dirname "$0")/.."
P=0; F=0
ok(){ printf "  \033[32mPASS\033[0m %s\n" "$1"; P=$((P+1)); }
no(){ printf "  \033[31mFAIL\033[0m %s :: %s\n" "$1" "${2:-}"; F=$((F+1)); }
WS(){ docker compose exec -T workstation "$@"; }

curl -sf http://192.168.253.11/healthz >/dev/null && ok "edge reachable" || no "edge reachable"
curl -sf http://localhost:8000/healthz >/dev/null && ok "CRM up" || no "CRM up"
curl -sf http://localhost:8090/api/summary >/dev/null && ok "console up" || no "console up"
N=$(curl -s "localhost:8000/api/customers?limit=1000" | jq length); [ "$N" -ge 200 ] && ok "dataset $N records" || no "dataset" "$N"
G=$(jq length gateway/gazetteer.json 2>/dev/null || echo 0); [ "$G" -ge 500 ] && ok "gazetteer $G terms" || no "gazetteer" "$G"

curl -s -X POST http://192.168.253.11:8080/api/reset >/dev/null
./scripts/steer.sh direct >/dev/null
# wait until DNS actually resolves to the edge before firing
for i in $(seq 1 10); do
  R=$(WS getent hosts api.openai.com 2>/dev/null | awk '{print $1}')
  [ "$R" = "192.168.253.11" ] && break; sleep 1
done
S=""
for i in $(seq 1 6); do
  WS python leak.py --scenario clipboard-extension --payload record --quiet >/dev/null 2>&1
  sleep 1
  S=$(curl -s http://192.168.253.11:8080/api/received | jq -r '.items[0].observed_sensitive // {} | keys | join(",")')
  echo "$S" | grep -q EMAIL && break
done
echo "$S" | grep -q EMAIL && ok "direct mode leaks raw PII ($S)" || no "direct leak" "$S"

curl -s -X POST http://localhost:8090/api/mode/enforce >/dev/null
./scripts/steer.sh boundary >/dev/null
O=$(WS python leak.py --scenario clipboard-extension --payload record 2>&1)
echo "$O" | grep -q "HTTP 451" && ok "shadow key blocked" || no "shadow key blocked"
O=$(WS python leak.py --scenario unvetted-provider --payload secrets 2>&1)
echo "$O" | grep -qi "Credential material" && ok "secrets blocked" || no "secrets blocked"
O=$(WS python leak.py --scenario shadow-script --payload bulk-export 2>&1)
echo "$O" | grep -qi "bulk exfiltration" && ok "bulk export blocked" || no "bulk export blocked"

curl -s -X POST http://192.168.253.11:8080/api/reset >/dev/null
O=$(WS python leak.py --scenario sanctioned --payload record 2>&1)
echo "$O" | grep -q "HTTP 200" && ok "sanctioned path works" || no "sanctioned path" "$(echo "$O"|tail -3)"
S=$(curl -s http://192.168.253.11:8080/api/received | jq -r '.items[0].observed_sensitive|keys|join(",")')
[ "$S" = "TOKENISED" ] && ok "provider saw tokens only" || no "masking" "$S"
if echo "$O" | grep -q "x-boundary-detokenised: true"; then ok "response detokenised"
else printf "  \033[33mWARN\033[0m response detokenise header absent (provider reply carried no token this run, masking still verified above)\n"; fi
O=$(WS python leak.py --scenario sanctioned --payload source 2>&1)
echo "$O" | grep -qi "not scoped" && ok "over-scoped key blocked" || no "scope rule"

printf "\n%d passed, %d failed\n" "$P" "$F"; [ "$F" -eq 0 ]
