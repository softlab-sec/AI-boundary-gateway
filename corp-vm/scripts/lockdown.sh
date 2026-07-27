#!/usr/bin/env bash
# ./lockdown.sh on|off   Only the gateway may reach the edge VM.
set -euo pipefail
SUBNET=172.30.0.0/24; GW=172.30.0.10; EDGE=192.168.253.11
case "${1:-on}" in
 on)
  sudo iptables -I DOCKER-USER 1 -s "$GW"     -d "$EDGE" -p tcp --dport 80 -j ACCEPT
  sudo iptables -I DOCKER-USER 2 -s "$SUBNET" -d "$EDGE" -p tcp --dport 80 -j REJECT --reject-with icmp-admin-prohibited
  echo "[+] only ${GW} may reach ${EDGE}:80" ;;
 off)
  sudo iptables -D DOCKER-USER -s "$SUBNET" -d "$EDGE" -p tcp --dport 80 -j REJECT --reject-with icmp-admin-prohibited 2>/dev/null || true
  sudo iptables -D DOCKER-USER -s "$GW"     -d "$EDGE" -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
  echo "[+] direct egress restored" ;;
esac
sudo iptables -S DOCKER-USER
