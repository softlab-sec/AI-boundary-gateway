# AI Egress Boundary 🛡️

**A content-aware shadow AI governance control.** It inspects AI-bound traffic, tokenizes sensitive data before it leaves the network, and blocks unregistered credentials, without breaking benign use of the same tools.

Two-VM lab, open-source components only, synthetic data generated locally at startup. No real AI provider and no real personal data are involved at any point.

---

## Overview

A firewall rule can block `chat.openai.com`. It cannot tell a harmless prompt apart from a customer record pasted into the same chat window, since both go to the same domain.

This project inspects the request itself instead: personal data, financial identifiers, and secrets get blocked or tokenized, a harmless prompt on the same unapproved tool still goes through, and an approved integration on a registered credential keeps working with real values, while the external provider only ever sees tokens.

---

## Key Features 🔑

- **Inspects content, not just domain.** Decision is made on what's inside the request.
- **Deterministic tokenization.** Same value always produces the same token; the key that reverses it never leaves the network.
- **Credential-aware.** An unregistered API key is flagged. A registered key used outside its declared data scope is blocked even though the key itself is valid.
- **Joint decision logic.** An unregistered credential alone doesn't block a request, only content does that. Prevents this from collapsing into a blanket blocklist.
- **Zero client config.** Runs as a reverse proxy behind internal DNS. No browser or app needs a proxy setting.
- **Hot-reloaded policy.** One YAML file, re-read on change, no restart.
- **Full audit trail.** Identity, destination, credential, data class, decision, and reason, per request. Values themselves are never logged.

---

## Architecture

<p align="center"><img src="docs/architecture.png" alt="AI egress boundary architecture, edge and corp hosts either side of the gateway" width="850"></p>

```
                    CLIENT (browser / scripted endpoint)
                              |
                              v
+------------------- CORP HOST --------------------+
|  System of record --+          +-- Endpoint       |
|   (CRM)              |          |   simulator     |
|                       v          v                |
|          +--------------------------------+       |
|          |   AI EGRESS BOUNDARY GATEWAY    |       |
|          | attribute -> authorise ->       |       |
|          | inspect -> act -> record        |       |
|          +---------------+------------------+      |
|                ^          |                        |
|        internal DNS   console                      |
+-------------------|-------------------------------+
          perimeter, only the gateway crosses it
                     |
+------------------- EDGE HOST --------------------+
|  consumer AI UI  <-- router --> mock provider     |
+----------------------------------------------------+
```

| Host | Role |
|---|---|
| Edge (`192.168.253.11`) | Simulated internet: router, mock AI provider, consumer chat UI |
| Corp (`192.168.253.12`) | CRM, internal DNS, boundary gateway, governance console, workstation simulator |

**Request lifecycle:** attribute the identity → authorise the destination and credential → inspect the payload (regex + a live gazetteer pulled from the CRM) → act (allow / alert / mask / block, strongest finding wins) → record one audit line, values never logged. Masked values become `<<CATEGORY_hash>>` tokens (HMAC), swapped back to real values before the response reaches the caller.

---

## Repository Structure

```
edge-vm/
  docker-compose.yml
  nginx/            # hostname-based routing
  mock-llm/          # simulated external AI provider
  shadow-ui/          # consumer AI interface
corp-vm/
  docker-compose.yml
  dns/                # traffic-steering config
  seeder/              # synthetic dataset generator
  crm/                 # internal system of record
  gateway/
    Dockerfile
    entrypoint.sh
    policy.yaml         # enforcement policy, hot-reloaded
    addons/
      boundary.py       # decision engine
      detectors.py      # pattern + gazetteer matching
      vault.py           # tokenization
  console/               # governance UI
  workstation/            # scripted test scenarios
scripts/
  steer.sh, lockdown.sh, reset.sh, smoke.sh
docs/
  architecture.png, lifecycle.png
```

---

## Installation & Setup 🚀

### Prerequisites

- Two Ubuntu 22.04/24.04 hosts, 4 vCPU / 8 GB RAM each
- Docker Engine + Compose plugin, nothing else
- Outbound internet during build only

### Addressing used below

```
Edge  192.168.253.11 /24
Corp  192.168.253.12 /24
```

### 1. Clone

```bash
git clone https://github.com/<org>/ai-egress-boundary-lab.git
cd ai-egress-boundary-lab
```

### 2. Edge host

```bash
sudo apt-get update -y && sudo apt-get install -y ca-certificates curl gnupg jq
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update -y && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker

cd edge-vm
docker compose up -d --build
curl -s http://localhost/healthz            # ok
curl -s http://localhost:8080/api/received  # {"items":[]}
```

### 3. Corp host

```bash
# same Docker install as above

cd corp-vm
cat > .env << EOF
EDGE_IP=192.168.253.11
CORP_IP=192.168.253.12
RECORDS=250
VAULT_SECRET=$(openssl rand -hex 16)
EOF

docker compose up -d --build
sleep 25
until [ -s gateway/gazetteer.json ]; do sleep 2; done
docker compose restart boundary-gateway

curl -s localhost:8000/api/dataset | jq
curl -s localhost:8090/api/summary | jq .mode   # "monitor"
```

### 4. Point a client at the gateway

Reverse proxy, no client proxy settings needed, only a hosts entry:

```
192.168.253.12   claude.ai
```

(`chat.openai.com` and `chatgpt.com` are HSTS-preloaded in most browsers and won't reach a plain-HTTP lab; `claude.ai` is not, use it for browser testing.)

### 5. Verify

```bash
cd corp-vm
./scripts/smoke.sh
```

---

## Access & Ports 🔌

| Host | Port | Service | URL |
|---|---|---|---|
| Edge (`192.168.253.11`) | 80 | Router / consumer AI UI | `http://192.168.253.11/` |
| Edge (`192.168.253.11`) | 8080 | Mock AI provider + inbound log | `http://192.168.253.11:8080/receipts` |
| Corp (`192.168.253.12`) | 80 | Boundary gateway (reverse proxy) | not browsed directly, reached via steered hostnames like `claude.ai` |
| Corp (`192.168.253.12`) | 8000 | Internal CRM | `http://192.168.253.12:8000/` |
| Corp (`192.168.253.12`) | 8090 | Governance console | `http://192.168.253.12:8090/` |

The gateway on port 80 is intentional: it is what a steered AI hostname resolves to, not a page meant to be opened by its raw IP. Everything else in the table is a normal browser tab.

---

## Configuration

`corp-vm/.env`: `EDGE_IP`, `CORP_IP`, `RECORDS` (dataset size), `VAULT_SECRET` (HMAC key, generate fresh, never reuse an example value).

`corp-vm/gateway/policy.yaml`: destinations (sanctioned / monitored / blocked), credential registry, per-data-class action, hot-reloaded on save. Keep `unknown_key_action: alert`, not `block`, or every unregistered key gets stopped regardless of content and the whole point of the project is lost.

---

## Usage 🎯

```bash
cd corp-vm && ./scripts/reset.sh
```

**Monitor mode:** paste a customer record into the consumer AI UI. It succeeds, and the edge host's `/receipts` view shows the raw identifiers in the clear.

**Enforce mode:** flip it from the console. No client-side change. Paste the same record again: blocked, reasons listed.

**Same tool, benign content:** still passes, since content decides, not the credential alone.

**Sanctioned path:** use the CRM's built-in AI button (registered credential). Succeeds, `/receipts` shows only tokens, the CRM itself shows real values.

```bash
curl -s http://localhost:8090/api/evidence   # report generated from the live audit log
```

---

## Remote Workforce 🌍

The steering here is internal DNS. A laptop off that network, no VPN, never asks that resolver, so it's never covered. Three ways to close it, in order of how much they change:

1. **Always-on VPN with forced DNS** (WireGuard, Tailscale, or a standard corp VPN client), split-tunnel DNS disabled. Cheapest, nothing else changes.
2. **MDM-pushed DNS policy** that follows the device off any network (Cloudflare Gateway, Cisco Umbrella, NextDNS via Jamf/Intune). No VPN dependency.
3. **A real SSE product** (Zscaler, Netskope, Cloudflare One) replacing the DIY gateway for actual scale, with proper TLS interception. The five-stage logic here maps onto their custom DLP rules.

None of the three cover a personal, unmanaged device. That's a device-trust policy decision, not a network one.

---

## Notes on TLS

Runs over plain HTTP on purpose: no internal CA to manage, and it surfaces the same HSTS-preload constraint a real TLS-terminating deployment has to solve anyway, rather than hiding it.

---

## Data Safety

Everything is generated locally from a fixed seed. Emails use `.example` (RFC 2606, can't resolve). Card numbers are published test BINs, Luhn-valid but tied to no real account. No real person appears anywhere in it.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Block should fire, returns 200 instead | Check the gateway's audit log volume is writable: `docker compose logs boundary-gateway` |
| Consumer page won't load under enforce | Move that hostname from `blocked` to `monitored` in policy |
| Every unregistered key blocked, even benign | Set `unknown_key_action: alert`, not `block` |
| Edited a `.py`/`.html`, nothing changed | Code is baked into the image, use `docker compose up -d --build <service>` |
| Edited `policy.yaml`, nothing changed | It's bind-mounted and should hot-reload, check the volume mapping |
| Gazetteer empty | Console hasn't synced yet, wait then `docker compose restart boundary-gateway` |

---

## Contributing 🤝

See [CONTRIBUTING.md](CONTRIBUTING.md). `docker compose config` must validate, `scripts/smoke.sh` must pass, new detector patterns need a smoke-test case.

---

## Limitations & Complementary Tools

- Managed traffic only → MDM DNS (Cloudflare Gateway) or a full SSE agent (Zscaler, Netskope)
- No cert-pinned client interception → endpoint visibility instead (CrowdStrike, osquery)
- Structural detection, not semantic → [Microsoft Presidio](https://github.com/microsoft/presidio) for NER
- No visibility into local models → endpoint DLP + app allowlisting
- Encoded attachments not decoded → [Apache Tika](https://tika.apache.org/) or a document AI service

---

## License

MIT, see [LICENSE](LICENSE).
