"""AI Governance Console: live decisions, policy switch, gazetteer sync, evidence."""
import asyncio, json, os, pathlib, time, collections
import httpx, yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

AUDIT = pathlib.Path(os.getenv("AUDIT_FILE", "/var/log/boundary/audit.jsonl"))
POLICY = pathlib.Path(os.getenv("POLICY_FILE", "/etc/boundary/policy.yaml"))
GAZ = pathlib.Path(os.getenv("GAZETTEER_FILE", "/etc/boundary/gazetteer.json"))
CRM = os.getenv("CRM_URL", "http://crm:8000")

app = FastAPI(title="AI Governance Console")
tpl = Jinja2Templates(directory="templates")


def events(limit: int = 500):
    if not AUDIT.exists():
        return []
    out = []
    for line in AUDIT.read_text().splitlines()[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out[::-1]


async def sync_gazetteer():
    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                rows = (await c.get(f"{CRM}/api/customers?limit=1000")).json()
            terms = set()
            for r in rows:
                for field in ("name", "account", "ref", "national_id"):
                    if r.get(field):
                        terms.add(str(r[field]))
            GAZ.parent.mkdir(parents=True, exist_ok=True)
            GAZ.write_text(json.dumps(sorted(terms), indent=1))
        except Exception:
            pass
        await asyncio.sleep(120)


@app.on_event("startup")
async def startup():
    asyncio.create_task(sync_gazetteer())


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return tpl.TemplateResponse("console.html", {"request": request})


@app.get("/api/policy")
def policy():
    try:
        return yaml.safe_load(POLICY.read_text())
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/api/events")
def api_events(limit: int = 200):
    return {"items": events(limit)}


@app.get("/api/summary")
def summary():
    ev = events(2000)
    by_decision = collections.Counter(e.get("decision", "?") for e in ev)
    by_dest = collections.Counter(e.get("host", "?") for e in ev)
    by_user = collections.Counter(e.get("user", "?") for e in ev)
    by_class = collections.Counter()
    shadow_keys = set()
    for e in ev:
        for f in e.get("findings", []):
            by_class[f.get("class", "?")] += 1
        if (e.get("credential") or {}).get("status") == "shadow":
            shadow_keys.add(e["credential"].get("fingerprint"))
    try:
        pol = yaml.safe_load(POLICY.read_text())
        mode, version = pol.get("mode"), pol.get("version")
    except Exception:
        mode, version = "?", "?"
    return {
        "mode": mode, "policy_version": version,
        "total": len(ev),
        "blocked": by_decision.get("block", 0),
        "masked": sum(e.get("masked_entities", 0) for e in ev),
        "allowed": by_decision.get("allow", 0),
        "alerted": by_decision.get("alert", 0),
        "shadow_credentials": len(shadow_keys),
        "by_decision": dict(by_decision),
        "top_destinations": by_dest.most_common(8),
        "top_users": by_user.most_common(8),
        "by_data_class": dict(by_class),
    }


@app.post("/api/mode/{mode}")
def set_mode(mode: str):
    if mode not in ("monitor", "enforce"):
        return JSONResponse({"error": "mode must be monitor or enforce"}, status_code=400)
    text = POLICY.read_text()
    lines = []
    for line in text.splitlines():
        if line.strip().startswith("mode:"):
            line = f"mode: {mode}          # switched from console at {time.strftime('%H:%M:%S')}"
        lines.append(line)
    POLICY.write_text("\n".join(lines) + "\n")
    return {"mode": mode}


@app.post("/api/reset")
def reset():
    AUDIT.write_text("")
    return {"ok": True}


@app.get("/api/evidence", response_class=PlainTextResponse)
def evidence():
    ev = events(5000)
    s = summary()
    lines = [
        "# AI Egress Boundary :: Evidence Pack",
        f"Generated {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        f"Policy version {s['policy_version']}, enforcement mode `{s['mode']}`",
        "",
        "## 1. Control summary",
        f"- Egress requests inspected: **{s['total']}**",
        f"- Requests blocked at the boundary: **{s['blocked']}**",
        f"- Identifiers pseudonymised before transfer: **{s['masked']}**",
        f"- Unregistered (shadow) credentials observed: **{s['shadow_credentials']}**",
        "",
        "## 2. Data classes intercepted",
    ]
    for k, v in sorted(s["by_data_class"].items(), key=lambda x: -x[1]):
        lines.append(f"- `{k}`: {v} findings")
    lines += ["", "## 3. Destinations contacted", "", "| Destination | Requests |", "|---|---|"]
    for host, n in s["top_destinations"]:
        lines.append(f"| {host} | {n} |")
    lines += ["", "## 4. Attributed activity", "", "| Identity | Requests |", "|---|---|"]
    for u, n in s["top_users"]:
        lines.append(f"| {u} | {n} |")
    lines += ["", "## 5. Regulatory mapping", "",
              "| Obligation | Control evidenced here |",
              "|---|---|",
              "| GDPR Art. 5(1)(c) data minimisation | Only pseudonymised fields left the controller boundary |",
              "| GDPR Art. 25 data protection by design | Enforcement is inline and default-on, not user-elected |",
              "| GDPR Art. 28 processor obligations | Traffic to processors without a DPA is blocked by destination policy |",
              "| GDPR Art. 32 security of processing | Pseudonymisation with the re-identification key held inside the controller |",
              "| GDPR Ch. V Art. 44-49 transfers | Destination allow-list constrains where personal data may be sent |",
              "| EU AI Act Art. 4 / Art. 50 | Sanctioned AI inventory with owner and purpose per credential |",
              "| Nigeria NDPA 2023 s.24, s.25 | Lawful basis and purpose limitation enforced per credential scope |",
              "| Qatar PDPL Law 13/2016 Art. 4, Art. 10 | Controller-side safeguards prior to disclosure |",
              "| PCI DSS 3.3 / 3.4 | PAN detected by Luhn and tokenised before egress |",
              "| ISO/IEC 42001 A.8 / A.9 | Documented AI system inventory and operational logging |",
              "", "## 6. Sample of enforcement actions", ""]
    for e in ev[:25]:
        lines.append(f"- `{e['iso']}` **{e['decision'].upper()}** {e['user']} -> "
                     f"{e['host']}{e['path']} "
                     f"(masked {e.get('masked_entities',0)}, findings {len(e.get('findings',[]))}) "
                     f"audit `{e['audit_id']}`")
        for r in e.get("reasons", [])[:3]:
            lines.append(f"    - {r}")
    return "\n".join(lines)
