#!/usr/bin/env python3
"""Employee workstation simulator. No proxy, no certificates, no client config."""
import argparse, json, os, socket, sys
import httpx

CRM = os.getenv("CRM_URL", "http://172.30.0.30:8000")
SHADOW_KEY = "sk-consumer-free-tier-9f2b71c4"
CORP_KEY = "sk-corp-sanctioned-0001-a94f2c"

SCENARIOS = {
    "clipboard-extension": dict(host="api.openai.com", key=SHADOW_KEY,
        ua="Mozilla/5.0 Chrome/126 SmartClipboardAI/1.4 (extension)",
        note="Unmonitored browser extension shipping clipboard contents"),
    "paste-webapp": dict(host="chat.openai.com", key=SHADOW_KEY,
        ua="Mozilla/5.0 Chrome/126", note="Employee pasting into a consumer chat UI"),
    "unvetted-provider": dict(host="api.deepseek.com", key=SHADOW_KEY,
        ua="python-requests/2.32", note="Provider with no assessment and no DPA"),
    "shadow-script": dict(host="api.anthropic.com", key=SHADOW_KEY,
        ua="curl/8.5.0", note="Analyst script with a personal API key"),
    "sanctioned": dict(host="api.openai.com", key=CORP_KEY,
        ua="northgate-crm/2.1", note="Registered credential on the approved endpoint"),
}

PAYLOADS = ["record", "bulk-export", "ticket", "source", "secrets", "custom"]


def get(path):
    return httpx.get(f"{CRM}{path}", timeout=30).json()


def build_payload(kind, customer, text):
    if kind == "record":
        return get(f"/api/customers/{customer}/record")["text"]
    if kind == "bulk-export":
        rows = get("/api/customers?limit=40")
        return "\n\n".join(
            f"Name: {r['name']}\nEmail: {r['email']}\nPhone: {r['phone']}\n"
            f"Account No: {r['account']}\nCard: {r['card']}\nNotes: {r['notes']}" for r in rows)
    if kind == "ticket":
        rows = get("/api/customers?limit=3")
        r = rows[0]
        return (f"Draft a reply to this case.\nCaller verified as {r['name']}, "
                f"reachable on {r['phone']} or {r['email']}. Account {r['account']}. "
                f"Notes: {r['notes']}")
    if kind == "source":
        return get("/api/assets/1")["text"]
    if kind == "secrets":
        return get("/api/assets/2")["text"] + "\n" + get("/api/assets/3")["text"]
    return text or "hello"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="clipboard-extension", choices=list(SCENARIOS))
    ap.add_argument("--payload", default="record", choices=PAYLOADS)
    ap.add_argument("--customer", type=int, default=7)
    ap.add_argument("--text", default="")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    sc = SCENARIOS[a.scenario]
    content = build_payload(a.payload, a.customer, a.text)
    prompt = "Summarise this for a handover note:\n\n" + content
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]}

    try:
        resolved = socket.gethostbyname(sc["host"])
    except Exception:
        resolved = "unresolved"
    route = "BOUNDARY GATEWAY" if resolved.startswith("172.30.0.10") else "DIRECT TO EDGE"

    if not a.quiet:
        print(f"\n=== {a.scenario} :: {sc['note']}")
        print(f"    payload={a.payload}  {len(content)} chars")
        print(f"    http://{sc['host']}/v1/chat/completions -> {resolved}  [{route}]")
        print(f"    key={sc['key'][:20]}...\n")

    try:
        r = httpx.post(f"http://{sc['host']}/v1/chat/completions", json=body, timeout=120,
                       headers={"Authorization": f"Bearer {sc['key']}",
                                "Content-Type": "application/json",
                                "User-Agent": sc["ua"],
                                "X-Corp-User": os.getenv("CORP_USER", "t.balogun@northgate.example")})
    except Exception as exc:
        print(f"[transport blocked] {exc}")
        return 2

    print(f"HTTP {r.status_code}")
    for h in ("x-boundary-decision", "x-boundary-audit-id", "x-boundary-detokenised",
              "x-boundary-params-injected"):
        if h in r.headers:
            print(f"  {h}: {r.headers[h]}")
    try:
        j = r.json()
    except Exception:
        print(r.text[:600]); return 0
    if r.status_code == 451:
        print("\n*** BLOCKED AT THE BOUNDARY ***")
        for reason in j.get("error", {}).get("reasons", []):
            print("  -", reason)
        return 0
    print("\nmodel reply:")
    print("  " + (j.get("choices", [{}])[0].get("message", {}).get("content", json.dumps(j))[:500]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
