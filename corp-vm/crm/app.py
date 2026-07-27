"""Internal CRM. Reads the synthetic dataset produced by the seeder."""
import os, sqlite3, pathlib, json
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

DB = pathlib.Path("/data/crm.db")
LLM_BASE = os.getenv("LLM_BASE", "http://api.openai.com")
LLM_KEY = os.getenv("LLM_KEY", "sk-corp-sanctioned-0001-a94f2c")

app = FastAPI(title="Northgate CRM")
tpl = Jinja2Templates(directory="templates")


def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


@app.get("/", response_class=HTMLResponse)
def index(request: Request, page: int = 1):
    off = (page - 1) * 25
    with conn() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM customers ORDER BY id LIMIT 25 OFFSET ?", (off,))]
        total = c.execute("SELECT count(*) n FROM customers").fetchone()["n"]
        assets = [dict(r) for r in c.execute("SELECT * FROM assets")]
    return tpl.TemplateResponse("index.html", {"request": request, "rows": rows,
                                               "page": page, "total": total, "assets": assets})


@app.get("/api/customers")
def customers(limit: int = 1000):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM customers ORDER BY id LIMIT ?", (limit,))]


@app.get("/api/customers/{cid}/record")
def record(cid: int):
    with conn() as c:
        r = c.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    if not r:
        return JSONResponse({"error": "not found"}, status_code=404)
    return {"text": (f"Name: {r['name']}\nEmail: {r['email']}\nPhone: {r['phone']}\n"
                     f"Account No: {r['account']}\nCustomer Ref: {r['ref']}\n"
                     f"National ID: {r['national_id']}\nCard: {r['card']}\n"
                     f"Tier: {r['tier']}\nNotes: {r['notes']}")}


@app.get("/api/assets/{aid}")
def asset(aid: int):
    with conn() as c:
        r = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return {"path": r["path"], "text": r["content"]} if r else JSONResponse(
        {"error": "not found"}, status_code=404)


@app.get("/api/dataset")
def dataset():
    p = pathlib.Path("/data/dataset-summary.json")
    return json.loads(p.read_text()) if p.exists() else {}


@app.post("/ai/summarise")
async def summarise(request: Request):
    body = await request.json()
    payload = {"model": "gpt-4o-mini",
               "messages": [{"role": "system", "content": "Summarise the customer record."},
                            {"role": "user", "content": body.get("text", "")}]}
    try:
        async with httpx.AsyncClient(timeout=90) as c:
            r = await c.post(f"{LLM_BASE}/v1/chat/completions", json=payload,
                             headers={"Authorization": f"Bearer {LLM_KEY}",
                                      "X-Corp-User": "crm-service",
                                      "Content-Type": "application/json"})
            out = r.json()
            out["_boundary"] = {k: v for k, v in r.headers.items()
                                if k.lower().startswith("x-boundary")}
            return JSONResponse(out, status_code=r.status_code)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)


@app.get("/healthz")
def healthz():
    return {"ok": True}
