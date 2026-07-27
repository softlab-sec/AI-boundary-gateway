#!/usr/bin/env python3
"""Synthetic dataset. Fixed seed, .example domains, published test BINs."""
import json, os, random, sqlite3, pathlib

SEED = int(os.getenv("SEED", "42"))
N = int(os.getenv("RECORDS", "250"))
DB = pathlib.Path("/data/crm.db")
random.seed(SEED)

FIRST = ["Adaeze","Emeka","Chidi","Ngozi","Yusuf","Fatima","Aisha","Ibrahim","Tunde","Bisi",
         "Kemi","Segun","Amina","Hassan","Zainab","Obinna","Chioma","Musa","Halima","Kunle",
         "Sarah","Daniel","Grace","Peter","Ruth","Samuel","Esther","Joseph","Mary","David",
         "Khalid","Noora","Ahmed","Maryam","Salem","Latifa","Rashid","Hessa","Jassim","Reem"]
LAST  = ["Okonkwo","Nwachukwu","Adeyemi","Balogun","Danladi","Okafor","Eze","Abubakar","Ogun",
         "Chukwu","Bello","Lawal","Ibeh","Oduya","Mbeki","Al-Kuwari","Al-Thani","Al-Mansoori",
         "Al-Sulaiti","Al-Naimi","Doe","Smith","Brown","Taylor","Wilson","Clarke","Hughes"]
TIERS = ["Platinum","Gold","Silver","Bronze"]
DEPTS = ["Retail Banking","Collections","Risk","Customer Care","Payments","Onboarding"]
NOTE_TEMPLATES = [
    "Disputed charge on invoice INV-{inv}, escalated {n} times.",
    "Requested account closure and a full data export under DSAR-{inv}.",
    "High-value corporate account, settlement in {cur}.",
    "Two failed KYC attempts, passport {pp} on file.",
    "Chargeback pattern flagged by the fraud engine on {n} transactions.",
    "Complaint about a failed transfer, national id {nid} verified.",
    "Requested a statement reissue for the last {n} months.",
    "Card {pan} reported lost, replacement dispatched.",
    "Overdraft limit review pending, relationship manager notified.",
    "Marketing consent withdrawn on all channels.",
]
TEST_BINS = ["411111","550000","378282","601111","353011"]


def luhn_complete(prefix: str, length: int) -> str:
    body = prefix + "".join(str(random.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    digits = [int(d) for d in body]
    parity = (len(digits) + 1) % 2
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def phone() -> str:
    style = random.choice(["ng", "qa", "uk"])
    if style == "ng":
        return f"+234 {random.choice(['703','805','816','901','913'])} {random.randint(100,999)} {random.randint(1000,9999)}"
    if style == "qa":
        return f"+974 {random.randint(3000,7999)} {random.randint(1000,9999)}"
    return f"+44 7{random.randint(100,999)} {random.randint(100000,999999)}"


def build():
    DB.parent.mkdir(parents=True, exist_ok=True)
    if DB.exists():
        DB.unlink()
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT,
        account TEXT, ref TEXT, tier TEXT, national_id TEXT, card TEXT, notes TEXT);
    CREATE TABLE employees(id INTEGER PRIMARY KEY, name TEXT, email TEXT, staff_id TEXT,
        department TEXT, band TEXT);
    CREATE TABLE tickets(id INTEGER PRIMARY KEY, customer_id INTEGER, subject TEXT, body TEXT);
    CREATE TABLE assets(id INTEGER PRIMARY KEY, path TEXT, content TEXT);
    """)

    customers = []
    for i in range(1, N + 1):
        fn, ln = random.choice(FIRST), random.choice(LAST)
        name = f"{fn} {ln}"
        email = f"{fn.lower()}.{ln.lower().replace('-','')}@northgate.example"
        pan = luhn_complete(random.choice(TEST_BINS), 16)
        nid = str(random.randint(10**10, 10**11 - 1))
        note = random.choice(NOTE_TEMPLATES).format(
            inv=random.randint(1000, 9999), n=random.randint(2, 9),
            cur=random.choice(["QAR", "NGN", "GBP"]),
            pp=f"{random.choice('AB')}{random.randint(1000000,9999999)}", nid=nid, pan=pan)
        customers.append((i, name, email, phone(), str(random.randint(10**9, 10**10 - 1)),
                          f"{random.choice(['NG','QA','GB'])}-{random.choice('ABC')}-{random.randint(1000,9999)}",
                          random.choice(TIERS), nid, pan, note))
    c.executemany("INSERT INTO customers VALUES(?,?,?,?,?,?,?,?,?,?)", customers)

    employees = []
    for i in range(1, 41):
        fn, ln = random.choice(FIRST), random.choice(LAST)
        employees.append((i, f"{fn} {ln}",
                          f"{fn[0].lower()}.{ln.lower().replace('-','')}@northgate.example",
                          f"EMP-{10000+i}", random.choice(DEPTS),
                          f"Band {random.choice('ABCDE')}"))
    c.executemany("INSERT INTO employees VALUES(?,?,?,?,?,?)", employees)

    tickets = []
    for i in range(1, 25):
        cust = random.choice(customers)
        tickets.append((i, cust[0], f"Case {2000+i}: {random.choice(['billing','access','fraud','kyc'])}",
                        f"Caller verified as {cust[1]}, reachable on {cust[3]} or {cust[2]}. "
                        f"Account {cust[4]} confirmed. Agent notes: {cust[9]}"))
    c.executemany("INSERT INTO tickets VALUES(?,?,?,?)", tickets)

    assets = [
        (1, "northgate-core/pricing/risk_multiplier.ts",
         'export function riskMultiplier(tier, exposure) {\n'
         '  const base = { platinum: 0.62, gold: 0.81, silver: 1.14, bronze: 1.37 }[tier];\n'
         '  const decay = Math.exp(-exposure / 18422.7);\n'
         '  return Number((base * (1 + 0.43 * decay)).toFixed(4));\n'
         '}\n'
         'const AWS_REPORTING_KEY = "AKIA5T3XQ2ZZP9LMN4WD";\n'),
        (2, "northgate-core/config/prod.env",
         'DATABASE_URL="postgresql://ngapp:Pr0dPassw0rd@db-prod-01.northgate.internal:5432/core"\n'
         'REDIS_URL="redis://cache:S3cretCache@cache-01.northgate.internal:6379/0"\n'
         'JWT_SIGNING="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmMtcHJvZCJ9.q7Fz3xTn0Yk9pLm2WdRb8Vc1AeHgJs4U"\n'),
        (3, "northgate-core/deploy/id_rsa",
         '-----BEGIN OPENSSH PRIVATE KEY-----\n'
         'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n'
         'NhAAAAAwEAAQAAAYEAxFAKELABORATEDUMMYKEYMATERIALFORDEMOONLYNOTREALxxxx\n'
         '-----END OPENSSH PRIVATE KEY-----\n'),
    ]
    c.executemany("INSERT INTO assets VALUES(?,?,?)", assets)
    c.commit()

    summary = {"seed": SEED, "customers": len(customers), "employees": len(employees),
               "tickets": len(tickets), "assets": len(assets),
               "note": "All data is synthetic. Domains use .example (RFC 2606). "
                       "Card numbers are published test BINs. No real person is represented."}
    pathlib.Path("/data/dataset-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    build()
