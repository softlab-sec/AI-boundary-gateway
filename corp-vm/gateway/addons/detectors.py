"""Detection layer: structural regex, master-data gazetteer, optional NER."""
from __future__ import annotations
import json, os, re, pathlib
from dataclasses import dataclass
from typing import Iterable, List, Optional

PRESIDIO_URL = os.getenv("PRESIDIO_URL", "").strip()
GAZETTEER_FILE = pathlib.Path(os.getenv("GAZETTEER_FILE", "/etc/boundary/gazetteer.json"))


@dataclass
class Finding:
    label: str
    data_class: str
    value: str
    start: int
    end: int
    detector: str
    severity: str


PATTERNS = [
    ("PRIVATE_KEY", "secret", "critical",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]{0,4000}?-----END [^-]{0,40}-----"),
    ("AWS_ACCESS_KEY", "secret", "critical", r"\bAKIA[0-9A-Z]{16}\b"),
    ("AWS_SECRET", "secret", "critical", r"(?i)aws_?secret_?access_?key\W{0,4}([A-Za-z0-9/+=]{40})"),
    ("PROVIDER_API_KEY", "secret", "critical", r"\b(?:sk|rk|pk)-[A-Za-z0-9_\-]{12,}\b"),
    ("GITHUB_TOKEN", "secret", "critical", r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    ("SLACK_TOKEN", "secret", "critical", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    ("JWT", "secret", "high", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ("DB_URI", "secret", "critical",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]{4,}:[^\s\"'<>@]{2,}@[^\s\"'<>]+"),
    ("IBAN", "financial", "high", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    ("PAN", "financial", "critical", r"\b(?:\d[ -]?){12,18}\d\b"),
    ("BVN", "pii", "high", r"(?i)\bbvn\W{0,4}(\d{11})\b"),
    ("NATIONAL_ID", "pii", "high", r"(?i)\bnational[ _-]?id\W{0,4}(\d{9,12})\b"),
    ("NIN", "pii", "high", r"(?i)\bnin\W{0,4}(\d{11})\b"),
    ("QID", "pii", "high", r"(?i)\b(?:qid|qatar id)\W{0,4}(\d{11})\b"),
    ("PASSPORT", "pii", "high", r"(?i)\bpassport\W{0,6}([A-Z]{1,2}\d{6,9})\b"),
    ("EMAIL", "pii", "medium", r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b"),
    ("MSISDN", "pii", "medium", r"\+\d{1,3}[\s.-]?(?:\(?\d{1,4}\)?[\s.-]?){2,5}\d{2,4}"),
    ("IPV4", "network", "low", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("SOURCE_CODE", "source_code", "high",
     r"(?m)^(?:\s*(?:export |async )?(?:function|class|def|const|let|var|public|private|import|from|package)\s+\w+.*$\n?){3,}"),
]
COMPILED = [(lbl, cls, sev, re.compile(rx)) for lbl, cls, sev, rx in PATTERNS]


def _luhn(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _load_gazetteer() -> List[str]:
    try:
        terms = json.loads(GAZETTEER_FILE.read_text())
        return sorted({t for t in terms if isinstance(t, str) and len(t) >= 4},
                      key=len, reverse=True)
    except Exception:
        return []


GAZETTEER = _load_gazetteer()
GAZ_RX = re.compile("|".join(re.escape(t) for t in GAZETTEER)) if GAZETTEER else None


def _presidio(text: str) -> List[Finding]:
    if not PRESIDIO_URL:
        return []
    try:
        import requests
        r = requests.post(f"{PRESIDIO_URL}/analyze", timeout=8, json={
            "text": text, "language": "en",
            "entities": ["PERSON", "LOCATION", "NRP", "DATE_TIME"]})
        out = []
        for e in r.json():
            if e.get("score", 0) < 0.6:
                continue
            out.append(Finding(e["entity_type"], "pii", text[e["start"]:e["end"]],
                               e["start"], e["end"], "presidio", "medium"))
        return out
    except Exception:
        return []


def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: List[Finding] = []
    last_end = -1
    for f in ordered:
        if f.start >= last_end:
            kept.append(f)
            last_end = f.end
    return kept


def scan(text: str, use_ner: bool = True) -> List[Finding]:
    if not text:
        return []
    found: List[Finding] = []

    for label, cls, sev, rx in COMPILED:
        for m in rx.finditer(text):
            span = m.span(1) if m.re.groups and m.group(1) else m.span(0)
            val = text[span[0]:span[1]]
            if label == "PAN" and not _luhn(val):
                continue
            if label == "IPV4" and any(int(o) > 255 for o in val.split(".")):
                continue
            found.append(Finding(label, cls, val, span[0], span[1], "regex", sev))

    if GAZ_RX:
        for m in GAZ_RX.finditer(text):
            found.append(Finding("MASTER_DATA", "pii", m.group(0), m.start(), m.end(),
                                 "gazetteer", "high"))

    if use_ner:
        found.extend(_presidio(text))

    return _dedupe(found)
