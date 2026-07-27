"""AI Egress Boundary Gateway (mitmproxy addon).

1 ATTRIBUTE  2 AUTHORISE  3 INSPECT  4 ACT  5 RECORD
Driven by /etc/boundary/policy.yaml, hot-reloaded on every request.
"""
from __future__ import annotations
import ipaddress, json, os, pathlib, time, uuid

import yaml
from mitmproxy import http, ctx

import detectors
import vault

POLICY_FILE = pathlib.Path(os.getenv("POLICY_FILE", "/etc/boundary/policy.yaml"))
AUDIT_FILE = pathlib.Path(os.getenv("AUDIT_FILE", "/var/log/boundary/audit.jsonl"))
AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)

ACTION_RANK = {"allow": 0, "alert": 1, "mask": 2, "block": 3}


def req_host(flow) -> str:
    h = flow.request.headers.get("host", "") or flow.request.pretty_host
    return h.split(":")[0].strip().lower()


class Boundary:
    def __init__(self) -> None:
        self._policy: dict = {}
        self._mtime: float = 0.0
        self.reload_policy()

    def reload_policy(self) -> dict:
        try:
            m = POLICY_FILE.stat().st_mtime
            if m != self._mtime:
                self._policy = yaml.safe_load(POLICY_FILE.read_text()) or {}
                self._mtime = m
                ctx.log.info(f"[boundary] policy loaded, mode={self._policy.get('mode')}")
        except Exception as exc:
            ctx.log.warn(f"[boundary] policy load failed: {exc}")
        return self._policy

    def identify(self, flow: http.HTTPFlow) -> str:
        p = self._policy.get("identity", {})
        hdr = flow.request.headers.get(p.get("header", "X-Corp-User"))
        if hdr:
            return hdr
        ip = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        try:
            ip = str(ipaddress.ip_address(ip.replace("::ffff:", "")))
        except ValueError:
            pass
        return p.get("ip_map", {}).get(ip) or f"{p.get('fallback','unattributed')}@{ip}"

    def classify_destination(self, host: str) -> str:
        d = self._policy.get("destinations", {})
        for bucket in ("blocked", "sanctioned", "monitored"):
            if host in (d.get(bucket) or []):
                return bucket
        return "unknown"

    def classify_key(self, flow: http.HTTPFlow) -> dict:
        raw = (flow.request.headers.get("authorization", "")
               or flow.request.headers.get("x-api-key", "")
               or flow.request.headers.get("x-goog-api-key", ""))
        token = raw.replace("Bearer ", "").strip()
        if not token:
            return {"present": False, "id": None, "status": "none", "fingerprint": ""}
        for k in self._policy.get("credentials", {}).get("sanctioned_keys", []) or []:
            if token.startswith(k["prefix"]):
                return {"present": True, "id": k["id"], "status": "sanctioned",
                        "owner": k.get("owner"), "scopes": k.get("scopes", []),
                        "allowed_data_classes": k.get("allowed_data_classes", []),
                        "max_body_bytes": k.get("max_body_bytes"),
                        "fingerprint": token[:14] + "..."}
        return {"present": True, "id": None, "status": "shadow",
                "fingerprint": token[:14] + "..."}

    def request(self, flow: http.HTTPFlow) -> None:
        self.reload_policy()
        if not flow.request.path.startswith(("/v1", "/v1beta")):
            return

        started = time.time()
        audit_id = uuid.uuid4().hex[:12]
        mode = self._policy.get("mode", "monitor")
        host = req_host(flow)
        user = self.identify(flow)
        dest_class = self.classify_destination(host)
        key = self.classify_key(flow)
        body = flow.request.get_text(strict=False) or ""

        decision, reasons = "allow", []

        if dest_class == "blocked":
            decision, _ = self._raise(decision, "block")
            reasons.append(f"Destination {host} is on the prohibited consumer AI list")
        elif dest_class == "unknown":
            act = self._policy.get("destinations", {}).get("unknown_destination_action", "alert")
            decision, _ = self._raise(decision, act)
            reasons.append(f"Destination {host} is not in the approved AI inventory")

        if key["status"] == "shadow":
            act = self._policy.get("credentials", {}).get("unknown_key_action", "block")
            decision, _ = self._raise(decision, act)
            reasons.append(f"Unregistered API key {key['fingerprint']} (shadow credential)")
        elif key["status"] == "sanctioned":
            mx = key.get("max_body_bytes")
            if mx and len(body.encode()) > mx:
                decision, _ = self._raise(decision, "block")
                reasons.append(f"Payload {len(body.encode())}B exceeds scope limit {mx}B for {key['id']}")

        findings = detectors.scan(body)
        classes = {}
        for f in findings:
            classes.setdefault(f.data_class, 0)
            classes[f.data_class] += 1

        dc_cfg = self._policy.get("data_classes", {})
        for cls, count in classes.items():
            act = (dc_cfg.get(cls) or {}).get("action", "allow")
            if act != "allow":
                decision, _ = self._raise(decision, act)
                reasons.append(f"{count} x {cls} -> {act}: {(dc_cfg.get(cls) or {}).get('reason','')}")
            if key["status"] == "sanctioned" and cls not in key.get("allowed_data_classes", []) \
               and cls not in ("network",):
                decision, _ = self._raise(decision, "block")
                reasons.append(f"Key {key['id']} is not scoped for data class '{cls}' (over-scoped use)")

        bulk = self._policy.get("limits", {}).get("alert_on_bulk_records", 5)
        master = sum(1 for f in findings if f.label == "MASTER_DATA")
        if master >= bulk:
            decision, _ = self._raise(decision, "block")
            reasons.append(f"{master} distinct customer master-data records in one call (bulk exfiltration pattern)")

        if key["status"] != "sanctioned" and decision == "mask":
            decision = "block"
            reasons.append("Sensitive data cannot be pseudonymised under an unregistered credential, "
                           "because no owner, purpose or processing agreement can be established")

        masked_count = 0
        if mode == "enforce" and decision == "block":
            self._write_audit(audit_id, user, flow, dest_class, key, findings,
                              "block", reasons, 0, started)
            flow.response = self._block_page(audit_id, host, reasons)
            return

        if decision in ("mask", "block") and mode == "enforce":
            body, masked_count = self._mask(body, findings)
            flow.request.set_text(body)

        if mode == "enforce":
            self._enforce_params(flow)

        flow.metadata["boundary"] = {"audit_id": audit_id, "user": user,
                                     "dest_class": dest_class, "key": key,
                                     "findings": findings, "decision": decision,
                                     "reasons": reasons, "masked": masked_count,
                                     "started": started}

    def response(self, flow: http.HTTPFlow) -> None:
        meta = flow.metadata.get("boundary")
        if not meta:
            return
        if meta["masked"]:
            try:
                text = flow.response.get_text(strict=False) or ""
                restored = vault.detokenise(text)
                if restored != text:
                    flow.response.set_text(restored)
                    flow.response.headers["X-Boundary-Detokenised"] = "true"
            except Exception as exc:
                ctx.log.warn(f"[boundary] detokenise failed: {exc}")
        flow.response.headers["X-Boundary-Audit-Id"] = meta["audit_id"]
        flow.response.headers["X-Boundary-Decision"] = meta["decision"]
        self._write_audit(meta["audit_id"], meta["user"], flow, meta["dest_class"],
                          meta["key"], meta["findings"], meta["decision"],
                          meta["reasons"], meta["masked"], meta["started"])

    @staticmethod
    def _raise(current: str, candidate: str):
        return (candidate, True) if ACTION_RANK.get(candidate, 0) > ACTION_RANK.get(current, 0) \
            else (current, False)

    @staticmethod
    def _mask(body: str, findings):
        n = 0
        for f in sorted(findings, key=lambda x: x.start, reverse=True):
            if f.data_class == "network":
                continue
            token = vault.tokenise(f.label, f.value)
            body = body[:f.start] + token + body[f.end:]
            n += 1
        return body, n

    def _enforce_params(self, flow: http.HTTPFlow) -> None:
        cfg = (self._policy.get("required_request_params", {}) or {})
        rule = cfg.get(req_host(flow)) or cfg.get("default") or {}
        for h in rule.get("strip_headers", []) or []:
            flow.request.headers.pop(h, None)
        for k, v in (rule.get("headers") or {}).items():
            flow.request.headers[k] = str(v)
        body_rules = rule.get("body") or {}
        if body_rules and "json" in flow.request.headers.get("content-type", "").lower():
            try:
                payload = json.loads(flow.request.get_text(strict=False) or "{}")
                changed = False
                for k, v in body_rules.items():
                    if payload.get(k) != v:
                        payload[k] = v
                        changed = True
                if changed:
                    flow.request.set_text(json.dumps(payload))
                    flow.request.headers["X-Boundary-Params-Injected"] = ",".join(body_rules)
            except Exception:
                pass

    @staticmethod
    def _block_page(audit_id: str, host: str, reasons) -> http.Response:
        payload = {
            "error": {
                "type": "corporate_policy_violation",
                "message": "This request was stopped at the AI egress boundary.",
                "destination": host, "audit_id": audit_id, "reasons": reasons,
                "policy_contact": "ai-governance@northgate.example",
            }
        }
        return http.Response.make(
            451, json.dumps(payload, indent=2).encode(),
            {"Content-Type": "application/json",
             "X-Boundary-Audit-Id": audit_id,
             "X-Boundary-Decision": "block",
             "X-Boundary-Policy": "ai-egress-boundary"})

    @staticmethod
    def _write_audit(audit_id, user, flow, dest_class, key, findings, decision,
                     reasons, masked, started) -> None:
        rec = {
            "audit_id": audit_id,
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "latency_ms": round((time.time() - started) * 1000, 1),
            "user": user,
            "src_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "",
            "method": flow.request.method,
            "host": req_host(flow),
            "path": flow.request.path.split("?")[0],
            "destination_class": dest_class,
            "credential": {"status": key.get("status"), "id": key.get("id"),
                           "fingerprint": key.get("fingerprint")},
            "decision": decision,
            "reasons": reasons,
            "masked_entities": masked,
            "findings": [{"label": f.label, "class": f.data_class, "detector": f.detector,
                          "severity": f.severity,
                          "preview": (f.value[:3] + "***") if len(f.value) > 3 else "***"}
                         for f in findings],
            "request_bytes": len(flow.request.content or b""),
            "response_status": flow.response.status_code if flow.response else None,
            "user_agent": flow.request.headers.get("user-agent", "")[:120],
        }
        with AUDIT_FILE.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        ctx.log.info(f"[boundary] {decision.upper()} {rec['user']} -> {rec['host']}{rec['path']} "
                     f"masked={masked} findings={len(findings)} audit={audit_id}")


addons = [Boundary()]
