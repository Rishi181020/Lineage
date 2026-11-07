"""Egress proxy with custody swap, tripwire, and allowlist (M3)."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx

from lineage_core import bindings as binding_match
from lineage_core.drip import DripDetector

CONTROL = os.environ.get("LINEAGE_CONTROL_INTERNAL", "http://172.30.0.10:8002")
SERVICE_TOKEN = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
POLICY_PATH = os.environ.get("LINEAGE_POLICY_PATH", "/app/policy/default.yaml")

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()
_drip = DripDetector()
_secret_cache: dict[str, str] = {}


def _load_policy() -> dict[str, Any]:
    try:
        import yaml
        from pathlib import Path

        return yaml.safe_load(Path(POLICY_PATH).read_text(encoding="utf-8")) or {}
    except Exception:
        return {
            "egress": {"allow_hosts": ["infra.demo", "registry.demo"]},
            "stubs": ["infra.demo", "collector.demo", "registry.demo"],
            "strict": {"allow": []},
            "drip": {
                "max_distinct_paths": 8,
                "window_s": 60,
                "max_body_bytes": 512,
                "min_substring": 8,
            },
        }


POLICY = _load_policy()


def _headers() -> dict[str, str]:
    return {"X-Lineage-Service-Token": SERVICE_TOKEN}


def _lookup_run(ip: str) -> dict[str, Any] | None:
    now = time.time()
    with _cache_lock:
        hit = _cache.get(ip)
        if hit and now - hit[0] < 1.0:
            return hit[1]
    try:
        resp = httpx.get(
            f"{CONTROL}/internal/runs/by-ip/{ip}",
            headers=_headers(),
            timeout=3,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None
    with _cache_lock:
        _cache[ip] = (now, data)
    return data


def _emit(run_id: str, event_type: str, payload: dict[str, Any]) -> None:
    try:
        httpx.post(
            f"{CONTROL}/internal/events",
            headers=_headers(),
            json={"run_id": run_id, "type": event_type, "payload": payload},
            timeout=3,
        )
    except Exception:
        pass


def _kill(run_id: str) -> None:
    try:
        httpx.post(
            f"{CONTROL}/internal/runs/{run_id}/kill",
            headers=_headers(),
            timeout=3,
        )
    except Exception:
        pass


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip in ipaddress.ip_network("169.254.0.0/16")
    )


def _real_secret(secret_ref: str) -> str:
    if secret_ref in _secret_cache:
        return _secret_cache[secret_ref]
    # Local file secrets mounted into the container when present.
    path = os.environ.get("LINEAGE_LOCAL_SECRETS_PATH", "/app/.lineage/secrets.yaml")
    try:
        import yaml
        from pathlib import Path

        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        value = str(data[secret_ref])
        _secret_cache[secret_ref] = value
        return value
    except Exception:
        # Demo fallback matching seed_secrets
        value = os.environ.get("STAGING_REAL_TOKEN", "lineage_demo_real_staging_token")
        _secret_cache[secret_ref] = value
        return value


def _scan_placeholders(haystacks: list[str], placeholders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    found = []
    joined = "\n".join(haystacks)
    for ph in placeholders:
        variants = set(ph.get("variants") or [])
        variants.add(ph["value"])
        if any(variant and variant in joined for variant in variants):
            found.append(ph)
    return found


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/health" and "://" not in self.path:
            # Health probe (relative path)
            host = self.headers.get("Host", "")
            if "egress" in host or host.startswith("127.") or host.startswith("172.30."):
                self._reply(200, b'{"status":"ok","service":"egress"}', "application/json")
                return
        if self.path == "/health":
            self._reply(200, b'{"status":"ok","service":"egress"}', "application/json")
            return
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_CONNECT(self):
        self._reply(403, b"Lineage E1: CONNECT blocked in demo HTTP proxy")

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _handle(self) -> None:
        target = urlsplit(self.path)
        if target.scheme != "http" or not target.hostname:
            self._reply(400, b"absolute HTTP URL required")
            return

        host = target.hostname.lower()
        path = target.path or "/"
        method = self.command.upper()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        body_text = body.decode("utf-8", errors="replace")

        run = _lookup_run(self._client_ip())
        if not run:
            self._reply(407, b"Lineage: unknown agent")
            return
        run_id = run["run_id"]
        if run["status"] in {"revoked", "killed", "stopped", "finished"}:
            _emit(run_id, "egress_block", {"rule": "K0", "host": host})
            self._reply(403, f'Lineage K0: run {run_id} is {run["status"]}'.encode())
            return

        stubs = {str(s).lower() for s in POLICY.get("stubs", [])}
        if _is_private(host) and host not in stubs:
            _emit(run_id, "egress_block", {"rule": "E2", "host": host})
            self._reply(403, b"Lineage E2: private/link-local destination blocked")
            return

        placeholders = run.get("placeholders_all") or []
        header_values = [f"{k}: {v}" for k, v in self.headers.items()]
        found = _scan_placeholders(
            [self.path, body_text, *header_values], placeholders
        )

        # C1 / C2 / custody before E1 so tripwire wins for collector.demo
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in {"proxy-connection", "connection", "host"}
        }
        for ph in found:
            binding = next(
                (b for b in run.get("bindings", []) if b["id"] == ph["binding_id"]),
                None,
            )
            if not binding:
                continue
            in_host = host in {h.lower() for h in binding.get("hosts", [])}
            placeholder = ph["value"]
            # Replace in Authorization / declared header when in scope
            header_name = binding.get("header", "Authorization")
            scheme = binding.get("scheme", "Bearer")
            scope_ok = binding_match.scope_allowed(
                {
                    "allow": binding.get("scope", {}).get("allow", []),
                    "deny": binding.get("scope", {}).get("deny", []),
                    "hosts": binding.get("hosts", []),
                },
                method=method,
                path=path,
            )
            if in_host and scope_ok:
                real = _real_secret(binding["secret_ref"])
                current = headers.get(header_name, "")
                if placeholder in current or placeholder in body_text:
                    if placeholder in current:
                        headers[header_name] = current.replace(placeholder, real)
                    if scheme and headers.get(header_name, "").startswith(f"{scheme} "):
                        pass
                    elif header_name.lower() == "authorization" and not headers.get(
                        header_name, ""
                    ).lower().startswith("bearer "):
                        headers[header_name] = f"{scheme} {real}"
                    body_text = body_text.replace(placeholder, real)
                    body = body_text.encode()
                    _emit(
                        run_id,
                        "custody_attach",
                        {
                            "binding_id": binding["id"],
                            "host": host,
                            "method": method,
                            "path": path,
                        },
                    )
            elif in_host and not scope_ok:
                _emit(
                    run_id,
                    "verdict",
                    {
                        "decision": "deny",
                        "rule_id": "C2",
                        "reason": "Lineage C2: placeholder out of binding scope",
                        "host": host,
                        "path": path,
                    },
                )
                self._reply(403, b"Lineage C2: credential out of scope")
                return
            else:
                # Tripwire C1
                _emit(
                    run_id,
                    "tripwire",
                    {
                        "rule_id": "C1",
                        "host": host,
                        "path": path,
                        "placeholder_binding": ph["binding_id"],
                        "redacted_auth": f"{scheme} {placeholder[:20]}…",
                    },
                )
                _kill(run_id)
                self._reply(403, b"Lineage C1: tripwire - placeholder left its binding")
                return

        allow_hosts = {
            str(h).lower() for h in (POLICY.get("egress", {}) or {}).get("allow_hosts", [])
        }
        allow_hosts |= {
            h.lower()
            for b in run.get("bindings", [])
            for h in b.get("hosts", [])
        }
        if host not in allow_hosts:
            _emit(run_id, "egress_block", {"rule": "E1", "host": host})
            self._reply(403, b"Lineage E1: host not allowlisted")
            return

        if run.get("strict"):
            allowed = False
            for rule in (POLICY.get("strict", {}) or {}).get("allow", []):
                if str(rule.get("host", "")).lower() != host:
                    continue
                methods = {m.upper() for m in rule.get("methods", ["*"])}
                if "*" not in methods and method not in methods:
                    continue
                if binding_match.glob_match(str(rule.get("path", "/**")), path):
                    allowed = True
                    break
            if not allowed:
                _emit(
                    run_id,
                    "verdict",
                    {
                        "decision": "deny",
                        "rule_id": "T1",
                        "reason": "Lineage T1: strict mode blocks this egress",
                    },
                )
                self._reply(403, b"Lineage T1: strict mode")
                return
            drip_cfg = POLICY.get("drip", {}) or {}
            result = _drip.check(
                host,
                path,
                body_size=len(body),
                sensitive_values=[p["value"] for p in placeholders],
            )
            if result.blocked:
                _emit(
                    run_id,
                    "verdict",
                    {
                        "decision": "deny",
                        "rule_id": "T2",
                        "reason": f"Lineage T2: {result.reason}",
                    },
                )
                self._reply(403, b"Lineage T2: drip detector")
                return

        # Forward
        headers["Host"] = target.netloc
        try:
            conn = http.client.HTTPConnection(host, target.port or 80, timeout=10)
            conn.request(method, path + (f"?{target.query}" if target.query else ""), body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            # Reverse-swap secrets → placeholders
            text = data.decode("utf-8", errors="replace")
            for binding in run.get("bindings", []):
                try:
                    real = _real_secret(binding["secret_ref"])
                except Exception:
                    continue
                ph = binding.get("placeholder")
                if ph and real and real in text:
                    text = text.replace(real, ph)
            data = text.encode()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() in {"transfer-encoding", "connection", "content-length"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            _emit(
                run_id,
                "egress",
                {
                    "host": host,
                    "method": method,
                    "path": path,
                    "bytes_out": len(body),
                    "status": response.status,
                },
            )
        except Exception as exc:
            self._reply(502, f"proxy error: {exc}".encode())

    def _reply(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        print(format % args, flush=True)


if __name__ == "__main__":
    # Ensure lineage_core is importable when running from /app
    ThreadingHTTPServer(("0.0.0.0", 8080), Proxy).serve_forever()
