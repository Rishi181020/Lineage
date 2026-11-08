"""Egress proxy with custody swap, tripwire, and allowlist (M3)."""

from __future__ import annotations

import http.client
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import httpx

from lineage_core import egress_rules

CONTROL = os.environ.get("LINEAGE_CONTROL_INTERNAL", "http://172.30.0.10:8002")
SERVICE_TOKEN = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
POLICY_PATH = os.environ.get("LINEAGE_POLICY_PATH", "/app/policy/default.yaml")

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = threading.Lock()
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
_drip = egress_rules.drip_for(POLICY)


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
        # HTTPS tunnels are refused, but recorded: most real exfiltration tries HTTPS first.
        run = _lookup_run(self._client_ip())
        if run:
            _emit(run["run_id"], "egress_block", {"rule": "E1", "host": self.path.rsplit(":", 1)[0].lower(), "path": " (HTTPS)"})
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

        run = _lookup_run(self._client_ip())
        if not run:
            self._reply(407, b"Lineage: unknown agent")
            return
        run_id = run["run_id"]

        outcome = egress_rules.decide(
            run,
            method=method,
            host=host,
            path=path,
            target=self.path,
            headers=dict(self.headers.items()),
            body=body,
            policy=POLICY,
            secret_for=_real_secret,
            drip=_drip,
        )
        for event_type, payload in outcome.events:
            _emit(run_id, event_type, payload)
        if outcome.action == "kill":
            _kill(run_id)
        if outcome.action != "forward":
            self._reply(outcome.status, outcome.message.encode())
            return

        headers = dict(outcome.headers)
        headers["Host"] = target.netloc
        try:
            conn = http.client.HTTPConnection(host, target.port or 80, timeout=10)
            conn.request(method, path + (f"?{target.query}" if target.query else ""), body=outcome.body, headers=headers)
            response = conn.getresponse()
            data = egress_rules.reverse_swap(run, response.read(), _real_secret)
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
                    "bytes_out": len(outcome.body),
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
