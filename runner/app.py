"""Starts and stops agent containers for control, in one fixed sandboxed shape."""

from __future__ import annotations

import fnmatch
import os
import re
import socket
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

SERVICE_TOKEN = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
CONTROL = os.environ.get("LINEAGE_CONTROL_INTERNAL", "http://control:8002")
IMAGE = os.environ.get("LINEAGE_AGENT_IMAGE", "lineage-agent-shell:latest")
NETWORK = os.environ.get("LINEAGE_SANDBOX_NETWORK", "lineage_sandbox")
WORKSPACE_MOUNT = "/workspace-src"
RUN_RE = re.compile(r"^run_[0-9a-f]{12}$")
IP_RE = re.compile(r"^172\.30\.0\.1\d\d$")


def _docker(timeout: float | None = 30) -> httpx.Client:
    return httpx.Client(
        transport=httpx.HTTPTransport(uds="/var/run/docker.sock"),
        base_url="http://docker",
        timeout=timeout,
    )


def _workspace_source() -> str:
    """The workspace's path on the host, which is what Docker needs for a bind mount."""
    with _docker() as docker:
        mounts = docker.get(f"/containers/{socket.gethostname()}/json").raise_for_status().json()["Mounts"]
    return next(m["Source"] for m in mounts if m["Destination"] == WORKSPACE_MOUNT)


def _strip_log_frames(raw: bytes) -> str:
    """Docker prefixes each non-TTY log chunk with an 8-byte header carrying its length."""
    out, at = [], 0
    while at + 8 <= len(raw):
        size = int.from_bytes(raw[at + 4 : at + 8], "big")
        out.append(raw[at + 8 : at + 8 + size])
        at += 8 + size
    return b"".join(out).decode("utf-8", errors="replace")


def _watch(container_id: str, run_id: str) -> None:
    """Waits for the container to end, tells control, and removes it."""
    code, logs = -1, ""
    try:
        with _docker(timeout=None) as docker:
            code = docker.post(f"/containers/{container_id}/wait").json().get("StatusCode", -1)
            raw = docker.get(
                f"/containers/{container_id}/logs",
                params={"stdout": 1, "stderr": 1, "tail": 40},
            ).content
            logs = _strip_log_frames(raw)
            docker.delete(f"/containers/{container_id}", params={"force": "true"})
    except httpx.HTTPError:
        pass
    try:
        httpx.post(
            f"{CONTROL}/internal/runs/{run_id}/exited",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            json={"code": code, "logs": logs},
            timeout=10,
            trust_env=False,
        )
    except httpx.HTTPError:
        pass


def _remove_all_agents() -> None:
    # Live agents would otherwise outlive the stack and block removing the sandbox network.
    with _docker() as docker:
        listed = docker.get(
            "/containers/json",
            params={"all": "true", "filters": '{"label":["lineage.run"]}'},
        ).json()
        for container in listed:
            docker.delete(f"/containers/{container['Id']}", params={"force": "true"})


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        _remove_all_agents()  # control's runs are in memory, so older containers are orphans
    except httpx.HTTPError:
        pass
    yield
    try:
        _remove_all_agents()
    except httpx.HTTPError:
        pass


app = FastAPI(title="Lineage Runner", lifespan=lifespan)


def _auth(token: str | None) -> None:
    if token != SERVICE_TOKEN:
        raise HTTPException(401, "invalid service token")


class AgentBody(BaseModel):
    run_id: str
    ip: str
    env: dict[str, str]
    issues: list[dict] | None = None


def _issues_tar(issues: list[dict]) -> bytes:
    """A tar with /etc/lineage/errortrack_issues.json, root-owned and read-only to the agent.

    Copied in before start rather than passed as an environment variable: `env` output is
    ordinary workspace content to Lineage, which would let an agent re-read the attacker's
    text from somewhere that isn't marked untrusted.
    """
    import io
    import json as _json
    import tarfile

    data = _json.dumps(issues, indent=2).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("errortrack_issues.json")
        info.size, info.mode, info.uid, info.gid = len(data), 0o644, 0, 0
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "workspace": _workspace_source()}


MANIFEST_PATTERNS = (
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements*.txt", "pyproject.toml", "poetry.lock", "uv.lock",
)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


@app.get("/workspace/manifests")
def manifests(x_lineage_service_token: str | None = Header(default=None)) -> dict[str, str]:
    """The workspace's manifests as they are before any agent touches them.

    Control trusts the dependencies these declare. Agents only ever see a copy, so this
    read-only original is the honest record of what the project asked for.
    """
    _auth(x_lineage_service_token)
    root = Path(WORKSPACE_MOUNT)
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if len(Path(dirpath).relative_to(root).parts) > 4:
            dirnames[:] = []
            continue
        for name in filenames:
            if not any(fnmatch.fnmatch(name, pat) for pat in MANIFEST_PATTERNS):
                continue
            path = Path(dirpath) / name
            if path.stat().st_size > 2_000_000 or len(found) >= 100:
                continue
            found[str(path.relative_to(root))] = path.read_text(encoding="utf-8", errors="replace")
    return found


@app.post("/agents")
def start(body: AgentBody, x_lineage_service_token: str | None = Header(default=None)) -> dict[str, str]:
    _auth(x_lineage_service_token)
    if not RUN_RE.match(body.run_id) or not IP_RE.match(body.ip):
        raise HTTPException(400, "invalid run id or ip")
    spec = {
        "Image": IMAGE,
        "Cmd": ["lineage-agent"],
        "WorkingDir": "/workspace",
        "Env": [f"{key}={value}" for key, value in body.env.items()],
        "Labels": {"lineage.run": body.run_id},
        "HostConfig": {
            "Binds": [f"{_workspace_source()}:/src:ro"],
            "NetworkMode": NETWORK,
            "Dns": ["127.0.0.1"],
            "ExtraHosts": [
                "control:172.30.0.10",
                "egress:172.30.0.11",
                "modeltap:172.30.0.12",
            ],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": 512,
            "Memory": 2 * 1024**3,
        },
        "NetworkingConfig": {
            "EndpointsConfig": {NETWORK: {"IPAMConfig": {"IPv4Address": body.ip}}}
        },
    }
    name = f"agent-{body.run_id}"
    try:
        with _docker() as docker:
            created = docker.post("/containers/create", params={"name": name}, json=spec)
            if created.status_code >= 400:
                raise HTTPException(502, created.text[:500])
            container_id = created.json()["Id"]
            if body.issues is not None:
                copied = docker.put(
                    f"/containers/{container_id}/archive",
                    params={"path": "/etc/lineage"},
                    content=_issues_tar(body.issues),
                    headers={"Content-Type": "application/x-tar"},
                )
                if copied.status_code >= 400:
                    docker.delete(f"/containers/{container_id}", params={"force": "true"})
                    raise HTTPException(502, f"couldn't give the agent its issues: {copied.text[:300]}")
            started = docker.post(f"/containers/{container_id}/start")
            if started.status_code >= 400:
                docker.delete(f"/containers/{container_id}", params={"force": "true"})
                raise HTTPException(502, started.text[:500])
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Docker isn't reachable: {exc}") from exc
    threading.Thread(target=_watch, args=(container_id, body.run_id), daemon=True).start()
    return {"container": name}


@app.delete("/agents/{run_id}")
def stop(run_id: str, x_lineage_service_token: str | None = Header(default=None)) -> dict[str, bool]:
    _auth(x_lineage_service_token)
    if not RUN_RE.match(run_id):
        raise HTTPException(400, "invalid run id")
    with _docker() as docker:
        docker.post(f"/containers/agent-{run_id}/kill")
    return {"stopped": True}
