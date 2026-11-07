from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
from typing import Any, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from lineage_core.models import RunStatus

from .bus import stream_from
from .state import get_state

router = APIRouter(prefix="/admin", tags=["admin"])


class CreateRunBody(BaseModel):
    task: str = ""
    mode: str = "interactive"
    mcp_allow: list[str] = Field(default_factory=list)
    bindings: list[str] = Field(default_factory=list)
    replay: bool = False
    # The workspace's manifests before the agent starts: {relative path: contents}.
    manifests: dict[str, str] = Field(default_factory=dict)
    protection: Literal["lineage", "baseline"] = "lineage"


class ModeBody(BaseModel):
    mode: str


def _require_operator(authorization: str | None) -> None:
    state = get_state()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "operator token required")
    token = authorization.split(" ", 1)[1].strip()
    if not secrets.compare_digest(token, state.operator_token):
        raise HTTPException(401, "invalid operator token")


def _public_run(run) -> dict[str, Any]:
    return {
        "run_id": run.id,
        "task": run.task,
        "mode": run.mode,
        "status": run.status.value if hasattr(run.status, "value") else run.status,
        "mcp_allow": run.mcp_allow,
        "bindings": [b.id for b in run.bindings],
        "placeholders": [
            {"binding_id": p.binding_id, "value": p.value} for p in run.placeholders
        ],
        "ip": run.ip,
        "token_jti": run.token_jti,
        "legs": run.legs,
        "strict": run.strict,
        "replay": run.replay,
        "headless": run.headless,
        "protection": run.protection,
        "created_at": run.created_at.isoformat(),
    }


@router.post("/runs")
def create_run(
    body: CreateRunBody,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_operator(authorization)
    state = get_state()
    try:
        run, run_token, env = state.create_run(
            task=body.task,
            mode=body.mode,
            mcp_allow=body.mcp_allow,
            binding_ids=body.bindings,
            replay=body.replay,
            manifests=body.manifests,
            protection=body.protection,
        )
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc
    state.publish("run_created", run.id, _public_run(run))
    return {
        "run_id": run.id,
        "run_token": run_token,
        "hook_token": run.hook_token,
        "ip": run.ip,
        "env": env,
        "run": _public_run(run),
    }


@router.get("/runs")
def list_runs(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_operator(authorization)
    return [_public_run(run) for run in get_state().store.list_runs()]


@router.get("/runs/{run_id}")
def get_run(run_id: str, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_operator(authorization)
    run = get_state().store.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return _public_run(run)


@router.get("/runs/{run_id}/events")
def list_events(
    run_id: str,
    after: int = 0,
    authorization: str | None = Header(default=None),
) -> list[dict[str, Any]]:
    _require_operator(authorization)
    events = get_state().store.list_events(run_id, after=after)
    return [
        {
            "seq": e.seq,
            "type": e.type,
            "payload": e.payload,
            "ts": e.ts.isoformat(),
        }
        for e in events
    ]


@router.post("/runs/{run_id}/revoke")
def revoke(run_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    _require_operator(authorization)
    state = get_state()
    if not state.store.get_run(run_id):
        raise HTTPException(404, "run not found")
    return {"status": state.end_run(run_id, RunStatus.REVOKED).value}


@router.post("/runs/{run_id}/stop")
def stop(run_id: str, authorization: str | None = Header(default=None)) -> dict[str, str]:
    _require_operator(authorization)
    state = get_state()
    if not state.store.get_run(run_id):
        raise HTTPException(404, "run not found")
    return {"status": state.end_run(run_id, RunStatus.STOPPED).value}


@router.post("/runs/{run_id}/mode")
def set_mode(
    run_id: str,
    body: ModeBody,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    _require_operator(authorization)
    state = get_state()
    if not state.store.get_run(run_id):
        raise HTTPException(404, "run not found")
    if body.mode not in {"interactive", "autonomous"}:
        raise HTTPException(400, "mode must be interactive or autonomous")
    state.store.update_run(run_id, mode=body.mode)
    state.publish("mode", run_id, {"mode": body.mode})
    return {"mode": body.mode}


@router.get("/runs/{run_id}/signal")
async def signal(
    run_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    _require_operator(authorization)
    state = get_state()
    for _ in range(30):
        run = state.store.get_run(run_id)
        if not run:
            raise HTTPException(404, "run not found")
        if run.signal == "stop" or run.status in {
            RunStatus.REVOKED,
            RunStatus.KILLED,
            RunStatus.STOPPED,
            RunStatus.FINISHED,
        }:
            return {"signal": "stop"}
        await asyncio.sleep(1)
    return {"signal": "none"}


@router.post("/scorecard")
def scorecard(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Runs every scorecard attack now, in a separate process with its own empty control plane,
    so live runs and this dashboard are untouched."""
    _require_operator(authorization)
    env = {k: v for k, v in os.environ.items() if k != "LINEAGE_OPERATOR_TOKEN"}
    done = subprocess.run(
        [sys.executable, "-m", "control.scorecard", "--json"],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if done.returncode != 0:
        raise HTTPException(500, f"The scorecard failed: {done.stderr[-500:]}")
    return json.loads(done.stdout)


@router.get("/stream")
def stream(authorization: str | None = Header(default=None)):
    _require_operator(authorization)
    return stream_from(get_state().bus)
