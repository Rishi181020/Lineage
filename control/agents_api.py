"""The web app's agents: real Claude Code runs started from the browser."""

from __future__ import annotations

import os
import re
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from lineage_core.models import RunStatus

from .admin_api import _public_run, _require_operator
from .attacker_api import current_issues
from .state import RUNNER_URL, get_state

router = APIRouter(prefix="/admin", tags=["agents"])

MODELTAP_URL = os.environ.get("LINEAGE_MODELTAP_URL", "http://modeltap:8100")
MODEL_RE = re.compile(r"^[\w.:/-]{1,200}$")
MCP_ALLOW = ["errortrack.list_issues", "errortrack.get_issue"]
BINDINGS = ["staging-infra"]


class AgentBody(BaseModel):
    task: str = Field(min_length=1, max_length=8000)
    model: str
    protection: Literal["lineage", "baseline"] = "lineage"


class ApprovalBody(BaseModel):
    decision: Literal["allow", "deny"]


def _service_headers() -> dict[str, str]:
    return {"X-Lineage-Service-Token": get_state().service_token}


@router.get("/system")
def system(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """What the app needs before an agent can start, with problems an operator can act on."""
    _require_operator(authorization)
    try:
        model = httpx.get(
            f"{MODELTAP_URL}/status", headers=_service_headers(), timeout=15, trust_env=False
        ).json()
    except (httpx.HTTPError, ValueError):
        model = {"ready": False, "problem": "The model service isn't responding. Check `docker compose ps`."}
    try:
        runner = httpx.get(f"{RUNNER_URL}/health", timeout=3, trust_env=False).json()
        runner["ready"] = True
    except (httpx.HTTPError, ValueError):
        runner = {"ready": False, "problem": "The agent launcher isn't responding. Check `docker compose ps`."}
    return {"model": model, "runner": runner}


def _starting_manifests() -> dict[str, str]:
    """Manifests from the runner's read-only copy of the workspace. Without them, nothing in
    the project's dependency list is trusted, which only means more approval requests."""
    try:
        resp = httpx.get(f"{RUNNER_URL}/workspace/manifests", headers=_service_headers(), timeout=10, trust_env=False)
        resp.raise_for_status()
        data = resp.json()
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (httpx.HTTPError, ValueError):
        return {}


@router.post("/agents")
def start_agent(
    body: AgentBody,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_operator(authorization)
    if not MODEL_RE.match(body.model):
        raise HTTPException(400, "invalid model id")
    state = get_state()
    run, run_token, env = state.create_run(
        task=body.task,
        mode="interactive",
        mcp_allow=MCP_ALLOW,
        binding_ids=BINDINGS,
        headless=True,
        manifests=_starting_manifests(),
        protection=body.protection,
    )
    state.publish("run_created", run.id, _public_run(run))
    try:
        resp = httpx.post(
            f"{RUNNER_URL}/agents",
            headers=_service_headers(),
            json={
                "run_id": run.id,
                "ip": run.ip,
                "env": {
                    **env,
                    "LINEAGE_RUN_ID": run.id,
                    "LINEAGE_HOOK_TOKEN": run.hook_token,
                    "LINEAGE_TASK": body.task,
                    "ANTHROPIC_AUTH_TOKEN": run_token,
                    "ANTHROPIC_MODEL": body.model,
                    "ANTHROPIC_SMALL_FAST_MODEL": body.model,
                },
                # What errortrack serves this agent, including anything planted from the attacker console.
                "issues": current_issues(),
            },
            timeout=30,
            trust_env=False,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        state.publish("agent_done", run.id, {"ok": False, "text": "The agent's container couldn't start."})
        state.end_run(run.id, RunStatus.STOPPED, stop_agent=False)
        state.release_ip(run.ip)
        raise HTTPException(502, f"The agent's container couldn't start: {exc}") from exc
    return _public_run(run)


@router.post("/runs/{run_id}/approvals/{approval_id}")
def answer_approval(
    run_id: str,
    approval_id: str,
    body: ApprovalBody,
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    _require_operator(authorization)
    state = get_state()
    if approval_id not in state.approvals:
        raise HTTPException(404, "That request is no longer waiting for an answer.")
    state.approvals[approval_id] = body.decision
    return {"decision": body.decision}
