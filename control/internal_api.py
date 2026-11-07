from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from lineage_core.models import RunStatus
from lineage_core.trifecta import update_legs

from .state import get_state

router = APIRouter(prefix="/internal", tags=["internal"])


class EventBody(BaseModel):
    run_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)


def _require_service(token: str | None) -> None:
    state = get_state()
    if not token or not secrets.compare_digest(token, state.service_token):
        raise HTTPException(401, "invalid service token")


@router.get("/status")
def status() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/runs/{run_id}")
def get_run(
    run_id: str,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_service(x_lineage_service_token)
    run = get_state().store.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return {
        "run_id": run.id,
        "status": run.status.value,
        "strict": run.strict,
        "mode": run.mode,
    }


@router.get("/runs/by-ip/{ip}")
def by_ip(
    ip: str,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_service(x_lineage_service_token)
    run = get_state().get_run_by_ip(ip)
    if not run:
        raise HTTPException(404, "unknown agent ip")
    return {
        "run_id": run.id,
        "status": run.status.value,
        "strict": run.strict,
        "legs": run.legs,
        "protection": run.protection,
        "bindings": [
            {
                "id": b.id,
                "hosts": b.hosts,
                "scope": {"allow": b.allow, "deny": b.deny},
                "secret_ref": b.secret_ref,
                "header": b.header,
                "scheme": b.scheme,
                "env_var": b.env_var,
                "placeholder": next(
                    (p.value for p in run.placeholders if p.binding_id == b.id), None
                ),
            }
            for b in run.bindings
        ],
        "placeholders_all": [
            {
                "binding_id": p.binding_id,
                "value": p.value,
                "variants": sorted(p.variants),
            }
            for p in run.placeholders
        ],
    }


@router.post("/events")
def post_event(
    body: EventBody,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, bool]:
    _require_service(x_lineage_service_token)
    state = get_state()
    run = state.store.get_run(body.run_id)
    if not run:
        raise HTTPException(404, "run not found")
    if body.type == "egress" and not run.legs.get("external"):
        # Every egress host is external: model traffic goes through the model tap, not egress.
        update_legs(run, egress_host=str(body.payload.get("host", "")))
        state.store.update_run(run.id, legs=run.legs, strict=run.strict)
        state.publish("legs", run.id, {"legs": run.legs, "strict": run.strict})
    state.publish(body.type, body.run_id, body.payload)
    return {"accepted": True}


class ModelRequestBody(BaseModel):
    user_texts: list[str] = Field(default_factory=list)


@router.post("/runs/{run_id}/model-request")
def model_request(
    run_id: str,
    body: ModelRequestBody,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, list[str]]:
    """The model tap reports the user-typed text in each model request (S2 corroboration)."""
    _require_service(x_lineage_service_token)
    state = get_state()
    if not state.store.get_run(run_id):
        raise HTTPException(404, "run not found")
    return {"verified": state.corroborate_prompts(run_id, [t[:20_000] for t in body.user_texts[:50]])}


@router.post("/runs/{run_id}/kill")
def kill(
    run_id: str,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, str]:
    _require_service(x_lineage_service_token)
    state = get_state()
    if not state.store.get_run(run_id):
        raise HTTPException(404, "run not found")
    return {"status": state.end_run(run_id, RunStatus.KILLED).value}


class ExitedBody(BaseModel):
    code: int
    logs: str = ""


@router.post("/runs/{run_id}/exited")
def exited(
    run_id: str,
    body: ExitedBody,
    x_lineage_service_token: str | None = Header(default=None),
) -> dict[str, bool]:
    """The runner reports a container is gone. Only now can its IP be reused."""
    _require_service(x_lineage_service_token)
    state = get_state()
    run = state.store.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    if run.status == RunStatus.ACTIVE:
        state.publish(
            "agent_done",
            run_id,
            {"ok": False, "text": f"The agent's container exited with code {body.code}.", "logs": body.logs[-4000:]},
        )
        state.end_run(run_id, RunStatus.FINISHED, stop_agent=False)
    state.release_ip(run.ip)
    return {"accepted": True}
