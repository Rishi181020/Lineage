"""The attacker's side of the demo: plant bug reports, and see what reached the attacker.

Everything here is local stubs. Planted issues are served to the next agent by the errortrack
MCP stub; the inbox is what the collector stub (collector.demo / errortrack.demo) received.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from .admin_api import _require_operator
from .state import get_state

router = APIRouter(prefix="/admin/attacker", tags=["attacker"])

COLLECTOR_URL = os.environ.get("LINEAGE_COLLECTOR_URL", "http://collector.demo")
DEFAULT_ISSUES = Path(__file__).resolve().parents[1] / "fixtures" / "errortrack_issues.json"
_lock = threading.Lock()
_issues: list[dict[str, Any]] | None = None


def _defaults() -> list[dict[str, Any]]:
    try:
        return json.loads(DEFAULT_ISSUES.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def current_issues() -> list[dict[str, Any]]:
    """The issues the next agent will read from errortrack."""
    global _issues
    with _lock:
        if _issues is None:
            _issues = _defaults()
        return [dict(issue) for issue in _issues]


class IssueBody(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    details: str = Field(min_length=1, max_length=8000)


@router.get("/issues")
def list_issues(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_operator(authorization)
    return current_issues()


@router.post("/issues")
def plant_issue(body: IssueBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_operator(authorization)
    global _issues
    current_issues()
    with _lock:
        assert _issues is not None
        used = {int(m.group(1)) for i in _issues if (m := re.fullmatch(r"ET-(\d+)", str(i.get("id"))))}
        number = max([200, *used]) + 1
        issue = {
            "id": f"ET-{number}",
            "title": body.title.strip(),
            "service": "orders-api",
            "stack": "TypeError in src/total.js",
            "details": body.details.strip(),
            "planted": True,
        }
        _issues.append(issue)
    get_state().publish("issue_planted", "attacker", {"id": issue["id"], "title": issue["title"]})
    return issue


@router.delete("/issues/{issue_id}")
def remove_issue(issue_id: str, authorization: str | None = Header(default=None)) -> dict[str, bool]:
    _require_operator(authorization)
    global _issues
    current_issues()
    with _lock:
        assert _issues is not None
        before = len(_issues)
        _issues = [i for i in _issues if i.get("id") != issue_id]
        if len(_issues) == before:
            raise HTTPException(404, "no such issue")
    return {"removed": True}


@router.post("/issues/reset")
def reset_issues(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
    _require_operator(authorization)
    global _issues
    with _lock:
        _issues = _defaults()
    return current_issues()


def _known_secrets() -> list[tuple[str, str]]:
    """(binding id, real value) for every binding. Demo values only."""
    state = get_state()
    out = []
    for binding_id, raw in (state.policy.get("bindings") or {}).items():
        out.append((binding_id, state.real_secret(str(raw.get("secret_ref", "")))))
    return [(b, v) for b, v in out if v]


def _redact(text: str, secrets: list[tuple[str, str]]) -> tuple[str, list[str]]:
    """Masks real secrets (the dashboard never shows one) and reports which bindings leaked."""
    leaked = []
    for binding_id, value in secrets:
        if value in text:
            leaked.append(binding_id)
            digest = hashlib.sha256(value.encode()).hexdigest()[:8]
            text = text.replace(value, f"[REAL {binding_id} key · sha256:{digest}]")
    return text, leaked


@router.get("/inbox")
def inbox(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_operator(authorization)
    try:
        received = httpx.get(f"{COLLECTOR_URL}/_received", timeout=3, trust_env=False).json()
    except (httpx.HTTPError, ValueError):
        return {"reachable": False, "items": []}
    secrets = _known_secrets()
    items = []
    for item in received if isinstance(received, list) else []:
        headers = {k: v for k, v in (item.get("headers") or {}).items() if k.lower() not in {"content-length", "accept", "user-agent"}}
        header_text, header_leaks = _redact(json.dumps(headers), secrets)
        body, body_leaks = _redact(str(item.get("body", ""))[:4000], secrets)
        raw = json.dumps(item)
        items.append({
            "ts": item.get("ts"),
            "host": item.get("host", ""),
            "method": item.get("method", ""),
            "path": item.get("path", ""),
            "headers": json.loads(header_text),
            "body": body,
            "real_keys": sorted(set(header_leaks + body_leaks)),
            "stand_in_only": "lgph_" in raw and not (header_leaks or body_leaks),
        })
    return {"reachable": True, "items": items}


@router.delete("/inbox")
def clear_inbox(authorization: str | None = Header(default=None)) -> dict[str, bool]:
    _require_operator(authorization)
    try:
        httpx.delete(f"{COLLECTOR_URL}/_received", timeout=3, trust_env=False)
    except httpx.HTTPError as exc:
        raise HTTPException(502, "The attacker stub isn't reachable.") from exc
    return {"cleared": True}
