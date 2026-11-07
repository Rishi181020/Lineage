from __future__ import annotations

import fnmatch
import re
from collections.abc import Mapping
from typing import Any

from .classify import classify
from .models import Run, SourceTier, Span

_SECRET_RE = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\bghp_[A-Za-z0-9]{20,}\b|"
    r"\bsk-[A-Za-z0-9_-]{16,}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|"
    r"\blgph_[A-Za-z0-9_-]+_[A-Za-z0-9]{24}\b"
)


def _get(value: Any, key: str, default: Any = None) -> Any:
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def is_private(
    event: Mapping[str, Any] | Any,
    *,
    secret_patterns: list[str] | None = None,
    workspace_root: str = "/workspace",
) -> bool:
    payload = _get(event, "payload")
    if payload is None and isinstance(event, Mapping):
        payload = event
    payload = payload or {}
    tool = str(
        _get(event, "tool_name", "")
        or (payload.get("tool_name") if isinstance(payload, Mapping) else "")
        or ""
    )
    data: Mapping[str, Any] = {}
    if isinstance(event, Span):
        text = event.text
        path = event.path or ""
    else:
        data = payload.get("tool_input") or payload.get("input") or payload
        data = data if isinstance(data, Mapping) else {}
        text = " ".join(str(v) for v in data.values() if isinstance(v, str))
        path = str(data.get("file_path") or data.get("path") or "")
    patterns = secret_patterns or [
        ".env",
        ".env.*",
        "*.pem",
        "id_rsa*",
        "~/.aws/*",
        "~/.npmrc",
        "~/.netrc",
    ]
    normalized = path.replace("\\", "/")
    if normalized and any(
        fnmatch.fnmatch(normalized, pattern)
        or fnmatch.fnmatch(normalized.rsplit("/", 1)[-1], pattern)
        for pattern in patterns
    ):
        return True
    if _SECRET_RE.search(text):
        return True
    return classify(
        {"tool_name": tool, "tool_input": data},
        workspace_root=workspace_root,
    ).secret_access


def update_legs(
    run: Run,
    *,
    span: Span | None = None,
    event: Mapping[str, Any] | Any | None = None,
    egress_host: str | None = None,
    model_hosts: set[str] | None = None,
    secret_patterns: list[str] | None = None,
) -> bool:
    """Update sticky trifecta legs and return the resulting strict state."""
    if span and span.tier == SourceTier.UNTRUSTED:
        run.legs["untrusted"] = True
    subject = span or event
    if subject and is_private(
        subject,
        secret_patterns=secret_patterns,
        workspace_root=run.workspace_root,
    ):
        run.legs["private"] = True
    tool_name = str(_get(event, "tool_name", "") or "") if event else ""
    if tool_name.rsplit("__", 1)[-1].lower() == "webfetch":
        run.legs["external"] = True
    if egress_host and egress_host.lower() not in (model_hosts or set()):
        run.legs["external"] = True
    run.strict = run.strict or all(
        run.legs.get(leg, False) for leg in ("untrusted", "private", "external")
    )
    return run.strict
