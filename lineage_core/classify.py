from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Mapping

from .entities import analyze_bash

_INSTALL_EXEC = re.compile(
    r"(?:^|[;&|]\s*)"
    r"(?:npx\b|npm\s+(?:i|install|exec)\b|pip3?\s+install\b|uvx\b|"
    r"pipx\s+(?:run|install)\b|bunx\b|pnpm\s+dlx\b|yarn\s+dlx\b)",
    re.I,
)
_NETWORK = re.compile(
    r"(?:^|[;&|]\s*)(?:curl|wget|nc|ncat|ssh|scp|rsync|ftp|telnet)\b"
    r"|\bgit\s+(?:push|remote\s+add)\b",
    re.I,
)
_SECRET_FILE = re.compile(
    r"(?:^|/)(?:\.env(?:\.[^/\s]+)?|[^/\s]+\.pem|id_rsa[^/\s]*|"
    r"\.npmrc|\.netrc)$",
    re.I,
)


@dataclass(frozen=True)
class Classification:
    high_risk: bool
    categories: frozenset[str] = field(default_factory=frozenset)
    runs_code: bool = False
    network: bool = False
    secret_access: bool = False


def _event_parts(event: Mapping[str, Any] | Any) -> tuple[str, dict[str, Any]]:
    if isinstance(event, Mapping):
        payload = event.get("payload") or {}
        tool = str(
            event.get("tool_name")
            or event.get("tool")
            or (payload.get("tool_name") if isinstance(payload, Mapping) else "")
            or ""
        )
        data = event.get("tool_input") or event.get("input") or payload
    else:
        payload = getattr(event, "payload", {}) or {}
        tool = str(
            getattr(event, "tool_name", "")
            or (payload.get("tool_name") if isinstance(payload, Mapping) else "")
            or ""
        )
        data = payload
    if isinstance(data, Mapping):
        data = data.get("tool_input") or data.get("input") or data
    return tool, dict(data) if isinstance(data, Mapping) else {}


def _outside_workspace(path: str, workspace_root: str) -> bool:
    path = path.replace("\\", "/")
    root = workspace_root.replace("\\", "/").rstrip("/")
    if path.startswith("~/"):
        return True
    if re.match(r"^[A-Za-z]:/", path):
        return not path.lower().startswith(root.lower() + "/")
    if not path.startswith("/"):
        return False
    try:
        return not PurePosixPath(path).is_relative_to(PurePosixPath(root))
    except ValueError:
        return True


def classify(
    event: Mapping[str, Any] | Any,
    *,
    workspace_root: str = "/workspace",
    trusted_hosts: set[str] | None = None,
) -> Classification:
    tool, data = _event_parts(event)
    short_tool = tool.rsplit("__", 1)[-1].lower()
    categories: set[str] = set()

    if short_tool == "bash":
        command = str(data.get("command", ""))
        analysis = analyze_bash(command)
        if _INSTALL_EXEC.search(command):
            categories.add("code")
        if analysis.pipe_to_shell:
            categories.update(("code", "pipe_to_shell"))
        if _NETWORK.search(command):
            categories.add("network")
        if (
            re.search(r"\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b", command, re.I)
            and any(
                _outside_workspace(p, workspace_root)
                for p in re.findall(r"(?:~|/)[^\s;&|]+", command)
            )
        ):
            categories.add("destructive")
        if (
            re.search(r"\bcurl\b.*(?:-X|--request)\s*DELETE\b", command, re.I)
            or re.search(r"\baws\b.*\bdelete-[\w-]+", command, re.I)
            or re.search(r"\bkubectl\s+delete\b", command, re.I)
            or re.search(r"\bterraform\s+destroy\b", command, re.I)
            or re.search(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", command, re.I)
        ):
            categories.add("destructive")
        if re.search(r"(?:^|[;&|]\s*)(?:env|printenv|set)(?:\s|$)", command, re.I):
            categories.add("secret")
        if re.search(r"/proc/(?:\d+|self)/(?:environ|mem)\b", command, re.I):
            categories.add("secret")
        file_args = re.findall(r"(?:~|/|\./)[^\s;&|]+", command)
        if re.search(r"(?:^|[;&|]\s*)(?:cat|cp)\b", command, re.I) and any(
            _SECRET_FILE.search(p.rstrip("'\"")) for p in file_args
        ):
            categories.add("secret")

    elif short_tool == "webfetch":
        url = str(data.get("url", ""))
        host_match = re.match(r"https?://([^/:]+)", url, re.I)
        host = host_match.group(1).lower() if host_match else ""
        if host and host not in (trusted_hosts or set()):
            categories.add("network")

    elif short_tool in {"write", "edit", "multiedit", "notebookedit"}:
        path = str(data.get("file_path") or data.get("path") or "")
        if path and _outside_workspace(path, workspace_root):
            categories.add("persistence")

    return Classification(
        high_risk=bool(categories),
        categories=frozenset(categories),
        runs_code="code" in categories,
        network="network" in categories,
        secret_access="secret" in categories,
    )


def is_high_risk(event: Mapping[str, Any] | Any, **kwargs: Any) -> bool:
    return classify(event, **kwargs).high_risk


classify_action = classify
