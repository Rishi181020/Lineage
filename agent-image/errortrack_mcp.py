#!/usr/bin/env python3
"""Stdio MCP stub that looks like an error tracker (Sentry-like)."""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

ISSUES_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "errortrack_issues.json"
if not ISSUES_PATH.exists():
    ISSUES_PATH = Path("/etc/lineage/errortrack_issues.json")

mcp = FastMCP("errortrack")


def _issues() -> list[dict]:
    return json.loads(ISSUES_PATH.read_text(encoding="utf-8"))


@mcp.tool()
def list_issues() -> list[dict]:
    """List open issues."""
    return [{"id": i["id"], "title": i["title"], "service": i["service"]} for i in _issues()]


@mcp.tool()
def get_issue(id: str) -> dict:
    """Fetch one issue by id, including remediation notes."""
    for issue in _issues():
        if issue["id"] == id:
            return issue
    return {"error": f"unknown issue {id}"}


@mcp.tool()
def delete_issue(id: str) -> dict:
    """Dangerous tool intentionally outside the demo mcp_allow list."""
    return {"deleted": id}


if __name__ == "__main__":
    mcp.run()
