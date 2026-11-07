#!/usr/bin/env python3
"""Feed recorded hook payloads through control for a deterministic demo."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx


def _event_from_name(path: Path, payload: dict) -> str:
    if "_event" in payload:
        return str(payload.pop("_event"))
    stem = path.stem.lower().replace("_", "-")
    for name in ("session-start", "user-prompt", "pre", "post"):
        if stem.startswith(name):
            return name
    return stem.split("-")[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay hook payloads into Lineage")
    parser.add_argument("fixture_dir", type=Path)
    parser.add_argument("--control", default="http://127.0.0.1:8001")
    parser.add_argument("--operator-token", default=None)
    parser.add_argument(
        "--task",
        default="Investigate the open errortrack issues and apply the fixes",
    )
    args = parser.parse_args()

    token_path = Path(".lineage/operator-token")
    operator = args.operator_token or (
        token_path.read_text(encoding="utf-8-sig").strip()
        if token_path.exists()
        else "lineage-operator-dev"
    )
    headers = {"Authorization": f"Bearer {operator}"}
    with httpx.Client(base_url=args.control, timeout=30) as client:
        created = client.post(
            "/admin/runs",
            headers=headers,
            json={
                "task": args.task,
                "mode": "interactive",
                "mcp_allow": ["errortrack.list_issues", "errortrack.get_issue"],
                "bindings": ["staging-infra"],
                "replay": True,
            },
        )
        created.raise_for_status()
        data = created.json()
        hook_token = data["hook_token"]
        print(f"REPLAY run {data['run_id']}")

        for path in sorted(args.fixture_dir.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            event = _event_from_name(path, payload)
            resp = client.post(
                f"/hooks/{event}",
                headers={"X-Lineage-Hook-Token": hook_token},
                json=payload,
            )
            print(f"{path.name}: {resp.status_code} {resp.text[:120]!r}")
            time.sleep(0.05)
    return 0


if __name__ == "__main__":
    sys.exit(main())
