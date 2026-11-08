"""Judge a dependency by what it did in the sandbox, not by reading its code.

Behaviors come from the npm behavior monitor (agent-image/watch.js), one dict per action:
{"op": "file" | "env" | "spawn" | "net", "target": ..., "phase": ...}.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

WORDS = {
    "file": "read credential file",
    "env": "read secret env var",
    "spawn": "started a process",
    "net": "opened a network connection",
}


def verdict(behaviors: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """clean: did nothing the monitor reports. suspicious: did something (credential access
    alone, a process, the network). malicious: read credentials and had a way to send them out."""
    behaviors = list(behaviors)
    ops = {str(b.get("op")) for b in behaviors}
    reasons = [f"{WORDS.get(str(b.get('op')), b.get('op'))}: {b.get('target')}" for b in behaviors]
    if ops & {"file", "env"} and ops & {"spawn", "net"}:
        level = "malicious"
    elif ops:
        level = "suspicious"
    else:
        level = "clean"
    return {"verdict": level, "reasons": reasons}
