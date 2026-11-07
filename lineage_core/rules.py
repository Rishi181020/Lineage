from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .classify import classify
from .entities import extract_entities
from .models import Decision, EntityRecord, Run, RunStatus, SourceTier, Verdict

_CONTROL_HOSTS = {"control", "egress", "modeltap"}
_CONTROL_IPS = {"172.30.0.10", "172.30.0.11", "172.30.0.12"}


def _parts(event: Mapping[str, Any] | Any) -> tuple[str, dict[str, Any], str]:
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
    data = dict(data) if isinstance(data, Mapping) else {}
    text = " ".join(str(v) for v in data.values() if isinstance(v, (str, int, float)))
    return tool, data, text


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _record(index: Any, entity: str) -> Any:
    if isinstance(index, Mapping):
        return index.get(entity)
    getter = getattr(index, "get", None)
    return getter(entity) if getter else None


def _tier(record: Any) -> SourceTier | None:
    value = _get(record, "best_tier") if record is not None else None
    try:
        return SourceTier(value) if value is not None else None
    except ValueError:
        return None


def _spans(index: Any, record: Any, tier: SourceTier) -> list[Any]:
    refs = _get(record, "first_span_by_tier", {}) or {}
    ref = refs.get(tier) or refs.get(tier.value)
    if not ref:
        return []
    if isinstance(ref, Mapping):
        return [ref]
    span_map = index.get("_spans", {}) if isinstance(index, Mapping) else {}
    return [span_map.get(ref, ref)]


def _source_details(index: Any, record: Any, tier: SourceTier) -> tuple[str, str]:
    chain = _spans(index, record, tier)
    span = chain[0] if chain else None
    source = (
        _get(span, "source")
        or _get(span, "tool_name")
        or _get(record, "source")
        or (str(span) if span else tier.value)
    )
    if isinstance(source, str) and source.startswith("mcp__"):
        parts = source.split("__", 2)
        source = f"{parts[1]}.{parts[2]}" if len(parts) == 3 else source
    ts = _get(span, "ts") or _get(record, "first_seen_ts") or ""
    if isinstance(ts, datetime):
        ts = ts.isoformat()
    return str(source), str(ts)


def _verdict(
    decision: Decision,
    rule_id: str,
    reason: str,
    entities: list[str],
    chain: list[Any] | None = None,
) -> Verdict:
    return Verdict(
        decision=decision,
        rule_id=rule_id,
        reason=reason,
        entities=entities,
        chain=chain or [],
    )


def _policy_trusted(policy: Mapping[str, Any]) -> set[str]:
    allowlist = policy.get("allowlist", {}) or {}
    trusted = {f"host:{str(h).lower()}" for h in allowlist.get("hosts", [])}
    for package in allowlist.get("packages", []):
        package = str(package).lower()
        trusted.add(package if package.startswith("pkg:") else f"pkg:npm:{package}")
    return trusted


def evaluate(
    run: Run | Mapping[str, Any],
    event: Mapping[str, Any] | Any,
    index: Any,
    policy: Mapping[str, Any],
) -> Verdict:
    """Apply K0/S1/I1/L1/L2/L3/T1 in policy order without I/O."""
    run_id = str(_get(run, "id", _get(run, "run_id", "")))
    status = str(_get(run, "status", RunStatus.ACTIVE))
    if status in {RunStatus.REVOKED.value, RunStatus.KILLED.value, RunStatus.STOPPED.value}:
        return _verdict(
            Decision.DENY,
            "K0",
            f"Lineage K0: run {run_id} is {status}.",
            [],
        )

    tool, data, text = _parts(event)
    entities = extract_entities(text, tool_name=tool, tool_input=data)
    lowered = text.lower()
    internal = any(f"host:{h}" in entities for h in _CONTROL_HOSTS | _CONTROL_IPS)
    internal = internal or any(
        path in lowered
        for path in (
            "/etc/claude-code",
            "/etc/lineage",
            "/usr/local/bin/lineage-hook",
            "~/.mitmproxy",
        )
    )
    internal = internal or bool(re.search(r"/proc/1(?:/|$)", lowered))
    if internal:
        return _verdict(
            Decision.DENY,
            "S1",
            "Lineage S1: action targets the control layer.",
            sorted(entities),
        )

    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        canonical = f"{parts[1]}.{parts[2]}" if len(parts) == 3 else tool
        allowed = {str(item).lower() for item in _get(run, "mcp_allow", [])}
        if canonical.lower() not in allowed:
            return _verdict(
                Decision.DENY,
                "I1",
                f"Lineage I1: MCP tool {canonical} is not allowed for this run.",
                [f"mcp:{canonical.lower()}"],
            )

    trusted_hosts = {
        str(host).lower()
        for binding in _get(run, "bindings", [])
        for host in _get(binding, "hosts", [])
    }
    trusted_hosts.update(
        str(host).lower()
        for host in (policy.get("allowlist", {}) or {}).get("hosts", [])
    )
    trusted_hosts.update(
        entity.removeprefix("host:")
        for entity in entities
        if entity.startswith("host:")
        and _tier(_record(index, entity)) == SourceTier.TRUSTED
    )
    classification = classify(
        event,
        workspace_root=str(_get(run, "workspace_root", "/workspace")),
        trusted_hosts=trusted_hosts,
    )
    if not classification.high_risk:
        return Verdict()

    decision_entities = sorted(
        entity
        for entity in entities
        if entity.startswith(("pkg:", "host:", "path:", "mcp:"))
    )
    virtual_trusted = _policy_trusted(policy) | {
        f"host:{host}" for host in trusted_hosts
    }

    def entity_tier(entity: str) -> SourceTier | None:
        if entity in virtual_trusted:
            return SourceTier.TRUSTED
        return _tier(_record(index, entity))

    untrusted = [
        entity for entity in decision_entities if entity_tier(entity) == SourceTier.UNTRUSTED
    ]
    if untrusted:
        entity = untrusted[0]
        record = _record(index, entity)
        source, ts = _source_details(index, record, SourceTier.UNTRUSTED)
        reason = (
            f'Lineage L1: "{entity}" first appeared in {source} at {ts} '
            "(untrusted) and never in your request or trusted files."
        )
        chain = _spans(index, record, SourceTier.UNTRUSTED)
        if classification.runs_code:
            return _verdict(Decision.DENY, "L1a", reason, untrusted, chain)
        decision = (
            Decision.ASK
            if str(_get(run, "mode", "interactive")) == "interactive"
            else Decision.DENY
        )
        return _verdict(decision, "L1b", reason, untrusted, chain)

    missing = [entity for entity in decision_entities if entity_tier(entity) is None]
    if missing:
        entity = missing[0]
        return _verdict(
            Decision.ASK,
            "L2",
            f'Lineage L2: "{entity}" has no source in this session. Did you ask for this?',
            missing,
        )

    checked = [
        entity for entity in decision_entities if entity_tier(entity) == SourceTier.CHECKED
    ]
    if checked:
        entity = checked[0]
        record = _record(index, entity)
        source, _ = _source_details(index, record, SourceTier.CHECKED)
        return _verdict(
            Decision.ASK,
            "L3",
            f'Lineage L3: "{entity}" came from workspace file {source}, not from you.',
            checked,
            _spans(index, record, SourceTier.CHECKED),
        )

    if bool(_get(run, "strict", False)) and classification.network:
        return _verdict(
            Decision.ASK,
            "T1",
            "Lineage T1: this run has read untrusted content and private data; "
            "outbound actions need approval.",
            decision_entities,
        )
    return Verdict()
