"""Egress decisions as a pure function: K0, E2, C1/C2 + custody, E1, T1/T2.

The proxy (egress/addon.py) does the I/O: it looks up the run, calls `decide`, then kills,
emits events and forwards as told. Keeping the rules here lets them be tested, and replayed
by the scorecard, without a live proxy.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import bindings as binding_match
from .drip import DripDetector

ENDED = {"revoked", "killed", "stopped", "finished"}
HOP_HEADERS = {"proxy-connection", "connection", "host", "proxy-authorization"}


@dataclass
class Outcome:
    action: str  # "forward" | "block" | "kill"
    status: int = 200
    message: str = ""
    rule: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


def is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)


def scan_placeholders(haystacks: list[str], placeholders: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    joined = "\n".join(haystacks)
    found = []
    for ph in placeholders:
        variants = set(ph.get("variants") or [])
        variants.add(ph["value"])
        if any(variant and variant in joined for variant in variants):
            found.append(ph)
    return found


def strict_now(run: Mapping[str, Any]) -> bool:
    """Strict once all three legs are on, or when this outbound request would turn on the last one.

    Egress traffic is the "external" leg, so a run that has read untrusted content and private
    data is strict for its first outbound request, not only from the second.
    """
    legs = run.get("legs") or {}
    return bool(run.get("strict")) or bool(legs.get("untrusted") and legs.get("private"))


def drip_for(policy: Mapping[str, Any]) -> DripDetector:
    cfg = policy.get("drip") or {}
    return DripDetector(
        max_distinct_paths=int(cfg.get("max_distinct_paths", 8)),
        window_s=float(cfg.get("window_s", 60)),
        max_body_bytes=int(cfg.get("max_body_bytes", 512)),
        min_substring=int(cfg.get("min_substring", 8)),
    )


def decide(
    run: Mapping[str, Any],
    *,
    method: str,
    host: str,
    path: str,
    target: str,
    headers: Mapping[str, str],
    body: bytes,
    policy: Mapping[str, Any],
    secret_for: Callable[[str], str],
    drip: DripDetector,
) -> Outcome:
    method = method.upper()
    host = host.lower()
    out = Outcome(
        action="forward",
        headers={k: v for k, v in headers.items() if k.lower() not in HOP_HEADERS},
        body=body,
    )
    run_id = run["run_id"]

    def block(status: int, rule: str, message: str, event: tuple[str, dict[str, Any]] | None = None) -> Outcome:
        out.action, out.status, out.rule, out.message = "block", status, rule, message
        if event:
            out.events.append(event)
        return out

    if run.get("status") in ENDED:
        return block(403, "K0", f"Lineage K0: run {run_id} is {run['status']}",
                     ("egress_block", {"rule": "K0", "host": host, "path": path}))

    stubs = {str(s).lower() for s in policy.get("stubs", [])}
    if is_private(host) and host not in stubs:
        return block(403, "E2", "Lineage E2: private/link-local destination blocked",
                     ("egress_block", {"rule": "E2", "host": host, "path": path}))

    baseline = run.get("protection") == "baseline"
    run_bindings = run.get("bindings") or []

    # C1 / C2 / custody come before E1, so a placeholder headed anywhere trips the wire,
    # even to a host that would also be refused.
    if not baseline:
        body_text = body.decode("utf-8", errors="replace")
        header_values = [f"{k}: {v}" for k, v in headers.items()]
        for ph in scan_placeholders([target, body_text, *header_values], run.get("placeholders_all") or []):
            binding = next((b for b in run_bindings if b["id"] == ph["binding_id"]), None)
            if binding is None:
                # Another run's placeholder: never legitimate here.
                binding = {"id": ph["binding_id"], "hosts": [], "scheme": "Bearer"}
            in_host = host in {h.lower() for h in binding.get("hosts", [])}
            placeholder = ph["value"]
            scheme = binding.get("scheme", "Bearer")
            if not in_host:
                out.action, out.status, out.rule = "kill", 403, "C1"
                out.message = "Lineage C1: tripwire - placeholder left its binding"
                out.events.append(("tripwire", {
                    "rule_id": "C1",
                    "host": host,
                    "path": path,
                    "method": method,
                    "placeholder_binding": ph["binding_id"],
                    "redacted_auth": f"{scheme} {placeholder[:20]}…",
                }))
                return out
            scope = binding.get("scope") or {}
            if not binding_match.scope_allowed(
                {"allow": scope.get("allow", []), "deny": scope.get("deny", []), "hosts": binding.get("hosts", [])},
                method=method,
                path=path,
            ):
                return block(403, "C2", "Lineage C2: credential out of scope", ("verdict", {
                    "decision": "deny",
                    "rule_id": "C2",
                    "reason": f"Lineage C2: the {binding['id']} key isn't allowed for {method} {path}",
                    "host": host,
                    "path": path,
                }))
            real = secret_for(binding["secret_ref"])
            header_name = binding.get("header", "Authorization")
            attached = False
            swap_headers = {header_name.lower(), "authorization", "x-api-key"}
            for key, value in list(out.headers.items()):
                if key.lower() in swap_headers and placeholder in value:
                    out.headers[key] = value.replace(placeholder, real)
                    attached = True
            if placeholder in body_text:
                body_text = body_text.replace(placeholder, real)
                out.body = body_text.encode()
                attached = True
            if attached:
                out.events.append(("custody_attach", {
                    "binding_id": binding["id"], "host": host, "method": method, "path": path, "header": header_name,
                }))

    allow_hosts = {str(h).lower() for h in (policy.get("egress") or {}).get("allow_hosts", [])}
    allow_hosts |= {h.lower() for b in run_bindings for h in b.get("hosts", [])}
    if host not in allow_hosts:
        return block(403, "E1", "Lineage E1: host not allowlisted",
                     ("egress_block", {"rule": "E1", "host": host, "path": path}))

    if not baseline and strict_now(run):
        allowed = False
        for rule in (policy.get("strict") or {}).get("allow", []):
            if str(rule.get("host", "")).lower() != host:
                continue
            methods = {m.upper() for m in rule.get("methods", ["*"])}
            if "*" not in methods and method not in methods:
                continue
            if binding_match.glob_match(str(rule.get("path", "/**")), path):
                allowed = True
                break
        if not allowed:
            return block(403, "T1", "Lineage T1: strict mode", ("verdict", {
                "decision": "deny",
                "rule_id": "T1",
                "reason": "Lineage T1: this run has read untrusted content and private data, so only "
                          "pre-approved paths are open",
                "host": host,
                "path": path,
            }))
        result = drip.check(
            host, path, body_size=len(body),
            sensitive_values=[p["value"] for p in run.get("placeholders_all") or []],
        )
        if result.blocked:
            return block(403, "T2", "Lineage T2: drip detector", ("verdict", {
                "decision": "deny", "rule_id": "T2", "reason": f"Lineage T2: {result.reason}", "host": host, "path": path,
            }))
    return out


def reverse_swap(run: Mapping[str, Any], data: bytes, secret_for: Callable[[str], str]) -> bytes:
    """Replaces any real secret in a response with its placeholder before the agent sees it."""
    if run.get("protection") == "baseline":
        return data
    text = data.decode("utf-8", errors="replace")
    changed = False
    for binding in run.get("bindings") or []:
        try:
            real = secret_for(binding["secret_ref"])
        except Exception:
            continue
        ph = binding.get("placeholder")
        if ph and real and real in text:
            text = text.replace(real, ph)
            changed = True
    return text.encode() if changed else data
