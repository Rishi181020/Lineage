from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .models import Binding


def _get(value: Any, key: str, default: Any = None) -> Any:
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def glob_match(pattern: str, path: str) -> bool:
    """Match URL paths where * stays in a segment and ** crosses slashes."""
    regex = ""
    i = 0
    while i < len(pattern):
        if pattern[i : i + 2] == "**":
            regex += ".*"
            i += 2
        elif pattern[i] == "*":
            regex += "[^/]*"
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    return bool(re.fullmatch(regex, path))


def _rule_matches(
    rule: Mapping[str, Any],
    method: str,
    path: str,
    environment: str | None,
) -> bool:
    methods = {str(item).upper() for item in rule.get("methods", ["*"])}
    environments = rule.get("environments")
    if environments is None and rule.get("environment") is not None:
        environments = [rule["environment"]]
    if environments is not None and environment not in {
        str(item) for item in environments
    }:
        return False
    return ("*" in methods or method.upper() in methods) and glob_match(
        str(rule.get("path", "/**")), path
    )


def host_matches(binding: Binding | Mapping[str, Any], host: str) -> bool:
    candidate = host.lower().rstrip(".")
    return candidate in {
        str(item).lower().rstrip(".") for item in _get(binding, "hosts", [])
    }


def scope_allowed(
    binding: Binding | Mapping[str, Any],
    *,
    method: str,
    path: str,
    environment: str | None = None,
) -> bool:
    required_env = _get(binding, "environment")
    if required_env is not None and environment != required_env:
        return False
    required_envs = _get(binding, "environments", []) or []
    if required_envs and environment not in required_envs:
        return False
    deny = _get(binding, "deny", []) or []
    if any(_rule_matches(rule, method, path, environment) for rule in deny):
        return False
    allow = _get(binding, "allow", []) or []
    return bool(allow) and any(
        _rule_matches(rule, method, path, environment) for rule in allow
    )


def matches(
    binding: Binding | Mapping[str, Any],
    *,
    host: str,
    method: str,
    path: str,
    environment: str | None = None,
) -> bool:
    return host_matches(binding, host) and scope_allowed(
        binding, method=method, path=path, environment=environment
    )


match_binding = matches
