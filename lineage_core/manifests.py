"""Dependency names in manifests and lockfiles.

Two uses:
- `baseline_entities` parses a manifest as it was when the run started. Those names are trusted,
  because the operator's project declared them before the agent did anything.
- `candidate_entities` pulls package-like names out of text the agent wrote into a manifest
  (an Edit fragment, a shell command). Those names are never trusted by being written; they're
  checked against wherever they first came from when an install runs.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from collections.abc import Iterable

DEFAULT_PATTERNS = (
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements*.txt",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
)
_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ]|$)")
_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SCOPED = re.compile(r"(?<![\w.-])(@[a-z0-9._-]+/[a-z0-9._-]+)", re.I)
# "name": "<version spec>" — the value must look like a version, so "main": "src/x.js" doesn't count.
_JSON_DEP = re.compile(
    r'"(@?[a-z0-9][\w./-]*)"\s*:\s*"\s*(?:[~^<>=]*\s*v?\d|\*|latest|next|npm:|git|https?:|file:|link:|workspace:)',
    re.I,
)
_PKG_SET = re.compile(r"\b(?:dependencies|devDependencies|optionalDependencies|peerDependencies)\.(@?[\w./-]+?)=", re.I)
_LOCK_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.M)
_YARN_ENTRY = re.compile(r'^"?(@?[^@\s"/][^@\s"]*(?:/[^@\s"]+)?)@', re.M)


def basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def is_manifest(path: str, patterns: Iterable[str] | None = None) -> bool:
    name = basename(path)
    return bool(name) and any(fnmatch.fnmatch(name, pat) for pat in (patterns or DEFAULT_PATTERNS))


def mentions_manifest(text: str, patterns: Iterable[str] | None = None) -> bool:
    words = re.findall(r"[\w./*-]+", text)
    return any(is_manifest(word, patterns) for word in words)


def _npm(name: str) -> str:
    return f"pkg:npm:{name.strip().lower()}"


def _pypi(name: str) -> str:
    # Lowercase only, to match the keys entities.py gives `pip install` targets.
    return f"pkg:pypi:{name.strip().lower()}"


def _ecosystem(filename: str) -> str:
    name = filename.lower()
    if name.startswith("requirements") or name in {"pyproject.toml", "poetry.lock", "uv.lock"}:
        return "pypi"
    return "npm"


def baseline_entities(filename: str, text: str) -> set[str]:
    """Every dependency a manifest or lockfile declares, as entity keys. Never raises."""
    name = basename(filename).lower()
    found: set[str] = set()
    try:
        if name == "package.json":
            data = json.loads(text)
            for section in _NPM_SECTIONS:
                found.update(_npm(dep) for dep in (data.get(section) or {}))
        elif name == "package-lock.json":
            data = json.loads(text)
            for key in data.get("packages") or {}:
                if "node_modules/" in key:
                    found.add(_npm(key.rsplit("node_modules/", 1)[-1]))
            found.update(_npm(dep) for dep in (data.get("dependencies") or {}))
        elif name == "yarn.lock":
            found.update(_npm(m.group(1)) for m in _YARN_ENTRY.finditer(text))
        elif name == "pnpm-lock.yaml":
            found.update(
                _npm(m.group(1))
                for m in re.finditer(r"^\s{2,4}'?/?(@?[^@\s'/:][^@\s':]*(?:/[^@\s':]+)?)[@:]", text, re.M)
            )
        elif name.startswith("requirements") and name.endswith(".txt"):
            for line in text.splitlines():
                line = line.split("#", 1)[0]
                if line.strip().startswith("-"):
                    continue
                match = _REQ_LINE.match(line)
                if match:
                    found.add(_pypi(match.group(1)))
        elif name == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project") or {}
            specs = list(project.get("dependencies") or [])
            for group in (project.get("optional-dependencies") or {}).values():
                specs.extend(group)
            for group in (data.get("dependency-groups") or {}).values():
                specs.extend(item for item in group if isinstance(item, str))
            for spec in specs:
                match = _PEP508.match(str(spec))
                if match:
                    found.add(_pypi(match.group(1)))
            poetry = (data.get("tool") or {}).get("poetry") or {}
            for section in ("dependencies", "dev-dependencies"):
                found.update(_pypi(dep) for dep in (poetry.get(section) or {}) if dep.lower() != "python")
        elif name in {"poetry.lock", "uv.lock"}:
            found.update(_pypi(m.group(1)) for m in _LOCK_NAME.finditer(text))
    except (ValueError, TypeError, AttributeError, tomllib.TOMLDecodeError):
        return found
    return found


def candidate_entities(text: str, filename: str = "package.json") -> set[str]:
    """Package-like names in text the agent wrote toward a manifest (fragments, commands)."""
    ecosystem = _ecosystem(basename(filename))
    found: set[str] = set()
    if ecosystem == "npm":
        found.update(_npm(m.group(1)) for m in _SCOPED.finditer(text))
        found.update(_npm(m.group(1)) for m in _JSON_DEP.finditer(text))
        found.update(_npm(m.group(1)) for m in _PKG_SET.finditer(text))
    else:
        for line in re.split(r"[\n,\"']", text):
            line = line.split("#", 1)[0]
            match = _REQ_LINE.match(line)
            if match and re.search(r"[<>=!~]", line):
                found.add(_pypi(match.group(1)))
    return found


def written_text(tool_input: dict) -> str:
    """The text an Edit/Write/MultiEdit call puts into a file."""
    parts = [tool_input.get(key) for key in ("content", "new_string", "new_source")]
    for edit in tool_input.get("edits") or []:
        if isinstance(edit, dict):
            parts.append(edit.get("new_string"))
    return "\n".join(str(part) for part in parts if part)


def read_manifests(root, patterns: Iterable[str] | None = None, max_depth: int = 4) -> dict[str, str]:
    """{relative path: text} for every manifest under `root`, skipping vendored folders."""
    import os
    from pathlib import Path

    root = Path(root)
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    found: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = [] if depth >= max_depth else [d for d in dirnames if d not in skip]
        for name in filenames:
            if is_manifest(name, patterns):
                path = Path(dirpath) / name
                found[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
    return found
