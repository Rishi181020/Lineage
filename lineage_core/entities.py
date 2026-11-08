from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import bashlex

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?::\d+)?\b",
    re.IGNORECASE,
)
_SCOPED_NPM_RE = re.compile(r"(?<![\w.-])(@[a-z0-9._-]+/[a-z0-9._-]+)", re.I)
_ABS_PATH_RE = re.compile(
    r"(?<![\w])((?:~|/)(?!/)[^\s'\"|;&<>]+|[A-Za-z]:\\[^\s'\"|;&<>]+)"
)
_TRAILING = ".,;:!?)]}>\"'"


@dataclass(frozen=True)
class BashAnalysis:
    words: tuple[str, ...]
    used_fallback: bool = False
    pipe_to_shell: bool = False


def _clean(value: str) -> str:
    return value.strip(" \t\r\n'\"([{<").rstrip(_TRAILING).lower()


def _walk_bash(node: Any) -> Iterable[str]:
    if getattr(node, "kind", None) == "word":
        yield getattr(node, "word", "")
    for attr in ("parts", "list", "command", "output", "input"):
        value = getattr(node, attr, None)
        if isinstance(value, list):
            for child in value:
                yield from _walk_bash(child)
        elif hasattr(value, "kind"):
            yield from _walk_bash(value)


def analyze_bash(command: str) -> BashAnalysis:
    try:
        trees = bashlex.parse(command)
        words = tuple(word for tree in trees for word in _walk_bash(tree) if word)
        fallback = False
    except Exception:
        words_list: list[str] = []
        for segment in re.split(r"(?:&&|\|\||[;|])", command):
            try:
                words_list.extend(shlex.split(segment, posix=True))
            except ValueError:
                words_list.extend(segment.split())
        words = tuple(words_list)
        fallback = True
    pipe_to_shell = bool(
        re.search(r"\|\s*(?:/usr/bin/|/bin/)?(?:sh|bash|python\d*)\b", command, re.I)
    )
    return BashAnalysis(words=words, used_fallback=fallback, pipe_to_shell=pipe_to_shell)


# (ecosystem, command, whether every argument is a package). Installers take a list of
# packages; runners (npx, uvx, dlx) take one package and pass the rest to it as arguments.
_INSTALLERS = (
    ("npm", r"\bnpm\s+(?:i|install|add)\b", True),
    ("npm", r"\bpnpm\s+(?:add|i|install)\b", True),
    ("npm", r"\byarn\s+add\b", True),
    ("npm", r"\bbun\s+(?:add|install|i)\b", True),
    ("npm", r"\bnpx\b", False),
    ("npm", r"\bnpm\s+exec\b", False),
    ("npm", r"\bpnpm\s+dlx\b", False),
    ("npm", r"\byarn\s+dlx\b", False),
    ("npm", r"\bbunx\b", False),
    ("pypi", r"\bpip3?\s+install\b", True),
    ("pypi", r"\buv\s+(?:add|pip\s+install)\b", True),
    ("pypi", r"\bpoetry\s+add\b", True),
    ("pypi", r"\bpipx\s+install\b", True),
    ("pypi", r"\buvx\b", False),
    ("pypi", r"\bpipx\s+run\b", False),
)
_COMMAND_END = re.compile(r"&&|\|\||[;|\n)]")
# A shell redirect: `2>&1`, `>log`, `2>`, `<in`, `&>out`. Digits right before > or < are a file
# descriptor, never a package name.
_REDIRECT = re.compile(r"^(?:\d*(?:>>?|<|>&|<&)|&>)")
_REDIRECT_ALONE = re.compile(r"^(?:\d*(?:>>?|<)|&>)$")
_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url",
    "-f", "--find-links", "-t", "--target", "--registry", "--prefix", "-w", "--workspace", "--cache",
}
_NAME_RE = re.compile(r"^[@a-z0-9][\w@./=<>!~\[\],-]*$", re.I)


def _package_args(text: str, start: int) -> list[str]:
    """The package arguments after an install or run verb, up to the end of that command."""
    segment = _COMMAND_END.split(text[start:], maxsplit=1)[0]
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        tokens = segment.split()
    names: list[str] = []
    skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        if _REDIRECT.match(token):
            skip = bool(_REDIRECT_ALONE.match(token))  # `2> file`: the file is the next word
            continue
        if token.startswith("-"):
            skip = token in _VALUE_FLAGS
            continue
        if _NAME_RE.match(token):
            names.append(token)
    return names


def _package_entities(text: str) -> set[str]:
    found: set[str] = set()
    for match in _SCOPED_NPM_RE.finditer(text):
        found.add(f"pkg:npm:{_clean(match.group(1))}")

    for ecosystem, pattern, every_arg in _INSTALLERS:
        for match in re.finditer(pattern, text, re.I):
            args = _package_args(text, match.end())
            for name in args if every_arg else args[:1]:
                if ecosystem == "npm":
                    name = re.split(r"(?<!^)[@=]", _clean(name), maxsplit=1)[0]
                else:
                    name = re.split(r"[<>=!~\[;]", _clean(name), maxsplit=1)[0]
                if name:
                    found.add(f"pkg:{ecosystem}:{name}")
    return found


def extract_entities(
    text: str,
    *,
    tool_name: str | None = None,
    tool_input: Mapping[str, Any] | None = None,
) -> set[str]:
    """Extract normalized entity keys from span text or a tool action."""
    text = text or ""
    found = _package_entities(text)

    for raw in _URL_RE.findall(text):
        full = raw.rstrip(_TRAILING)
        parsed = urlsplit(full)
        if not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        path = parsed.path or "/"
        port = f":{parsed.port}" if parsed.port else ""
        found.add(f"host:{host}")
        found.add(f"url:{parsed.scheme.lower()}://{host}{port}{path}")

    for match in _DOMAIN_RE.finditer(text):
        found.add(f"host:{match.group(0).lower().split(':', 1)[0]}")

    for match in re.finditer(r"\b[\w.-]+@([a-z0-9.-]+\.[a-z]{2,63})\b", text, re.I):
        found.add(f"host:{match.group(1).lower()}")

    if tool_name and tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3:
            found.add(f"mcp:{parts[1].lower()}.{parts[2].lower()}")

    if tool_input:
        server = tool_input.get("mcp_server")
        name = tool_input.get("name")
        if isinstance(server, str) and isinstance(name, str):
            found.add(f"mcp:{_clean(server)}.{_clean(name)}")

    path_text = _URL_RE.sub(" ", text)
    if tool_input:
        path_text += " " + " ".join(
            str(tool_input[key])
            for key in ("file_path", "path")
            if key in tool_input
        )
    for match in _ABS_PATH_RE.finditer(path_text):
        path = match.group(1).rstrip(_TRAILING)
        if not path.startswith("//"):
            found.add(f"path:{path}")
    return found


def extract_bash(command: str) -> tuple[set[str], BashAnalysis]:
    analysis = analyze_bash(command)
    return extract_entities(command), analysis


extract = extract_entities
