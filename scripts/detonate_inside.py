"""Runs INSIDE a sealed Lineage sandbox container. Never run this on a host.

Unpacks one npm package sample, then sets it off the two ways npm would: its install
scripts, and require(). The behavior monitor (agent-image/watch.js) reports what it does;
egress records where it tries to send data. Prints a JSON summary on the last line.

Usage (in the container): python3 detonate_inside.py /sample/<file>
Accepts a .tgz/.tar.gz, a .zip (password "infected", as malware datasets ship them),
or a directory containing package.json.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

WORK = Path("/tmp/work")
UNPACK = Path("/tmp/unpack")
SCRIPTS = ("preinstall", "install", "postinstall")
WATCH = "--require /opt/lineage/watch.js"


def unpack(sample: Path) -> None:
    UNPACK.mkdir(parents=True, exist_ok=True)
    name = sample.name.lower()
    if sample.is_dir():
        shutil.copytree(sample, UNPACK / "pkg", dirs_exist_ok=True)
    elif name.endswith(".zip"):
        with zipfile.ZipFile(sample) as archive:
            archive.extractall(UNPACK, pwd=b"infected")
        # Datasets often wrap the npm tarball inside the zip.
        for inner in list(UNPACK.rglob("*.tgz")) + list(UNPACK.rglob("*.tar.gz")):
            with tarfile.open(inner) as tar:
                tar.extractall(inner.parent / (inner.name + ".d"), filter="data")
    else:
        with tarfile.open(sample) as tar:
            tar.extractall(UNPACK, filter="data")


def find_package() -> Path:
    found = sorted(UNPACK.rglob("package.json"), key=lambda p: (len(p.parts), str(p)))
    found = [p for p in found if "node_modules" not in p.parts]
    if not found:
        raise SystemExit(json.dumps({"error": "no package.json in the sample"}))
    return found[0].parent


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: int) -> dict:
    try:
        done = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout, capture_output=True, text=True)
        return {"cmd": " ".join(cmd), "code": done.returncode, "stderr": done.stderr[-600:]}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "code": None, "timeout": True}


def main() -> None:
    sample = Path(sys.argv[1])
    timeout = int(os.environ.get("DETONATE_STEP_TIMEOUT", "45"))
    bait = os.environ.pop("DETONATE_BAIT", "")
    if bait:
        # npm token stealers read ~/.npmrc first; give them the run's stand-in key.
        with open(Path.home() / ".npmrc", "a", encoding="utf-8") as npmrc:
            npmrc.write(f"//registry.npmjs.org/:_authToken={bait}\n")
    unpack(sample)
    source = find_package()
    meta = json.loads((source / "package.json").read_text(encoding="utf-8", errors="replace"))
    name = str(meta.get("name") or "unknown-package")
    # Placed under node_modules so the monitor attributes what it does to this package.
    dest = WORK / "node_modules" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, dest, dirs_exist_ok=True)
    (WORK / "package.json").write_text(json.dumps({"name": "detonation-host", "version": "1.0.0", "private": True}))

    env = dict(os.environ)
    steps = []
    scripts = meta.get("scripts") or {}
    for script in SCRIPTS:
        if script in scripts:
            # npm preloads the monitor into scripts through NPM_CONFIG_NODE_OPTIONS (set in the image).
            steps.append(run(["npm", "run-script", script], dest, env, timeout))
    steps.append(run(["node", "-e", f"require({json.dumps(name)})"], WORK, {**env, "NODE_OPTIONS": WATCH}, timeout))
    print(json.dumps({"package": name, "version": meta.get("version"), "scripts": {k: scripts[k] for k in SCRIPTS if k in scripts}, "steps": steps}))


if __name__ == "__main__":
    main()
