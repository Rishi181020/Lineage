"""npm registry stub. Serves only the demo packages in ./packages; everything else is a 404.

Layout: packages/<name>/<version>/ holds the package's files. Tarballs are built on request.
"""

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

app = FastAPI(title="Lineage Registry Stub")
PACKAGES = Path(__file__).resolve().parent / "packages"


def _tarball(name: str, version: str) -> bytes:
    root = PACKAGES / name / version
    if not root.is_dir() or name.startswith(".") or version.startswith("."):
        raise HTTPException(404, "not found")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for file in sorted(p for p in root.rglob("*") if p.is_file()):
            data = file.read_bytes()
            info = tarfile.TarInfo(f"package/{file.relative_to(root).as_posix()}")
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/{name}/-/{file}")
def tarball(name: str, file: str):
    prefix = f"{name}-"
    if not (file.startswith(prefix) and file.endswith(".tgz")):
        raise HTTPException(404, "not found")
    return Response(_tarball(name, file[len(prefix):-4]), media_type="application/octet-stream")


@app.get("/{name}")
def packument(name: str):
    folder = PACKAGES / name
    if name.startswith(".") or not folder.is_dir():
        raise HTTPException(404, "demo registry only serves its demo packages")
    versions = {}
    for version_dir in sorted(p for p in folder.iterdir() if p.is_dir()):
        meta = json.loads((version_dir / "package.json").read_text(encoding="utf-8"))
        data = _tarball(name, version_dir.name)
        meta["dist"] = {
            "tarball": f"http://registry.demo/{name}/-/{name}-{version_dir.name}.tgz",
            "shasum": hashlib.sha1(data).hexdigest(),
        }
        versions[version_dir.name] = meta
    latest = sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")))[-1]
    return {"name": name, "dist-tags": {"latest": latest}, "versions": versions}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def not_found(path: str):
    raise HTTPException(404, "demo registry only serves its demo packages")
