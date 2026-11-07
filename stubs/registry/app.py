from fastapi import FastAPI, HTTPException

app = FastAPI(title="Lineage Registry Stub")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def not_found(path: str):
    raise HTTPException(404, "demo registry never serves packages")
