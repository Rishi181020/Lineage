from fastapi import FastAPI, Request

app = FastAPI(title="Lineage Collector Stub")
received: list[dict] = []


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/_received")
def list_received():
    return received


@app.delete("/_received")
def clear_received():
    received.clear()
    return {"cleared": True}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def collect(path: str, request: Request):
    item = {
        "method": request.method,
        "path": "/" + path,
        "headers": dict(request.headers),
        "body": (await request.body()).decode("utf-8", errors="replace"),
    }
    received.append(item)
    return {"received": True}
