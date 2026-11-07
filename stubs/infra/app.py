import os

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="Lineage Infrastructure Stub")
calls: list[dict] = []


def require_token(authorization: str | None) -> None:
    expected = f"Bearer {os.environ['STAGING_REAL_TOKEN']}"
    if authorization != expected:
        raise HTTPException(401, "real staging token required")


@app.middleware("http")
async def log_calls(request: Request, call_next):
    response = await call_next(request)
    if request.url.path != "/health":
        calls.append(
            {
                "method": request.method,
                "path": request.url.path,
                "authorization": request.headers.get("authorization"),
                "status": response.status_code,
            }
        )
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/_calls")
def list_calls():
    return calls


@app.delete("/_calls")
def clear_calls():
    calls.clear()
    return {"cleared": True}


@app.get("/v1/envs/{env}/status")
def status(env: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    # Echo would prove reverse-swap; include a decoy field without the real token.
    return {
        "env": env,
        "status": "ready",
        "token_echo": authorization,
    }


@app.post("/v1/envs/{env}/deploys")
def deploy(env: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return {"env": env, "deployment": "demo-001", "status": "queued"}


@app.delete("/v1/envs/{env}/volumes/{volume_id}")
def delete_volume(
    env: str, volume_id: str, authorization: str | None = Header(default=None)
):
    require_token(authorization)
    return {"env": env, "deleted": volume_id}
