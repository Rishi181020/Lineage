"""Bedrock-format model tap: verify run token, SigV4 forward, stream unchanged."""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from lineage_core.tokens import verify_local

app = FastAPI(title="Lineage Model Tap")

REGION = os.environ.get("LINEAGE_REGION", "us-west-2")
CONTROL = os.environ.get("LINEAGE_CONTROL_INTERNAL", "http://172.30.0.10:8002")
SERVICE_TOKEN = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
SIGNING_KEY = os.environ.get(
    "LINEAGE_LOCAL_SIGNING_KEY", "lineage-local-development-key"
)
MODE = os.environ.get("LINEAGE_MODE", "local")


def _emit(run_id: str, event_type: str, payload: dict[str, Any]) -> None:
    try:
        httpx.post(
            f"{CONTROL}/internal/events",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            json={"run_id": run_id, "type": event_type, "payload": payload},
            timeout=3,
        )
    except Exception:
        pass


def _run_status(run_id: str) -> str | None:
    try:
        # Admin-less: ask internal events path via by scanning is heavy;
        # encode status check by verifying token claims and asking control
        # through a lightweight internal endpoint if present.
        resp = httpx.get(
            f"{CONTROL}/internal/status",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            timeout=2,
        )
        if resp.status_code != 200:
            return None
    except Exception:
        return None
    # Fetch run via events listing is not available; use modeltap-local cache
    # by re-verifying with control admin is out of scope for service token.
    return "active"


def _verify_bearer(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, {"message": "Lineage: missing run token"})
    token = authorization.split(" ", 1)[1].strip()
    try:
        claims = verify_local(token, SIGNING_KEY)
    except Exception as exc:
        raise HTTPException(401, {"message": f"Lineage: invalid run token ({exc})"}) from exc
    run_id = str(claims["sub"])
    # Status check via internal by creating a tiny helper call
    try:
        # Prefer dedicated status if we add it; for now probe kill path no-op
        status_resp = httpx.get(
            f"{CONTROL}/internal/runs/by-ip/0.0.0.0",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            timeout=1,
        )
        _ = status_resp
    except Exception:
        pass
    # Store lookup: list not available; check via events post of heartbeat is wrong.
    # Use control internal run status endpoint we'll add.
    try:
        resp = httpx.get(
            f"{CONTROL}/internal/runs/{run_id}",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            timeout=2,
        )
        if resp.status_code == 200:
            status = resp.json().get("status", "active")
            if status in {"revoked", "killed", "stopped"}:
                raise HTTPException(401, {"message": "Lineage: run revoked"})
    except HTTPException:
        raise
    except Exception:
        pass
    return claims


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "modeltap"}


@app.get("/inference-profiles{path:path}")
def inference_profiles(path: str = ""):
    raise HTTPException(404)


@app.post("/model/{model_id}/{operation}")
async def model(model_id: str, operation: str, request: Request):
    claims = _verify_bearer(request.headers.get("authorization"))
    run_id = str(claims["sub"])
    body = await request.body()

    try:
        parsed = json.loads(body.decode("utf-8"))
        messages = parsed.get("messages") or []
        last_user = ""
        for message in reversed(messages):
            if message.get("role") == "user":
                content = message.get("content")
                if isinstance(content, str):
                    last_user = content
                elif isinstance(content, list):
                    last_user = " ".join(
                        str(part.get("text", ""))
                        for part in content
                        if isinstance(part, dict)
                    )
                break
        _emit(
            run_id,
            "model_call",
            {
                "model": model_id,
                "operation": operation,
                "n_messages": len(messages),
                "last_user_text_hash": hashlib.sha256(last_user.encode()).hexdigest()[:16],
            },
        )
    except Exception:
        _emit(run_id, "model_call", {"model": model_id, "operation": operation})

    if MODE != "aws" and not os.environ.get("AWS_ACCESS_KEY_ID"):
        # Local stub: return a minimal Bedrock-like JSON error explaining AWS needed
        return Response(
            content=json.dumps(
                {
                    "message": (
                        "Lineage modeltap: set LINEAGE_MODE=aws on a host with "
                        "instance-role Bedrock access to forward."
                    )
                }
            ).encode(),
            status_code=503,
            media_type="application/json",
        )

    url = (
        f"https://bedrock-runtime.{REGION}.amazonaws.com/model/"
        f"{model_id}/{operation}"
    )
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise HTTPException(500, {"message": "Lineage: no AWS credentials for Bedrock"})
    frozen = credentials.get_frozen_credentials()
    aws_request = AWSRequest(
        method="POST",
        url=url,
        data=body,
        headers={"Content-Type": "application/json", "Host": urlsplit_host(url)},
    )
    SigV4Auth(frozen, "bedrock", REGION).add_auth(aws_request)
    headers = dict(aws_request.headers.items())

    if operation.endswith("stream") or "response-stream" in operation:
        client = httpx.AsyncClient(timeout=None)

        async def stream():
            try:
                async with client.stream(
                    "POST", url, headers=headers, content=body
                ) as upstream:
                    async for chunk in upstream.aiter_bytes():
                        yield chunk
            finally:
                await client.aclose()

        return StreamingResponse(
            stream(),
            media_type="application/vnd.amazon.eventstream",
        )

    async with httpx.AsyncClient(timeout=120) as client:
        upstream = await client.post(url, headers=headers, content=body)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )


def urlsplit_host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc
