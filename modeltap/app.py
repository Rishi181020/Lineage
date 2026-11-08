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
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from lineage_core.tokens import verify_local

app = FastAPI(title="Lineage Model Tap")

REGION = os.environ.get("LINEAGE_REGION", "us-east-1")
CONTROL = os.environ.get("LINEAGE_CONTROL_INTERNAL", "http://172.30.0.10:8002")
SERVICE_TOKEN = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
SIGNING_KEY = os.environ.get(
    "LINEAGE_LOCAL_SIGNING_KEY", "lineage-local-development-key"
)


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
            if status in {"revoked", "killed", "stopped", "finished"}:
                _emit(run_id, "model_refused", {"status": status})
                raise HTTPException(401, {"message": "Lineage: run revoked"})
    except HTTPException:
        raise
    except Exception:
        pass
    return claims


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "modeltap"}


@app.get("/status")
def status(x_lineage_service_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Whether Bedrock is usable right now, in terms an operator can act on."""
    if x_lineage_service_token != SERVICE_TOKEN:
        raise HTTPException(401, "invalid service token")
    configured = os.environ.get("LINEAGE_MODEL_ID", "")
    config = Config(connect_timeout=4, read_timeout=6, retries={"max_attempts": 1})
    try:
        client = boto3.Session().client("bedrock", region_name=REGION, config=config)
        pages = client.get_paginator("list_inference_profiles").paginate()
        models = sorted(
            (
                summary["inferenceProfileId"]
                for page in pages
                for summary in page["inferenceProfileSummaries"]
                if "anthropic" in summary["inferenceProfileId"]
            ),
            reverse=True,
        )
    except NoCredentialsError:
        return {"ready": False, "problem": f"No AWS credentials found. Add them to ~/.aws/credentials, then check again."}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if "AccessDenied" in code and configured:
            return {"ready": True, "models": [configured], "default": configured, "region": REGION}
        if "AccessDenied" in code:
            return {"ready": False, "problem": "These AWS credentials can't list Bedrock models. Set LINEAGE_MODEL_ID in .env, or allow bedrock:ListInferenceProfiles."}
        return {"ready": False, "problem": "AWS rejected the credentials in ~/.aws/credentials. They may have expired. Update them, then check again."}
    except BotoCoreError as exc:
        return {"ready": False, "problem": f"Couldn't reach AWS Bedrock: {type(exc).__name__}."}
    if configured:
        models = [configured, *[m for m in models if m != configured]]
    if not models:
        return {"ready": False, "problem": f"No Claude models are available in {REGION}. Enable one in the Bedrock console, then check again."}
    default = configured or next((m for m in models if "sonnet" in m), models[0])
    return {"ready": True, "models": models, "default": default, "region": REGION}


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
        _report_user_texts(run_id, user_typed_texts(messages))
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

    url = (
        f"https://bedrock-runtime.{REGION}.amazonaws.com/model/"
        f"{model_id}/{operation}"
    )
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        return Response(
            content=json.dumps({"message": "Lineage: no AWS credentials for Bedrock"}).encode(),
            status_code=503,
            media_type="application/json",
        )
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
        upstream = await client.send(
            client.build_request("POST", url, headers=headers, content=body), stream=True
        )

        async def stream():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()

        if upstream.status_code >= 400:
            detail = await upstream.aread()
            await upstream.aclose()
            await client.aclose()
            _report_refusal(run_id, upstream.status_code, detail)
            return Response(
                content=detail,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type", "application/json"),
            )

        return StreamingResponse(
            stream(),
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/vnd.amazon.eventstream"),
        )

    async with httpx.AsyncClient(timeout=120) as client:
        upstream = await client.post(url, headers=headers, content=body)
        if upstream.status_code >= 400:
            _report_refusal(run_id, upstream.status_code, upstream.content)
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )


def user_typed_texts(messages: list[Any]) -> list[str]:
    """Text blocks in user messages, which is where a typed prompt travels.

    Tool results ride in `tool_result` blocks and Claude Code's own notes (file changes, hook
    context) in `<system-reminder>` text, and both can carry attacker-written text, so neither counts.
    """
    texts: list[str] = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        blocks = [{"type": "text", "text": content}] if isinstance(content, str) else content or []
        for block in blocks:
            if not isinstance(block, dict) or block.get("type", "text") != "text":
                continue
            text = str(block.get("text") or "")
            if text.strip() and "<system-reminder>" not in text:
                texts.append(text)
    return texts


def _report_user_texts(run_id: str, texts: list[str]) -> None:
    """Sent before the request is forwarded, so control can trust a typed prompt before any tool call it leads to."""
    if not texts:
        return
    try:
        httpx.post(
            f"{CONTROL}/internal/runs/{run_id}/model-request",
            headers={"X-Lineage-Service-Token": SERVICE_TOKEN},
            json={"user_texts": texts[-10:]},
            timeout=3,
        )
    except Exception:
        pass


def _report_refusal(run_id: str, status_code: int, detail: bytes) -> None:
    """Claude Code retries for minutes without saying why, so the operator hears it from here."""
    try:
        message = json.loads(detail).get("message", "")
    except ValueError:
        message = detail.decode("utf-8", errors="replace")
    _emit(run_id, "model_error", {"status": status_code, "message": str(message)[:500]})


def urlsplit_host(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).netloc
