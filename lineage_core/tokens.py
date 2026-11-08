from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt

ISSUER = "lineage"
AUDIENCE = "lineage-run"


def mint_local(
    run_id: str,
    key: str,
    *,
    mcp_allow: list[str] | None = None,
    bindings: list[str] | None = None,
    lifetime: timedelta = timedelta(hours=2),
    now: datetime | None = None,
) -> str:
    now = now or datetime.now(UTC)
    claims = {
        "sub": run_id,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + lifetime,
        "jti": uuid4().hex,
        "mcp_allow": mcp_allow or [],
        "bindings": bindings or [],
    }
    return jwt.encode(claims, key, algorithm="HS256", headers={"alg": "HS256"})


def verify_local(token: str, key: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        key,
        algorithms=["HS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["sub", "iss", "aud", "iat", "exp", "jti"]},
    )


class KmsEs256Tokens:
    """AWS ES256 token adapter reserved for the M4 KMS implementation."""

    def __init__(self, key_id: str, region: str = "us-east-1") -> None:
        self.key_id = key_id
        self.region = region

    def mint(self, *args: Any, **kwargs: Any) -> str:
        raise NotImplementedError("KMS ES256 signing is implemented in M4")

    def verify(self, token: str) -> dict[str, Any]:
        raise NotImplementedError("KMS ES256 verification is implemented in M4")
