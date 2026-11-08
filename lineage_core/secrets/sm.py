from __future__ import annotations

import base64
from typing import Any

import boto3

from .base import SecretsBackend


class SecretsManagerSecrets(SecretsBackend):
    def __init__(self, region: str = "us-east-1", client: Any | None = None) -> None:
        self.client = client or boto3.client("secretsmanager", region_name=region)

    def get(self, secret_ref: str) -> str:
        response = self.client.get_secret_value(SecretId=secret_ref)
        if "SecretString" in response:
            return str(response["SecretString"])
        return base64.b64decode(response["SecretBinary"]).decode()
