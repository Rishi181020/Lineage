from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LINEAGE_", env_file=".env", extra="ignore"
    )

    mode: Literal["local", "aws"] = "local"
    region: str = "us-east-1"
    model_id: str = ""
    operator_token_path: Path = Path(".lineage/operator-token")
    service_token_path: Path = Path(".lineage/service-token")
    local_secrets_path: Path = Path(".lineage/secrets.yaml")
    runs_table: str = "lineage-runs"
    events_table: str = "lineage-events"
    entities_table: str = "lineage-entities"
    kms_key_id: str = ""
    policy_path: Path = Path("policy/default.yaml")
    local_signing_key: str = Field(
        default="lineage-local-development-key-32b!"
    )

    @model_validator(mode="after")
    def require_aws_identity(self) -> "Settings":
        if self.mode == "aws" and not self.kms_key_id:
            raise ValueError("LINEAGE_KMS_KEY_ID is required in aws mode")
        return self

    @property
    def store_backend(self) -> Literal["memory", "dynamo"]:
        return "dynamo" if self.mode == "aws" else "memory"

    @property
    def secrets_backend(self) -> Literal["file", "sm"]:
        return "sm" if self.mode == "aws" else "file"


@lru_cache
def get_settings() -> Settings:
    return Settings()
