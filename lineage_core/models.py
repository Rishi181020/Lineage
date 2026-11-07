from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class RunStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    KILLED = "killed"
    STOPPED = "stopped"
    FINISHED = "finished"


class SourceTier(StrEnum):
    TRUSTED = "trusted"
    CHECKED = "checked"
    UNTRUSTED = "untrusted"


class Decision(StrEnum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"
    KILL = "kill"


class Span(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(validation_alias=AliasChoices("id", "span_id"))
    run_id: str
    source: str
    tier: SourceTier
    text: str = ""
    tool_name: str | None = None
    path: str | None = None
    # False for a "user prompt" nobody can vouch for yet; its names aren't trusted until it is.
    corroborated: bool = True
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EntityRecord(BaseModel):
    entity: str
    best_tier: SourceTier
    first_span_by_tier: dict[SourceTier, str] = Field(default_factory=dict)
    first_seen_ts: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def observe(self, tier: SourceTier, span_id: str) -> None:
        self.first_span_by_tier.setdefault(tier, span_id)
        # A workspace file can't wash an untrusted name: the agent may have written it there.
        # Only a trusted source (the user, the starting manifests, a binding) raises it.
        if tier == SourceTier.CHECKED and self.best_tier == SourceTier.UNTRUSTED:
            return
        if _TIER_RANK[tier] > _TIER_RANK[self.best_tier]:
            self.best_tier = tier


_TIER_RANK = {
    SourceTier.UNTRUSTED: 0,
    SourceTier.CHECKED: 1,
    SourceTier.TRUSTED: 2,
}


class Binding(BaseModel):
    id: str
    env_var: str
    secret_ref: str
    hosts: list[str]
    header: str = "Authorization"
    scheme: str = "Bearer"
    environment: str | None = None
    environments: list[str] = Field(default_factory=list)
    allow: list[dict[str, Any]] = Field(default_factory=list)
    deny: list[dict[str, Any]] = Field(default_factory=list)


class Placeholder(BaseModel):
    binding_id: str
    value: str
    variants: set[str] = Field(default_factory=set)


class Run(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(validation_alias=AliasChoices("id", "run_id"))
    task: str = ""
    mode: str = "interactive"
    status: RunStatus = RunStatus.ACTIVE
    workspace_root: str = "/workspace"
    mcp_allow: list[str] = Field(default_factory=list)
    bindings: list[Binding] = Field(default_factory=list)
    placeholders: list[Placeholder] = Field(default_factory=list)
    ip: str | None = None
    session_id: str | None = None
    hook_token: str = ""
    token_jti: str = ""
    replay: bool = False
    headless: bool = False
    # "lineage", or "baseline": a normal allowlist gateway only, for before/after comparisons.
    # A baseline agent holds the real secrets and its tool calls aren't judged.
    protection: str = "lineage"
    signal: str = "none"
    legs: dict[str, bool] = Field(
        default_factory=lambda: {
            "untrusted": False,
            "private": False,
            "external": False,
        }
    )
    strict: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def run_id(self) -> str:
        return self.id


class Event(BaseModel):
    run_id: str
    type: str
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    seq: int = 0


class Verdict(BaseModel):
    decision: Decision = Decision.ALLOW
    rule_id: str | None = None
    reason: str = ""
    chain: list[Any] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
