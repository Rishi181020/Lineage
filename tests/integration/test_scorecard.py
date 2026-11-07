"""The scorecard must stay honest: a normal gateway lets every attack through, and Lineage
stops each one for the expected reason even when the operator approves every prompt."""

from control.scorecard import run_all

EXPECTED = {
    "agentjacking": "L1a",
    "saas-exfil": "C1",
    "valid-key-misuse": "C2",
    "pipe-to-shell": "L1a",
    "manifest-laundering": "L1a",
    "fake-prompt": "L1a",
    "env-leak": "T1",
}


def test_scorecard(monkeypatch):
    rows = {row["id"]: row for row in run_all()}
    assert set(rows) == set(EXPECTED)
    for scenario_id, rule in EXPECTED.items():
        assert rows[scenario_id]["baseline"]["stopped"] is False, scenario_id
        assert rows[scenario_id]["lineage"]["stopped"] is True, scenario_id
        assert rows[scenario_id]["lineage"]["rule"] == rule, scenario_id
    assert "url:http://registry.demo/acme-diag/setup" in rows["pipe-to-shell"]["lineage"]["reason"]
