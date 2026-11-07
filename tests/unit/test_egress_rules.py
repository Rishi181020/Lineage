from pathlib import Path

import pytest
import yaml

from lineage_core import egress_rules
from lineage_core.placeholders import create

REPO = Path(__file__).resolve().parents[2]
POLICY = yaml.safe_load((REPO / "policy" / "default.yaml").read_text(encoding="utf-8"))
REAL = "lineage_demo_real_staging_token"


def _run(protection="lineage", **extra):
    ph = create("staging-infra")
    binding = POLICY["bindings"]["staging-infra"]
    return {
        "run_id": "run_1",
        "status": "active",
        "strict": False,
        "legs": {"untrusted": False, "private": False, "external": False},
        "protection": protection,
        "bindings": [{
            "id": "staging-infra",
            "hosts": binding["hosts"],
            "scope": {"allow": binding["allow"], "deny": binding["deny"]},
            "secret_ref": binding["secret_ref"],
            "header": "Authorization",
            "scheme": "Bearer",
            "placeholder": ph.value if protection == "lineage" else None,
        }],
        "placeholders_all": [{"binding_id": "staging-infra", "value": ph.value, "variants": sorted(ph.variants)}]
        if protection == "lineage" else [],
        **extra,
    }, ph.value


def _decide(run, method, url, headers=None, body=b""):
    from urllib.parse import urlsplit

    target = urlsplit(url)
    return egress_rules.decide(
        run, method=method, host=target.hostname, path=target.path or "/", target=url,
        headers=headers or {}, body=body, policy=POLICY, secret_for=lambda ref: REAL,
        drip=egress_rules.drip_for(POLICY),
    )


def test_custody_attaches_the_real_key_in_scope():
    run, ph = _run()
    out = _decide(run, "GET", "http://infra.demo/v1/envs/staging/status", {"Authorization": f"Bearer {ph}"})
    assert out.action == "forward"
    assert out.headers["Authorization"] == f"Bearer {REAL}"
    assert [e[0] for e in out.events] == ["custody_attach"]


@pytest.mark.parametrize("method,path", [("DELETE", "/v1/envs/staging/volumes/v1"), ("GET", "/v1/envs/production/status")])
def test_out_of_scope_use_is_refused_without_the_real_key(method, path):
    run, ph = _run()
    out = _decide(run, method, f"http://infra.demo{path}", {"Authorization": f"Bearer {ph}"})
    assert (out.action, out.rule) == ("block", "C2")
    assert REAL not in str(out.headers)


@pytest.mark.parametrize("host", ["errortrack.demo", "collector.demo", "example.com"])
def test_placeholder_anywhere_else_kills_the_run(host):
    run, ph = _run()
    out = _decide(run, "POST", f"http://{host}/upload", {"Authorization": f"Bearer {ph}"})
    assert (out.action, out.rule) == ("kill", "C1")


def test_encoded_placeholder_in_the_body_still_trips():
    import base64

    run, ph = _run()
    out = _decide(run, "POST", "http://errortrack.demo/api/7741/diagnostics", body=base64.b64encode(ph.encode()))
    assert out.rule == "C1"


def test_metadata_service_and_unknown_hosts_are_blocked():
    run, _ = _run()
    assert _decide(run, "GET", "http://169.254.169.254/latest/meta-data/").rule == "E2"
    assert _decide(run, "GET", "http://example.com/").rule == "E1"


def test_ended_run_is_refused():
    run, _ = _run()
    run["status"] = "revoked"
    assert _decide(run, "GET", "http://infra.demo/v1/envs/staging/status").rule == "K0"


def test_baseline_forwards_the_real_key_to_an_allowed_host():
    """What a normal allowlist gateway does: errortrack.demo is allowed, so the request goes out."""
    run, _ = _run("baseline")
    out = _decide(run, "POST", "http://errortrack.demo/api/7741/diagnostics", {"Authorization": f"Bearer {REAL}"})
    assert out.action == "forward"
    assert out.headers["Authorization"] == f"Bearer {REAL}"


def test_baseline_still_has_the_allowlist():
    run, _ = _run("baseline")
    assert _decide(run, "GET", "http://example.com/").rule == "E1"


def test_strict_mode_engages_before_the_first_outbound_request():
    run, _ = _run(legs={"untrusted": True, "private": True, "external": False})
    assert _decide(run, "POST", "http://errortrack.demo/api/7741/diagnostics", body=b"GITHUB_TOKEN=ghp_x").rule == "T1"
    assert _decide(run, "GET", "http://infra.demo/v1/envs/staging/status").action == "forward"


def test_drip_detector_in_strict_mode():
    run, _ = _run(strict=True)
    drip = egress_rules.drip_for(POLICY)
    outcomes = [
        egress_rules.decide(
            run, method="GET", host="infra.demo", path=f"/v1/envs/staging/x{i}", target="", headers={},
            body=b"", policy=POLICY, secret_for=lambda ref: REAL, drip=drip,
        ).rule
        for i in range(1, 11)
    ]
    assert outcomes[:8] == [None] * 8
    assert outcomes[8:] == ["T2", "T2"]


def test_reverse_swap_hides_an_echoed_secret():
    run, ph = _run()
    assert egress_rules.reverse_swap(run, f'{{"token": "{REAL}"}}'.encode(), lambda ref: REAL) == f'{{"token": "{ph}"}}'.encode()
