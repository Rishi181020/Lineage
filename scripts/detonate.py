#!/usr/bin/env python3
"""Set off npm package samples inside Lineage's sandbox and report what Lineage saw.

    python3 scripts/detonate.py SAMPLE [SAMPLE ...] [--out DIR]

A SAMPLE is a .tgz, a .zip (password "infected", the convention of malware datasets such
as DataDog/malicious-software-packages-dataset) or a package directory.

SAFETY. Real malware. Run this only on a disposable Linux machine (the demo EC2 host),
never on a laptop, with the Lineage stack up (`docker compose up -d`). It refuses to run
anywhere else, or if the sandbox network can reach the internet. Each sample runs in its
own container: sandbox network only (egress allows only the demo stubs), no DNS,
non-root, all capabilities dropped, no-new-privileges, memory and process limits.
Never extract samples on the host; this script mounts them read-only into the container.

Each sample is a real Lineage run, so it also shows up in the dashboard's Agents view.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTROL = os.environ.get("LINEAGE_CONTROL", "http://127.0.0.1:8001")
OPERATOR = os.environ.get("LINEAGE_OPERATOR_TOKEN", "lineage-operator-dev")
SERVICE = os.environ.get("LINEAGE_SERVICE_TOKEN", "lineage-service-dev")
IMAGE = os.environ.get("LINEAGE_AGENT_IMAGE", "lineage-agent-shell:latest")
NETWORK = os.environ.get("LINEAGE_SANDBOX_NETWORK", "lineage_sandbox")
# The run's stand-in key, planted under the names real npm malware hunts for.
BAIT_NAMES = ("STAGING_TOKEN", "NPM_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY")


def api(path: str, body: dict | None = None, service: bool = False):
    headers = {"Content-Type": "application/json"}
    headers.update({"X-Lineage-Service-Token": SERVICE} if service else {"Authorization": f"Bearer {OPERATOR}"})
    request = urllib.request.Request(
        CONTROL + path, data=json.dumps(body).encode() if body is not None else None,
        headers=headers, method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=15) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else None


def preflight(allow_any_host: bool) -> None:
    if not sys.platform.startswith("linux") and not allow_any_host:
        sys.exit("Refusing: run this on a disposable Linux machine, not a laptop (see the docstring).")
    try:
        net = json.loads(subprocess.run(["docker", "network", "inspect", NETWORK], capture_output=True, text=True, check=True).stdout)[0]
    except (subprocess.CalledProcessError, IndexError, ValueError):
        sys.exit(f"Refusing: Docker network {NETWORK} not found. Start Lineage first: docker compose up -d")
    if not net.get("Internal"):
        sys.exit(f"Refusing: {NETWORK} is not an internal network, so samples could reach the internet.")
    try:
        api("/admin/runs")
    except OSError as exc:
        sys.exit(f"Refusing: Lineage control isn't reachable at {CONTROL}: {exc}")


def detonate(sample: Path, timeout: int, step_timeout: int) -> dict:
    run = api("/admin/runs", {
        "task": f"Detonate npm sample {sample.name}", "mode": "interactive",
        "bindings": ["staging-infra"], "protection": "lineage",
    })
    run_id, ip = run["run_id"], run["ip"]
    bait = run["env"]["STAGING_TOKEN"]
    name = f"agent-{run_id}"  # the name control kills on a tripwire
    cmd = [
        "docker", "run", "--name", name,
        "--network", NETWORK, "--ip", ip, "--dns", "127.0.0.1",
        "--add-host", "control:172.30.0.10", "--add-host", "egress:172.30.0.11",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
        "-e", f"LINEAGE_RUN_ID={run_id}", "-e", f"LINEAGE_HOOK_TOKEN={run['hook_token']}",
        "-e", f"DETONATE_STEP_TIMEOUT={step_timeout}", "-e", f"DETONATE_BAIT={bait}",
        *[arg for key in BAIT_NAMES for arg in ("-e", f"{key}={bait}")],
        "-v", f"{sample.resolve()}:/sample/{sample.name}:ro",
        "-v", f"{REPO / 'scripts' / 'detonate_inside.py'}:/opt/detonate_inside.py:ro",
        IMAGE, "python3", "/opt/detonate_inside.py", f"/sample/{sample.name}",
    ]
    started = time.time()
    code, out = -1, ""
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        code, out = done.returncode, done.stdout + done.stderr
    except subprocess.TimeoutExpired:
        out = "timed out"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    # Ends the run if it's still active and frees its sandbox IP.
    api(f"/internal/runs/{run_id}/exited", {"code": code, "logs": out[-4000:]}, service=True)

    summary = {}
    for line in reversed(out.strip().splitlines()):
        try:
            summary = json.loads(line)
            break
        except ValueError:
            continue
    events = api(f"/admin/runs/{run_id}/events")
    of = lambda kind: [e["payload"] for e in events if e["type"] == kind]  # noqa: E731
    verdicts = of("pkg_verdict")
    return {
        "sample": sample.name,
        "run_id": run_id,
        "package": summary.get("package"),
        "version": summary.get("version"),
        "install_scripts": summary.get("scripts", {}),
        "steps": summary.get("steps", []),
        "error": summary.get("error") or (None if summary else out[-600:]),
        "verdict": verdicts[-1]["verdict"] if verdicts else "clean",
        "behaviors": [{k: b[k] for k in ("package", "phase", "op", "target")} for b in of("pkg_behavior")],
        "network_allowed": [f"{p['method']} {p['host']}{p['path']}" for p in of("egress")],
        "network_blocked": [f"{p['host']}{p.get('path', '')} ({p['rule']})" for p in of("egress_block")],
        "tripwire": [f"{p['method']} {p['host']}{p['path']}" for p in of("tripwire")],
        "run_status": api(f"/admin/runs/{run_id}")["status"],
        "seconds": round(time.time() - started, 1),
    }


def markdown(results: list[dict]) -> str:
    lines = [
        "# Lineage detonation report", "",
        f"{len(results)} samples. Each ran in a sealed Lineage sandbox holding only a stand-in key.", "",
        "| Sample | Package | Install scripts | Verdict | Behaviors | Network blocked | Tripwire |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append("| {} | {} | {} | **{}** | {} | {} | {} |".format(
            r["sample"], f"{r['package']}@{r['version']}" if r["package"] else "?",
            ", ".join(r["install_scripts"]) or "none", r["verdict"], len(r["behaviors"]),
            len(r["network_blocked"]), "fired, run killed" if r["tripwire"] else "no"))
    for r in results:
        lines += ["", f"## {r['sample']} ({r['run_id']})", ""]
        if r["error"]:
            lines.append(f"- Error: `{str(r['error'])[:300]}`")
        lines += [f"- {b['phase']}: {b['op']} `{b['target']}`" for b in r["behaviors"]] or ["- No behavior reported."]
        lines += [f"- Network blocked: `{n}`" for n in r["network_blocked"]]
        lines += [f"- Network allowed: `{n}`" for n in r["network_allowed"]]
        lines += [f"- Tripwire: `{t}`" for t in r["tripwire"]]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("samples", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=REPO / ".lineage" / "detonations" / time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--timeout", type=int, default=180, help="seconds per sample, overall")
    parser.add_argument("--step-timeout", type=int, default=45, help="seconds per install script")
    parser.add_argument("--allow-any-host", action="store_true", help="only for the harmless built-in demo sample")
    args = parser.parse_args()
    preflight(args.allow_any_host)
    missing = [s for s in args.samples if not s.exists()]
    if missing:
        sys.exit(f"Not found: {', '.join(map(str, missing))}")

    results = []
    for sample in args.samples:
        print(f"-> {sample.name}", flush=True)
        result = detonate(sample, args.timeout, args.step_timeout)
        results.append(result)
        print(f"   {result['verdict']}: {len(result['behaviors'])} behaviors, "
              f"{len(result['network_blocked'])} blocked, tripwire {'fired' if result['tripwire'] else 'no'}", flush=True)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(results, indent=2))
    (args.out / "report.md").write_text(markdown(results))
    print(f"Report: {args.out / 'report.md'}")


if __name__ == "__main__":
    main()
