from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx


def _operator_token() -> str:
    path = Path(".lineage/operator-token")
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return os.environ.get("LINEAGE_OPERATOR_TOKEN", "lineage-operator-dev")


def _watch_signal(control: str, run_id: str, token: str, container: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=control, timeout=60) as client:
        while True:
            try:
                resp = client.get(f"/admin/runs/{run_id}/signal", headers=headers)
                if resp.status_code == 200 and resp.json().get("signal") == "stop":
                    subprocess.run(["docker", "kill", container], check=False)
                    return
            except Exception:
                time.sleep(1)


def cmd_run(args: argparse.Namespace) -> int:
    control = args.control
    token = _operator_token()
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(base_url=control, timeout=30) as client:
        created = client.post(
            "/admin/runs",
            headers=headers,
            json={
                "task": args.task,
                "mode": args.mode,
                "mcp_allow": args.mcp_allow.split(",") if args.mcp_allow else [],
                "bindings": [args.bind] if args.bind else [],
            },
        )
        created.raise_for_status()
        data = created.json()

    run_id = data["run_id"]
    container = f"agent-{run_id}"
    env = {
        **os.environ,
        "LINEAGE_RUN_ID": run_id,
        "LINEAGE_HOOK_TOKEN": data["hook_token"],
        "ANTHROPIC_AUTH_TOKEN": data["run_token"],
        **data.get("env", {}),
    }
    if args.model:
        env["ANTHROPIC_MODEL"] = args.model

    docker_cmd = [
        "docker",
        "run",
        "-it",
        "--rm",
        "--name",
        container,
        "--network",
        "lineage_sandbox",
        "--ip",
        data["ip"],
        "--dns",
        "127.0.0.1",
        "--add-host",
        "control:172.30.0.10",
        "--add-host",
        "egress:172.30.0.11",
        "--add-host",
        "modeltap:172.30.0.12",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "512",
        "--memory",
        "2g",
        "-v",
        f"{Path('fixtures/demo-repo').resolve()}:/workspace",
        "-w",
        "/workspace",
    ]
    for key, value in env.items():
        if key.startswith(("LINEAGE_", "ANTHROPIC_", "STAGING_")):
            docker_cmd.extend(["-e", f"{key}={value}"])
    docker_cmd.append(args.image)
    docker_cmd.extend(args.command or ["bash"])

    watcher = threading.Thread(
        target=_watch_signal,
        args=(control, run_id, token, container),
        daemon=True,
    )
    watcher.start()
    print(f"starting {container} on {data['ip']}")
    return subprocess.call(docker_cmd)


def cmd_replay(args: argparse.Namespace) -> int:
    from scripts.replay import main as replay_main

    sys.argv = ["replay", str(args.fixture), "--control", args.control]
    return replay_main()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="lineage")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Create a run and start the agent container")
    run.add_argument("--task", default="")
    run.add_argument("--mode", default="interactive", choices=["interactive", "autonomous"])
    run.add_argument("--mcp-allow", default="errortrack.list_issues,errortrack.get_issue")
    run.add_argument("--bind", default="staging-infra")
    run.add_argument("--control", default="http://127.0.0.1:8001")
    run.add_argument("--image", default="lineage-agent-shell:latest")
    run.add_argument("--model", default=os.environ.get("ANTHROPIC_MODEL", ""))
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=cmd_run)

    replay = sub.add_parser("replay", help="Deterministic hook replay (REPLAY)")
    replay.add_argument("fixture", type=Path)
    replay.add_argument("--control", default="http://127.0.0.1:8001")
    replay.set_defaults(func=cmd_replay)

    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
