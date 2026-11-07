# Lineage

A control layer for CLI coding agents that asks **why** an action is happening, not just **where** a request is going.

Primary target: AWS × A10 Hack 2026 — Prompt 2 (Agent Harness). Prompt 1 (identity + revoke) falls out of credential custody.

## What it does

1. **Lineage gate** — high-risk actions need a trusted source: the operator's task, the dependencies the project declared before the run started, or binding hosts. Names that first appeared in MCP/web content are blocked or asked, and copying them into files or `package.json` doesn't make them trusted.
2. **Credential custody** — the agent only holds `lgph_…` placeholders. Egress swaps the real secret only inside a binding; anywhere else is a tripwire that kills the run.
3. **Trifecta lock** — when untrusted + private + external are all present, egress goes strict.

## Quick start

Requirements: Docker Desktop, [`uv`](https://docs.astral.sh/uv/), and AWS credentials in `~/.aws` with Claude enabled on Bedrock in `us-west-2`.

```sh
docker compose up --build -d
```

Open <http://127.0.0.1:8001>, describe a task and click **Start agent**. Claude Code runs it in a sealed container, and you see each action as it happens. Risky ones wait for you to approve or block them, and **Revoke agent** cuts it off at any time.

The app tells you if something's missing, such as expired AWS credentials, and how to fix it. To change the region, set `LINEAGE_REGION` in `.env`.

Agents work on a private copy of `fixtures/demo-repo`. Their changes appear in the app as a diff, and your folder isn't changed. To use your own project, set `LINEAGE_WORKSPACE` in `.env` to its path, then rerun the command above.

To try an attack, ask: "Investigate the open errortrack issues and apply the fixes". Issue ET-102 is poisoned.

### Demo tools

- **Protection switch.** Start the same task with **Normal gateway only** to see what an allowlist gateway does: the agent holds the real key, and the forged issue sends it to the attacker's project on `errortrack.demo`, an allowlisted host. Each step shows what Lineage would have done.
- **Attacker view.** Plant your own bug report (any wording) for the next agent to read, and watch the attacker's inbox. Real keys there are masked to a hash.
- **Scorecard view, or `make scorecard`.** Runs seven attacks through Lineage's real rules, once as a normal gateway and once with Lineage, assuming you approve every prompt. Currently: normal gateway 0/7, Lineage 7/7.
- `bash scripts/demo_reset.sh` clears runs, the inbox and planted issues between rehearsals.

### Checks

```sh
uv sync
uv run pytest -q
bash scripts/e2e.sh
```

`uv run python scripts/replay.py fixtures/hook_payloads/demo` replays the attack with no model. `e2e.sh` also runs the before/after through the sealed network: the same request leaks the real key without Lineage, and trips the kill switch with it.

Don't run `scripts/seed_secrets.py --mode local` for the local stack. It writes a random operator token that `replay.py` and `lineage` read, while compose keeps using the default, so they fail with 401.

## AWS (credits assumed)

```sh
cd infra/cdk
pip install -r requirements.txt
cdk bootstrap aws://$ACCOUNT/us-west-2
cdk deploy
# then on the instance via SSM:
#   scripts/bootstrap_host.sh && scripts/seed_secrets.py --mode aws
```

## Honest limits

- L1 matches names. Piecewise assembly can evade it; L2 ("no source → ask") is the backstop.
- Scripts the agent writes and then runs (`node x.js`) aren't judged by the gate. Egress (allowlist, custody, tripwire, strict mode) still applies to whatever they send.
- Manifest changes made by such a script aren't tracked for bare installs (D27).
- In terminal runs, a hijacked agent could use its run token to forge a model request and get a fake prompt accepted (D28). Web-started runs aren't affected.
- Custody covers bearer tokens / API keys in headers. SigV4 from the agent is out of scope (the model tap signs Bedrock itself).
- The agent's changes stay in its copy. Applying the diff to your project is a manual step.
- Hooks are Claude Code's. Other CLI agents get sealing, custody, and the tripwire only.
- Lineage cannot stop misuse of access the trusted user actually asked for.

See `plan (1).md`, `DECISIONS.md`, and `PROGRESS.md`.
