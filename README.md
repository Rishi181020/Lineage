# Lineage

A control layer for CLI coding agents that asks **why** an action is happening, not just **where** a request is going.

Primary target: AWS × A10 Hack 2026 — Prompt 2 (Agent Harness). Prompt 1 (identity + revoke) falls out of credential custody.

## What it does

1. **Lineage gate** — high-risk actions need a trusted source (user prompt, manifests, binding hosts). Names that first appeared in MCP/web content are blocked or asked.
2. **Credential custody** — the agent only holds `lgph_…` placeholders. Egress swaps the real secret only inside a binding; anywhere else is a tripwire that kills the run.
3. **Trifecta lock** — when untrusted + private + external are all present, egress goes strict.

## Quick start (local)

Requirements: Docker Desktop, Bash (Git Bash / WSL), [`uv`](https://docs.astral.sh/uv/).

```sh
cp .env.example .env
uv sync
uv run python scripts/seed_secrets.py --mode local
# keep compose defaults: overwrite tokens if you want them stable
make up
curl http://127.0.0.1:8001/health
uv run pytest -q
make e2e
```

Dashboard: <http://127.0.0.1:8001> (operator token default `lineage-operator-dev`).

```sh
# Deterministic L1 demo without the model
uv run python scripts/replay.py fixtures/hook_payloads/demo   # after you capture payloads
# Or create a run via admin API / lineage CLI
uv run lineage run --task "Investigate the open errortrack issues" -- bash
```

## AWS (credits assumed)

```sh
cd infra/cdk
pip install -r requirements.txt
cdk bootstrap aws://$ACCOUNT/us-west-2
cdk deploy
# then on the instance via SSM:
#   scripts/bootstrap_host.sh && scripts/seed_secrets.py --mode aws
```

**You still need to confirm (D16):** Bedrock model access in `us-west-2` and the Claude inference profile ID (`aws bedrock list-inference-profiles --region us-west-2`).

## Honest limits

- L1 matches names. Piecewise assembly can evade it; L2 ("no source → ask") is the backstop.
- Custody covers bearer tokens / API keys in headers. SigV4 from the agent is out of scope (the model tap signs Bedrock itself).
- Hooks are Claude Code's. Other CLI agents get sealing, custody, and the tripwire only.
- Lineage cannot stop misuse of access the trusted user actually asked for.

See `plan (1).md`, `DECISIONS.md`, and `PROGRESS.md`.
