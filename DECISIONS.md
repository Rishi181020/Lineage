# DECISIONS.md — Lineage

Decisions made before the build, from the research on Nov 6, 2026. The coding agent appends new decisions as D19, D20 and so on. Each entry says what was decided, why, what was rejected, and when to revisit it.

Status key: **Settled** (don't change without the human) · **Default** (agent may change; log why) · **Open** (human decides)

---

## Product

### D1. Primary prompt is Prompt 2; Prompt 1 is demoed through the same design — Settled
- **Decision:** Build the agent-harness gateway (Prompt 2). Show Prompt 1 (authenticate, allow selected MCP tools, revoke mid-task) through per-run identity and credential custody.
- **Why:** Custody makes revoke complete, because the agent never held a real secret. Prompt 1's best demo beat comes for free, and one demo covers both prompts.
- **Rejected:** a separate Prompt 1 identity broker (less visible drama, a second codebase).

### D2. Judge each action by **why** it happens, not only **where** it goes — Settled
- **Decision:** The core differentiator is provenance: every high-risk action must trace back to a trusted source.
- **Why:** Nearly every 2026 incident went through requests a per-request gateway would allow:
  - Agentjacking used the approved npm registry and an approved Sentry MCP server;
  - CVE-2026-54316 used a pre-approved Hugging Face domain;
  - PocketOS used a valid token on a legitimate host;
  - Comment and Control used the GitHub API.
- **Rejected:** an allow/block gateway alone. Any team can build it, and it misses these attacks.

### D3. Require positive provenance; don't try to detect injections — Settled
- **Decision:** Rules ask "does this action have a trusted source?", not "does this text look like an injection?"
- **Why:** Detection is an arms race. Simon Willison argues guardrails can't reliably stop the "lethal trifecta". A name that came from nowhere trusted fails the check whatever the wording, including Base64-hidden instructions.
- **Rejected:** an LLM classifier for injected text (non-deterministic, easy to paraphrase around, slow).

### D4. Split L1 into L1a (always deny) and L1b (ask when interactive) — Settled
- **Decision:** Running or installing code whose name came from untrusted content is **never approvable** (L1a). Other high-risk actions from untrusted content (network, destructive, persistence) are denied when autonomous and asked when interactive (L1b).
- **Why:** Running code an attacker named has no legitimate case. Sending data somewhere sometimes does. This also gives the demo both a hard block (beat 3) and the "human approved it anyway and the tripwire still caught it" moment (beat 4).

### D5. Credential custody with placeholders that double as tripwires — Settled
- **Decision:** The agent holds placeholders (`lgph_<binding>_<random>`). The egress proxy swaps in the real secret only when host, method, path and environment match the binding. A placeholder seen anywhere else kills the run inline.
- **Why:**
  - A stolen value is worthless.
  - The tripwire can't fire falsely, because nothing legitimate sends a placeholder outside its binding.
  - Revoke is complete.
  - It closes the gap Unit 42 found in AWS AgentCore Harness, where the resolved token was readable from process memory.
- **Scope:** bearer tokens and API keys in headers only. AWS SigV4-signed requests from the agent are out of scope; the model tap signs Bedrock calls itself.
- **Rejected:** redaction only (Webflow ctxcop style: no swap and no tripwire); decoys only (Tracebit style: detection after the fact).

### D6. Positioning: complement A10, don't compete — Settled
- **Decision:** Pitch Lineage as the agent-side layer A10's stack doesn't have.
  - A10 AI Gateway: routing, cost, governance.
  - TrojAI Defend for MCP: server registry, tool tampering.
  - TrojAI Defend: prompt/response firewall.
- **Why:** Their public pages don't describe instruction provenance or keeping credentials out of agents. TLS inspection in the traffic path, which custody depends on, is already A10's core business.

## Agent integration

### D7. Target agent is Claude Code; other agents get egress-only coverage — Settled
- **Why:** Claude Code has documented hooks that see the user prompt, every tool result (including the MCP server name) and every tool call before it runs, plus managed settings that lock them in.
- **Consequence:** Other CLI agents get sealing, custody and the tripwire, but not the L1/L2/L3 rules. Say so in the README.

### D8. Hooks: command hooks, fail closed, managed-only — Settled
- **Decision:**
  - Use `type: "command"` hooks for SessionStart, UserPromptSubmit, PreToolUse and PostToolUse, each with `onFailure: "block"`.
  - Pin Claude Code to **v2.1.295 or later**.
  - Set `allowManagedHooksOnly: true`.
  - The hook script also prints a deny on any error for `pre`.
- **Why:** By default a hook that errors or times out lets the action through; `onFailure: "block"` (v2.1.295+) changes that. SessionStart doesn't support `http` hooks, so command hooks keep one mechanism everywhere. Managed-only stops a poisoned repo from swapping out the hooks.
- **Rejected:** `type: "http"` hooks (not available on SessionStart; fail-closed behavior is easier to own in the script).

### D9. Allow means "no output" — Settled
- **Decision:** When Lineage has no objection, the hook prints nothing, so Claude Code's own permission prompts still apply. Only `ask` and `deny` produce output.
- **Why:** Returning an explicit allow would bypass the user's own permission settings.

### D10. Judge URLs by their host; binding hosts count as trusted — Settled
- **Why:** Without this, every new URL path on a trusted host would trigger "no source" prompts. The operator chose binding hosts at launch, so they are a trusted source.

## AWS and infrastructure

### D11. One EC2 host with Docker Compose, reached through SSM — Default
- **Decision:**
  - Amazon Linux 2023, t3.large, public subnet, **no inbound ports**.
  - Shell and dashboard through SSM Session Manager (port-forward 8001).
  - CDK in Python.
- **Why:** Fastest path that is still clearly on AWS; easy to debug; nothing exposed to the internet.
- **Rejected:** ECS Fargate + ALB + NLB (more moving parts; the proxy needs an NLB for CONNECT); Lambda (long-lived streaming proxy).
- **Revisit if:** the demo needs several agent hosts.

### D12. Seal the agent: internal network, no DNS — Settled
- **Decision:**
  - The agent container lives only on an `internal: true` Docker network (172.30.0.0/24).
  - It runs with `--dns 127.0.0.1` and no resolver; service names come from `--add-host`.
  - Its only peers are control, egress and modeltap.
- **Why:** Unsetting `HTTPS_PROXY` gets a hijacked agent nothing, and DNS tunneling has no channel (see the OpenAI DNS sandbox escape, Sep 2026).
- **Test:** `scripts/dns_leak_test.sh` must pass in M0.

### D13. Model path: Bedrock through the model tap; the agent holds no AWS credentials — Default
- **Decision:**
  - Claude Code runs with `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_BEDROCK_BASE_URL=http://modeltap:8100`, `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1`, and the run token in `ANTHROPIC_AUTH_TOKEN`.
  - The tap verifies the run token, signs with the instance role, and streams the Bedrock event stream back **unchanged**, decoding a copy.
- **Why:** Revoke cuts off the model, and the agent has no cloud credential to steal. Claude Code's gateway docs warn that rewriting bodies or buffering or converting the stream breaks the client.
- **Fallback:** an IAM user limited to `bedrock:InvokeModel*`, with Bedrock as TLS passthrough in egress. Log it here if used, because the agent then holds a model credential.

### D14. IMDSv2 hop limit 2, plus egress rule E2 — Settled
- **Why:** control, egress and modeltap need instance-role credentials from inside containers, so a hop limit of 1 would break them. The agent can't reach the metadata service anyway (no route), and E2 blocks private and link-local destinations through the proxy.

### D15. Storage and identity — Default
- **Decision:**
  - DynamoDB on-demand, 3 tables (runs, events, entities); an in-memory store for all tests.
  - Run tokens are ES256 JWTs signed by a KMS `ECC_NIST_P256` key.
  - Revocation is a status checked on every hook, egress and model request, with a 1-second cache.
- **Why:** Serverless, no ops, visibly AWS-native. KMS signing means no signing key exists on the box.

### D16. Region us-west-2 — Open
- **Why default:** closest to the venue in Santa Clara.
- **Human must confirm:** the region, that Bedrock model access is enabled, and the Claude inference profile ID (`aws bedrock list-inference-profiles`).

## Demo

### D17. Only local stubs in the demo; a registry that can never fetch real code — Settled
- **Decision:**
  - The infrastructure API, error tracker (`errortrack` MCP), attacker collector and npm registry are all local stubs.
  - The registry returns 404 for everything.
  - Bedrock is the only real external service.
- **Why:** If a rule ever misses, nothing real can be harmed or fetched on stage.

### D18. Demo settings: interactive mode, untrusted-content labeling off, replay fallback — Settled
- **Decision:**
  - Run the demo in interactive mode.
  - Set `label_untrusted: false` in `policy/demo.yaml`. Labeling untrusted content makes the model less likely to attempt the injected step, and the demo needs the attempt.
  - Keep `lineage replay` as a deterministic fallback, always labeled **REPLAY** on the dashboard.
- **Why:** The biggest demo risk is the model refusing the injected step, which would leave nothing to block. Be honest on stage if replay is used.

---

## Open questions for the human
- Is code written before the event allowed? (Ask the organizers before building anything beyond spikes.)
- Region and Bedrock model ID (D16).
- Team roles: core rules + hooks · egress + custody · model tap + AWS · dashboard + demo script.

---

## Build-time decisions

### D19. Region default us-west-2 until human confirms — Default
- **Decision:** Use `us-west-2` for CDK, compose defaults, and Bedrock endpoint construction.
- **Why:** Closest to Santa Clara (D16); user confirmed Amazon credits are available.
- **Revisit when:** Human provides the Bedrock inference profile ID and confirms model access.

### D20. Local demo tokens shared via compose env — Default
- **Decision:** Default `LINEAGE_OPERATOR_TOKEN=lineage-operator-dev` and `LINEAGE_SERVICE_TOKEN=lineage-service-dev` in compose so control and egress agree without reading seeded files.
- **Why:** Avoids token skew between services when `.lineage/` is freshly seeded with random values.
- **Revisit when:** Moving to AWS Secrets Manager in `LINEAGE_MODE=aws`.

### D21. Control serves 8000/8001/8002 in one process — Settled
- **Decision:** `python -m control.main` runs three uvicorn servers in one asyncio process sharing `ControlState`.
- **Why:** Three separate uvicorn processes (original M0 scaffold) did not share memory, so hooks/admin/internal disagreed about runs.
- **Rejected:** Redis/shared DB just for local mode.

### D22. M0 agent base image uses `python:3.12-slim` — Default
- **Decision:** Agent image FROM `python:3.12-slim` instead of `debian:bookworm-slim`.
- **Why:** Docker Hub pulls for debian timed out on the build host; python slim was already cached and enough for sealing tests.
- **Revisit when:** M2 pins Claude Code / Node — may need a Node-capable base.
