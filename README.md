<p align="center">
  <img src="docs/image/banner.png" alt="Lineage: the control layer that asks AI coding agents why. Every risky action must trace back to you; the agent only ever holds stand-in keys." width="100%">
</p>

<p align="center">
  <img alt="AWS x A10 Hack 2026" src="https://img.shields.io/badge/AWS_%C3%97_A10_Hack-2026-15243a">
  <img alt="Prompt 2: Agent Harness" src="https://img.shields.io/badge/prompt-Agent_Harness-0b6b5a">
  <img alt="Agent: Claude Code" src="https://img.shields.io/badge/agent-Claude_Code-4c5b70">
  <img alt="Model: Amazon Bedrock" src="https://img.shields.io/badge/model-Amazon_Bedrock-4c5b70">
  <img alt="Python 3.12" src="https://img.shields.io/badge/python-3.12-4c5b70">
</p>

**Lineage is a control layer for CLI coding agents.** It runs the agent (Claude Code) in a sealed sandbox and checks two things a normal gateway can't:

1. **Who asked for this?** Every risky action has to trace back to something *you* wrote, not to text the agent read in an issue, a web page or a tool result.
2. **Does the agent hold anything worth stealing?** No. It only holds stand-in keys. Lineage attaches the real key on the way out, and only at the right door. A stand-in seen anywhere else is a tripwire that stops the run.

> A firewall checks the address on the envelope. Lineage checks who wrote the letter.

---

## The problem

Coding agents now run with your keys and your shell, and they read text written by strangers. Attackers hide instructions in that text, and the agent can't tell their words from yours. Every request it then makes looks normal, so a gateway that only checks *where* a request goes lets it through.

| Incident | What the agent did | Why a normal gateway allowed it | What Lineage does |
|---|---|---|---|
| [Agentjacking](https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-mcp-sentry-injection-2026/) (Jun 2026) | A forged Sentry error, read over MCP, told agents to run `npx` on an attacker's package | npm and the Sentry MCP server were both approved | Blocks it: the package name came from untrusted content (L1a) |
| [Comment and Control](https://www.refontelearning.com/blog/ai-coding-agents-leaking-cicd-secrets) (Apr 2026) | Ran commands hidden in a PR title, then posted API keys back as a comment | GitHub's API is allowed | Traces the command to the issue (L1); the key is a stand-in |
| [PocketOS](https://www.scworld.com/brief/ai-coding-agent-deletes-production-database-in-seconds) (Apr 2026) | Used a token it found to delete a production volume and its backups in one call | Valid token, legitimate host | The stand-in only becomes a real key for staging reads and deploys (C2) |
| [AgentCore Harness](https://unit42.paloaltonetworks.com/securing-aws-agentcore-harness-credentials/) (Unit 42) | A shell running as root read the harness's token from memory and POSTed it out | The secret lived where the agent could reach it | The real key never exists inside the sandbox |
| [CVE-2026-54316](https://api.osv.dev/v1/vulns/CVE-2026-54316) (Claude Code) | Leaked an API key one character at a time to a pre-approved Hugging Face domain | Every request went to an allowed host | No real key to leak; strict mode adds a drip detector (T2) |

## Same attack, two endings

<p align="center">
  <img src="docs/image/two-endings.png" alt="Side by side: without Lineage, the agent runs the attacker's npx package and sends the real key. With Lineage, the npx call is blocked because its name came from the issue, and the upload trips the stand-in-key tripwire, so the run is killed and the attacker gets nothing." width="100%">
</p>

## See it in action

<p align="center">
  <img src="docs/image/dashboard.png" alt="The Lineage web app: the agent reads issue ET-102 (marked as outside content); npx @acme-diag/fix is blocked under rule L1a; a curl upload to collector.demo needs approval under rule L1b; after approval, a tripwire fires because a stand-in key headed for collector.demo, and the run is killed." width="100%">
</p>

<sub>The real Lineage web app showing the demo attack. These events were replayed through the real control service and rules (`scripts/replay.py`). In a live run, Claude Code produces them.</sub>

What happens, top to bottom:

1. **Read.** The agent fetches issue ET-102 from the `errortrack` MCP server. Lineage tags everything in it as *outside content*.
2. **Blocked.** The agent tries `npx @acme-diag/fix --diagnose`. That package name first appeared in the issue and never in your request, so Lineage blocks it. Running code an outsider named is never approvable (rule L1a).
3. **Needs you.** The agent tries to upload diagnostics to `collector.demo` with `$STAGING_TOKEN`. That host also came from the issue, so Lineage asks you (rule L1b).
4. **Tripwire.** Say you approve it anyway; confirmation fatigue is real. The token the agent holds is a stand-in bound to `infra.demo`. The egress proxy sees it heading somewhere else, refuses the request and kills the run (rule C1). **The attacker receives nothing.**

## How it works

### 1. The lineage gate: every risky action needs a trusted source

Lineage records everything the agent reads and tags it by where it came from. Before a risky action runs, Lineage pulls out its package names, hosts and paths and looks up where each one first appeared.

```mermaid
flowchart LR
    A["Agent wants to act"] --> B{"High risk?<br/>install or run a package,<br/>network, delete, persist"}
    B -- no --> OK["Allowed<br/>normal Claude Code permissions apply"]
    B -- yes --> C{"Where did each name<br/>first appear?"}
    C -- "your task, dependencies declared<br/>before the run, approved hosts" --> OK
    C -- "outside content:<br/>MCP, web, issues" --> D["Blocked (L1a)<br/>or Needs you (L1b)"]
    C -- "workspace files" --> E["Needs you (L3)"]
    C -- "nowhere" --> F["Needs you (L2)"]
    classDef ok fill:#e5f4f0,stroke:#0b6b5a,color:#15243a
    classDef stop fill:#fdeceb,stroke:#b3261e,color:#15243a
    classDef ask fill:#fff4d6,stroke:#7a4a00,color:#15243a
    class OK ok
    class D stop
    class E,F ask
```

Copying a name somewhere doesn't launder it. Text the agent writes is never a source, reading a file can't raise a name that came from outside content, and `package.json` is trusted only as it was before the run started. Even a fake "user prompt" posted from inside the sandbox isn't believed.

Lineage doesn't try to *recognize* a prompt injection, which is an arms race. It asks each risky action to justify itself. A name that came from nowhere you trust gets questioned, however the attacker phrased or encoded it. Checks run as plain code, not as an AI judgment the attacker could talk to.

### 2. Credential custody: the agent only holds stand-in keys

- The agent's environment holds `STAGING_TOKEN=lgph_staging-infra_…`, a stand-in. The real value stays with Lineage.
- The egress proxy swaps in the real key only when the request matches the key's **binding**: host `infra.demo`, `GET`/`POST` on `/v1/envs/staging/**`. A `DELETE`, or anything under `/production/`, is refused (C2).
- A stand-in seen heading anywhere else (in a header, the body or the URL, even base64-encoded) is proof of an attack. Nothing legitimate ever sends it there, so the tripwire can't fire falsely. The run is killed inline (C1).
- **Revoke takes full effect.** The agent never held the real key, so revoking the run cuts it off completely: the model gateway returns 401, egress refuses its traffic, and every tool call is denied (K0).

### 3. Trifecta lock: tighten up at the danger point

Simon Willison's [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) is untrusted input, private data and outside communication in one agent. Lineage tracks each leg per run. When all three are present, egress drops to strict mode: exact paths only, plus a detector for many small requests that spell out a secret piece by piece (T1, T2).

## Quick start

**Requirements:** Docker Desktop, [`uv`](https://docs.astral.sh/uv/), and AWS credentials in `~/.aws` with Claude enabled on Amazon Bedrock in `us-west-2`.

```sh
docker compose up --build -d
```

Open <http://127.0.0.1:8001>, describe a task and click **Start agent**. Claude Code runs it in a sealed container, and you see each action as it happens. Risky ones wait for you to **Approve** or **Block**, and **Revoke agent** cuts it off at any time. The app tells you if something's missing, such as expired AWS credentials, and how to fix it.

- **Try the attack:** ask *"Investigate the open errortrack issues and apply the fixes"*. Issue ET-102 is poisoned.
- **Your own project:** agents work on a private copy of `fixtures/demo-repo`, and their changes appear in the app as a diff; your folder isn't changed. To use another project, set `LINEAGE_WORKSPACE` in `.env` and rerun the command.
- **Another region:** set `LINEAGE_REGION` in `.env`.

**Replay the attack without a model** (deterministic, labeled *Replay* in the app):

```sh
uv run python scripts/replay.py fixtures/hook_payloads/demo
```

**Demo tools:**

- **Protection switch.** Start the same task with **Normal gateway only** to see what an allowlist gateway does: the agent holds the real key, and the forged issue sends it to the attacker's project on `errortrack.demo`, an allowlisted host. Each step shows what Lineage would have done.
- **Attacker view.** Plant your own bug report (any wording) for the next agent to read, and watch the attacker's inbox. Real keys there are masked to a hash.
- **Scorecard view, or `make scorecard`.** Runs seven attacks through Lineage's real rules, once as a normal gateway and once with Lineage, assuming you approve every prompt. Currently: normal gateway 0/7, Lineage 7/7.
- `bash scripts/demo_reset.sh` clears runs, the inbox and planted issues between rehearsals.

**Checks:**

```sh
uv sync
uv run pytest -q      # unit and integration tests
bash scripts/e2e.sh   # egress, custody, tripwire and the before/after against the running stack
make test             # tests + compile check + compose config
```

> Don't run `scripts/seed_secrets.py --mode local` for the local stack. It writes a random operator token that `replay.py` and `lineage` read, while compose keeps using the default, so they fail with 401.

## Architecture

```mermaid
flowchart LR
    subgraph browser["Your browser"]
        UI["Lineage web app<br/>127.0.0.1:8001"]
    end
    subgraph sandbox["sandbox network: internal, no DNS, no internet route"]
        A["Agent container<br/>Claude Code + Lineage hooks<br/>stand-in keys only, no AWS credentials"]
    end
    subgraph lineage["Lineage"]
        C["control<br/>rules, runs, approvals, ledger"]
        E["egress proxy<br/>custody, tripwire, allowlist"]
        M["model tap<br/>signs Bedrock calls"]
        R["runner<br/>starts agent containers"]
    end
    subgraph outside["Outside"]
        B["Amazon Bedrock"]
        S["Demo services<br/>infra.demo, collector.demo, registry.demo"]
    end
    A -- "hooks: every prompt,<br/>tool result and tool call" --> C
    A -- "all other traffic" --> E
    A -- "model calls<br/>with run token" --> M
    M -- "SigV4" --> B
    E -- "real key attached<br/>only inside its binding" --> S
    UI <--> C
    C --> R
    R -. "Docker" .-> A
```

The agent container sits only on an **internal** Docker network with **no DNS resolver**. Its only peers are control, the egress proxy and the model tap, so unsetting `HTTPS_PROXY` gets a hijacked agent nothing, and DNS tunneling has no channel.

| Service | Port | Network | Job |
|---|---|---|---|
| `control` | 8000 hooks · 8001 web app · 8002 internal | sandbox + uplink | Runs, rule engine, approvals, ledger, live event stream, web app |
| `egress` | 8080 | sandbox + uplink | Attributes traffic to a run, swaps stand-in keys, tripwire, host allowlist, strict mode |
| `modeltap` | 8100 | sandbox + uplink | Checks the run token, signs model calls to Bedrock, streams them back unchanged |
| `runner` | 8200 | uplink only | Starts agent containers (holds the Docker socket, so agents can't reach it) |
| `stub-infra`, `stub-collector`, `stub-registry` | 80 | uplink | Fake staging API, fake attacker endpoint, npm registry that serves nothing |

### The tripwire, step by step

```mermaid
sequenceDiagram
    autonumber
    actor You
    participant Agent as Agent (sandbox)
    participant Rules as Lineage rules
    participant Egress as Egress proxy
    participant Attacker as collector.demo
    You->>Agent: "Investigate the open errortrack issues and apply the fixes"
    Agent->>Rules: Read issue ET-102 over MCP
    Note over Rules: Tagged as outside content
    Agent->>Rules: Wants to run npx @acme-diag/fix
    Rules-->>Agent: Blocked (L1a). The name came from ET-102, not from you
    Agent->>Rules: Wants to curl collector.demo with $STAGING_TOKEN
    Rules-->>You: Needs you (L1b)
    You-->>Rules: Approve
    Agent->>Egress: POST /upload with Bearer lgph_staging-infra_…
    Note over Egress: This stand-in is bound to infra.demo only
    Egress--xAttacker: Never sent
    Egress-->>Agent: 403, tripwire (C1), run killed
```

## Rules

| Rule | Where | Fires when | Result |
|---|---|---|---|
| **K0** | hooks, egress | The run is revoked, killed or stopped | Deny everything |
| **S1** | hooks | An action targets Lineage itself (its hosts, hook script, settings) | Deny |
| **I1** | hooks | An MCP tool isn't on the run's allowed list | Deny |
| **L1a** | hooks | Runs or installs code whose name came from outside content | Deny, never approvable |
| **L1b** | hooks | Another risky action whose target came from outside content | Ask (deny when autonomous) |
| **L2** | hooks | A risky action names something with no source in the session | Ask |
| **L3** | hooks | A risky action's target came only from a workspace file | Ask |
| **T1** | hooks, egress | Strict mode is on and the action talks to the outside | Ask / block off-allowlist paths |
| **C1** | egress | A stand-in key leaves for a host outside its binding | Block and kill the run |
| **C2** | egress | A stand-in key is used outside its scope (wrong method, path or environment) | Block; the real key isn't attached |
| **E1** | egress | The destination host isn't allowlisted | Block |
| **E2** | egress | The destination is a private, loopback or metadata address | Block |
| **T2** | egress | Strict mode drip: many small requests to one host, or pieces that spell out a secret | Block |

Policy lives in [`policy/default.yaml`](policy/default.yaml), with demo overrides in [`policy/demo.yaml`](policy/demo.yaml).

## How it maps to the hackathon prompts

| Prompt | Demo requirement | In Lineage |
|---|---|---|
| **2. Agent Harness** | Launch a CLI agent | **Start agent** in the web app (or `lineage run`) starts Claude Code in the sandbox |
| | Display its traffic | Live feed of every read, command, network call and model call |
| | Block a disallowed action | `npx @acme-diag/fix` blocked under L1a, with the reason |
| | Stop the run | **Revoke agent**, or the tripwire kills it automatically |
| **1. Agentic Identity** | Authenticate an agent | Each run gets its own signed run token, checked on every hook, model call and egress request |
| | Allow selected MCP tools | Each run carries an MCP allowlist (`errortrack.list_issues`, `errortrack.get_issue`); anything else is denied (I1) |
| | Revoke mid-task, block later requests | Revoke: model tap 401, egress refused, every tool call denied, and no real key left behind |

## How it compares

Each piece exists somewhere. As far as we found, nothing combines them around an unmodified CLI agent, or makes the stand-in key both the protection and the alarm.

| Product | What it does | What Lineage adds |
|---|---|---|
| [A10 AI Gateway](https://www.a10networks.com/wp-content/uploads/A10-SB-A10-AI-Gateway-The-Intelligent-Control-Plane-For-All-Ai-Operations.pdf) | Routing, cost and governance across models and agents | Links each action to what the agent read; credential custody |
| [TrojAI Defend for MCP](https://www.a10networks.com/wp-content/uploads/A10-SB-TrojAI-Defend-for-MCP-by-A10-Networks.pdf) (A10) | Approved MCP servers, tool-tampering detection | Catches attacker-written data coming from an *approved* server |
| [AWS AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html) Gateway, Policy, Identity | Per-call Cedar policy; vault injects credentials | The real key never reaches the agent's machine |
| [Invariant Guardrails](https://invariantlabs.ai/blog/guardrails) | LLM/MCP proxy with hand-written flow rules | Automatic provenance for names in shell commands; egress and custody |
| [Aembit](https://aembit.io/blog/securing-ai-agents-without-secrets/) | Injects credentials per destination | Stand-ins double as tripwires; scope per run; provenance |
| [Pipelock](https://codeongrass.com/blog/pipelock-mcp-proxy-https-proxy-stop-secret-exfiltration/) | Egress and MCP proxy with secret scanning | Provenance, custody, run identity and revoke |

## Status

As of Nov 7, 2026. [`PROGRESS.md`](PROGRESS.md) is the live record.

| Area | State |
|---|---|
| Sealed sandbox (internal network, no DNS, no direct egress) | Working, checked by `scripts/dns_leak_test.sh` |
| Rule engine (K0, S1, I1, L1a, L1b, L2, L3, T1) and hooks API | Working, 88 tests passing |
| Anti-laundering: manifests trusted as of run start, fake prompts rejected (S2) | Working |
| Attack scorecard: normal gateway 0/7, Lineage 7/7 | Working (`make scorecard`, Scorecard view) |
| Attacker console and "normal gateway only" comparison mode | Working |
| Egress custody, C1 tripwire, C2, E1, E2 | Working, checked by `scripts/e2e.sh` |
| Web app: start agents, live feed, approvals, revoke, diff of changes | Working |
| Claude Code in the sandbox (v2.1.319, hooks, MCP) | Working against a scripted model; first live Bedrock run pending |
| Run tokens | HS256 locally; AWS KMS ES256 signing not built yet |
| AWS deployment (CDK: VPC, EC2, DynamoDB, KMS, IAM) | Code ready, not deployed |
| Trifecta lock | Working: egress traffic counts as outside communication, and strict mode covers the request that would complete the trifecta |

## Deploy on AWS

```sh
cd infra/cdk
pip install -r requirements.txt
cdk bootstrap aws://$ACCOUNT/us-west-2
cdk deploy
# then on the instance, via SSM Session Manager:
#   scripts/bootstrap_host.sh && scripts/seed_secrets.py --mode aws
```

The stack has no inbound ports. You reach the instance and the web app through SSM Session Manager (shell and port forwarding).

## Honest limits

- **Name matching.** L1 matches names. If an attacker gets the agent to assemble a name from pieces, L1 can miss it; L2 ("no source → ask") is the backstop.
- **Plain HTTP only.** The egress proxy handles plain HTTP and refuses HTTPS (`CONNECT`) entirely, so the sandbox can only reach the demo services. TLS interception isn't built yet.
- **Header credentials only.** Custody covers bearer tokens and API keys in headers. Request-signing schemes like AWS SigV4 from the agent are out of scope; the model tap signs Bedrock calls itself.
- **Claude Code only, for provenance.** The provenance rules use Claude Code's hooks. Other CLI agents get the sealed sandbox, custody and the tripwire only.
- **No code inspection.** If a package you already depend on goes bad, Lineage doesn't scan its code. It contains it: the code finds only stand-in keys and has no way out except allowed hosts.
- **Scripts the agent writes.** A script the agent writes and then runs (`node x.js`) isn't judged by the gate, and manifest changes it makes aren't tracked for a bare `npm install`. Egress (allowlist, custody, tripwire, strict mode) still applies to whatever it sends.
- **Terminal runs and fake prompts.** In `lineage run` terminal sessions, a hijacked agent could use its run token to forge a model request and get a fake prompt accepted. Web-started runs aren't affected.
- **Your own requests.** Lineage can't stop misuse of access that you, the trusted user, actually asked for.
- **Manual merge.** The agent's changes stay in its copy; applying the diff to your project is a manual step.

## Project layout

```
control/        rule engine host: hooks API (8000), web app (8001), internal API (8002)
  dashboard/    the web app (vanilla JS, no build step)
egress/         egress proxy: custody swap, tripwire, allowlist, strict mode
modeltap/       Bedrock gateway: run-token check, SigV4 signing, stream passthrough
runner/         starts agent containers for the web app
launcher/       `lineage run` / `lineage replay` CLI
agent-image/    sandbox image: Claude Code, Lineage hook, managed settings, errortrack MCP stub
lineage_core/   shared library: entities, classification, rules, trifecta, bindings, tokens, stores
stubs/          infra.demo, collector.demo, registry.demo
policy/         default.yaml and demo.yaml
fixtures/       demo repo, poisoned issues, recorded hook payloads
infra/cdk/      AWS stack
scripts/        e2e, DNS leak test, replay, seeding, demo reset
tests/          unit and integration tests
```

## The ideas behind it

- **[Taint tracking](https://tianpan.co/blog/2026-04-23-tool-outputs-untrusted-channel-taint-tracking)** (information flow control): content from untrusted sources is marked, and marked content can't drive a dangerous action. Lineage applies it from *outside* an unmodified agent.
- **Credential brokering:** the agent never holds the secret; a broker attaches it on the way out.
- **Honeytokens:** decoys whose use proves theft. Lineage's stand-ins are both: they do real work at the right door and raise the alarm everywhere else.
- **[The lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)** (Simon Willison) and the **[Dual LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)** / **[CaMeL](https://arxiv.org/abs/2503.18813)**: keep authority away from whatever reads untrusted text. Lineage retrofits that idea onto agents you didn't build.

## More

- [`plan.md`](plan.md): the full build plan and spec
- [`DECISIONS.md`](DECISIONS.md): design decisions and why
- [`PROGRESS.md`](PROGRESS.md): milestone status

<sub>Graphics are generated from [`docs/graphics/`](docs/graphics) (HTML rendered to PNG at 2×). Edit the HTML and re-render to update them.</sub>
