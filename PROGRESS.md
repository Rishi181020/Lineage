# Progress

## M0 — Scaffold, local compose, sandbox sealing
Status: **PASS**

- Compose healthy (control/egress/modeltap/runner/stubs)
- `scripts/dns_leak_test.sh` PASS (no DNS, no direct egress, proxy to `infra.demo` works)

## M0b — AWS CDK skeleton
Status: **code ready; not deployed**

- `infra/cdk/` — VPC, t3.large, no inbound, IMDSv2 hop 2, DynamoDB×3, KMS P-256, IAM, CW Logs
- Needs human: AWS login, Bedrock model access, inference profile ID (D16)

## M1 — Core rules + hooks API
Status: **PASS**

- Manifests are now trusted as they were at run start, not when read (D26). Bare installs are judged on what the agent added (D27).
- Script URLs in code-running actions are judged by full URL (D29).

## M2 — Claude Code + modeltap
Status: **working against a scripted model; real Bedrock not yet run**

- Claude Code 2.1.319 pinned in the agent image; hooks, MCP and stream output tested live
- Modeltap's SigV4 path to Bedrock still needs a run with valid credentials

## M3 — Egress custody
Status: **PASS** via `scripts/e2e.sh`

- Egress rules moved to `lineage_core/egress_rules.py` (pure, unit-tested); the proxy only does I/O
- e2e also checks the before/after: the same request leaks the real key without Lineage and trips C1 with it

## M4 — Identity / revoke / stop
Status: **partial**

- Local HS256 run tokens, admin revoke/stop/signal, I1 in rules
- The model tap reports refused calls after revoke; the dashboard shows Model / Tools / Network cut off
- KMS ES256 for aws mode still TODO

## M5 — S2 corroboration
Status: **PASS**

- Web runs trust only the operator's task; terminal runs need the model tap to see a typed prompt (D28)
- Residual: in terminal runs, a hijacked agent could forge a model request with its run token

## M6 — Dashboard
Status: **PASS (local)**

- Views: Agents, Attacker console, Scorecard
- Protection switch (Lineage / normal gateway only); unprotected runs show what Lineage would have done
- Trifecta lights, revoke tiles, per-run attacker inbox strip
- Checked in headless Brave at 1440px and 390px with simulated events; no console errors

## M7 — Trifecta strict mode, T1 and T2
Status: **PASS (unit + scorecard)**

- Egress traffic now sets the external leg; strict applies to the request that would complete the trifecta (D31)

## M8 — Hardening and AWS polish
Status: **partial**

- `scripts/demo_reset.sh` clears runs, attacker inbox, infra log and planted issues in about 2s
- CloudWatch logs and the secret-in-logs grep: TODO

## M9 — Demo safety net
Status: **partial**

- `lineage replay fixtures/hook_payloads/demo/` works against the live stack
- `make scorecard`: normal gateway 0/7, Lineage 7/7, assuming every prompt is approved (D32)
- Still to do: a recorded live run with the real model, and two rehearsals

## M10 — npm supply-chain demo
Status: **working locally (scripted install); full Claude run not yet recorded**

- Dashboard "Supply chain" view: dependencies with behavior verdicts, live trace, live checks, Run with/without Lineage (D34)
- `npm install` in a sealed agent: with Lineage, orders-telemetry flagged malicious, C1 kill, attacker inbox empty; without, the real key reaches the inbox
- Unit tests removed at the user's request

## Blockers for the human
1. Confirm region `us-west-2` and enable Bedrock Claude access
2. Pick inference profile ID: `aws bedrock list-inference-profiles --region us-west-2`
3. Run one live agent with Bedrock (this Mac has `~/.aws` credentials; the Nov 7 hardening work made no AWS calls)
4. `cdk deploy` + SSM into the host for the live demo
