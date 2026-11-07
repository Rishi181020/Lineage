# Progress

## M0 — Scaffold, local compose, sandbox sealing
Status: **PASS**

- Compose healthy (control/egress/modeltap/stubs)
- `scripts/dns_leak_test.sh` PASS (no DNS, no direct egress, proxy to `infra.demo` works)
- Dotted aliases verified

## M0b — AWS CDK skeleton
Status: **code ready; not deployed**

- `infra/cdk/` — VPC, t3.large, no inbound, IMDSv2 hop 2, DynamoDB×3, KMS P-256, IAM, CW Logs
- Needs human: AWS login, Bedrock model access, inference profile ID (D16)

## M1 — Core rules + hooks API
Status: **PASS** (24 pytest incl. L1a/L1b/L2/binding allow)

## M2 — Claude Code + modeltap
Status: **working against a scripted model; real Bedrock not yet run**

- Claude Code 2.1.319 pinned in the agent image; hooks, MCP and stream output tested live
- Modeltap's SigV4 path to Bedrock still needs a run with valid credentials

## M3 — Egress custody
Status: **PASS** via `scripts/e2e.sh`

- Custody attach to infra.demo (real token at stub, placeholder back to agent)
- C2 DELETE → 403
- C1 tripwire to collector.demo → run `killed`
- E2 metadata → 403; E1 example.com → 403/502

## M4 — Identity / revoke / stop
Status: **partial**

- Local HS256 run tokens, admin revoke/stop/signal, I1 in rules
- KMS ES256 for aws mode still TODO

## M5–M9
Status: guided dashboard + trifecta/strict/T2 hooks in egress; polish remaining

- Web app starts real agents, with live approvals, revoke and a diff of changes
- Trifecta `external` leg only trips on WebFetch; egress traffic doesn't report it yet

## Blockers for the human
1. Confirm region `us-west-2` and enable Bedrock Claude access
2. Pick inference profile ID: `aws bedrock list-inference-profiles --region us-west-2`
3. `cdk deploy` + SSM into the host for the live demo with Claude Code
