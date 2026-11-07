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
Status: **partial**

- Modeltap: run-token verify + Bedrock SigV4 path when AWS creds present; local returns 503
- Managed settings + errortrack MCP stub present
- Claude Code **not yet pinned** in agent image (Docker Hub flaky; do on EC2)

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
Status: dashboard MVP + trifecta/strict/T2 hooks in egress; polish remaining

## Blockers for the human
1. Confirm region `us-west-2` and enable Bedrock Claude access
2. Pick inference profile ID: `aws bedrock list-inference-profiles --region us-west-2`
3. `cdk deploy` + SSM into the host for the live demo with Claude Code
