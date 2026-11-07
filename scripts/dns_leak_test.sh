#!/usr/bin/env bash
set -euo pipefail

IMAGE="${LINEAGE_AGENT_IMAGE:-lineage-agent-shell:latest}"
OPERATOR_TOKEN="${LINEAGE_OPERATOR_TOKEN:-lineage-operator-dev}"
CONTROL="http://127.0.0.1:8001"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "missing $IMAGE — run: docker compose --profile tools build --pull=false agent-shell" >&2
  exit 1
fi

CREATE=$(curl -fsS -X POST "$CONTROL/admin/runs" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"task":"dns-leak","mode":"interactive","mcp_allow":[],"bindings":["staging-infra"]}')
IP=$(printf '%s' "$CREATE" | grep -o '"ip"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
NAME="dns-leak-$$"

docker run --rm --name "$NAME" \
  --network lineage_sandbox --ip "$IP" \
  --dns 127.0.0.1 \
  --add-host control:172.30.0.10 \
  --add-host egress:172.30.0.11 \
  --add-host modeltap:172.30.0.12 \
  "$IMAGE" sh -ec '
  if getent hosts example.com >/dev/null 2>&1; then
    echo "FAIL: external DNS resolved" >&2
    exit 1
  fi
  if curl --noproxy "*" --connect-timeout 3 https://example.com >/dev/null 2>&1; then
    echo "FAIL: direct external egress succeeded" >&2
    exit 1
  fi
  # collector.demo is intentionally not allowlisted (tripwire target).
  # Prove the proxy path + dotted alias with an allowlisted stub instead.
  curl --fail --silent --show-error --max-time 10 \
    -x http://egress:8080 http://infra.demo/health >/dev/null
'

echo "PASS: DNS/direct egress blocked; proxy + infra.demo alias work"
