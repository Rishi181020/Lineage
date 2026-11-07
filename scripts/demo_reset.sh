#!/usr/bin/env bash
# Clean state between rehearsals: empty the attacker's inbox and infra log, restore the demo's
# bug reports, and restart control so no old runs are listed. Takes a few seconds.
set -euo pipefail
OPERATOR_TOKEN="${LINEAGE_OPERATOR_TOKEN:-lineage-operator-dev}"
CONTROL="http://127.0.0.1:8001"

for stub in stub-collector stub-infra; do
  path=$([ "$stub" = stub-collector ] && echo _received || echo _calls)
  docker compose exec -T "$stub" python -c \
    "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1/$path', method='DELETE'))" \
    >/dev/null
done
# Runs live in control's memory, and the runner removes leftover agent containers on restart.
docker compose restart control runner >/dev/null
for _ in $(seq 1 30); do
  curl -fsS "$CONTROL/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -fsS -X POST -H "Authorization: Bearer $OPERATOR_TOKEN" "$CONTROL/admin/attacker/issues/reset" >/dev/null
echo "Reset: no runs, empty attacker inbox, the demo's two bug reports."
