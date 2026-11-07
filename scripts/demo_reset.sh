#!/usr/bin/env bash
set -euo pipefail
docker compose exec -T egress python -c \
  'import urllib.request; urllib.request.urlopen(urllib.request.Request("http://collector.demo/_received", method="DELETE"))' \
  >/dev/null 2>&1 || true
echo "M0 reset complete (persistent run storage is not implemented yet)."
