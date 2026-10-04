#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

MODE="${1:-}"
case "$MODE" in
  baseline) PREFIX="owasp_zap_baseline" ;;
  after) PREFIX="owasp_zap_after" ;;
  *) echo "uso: bash scripts/run_zap_scan.sh <baseline|after>" >&2; exit 2 ;;
esac

[ -f .env ] || { echo ".env ausente: copie .env.example e preencha os valores locais" >&2; exit 1; }

COMPOSE="docker compose -f docker-compose.zap.yml"
trap '$COMPOSE down -v >/dev/null 2>&1 || true' EXIT

$COMPOSE up -d --build --wait api

ZAP_ARGS=(-t http://api:8000/openapi.json -f openapi -J "$PREFIX.json" -r "$PREFIX.html" -S -I)

if [ "$MODE" = "after" ]; then
  TOKEN="$($COMPOSE exec -T api python - <<'PY'
import json
import os
import urllib.parse
import urllib.request

from app.core.security import totp_code

BASE = "http://127.0.0.1:8000"


def call(path, data, headers):
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


form = urllib.parse.urlencode({"username": "admin", "password": os.environ["DEMO_USERS_PASSWORD"]}).encode()
first = call("/auth/token", form, {"Content-Type": "application/x-www-form-urlencoded"})
body = json.dumps({"mfa_code": totp_code(os.environ["DEMO_ADMIN_MFA_SECRET"])}).encode()
second = call(
    "/auth/mfa/verify",
    body,
    {"Content-Type": "application/json", "Authorization": "Bearer " + first["access_token"]},
)
print(second["access_token"])
PY
)"
  [ -n "$TOKEN" ] || { echo "falha ao obter o token admin+MFA" >&2; exit 1; }
  REPLACER="-config replacer.full_list(0).description=auth"
  REPLACER="$REPLACER -config replacer.full_list(0).enabled=true"
  REPLACER="$REPLACER -config replacer.full_list(0).matchtype=REQ_HEADER"
  REPLACER="$REPLACER -config replacer.full_list(0).matchstring=Authorization"
  REPLACER="$REPLACER -config replacer.full_list(0).regex=false"
  REPLACER="$REPLACER -config replacer.full_list(0).replacement=Bearer $TOKEN"
  ZAP_ARGS+=(-z "$REPLACER")
fi

$COMPOSE run --rm --no-deps zap zap-api-scan.py "${ZAP_ARGS[@]}"

PYTHON="${PYTHON:-python3}"
[ -x .venv/bin/python ] && PYTHON=".venv/bin/python"
"$PYTHON" scripts/zap_gate.py "docs/$PREFIX.json"
