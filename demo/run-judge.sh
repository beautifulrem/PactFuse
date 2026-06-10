#!/usr/bin/env bash
# PactFuse one-command judge run (current design locks: W8 backend + W9 Fusebox).
# Fail-closed: starts the P0 backend when available, prints real backend links,
# and still exits non-zero until live proof rows and the final verifier pass.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== PactFuse judge run =="
echo

MISSING=0
API_PID=""
PACTFUSE_API_PORT="${PACTFUSE_API_PORT:-8787}"
USER_PACTFUSE_API_URL="${PACTFUSE_API_URL:-}"
PACTFUSE_API_URL="${PACTFUSE_API_URL:-http://127.0.0.1:${PACTFUSE_API_PORT}}"
PACTFUSE_DB_PATH="${PACTFUSE_DB_PATH:-.pactfuse/judge.sqlite}"
API_LOG="${API_LOG:-.pactfuse/judge-api.log}"

cleanup() {
  if [ -n "$API_PID" ]; then
    kill "$API_PID" >/dev/null 2>&1 || true
    wait "$API_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

api_ready() {
  curl -fsS "$PACTFUSE_API_URL/healthz" >/dev/null 2>&1
}

if [ ! -d "apps/fusebox" ]; then
  echo "[pending] apps/fusebox does not exist yet"
  MISSING=1
fi

if [ ! -f "apps/pactfuse-api/package.json" ]; then
  echo "[pending] apps/pactfuse-api does not exist yet (plan stage; see research/pactfuse-backend-w8-hardening-2026-06-10.md)"
  MISSING=1
elif api_ready; then
  echo "[backend] pactfuse-api already reachable: $PACTFUSE_API_URL"
else
  if [ ! -d "node_modules" ]; then
    echo "[pending] dependencies not installed; run pnpm install before live judge run"
    MISSING=1
  else
    mkdir -p "$(dirname "$API_LOG")"
    if [ -n "$USER_PACTFUSE_API_URL" ]; then
      PORT_CANDIDATES="$PACTFUSE_API_PORT"
    else
      PORT_CANDIDATES="$PACTFUSE_API_PORT 8788 8789 8790 8791"
    fi
    for candidate_port in $PORT_CANDIDATES; do
      PACTFUSE_API_PORT="$candidate_port"
      if [ -z "$USER_PACTFUSE_API_URL" ]; then
        PACTFUSE_API_URL="http://127.0.0.1:${PACTFUSE_API_PORT}"
      fi
      echo "[backend] starting pactfuse-api on $PACTFUSE_API_URL"
      PORT="$PACTFUSE_API_PORT" PACTFUSE_DB_PATH="$PACTFUSE_DB_PATH" pnpm --filter @pactfuse/api start >"$API_LOG" 2>&1 &
      API_PID="$!"
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if api_ready; then
          break
        fi
        sleep 0.25
      done
      if api_ready; then
        break
      fi
      kill "$API_PID" >/dev/null 2>&1 || true
      wait "$API_PID" >/dev/null 2>&1 || true
      API_PID=""
    done
    if api_ready; then
      echo "[backend] pactfuse-api health OK: $PACTFUSE_API_URL/healthz"
    else
      echo "[blocked] pactfuse-api did not become ready; see $API_LOG"
      MISSING=1
    fi
  fi
fi

if [ -f "apps/fusebox/preview/fusebox-v2/index.html" ]; then
  echo "[fixture] Fusebox v2 visual prototype exists: apps/fusebox/preview/fusebox-v2/index.html"
elif [ -f "apps/fusebox/preview/fusebox/index.html" ]; then
  echo "[fixture] legacy Fusebox design preview exists: apps/fusebox/preview/fusebox/index.html"
else
  echo "[pending] Fusebox design preview missing (/preview/fusebox-v2 fixture gate)"
  MISSING=1
fi

echo
echo "-- Receipt verifier preflight (fail-closed; pending example) --"
node packages/verifier/pactfuse-verify-receipt.mjs --schema-only docs/evidence/receipt-pack.pending.example.json || true

if api_ready; then
  echo
  echo "-- Backend P0 evidence endpoints (fail-closed session) --"
  SESSION_JSON="$(curl -fsS -H 'content-type: application/json' --data '{"idempotencyKey":"judge-session-p0","payload":{"label":"judge-p0"}}' "$PACTFUSE_API_URL/api/v1/sessions")"
  SESSION_ID="$(node -e 'const j=JSON.parse(process.argv[1]); console.log(j.data.sessionId)' "$SESSION_JSON")"
  echo "Backend URL                  : $PACTFUSE_API_URL"
  echo "Health                       : $PACTFUSE_API_URL/healthz"
  echo "Judge Check                  : $PACTFUSE_API_URL/api/v1/evidence/judge-check?sessionId=$SESSION_ID"
  echo "Replay bundle                : $PACTFUSE_API_URL/api/v1/evidence/replay-bundle?sessionId=$SESSION_ID"
  echo "SSE stream                   : $PACTFUSE_API_URL/api/v1/evidence/stream?sessionId=$SESSION_ID"
  curl -fsS "$PACTFUSE_API_URL/api/v1/evidence/judge-check?sessionId=$SESSION_ID" \
    | node -e 'let s=""; process.stdin.on("data",d=>s+=d); process.stdin.on("end",()=>{const j=JSON.parse(s); console.log("Judge rows                    : "+j.data.rows.map(r=>r.rowId+"="+r.status).join(", ")); console.log("winnerClaimAllowed           : "+j.data.winnerClaimAllowed);})'
fi

echo
echo "-- Evidence links (live values replace these after the evidence lock) --"
echo "1. Cobo Pact boundary receipts : docs/evidence/caw-policy-receipt.example.json (pending)"
echo "2. SourceChallenged tx          : pending"
echo "3. SpendTripped A/B txs         : pending"
echo "4. SpendSettled C + balance     : pending"
echo "5. Artifact + lease run         : pending (lease-execution-pending)"
echo "6. MCP Agent Transcript         : pending"
echo "7. Judge Check                  : pending"
echo "8. Replay bundle                : pending"
echo "9. Fusebox visual prototype     : apps/fusebox/preview/fusebox-v2/index.html (fixture only; not proof)"
echo
echo "Current modes: see README.md top block (CLAIM_MODE: simulated until gates pass)."

if [ "$MISSING" -eq 1 ]; then
  echo
  echo "RESULT: NOT LIVE — missing app/dependency gates remain."
  exit 1
fi

echo
echo "RESULT: BACKEND P0 RUNNING, PROOF NOT LIVE — Judge Check remains pending and winnerClaimAllowed=false."
exit 1
