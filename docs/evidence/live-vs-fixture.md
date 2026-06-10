# Live vs Fixture Matrix

Final demo rule: a proof chip may appear in the winner claim only when `mode = real`. Fixture, manual, pending, or blocked rows stay in Open Evidence or are removed from the public script.

| Evidence | Required mode for winner claim | Fixture label | Downgrade |
|---|---|---|---|
| Cobo Pact boundary | real CAW deny + real CAW approve + real CAW clean allow | `fixture-caw-policy` | `simulated` claim mode |
| SourceChallenged | real SourceStateRegistry tx from issuer key | `fixture-source-challenge` | no blast-radius claim |
| A/B SpendTripped | two real `SpendTripped` events | `fixture-trip` | `1 real CAW Pact + 1 on-chain fixture` |
| C settlement + balance delta | real `SpendSettled` plus token balance delta | `fixture-settlement` | no payment-path winner claim |
| Artifact preflight + quote | real preflight output before quote signing: manifest fetch, endpoint reachability, lease dry-run, artifact hash preview, price/source disclosure hash | `fixture-preflight` | no paid-content-unlock or lease-execution claim |
| Artifact hash + receipt pack | verified `artifactPayloadHash` and `receiptPackHash` | `fixture-artifact` | `artifact-hash-proof` only |
| Bearer-token artifact access | real API response proving Bearer-token access is bound to `(sessionId, spendId, payer, artifactHash)` | `fixture-access` | no paid-content-unlock claim |
| Raw MCP Agent Transcript | real MCP JSON-RPC `tools/list` + `tools/call` transcript hash, bounded to the pinned manifest | `fixture-agent-transcript` | no "agent used what it bought" claim |
| Lease execution | real Bearer-bound `/api/lease/execute` output on the pinned repo/commit plus recomputed `leaseRunHash` | `fixture-lease-run` | `lease-execution-pending` |
| CAW receipt ingest | raw CAW API/export bundle, JCS hash, and operation links | `fixture-caw-ingest` | no CAW proof chip |
| Judge Check | machine-generated pass/fail response where winner chip rows are all `pass` | `fixture-judge-check` | remove any non-pass chip from winner claim |
| Replay bundle | one `PACTFUSE_EVIDENCE_V1` bundle tying all winner rows to one `sessionId` | `fixture-replay-bundle` | `WINNER_CLAIM_ALLOWED: false` |

Labels:

- `real`: CAW receipt, chain tx/log, or deterministic hash proof is present and re-runnable.
- `manual`: human action outside the app, visible and documented.
- `pending`: required live run has not happened yet; cannot support a winner claim.
- `fixture`: local or preloaded data that cannot support a winner claim.
- `blocked`: attempted but failed due to auth, chain, CAW, token, or API condition.
