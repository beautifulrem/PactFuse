# PactFuse Evidence Re-Run Plan

Purpose: every primary proof slot must be re-runnable from a clean demo state in five minutes or less. Fusebox has seven primary proof slots that map to six Judge Check proof rows; Agent Transcript, replay bundle, CAW receipt ingest, and verifier output are secondary audit prerequisites. If a primary row cannot be re-run live, the chip is marked `fixture` and removed from the winner claim.

| Chip | Clean state | Trigger | Expected evidence | Max runtime | Failure downgrade |
|---|---|---|---|---:|---|
| Cobo Pact boundary | CAW Pact active, fresh test wallet, zero or exact expected allowance, session not started | `Start Session` then bypass attempt | CAW deny request id/audit log, approve tx hash, clean Gate activation allow receipt, policy digest, tx-count/expiry | 90s | `simulated` claim mode |
| SourceChallenged | Source registered as Active; issuer key separate from owner/runner | `Challenge Shared Source` | `SourceChallenged` tx hash/log, reason JSON, reasonHash, issuer address | 45s | `fixture` challenge |
| A/B SpendTripped | A and B spends registered with challenged source; no prior settlement | automatic A/B `activateTool` after challenge | Two `SpendTripped` events, no token balance delta | 90s | `1 real CAW Pact + 1 on-chain fixture` |
| C settlement + balance delta | C spend registered with clean source; locked payment mode ready | `Run Clean Pact C` | CAW allow receipt, `SpendSettled` tx/log, ERC20 `Transfer`, `agentWallet` and market balance delta | 120s | `mocked` / no payment-path winner claim |
| Artifact preflight + quote | Pinned source pair and target repo configured; artifact API running; no quote signed yet | `POST /api/v1/artifacts/preflight` then `POST /api/v1/artifacts/preflight/verify` | manifest fetch/canonicalization, endpoint reachability, lease dry-run, artifact hash preview, quote preview, price/source disclosure hash, `artifact.preflight.verified` event | 30s | no quote signing / no paid-content-unlock claim |
| Artifact hash + receipt pack | `SpendSettled` exists and artifact API is running | fetch receipt pack by artifact hash with verifier-issued Bearer token | `artifactPayloadHash`, `receiptPackHash`, downloaded JSON, Bearer-token access proof bound to `(sessionId, spendId, payer, artifactHash)` | 30s | no paid-content-unlock claim |
| Raw MCP Agent Transcript | Verified artifact access exists; pinned manifest and independent target repo configured | runner performs MCP JSON-RPC `tools/list` then `tools/call` | transcript hash, tools-list hash, tools-call hash, pinned-manifest match, artifact payload hash in `tools/call` arguments | 30s | no "agent used what it bought" claim |
| Lease execution | Verified artifact access exists; pinned target repo/commit reachable | `POST /api/v1/lease/execute` with Bearer token | manifest-bounded tool calls, scan output from real repo, `consumedArtifactPayloadHash`, `leaseRunHash` | 30s | `lease-execution-pending` |
| CAW receipt ingest | CAW API/export reachable and raw receipts available for the session | `POST /api/caw/receipts/ingest` | raw receipt bundle hash, operation hashes, source label, fetched timestamp | 20s | no CAW proof chip |
| Judge Check | Evidence rows above exist in the same session | `GET /api/evidence/judge-check?sessionId=<id>` | Six machine-generated proof rows for CAW boundary, source challenge, A/B trip, C settlement, artifact access, and lease execution; Agent Transcript, replay bundle, raw CAW receipts, and verifier output appear as secondary audit links; every winner chip row is `pass` | 10s | remove non-pass proof chip |
| Replay bundle | All winner rows above exist in the same session | `GET /api/evidence/replay-bundle?sessionId=<id>` | `PACTFUSE_EVIDENCE_V1` hash binding config, raw CAW receipts, tx/log refs, preflight, agent transcript, lease run, Judge Check, verifier output | 10s | `WINNER_CLAIM_ALLOWED: false` |

Hour-4 gate:

- The first recorded artifact is `docs/evidence/caw-identity-probe.json`; use `docs/evidence/caw-identity-probe.example.json` only as the pre-run template.
- It must prove `SenderProbe` sender, approve owner, activation payer, and `SourceBoundSpend.agentWallet` are the same on-chain wallet for `gate-paid-artifact-real`.
- If this artifact is not green by hour 4, regenerate the public README top block with `PAYMENT_MODE: mocked` or the already-proven `permit-payment-real` fallback.
- Public token labeling is locked here too. If the token is a mock, all UI and docs must say `public testnet mock ERC20`, not USDC.
- Artifact preflight must reach `passed_live_delivery` before quote signing. If not, the operator records `blocked-preflight` and does not ask CAW to activate the clean spend.
- The independent target repo/commit must be locked before quote signing. Team-owned targets are permitted only with an explicit downgrade label.
- CAW receipt ingest must be green before any CAW proof chip is shown. Manual receipt JSON remains fixture evidence.
