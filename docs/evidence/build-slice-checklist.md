# PactFuse P0 Build Slice Checklist

Purpose: keep implementation aligned with the proof gates. This checklist is not evidence and does not upgrade any public mode.

## Build Order

1. Evidence shell first
   - Keep README current block at simulated/mocked/local-mocked until live artifacts replace pending files.
   - Keep `docs/evidence/mode-lock-runbook.md` and `docs/evidence/rerun.md` as the operator contract.
   - Add only links that can later point to real tx/request/verifier artifacts.
   - Add Judge Check output slots early, but keep every row `pending` until raw evidence exists.

2. Hour-0 to hour-4 deploy/probe slice
   - Do not start Fusebox polish, GLM work, or Guard Kit packaging until this slice has written current evidence files.
   - Deploy public testnet mock ERC20 or record the exact already-deployed mock token.
   - Deploy `SenderProbe`.
   - Deploy a final-selector `ProcurementGate` stub with the same `activateTool` selector planned for P0.
   - Generate concrete A/B/C Pact JSON with `pact-template/render-pact-series.mjs`.
   - Run one script/manual CAW path for wrong-target deny, approve, and clean activate.
   - Fill `docs/evidence/caw-identity-probe.json` and `docs/evidence/mock-token.json` with live evidence or keep public modes mocked.
   - Run artifact preflight against the pinned source pair and target repo: manifest fetch, endpoint reachability, lease dry-run, artifact hash preview, quote preview, and price/source disclosure hash.
   - Lock an independent public target repo/commit plus expected finding class. If the target is team-owned, record the downgrade before any winner copy is written.
   - Implement CAW receipt ingest before accepting any CAW receipt as proof: raw API/export JSON, source label, fetched timestamp, JCS hash, and operation linkage.
   - Before using the differentiation language as demonstrated behavior, run at least one controlled local or public-testnet probe where a registered spend bound to a challenged source fails at the Gate/verifier boundary. If this does not run, keep the differentiation as target design only.

3. Contracts
   - `SourceStateRegistry`: register signed immutable source refs, challenge by issuer key, emit `SourceChallenged`.
   - `ProcurementGate`: register spends, check source freshness inside `activateTool`, emit `SpendTripped` or `SpendSettled`.
   - `PaidArtifactMarket`: only accept successful Gate settlement before artifact delivery.
   - `PublicTestMockERC20`: public testnet mock token only; never label it USDC.

4. Contract tests
   - A/B spends bound to challenged source trip before token movement.
   - C spend bound to clean source settles.
   - Wrong source state reverts before quote/payment nonce consumption.
   - Quote price equals approved/settled amount.

5. CAW adapter
   - Record SenderProbe, approve owner, activation payer, and registered spend agent wallet.
   - Execute ERC20 approve through CAW.
   - Execute `ProcurementGate.activateTool` through CAW.
   - Capture CAW deny request id, approve tx, clean allow receipt, policy digest, tx-count/request-count, and expiry.
   - Every CAW receipt must be linked to an ingested raw receipt hash; manual rows are fixtures and cannot pass Judge Check.

6. Artifact API and verifier
   - `/api/v1/artifacts/preflight` plus `/api/v1/artifacts/preflight/verify` must produce `passed_live_delivery` before a quote signer can sign; winner mode requires `chain_settleable_after_preflight`, a quote hash bound to chain/payment/preflight fields, and quote chain/expiry matching the verified token settlement.
   - Generate Source-Bound Code-Scan MCP Lease receipt pack.
   - Hash artifact payload and receipt pack separately.
   - Include `priceDisclosure` and `deliveryPreflight` in the receipt pack and verify their hashes against displayed UI values.
   - Include `agentTranscript` in the receipt pack for any "agent used what it bought" chip: MCP JSON-RPC `tools/list`, `tools/call`, transcript hash, and pinned-manifest binding.
   - Include `cawReceiptIngest` and the `PACTFUSE_EVIDENCE_V1` replay bundle hash before any CAW or winner proof chip can pass.
   - `/api/evidence/verify` validates source proof, CAW receipts/operations, payment proof, trip/settle events, balance delta, artifact hash, and block window.
   - `/api/evidence/judge-check` returns pass/fail rows backed by raw evidence links; no row can pass from prose-only evidence.
   - Reuse `verifyEvidence(input, chainClient)` from `packages/verifier/pactfuse-verify-receipt.mjs` in both CLI and `/api/evidence/verify`; only the API/runtime may pass `proofProviderAuthority: "server-runtime"` for final replay authority.
   - Use `--schema-only` only for structural preflight; default CLI mode must fail closed unless `proofChipAllowed: true`.
   - Keep winner claims blocked unless the replay verifier reports no `proofCompletenessErrors` and the app verifier accepts the same evidence snapshot.
   - Implement one paid-but-undelivered negative path: either `QuoteVoided` before settlement or `ArtifactRefunded` after settlement.

7. Fusebox UI (W5/W6 surface)
   - First viewport is the board-dominant Fuse Stage: physical cartridges with ferrules/clips/filament/trip-flag/rating-stamp, compact seven-slot proof rail as animated nodes, collapsed Judge Check tray, in-lane manifest delta callout, thin consequence strip, animated runner heartbeat rail. No first-viewport cards, no source card, no marketing hero.
   - Pre-gate dev builds keep the honest inline mode banners; the `Evidence modes` chip collapse applies only after mode-lock gates pass.
   - Fixture states stay visually separated from live evidence; fixture/manual/pending/blocked can never render pass-green.
   - Wire the SSE evidence stream consumer plus the 2s polling fallback and `degraded: polling` chip; implement the live-state ladder (`awaiting-caw-approval`, `tx-pending` ticks, `indexing`, error chips with `code`+`requestId`, de-energized empty board, elapsed timers).
   - Add price/source disclosure before `Run Clean Pact C`; if the disclosure is missing, the clean activation control is disabled.
   - Runner heartbeat rail and Judge Check read machine records, not manually edited copy.
   - Issuer/challenge provenance row lives in the evidence sheet; consequence strip shows observed blocked spend amount, denied write-capability delta, and clean scan result. Do not show speculative loss-prevented numbers.
   - If `DRIFT_WATCH_MODE: advisory` is on, drift renders only as the amber advisory tag and changes no proof state.
   - Final-video run must pass the W5 performance and console gates: <3s first viewport, <1s action feedback, zero `console.error`.

8. Final evidence swap
   - Replace pending JSON files with live evidence artifacts.
   - Run `docs/evidence/mode-lock-runbook.md` final gate.
   - Run clean-state re-run rows in `docs/evidence/rerun.md`.
   - Only then regenerate README/UI final winner banner.

## Stop Rules

- If CAW deny/allow is not live, keep `CLAIM_MODE: simulated`.
- If same-wallet proof fails, keep `PAYMENT_MODE: mocked` unless `permit-payment-real` is separately proven.
- If mock token has no public deployment evidence, keep `TOKEN_MODE: local-mocked`.
- If the full receipt verifier is not ready, keep `WINNER_CLAIM_ALLOWED: false`.
- If artifact delivery is missing after real settlement, show `artifact-hash-proof` only.
- If artifact preflight is missing or failed, do not sign quotes and do not show a paid-content-unlock claim.
- If any Judge Check row is not `pass`, remove that row's proof chip from the winner script.
- If CAW receipts are manually entered or not present in the ingest bundle, remove the CAW proof chip.
- If the Agent Transcript is missing or not bound to the pinned manifest, remove the "agent used what it bought" chip.
- If the scan target is team-owned, label it and remove the external-workflow proof chip.
- If the replay bundle cannot bind all winner rows to one `sessionId`, keep `WINNER_CLAIM_ALLOWED: false`.

## Minimum Demo Links

- CAW deny request id or audit receipt.
- CAW approve tx hash.
- CAW clean allow receipt.
- `SourceChallenged` tx hash.
- A/B `SpendTripped` tx hashes.
- C `SpendSettled` tx hash plus ERC20 `Transfer` and `agentWallet`/market balance delta.
- Receipt-pack verifier output.
- Artifact Bearer-token access proof.
- Artifact preflight output and price/source disclosure hash.
- Judge Check URL / JSON.
- Runner heartbeat log hash for the clean recovery path.
- CAW receipt ingest bundle hash.
- Raw MCP Agent Transcript hash.
- `PACTFUSE_EVIDENCE_V1` replay bundle hash.
