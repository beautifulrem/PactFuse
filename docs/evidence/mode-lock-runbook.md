# PactFuse Mode-Lock Runbook

Purpose: convert the winning-project rule into an executable demo gate: one narrow closed loop, one hard sponsor-dependent path, and clickable proof for every public claim.

This file does not upgrade any claim by itself. It tells the demo operator what must be true before changing README/UI modes.

## Current Default

Until the gates below pass, public status stays:

```text
CLAIM_MODE: simulated
PAYMENT_MODE: mocked
TOKEN_MODE: local-mocked
IDENTITY_MODE: pending
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: false
```

## Hour-4 Candidate Gate

Hour 4 may create a target candidate block, not current real modes and not a winner banner. `TARGET_*` values mean the desired path is still viable to pursue; they do not change the current public modes listed above.

W1 probe order (run before the candidate gate): (1) attempt separate CAW wallets/identities for A/B/C — `p0-win-separate-identities` is the default target, floor requires the recorded failure reason; (2) probe official Circle Base Sepolia USDC (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`) before deploying any mock token — mock requires the recorded official-probe failure reason; (3) lock the spec §16.1 real manifest commit pair or record the labeled fallback.

Required inputs:

- `docs/evidence/caw-identity-probe.json` has `mode: real`, `isRealEvidence: true`, and `pass: true`, plus the identity-tier outcome (win/floor + reason).
- `docs/evidence/mock-token.json` records the official-USDC probe result; if fallback, it contains public testnet mock ERC20 chain id, token address, deployment tx hash, explorer URL, decimals, and code hash.
- `pact-template/render-pact-series.mjs` has generated Pact A, Pact B, and Pact C with distinct `pactId`, `spendId`, `quoteNonce`, and expected receipt slots.
- Artifact preflight has passed for the pinned source pair and target repo: source fetch/canonicalization, endpoint reachability, lease dry-run, artifact hash preview, quote preview, and price/source disclosure hash.
- Independent public target repo/commit and expected finding class are locked, or the target is explicitly downgraded as `team-authored target`.
- CAW receipt ingest is configured and can produce raw receipt bundle hashes; manual CAW receipt rows are marked fixture.
- CAW policy receipt captures the intended two-call boundary: ERC20 `approve(spender=ProcurementGate, amount<=maxPrice)` and `ProcurementGate.activateTool(...)`.
- Wrong-target bypass attempt has a real CAW deny request id or audit receipt.
- Clean activation attempt has a real CAW allow receipt.

Allowed output only after all inputs pass:

```text
TARGET_CLAIM_MODE: caw-target-real
TARGET_PAYMENT_MODE: gate-paid-artifact-real
TARGET_TOKEN_MODE: official-testnet-usdc (fallback rung: mock-test-token, deployment tx shown)
TARGET_IDENTITY_MODE: p0-win-separate-identities (fallback rung: p0-floor-one-wallet)
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: false
```

Candidate sanity checks:

- Local receipt structural preflight should use `node packages/verifier/pactfuse-verify-receipt.mjs --schema-only <receipt-pack.json>` and return `schemaOk: true` before the operator inspects it.
- A receipt-pack proof chip requires default verifier mode to exit 0 with `proofChipAllowed: true`; pending/placeholder receipts can be schema-valid but still cannot be proof chips.
- Passing structural preflight does not authorize any `TARGET_*` value, current mode upgrade, or winner claim.
- If `statusFields.winnerClaimAllowed` appears inside an evidence file during candidate mode, treat it only as that file's local readiness flag; the top-level public `WINNER_CLAIM_ALLOWED` remains `false`.

## Hour-4 Downgrades

| Failed gate | Required public mode |
|---|---|
| CAW identity probe missing, pending, blocked, or failed | `CLAIM_MODE: simulated` |
| Same-wallet approve owner / activation payer / SenderProbe / agent wallet mismatch | `PAYMENT_MODE: mocked` unless `permit-payment-real` is separately proven |
| Mock token lacks public deployment evidence | `TOKEN_MODE: local-mocked` |
| Artifact preflight missing or blocked | no paid-content-unlock or lease-execution claim |
| CAW receipt ingest missing or manual-only | no CAW proof chip |
| Independent target repo missing | no external-workflow proof chip |
| CAW wrong-target deny missing | `CLAIM_MODE: simulated` |
| CAW clean allow missing | `CLAIM_MODE: simulated` |
| Receipt `schemaOk` fails or `proofChipAllowed` is false | no receipt-pack proof chip |
| Judge Check row is not `pass` in winner mode | remove that proof chip from winner claim |
| Operator cannot re-run a proof chip from clean state | mark that chip `fixture` and remove it from winner script |

## Final Winner Gate

The final winner banner is allowed only after the full evidence chain passes. The local preflight scaffold is not enough.

Required winner inputs:

- CAW identity probe proves same-wallet semantics with live evidence, and the probed wallet address matches the settled C spend payer/agentWallet.
- Token evidence is public and inspectable.
- CAW policy receipts plus matching on-chain tx evidence prove deny, approve, clean allow, policy digest, tx-count/request-count, and expiry.
- Raw CAW receipt ingest bundle links every CAW operation to API/export JSON; no CAW winner chip may depend on hand-entered receipt fields.
- `SourceChallenged` is a real chain tx from an issuer key separate from owner/runner.
- A and B have real `SpendTripped` events, canonical tx ordering, and no token movement.
- C has a real `SpendSettled` event plus ERC20 `Transfer` and balance delta from `agentWallet` to market, verified through a live chain provider; `payer` must equal `agentWallet` until wallet ownership proof exists.
- Artifact quote was signed only after preflight passed, has `chain_settleable_after_preflight` status for winner mode, its `quoteHash` binds status, chain id, payer, agent wallet, token, market, price, and preflight fields, and its chain id plus expiry match the token settlement.
- Agent Transcript includes raw MCP JSON-RPC `tools/list` and `tools/call` hashes, bounded to the pinned manifest, before any "agent used what it bought" chip is shown.
- Lease target is an independent pinned public repo/commit for the external-workflow chip; team-owned target requires a visible downgrade.
- `PACTFUSE_EVIDENCE_V1` replay bundle binds run config, raw CAW receipts, tx/log refs, source proof, artifact preflight, agent transcript, lease run, Judge Check, and verifier output under one `sessionId`.
- Receipt pack is verified by the full chain/signature/hash verifier, not only `schemaOk`; replay verification must have no `proofCompletenessErrors` before `finalVerifierComplete` can become true.
- Artifact API returns full payload only with a verifier-issued Bearer token bound to `(sessionId, spendId, payer, artifactHash)`.
- If artifact delivery fails after settlement, `ArtifactRefunded` or equivalent refund evidence is shown and paid-content-unlock is removed from the winner script.
- `/api/evidence/judge-check` returns six rows and every public proof chip row is `pass`.
- Runner heartbeat rows are hash-linked to the evidence timeline: plan, CAW request, trip reaction, clean recovery, lease execution/pending.
- No proof chip is `pending`, `fixture`, `manual`, or `blocked`.

Allowed final output:

```text
CLAIM_MODE: caw-target-real
PAYMENT_MODE: gate-paid-artifact-real
TOKEN_MODE: <locked at hour 4: official-testnet-usdc | mock-test-token>
IDENTITY_MODE: <locked at hour 4: p0-win-separate-identities | p0-floor-one-wallet>
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: true
```

## Forbidden Upgrades

- Do not claim `official-testnet-usdc` for a mock token.
- Do not claim `gate-paid-artifact-real` without same-wallet proof and CAW approve evidence.
- Do not claim `permit-payment-real` without CAW `message_sign` receipts for both `GatePaymentAuthorization` and EIP-2612 Permit.
- Do not use EIP-3009 in P0 winner copy.
- Do not treat `packages/verifier/pactfuse-verify-receipt.mjs` as winner-grade verification while it reports any final replay blocker or keeps `proofChipAllowed=false`.
- Do not present source challenge as independent fraud detection; it is issuer-declared source freshness at settlement.
- Do not show a paid-content-unlock claim if artifact delivery is missing. Use `artifact-hash-proof` only.
- Do not show a CAW proof chip from hand-entered receipts.
- Do not show "agent used what it bought" without a raw MCP Agent Transcript.
- Do not show an external-workflow chip for a team-owned target repo.
- Do not show speculative loss-prevented numbers; only observed blocked spend amount and denied capability delta are allowed.

## Judge-Facing Proof Order

Use this order in the live demo and README top links:

1. CAW boundary: deny request id, approve tx, clean allow receipt, policy digest, tx-count/expiry.
2. Source challenge: issuer key, `SourceChallenged` tx, reason hash, in-lane manifest delta, expanded full diff evidence.
3. A/B trip: two `SpendTripped` events, no token delta, event-reconstructed affected set.
4. C settlement: `SpendSettled` tx, ERC20 `Transfer`, `agentWallet`/market balance delta, quote price.
5. Artifact receipt: preflight proof, artifact hash, receipt pack hash, verifier output, Bearer-token access proof.
6. Agent transcript: MCP `tools/list` + `tools/call` transcript hash, pinned-manifest tool set, independent target repo/commit.
7. Lease execution: scan output on the pinned target repo + `leaseRunHash` (or honest `lease-execution-pending`).
8. Judge Check + replay bundle: pass/fail rows matching the raw proof links, plus `PACTFUSE_EVIDENCE_V1` bundle hash.

## Winning-Pattern Mapping

- Narrow closed loop: one agent buys one source-bound code-scan MCP lease; two dependent leases trip; one clean lease settles **and runs** (W1: the purchase is consumed, not just receipted).
- Sponsor load-bearing: without Cobo CAW approve/activate policy receipts, the project downgrades to simulated.
- Hard evidence on the main path: chain tx/logs, raw-ingested CAW receipts, balance deltas, artifact hashes, MCP Agent Transcript, lease run output, replay bundle, verifier output.
- Visual proof: Fusebox first viewport leads with the physical fuse board, seven-slot animated proof rail, A/B breaker state, in-lane manifest delta, compact C-lane lease output callout, and animated runner heartbeat rail; raw mode enums, full source cards, full manifest diff, and long receipt tables live in Open Evidence after gates pass (W5).
- Reusable primitive: PactFuse Guard Kit = `SourceFreshGuard` modifier + second adopter example + one Cobo Pact template + receipt verifier + Judge Check output, not a broad agent marketplace (W1/W2).
- Judge repeatability: `./demo/run-judge.sh` one-command run from clean checkout, printing Judge Check and replay bundle hashes (W1/W3).
- Demo fallback ladder (W6): rung 1 live run; rung 2 `/replay/:sessionId` over the pre-recorded green session with a persistent `replay of recorded session <id>` label; rung 3 stamped fixture preview with no proof language. A mid-demo stall never justifies hand-edited evidence or re-labeling a fixture as live. Record the fallback green session in hour 44-48 before any stage time.
