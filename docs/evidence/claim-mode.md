# Claim Mode Rules

Public claim modes are evidence-derived. Do not set them by pitch preference.

## Current Checked-In State

```text
CLAIM_MODE: simulated
PAYMENT_MODE: mocked
TOKEN_MODE: local-mocked
WINNER_CLAIM_ALLOWED: false
```

This remains true while any required live evidence file is `pending`, `fixture`, `manual`, or `blocked`.

## Hour-4 Mode-Lock Candidate

Hour 4 may lock target values such as `TARGET_CLAIM_MODE: caw-target-real` and `TARGET_PAYMENT_MODE: gate-paid-artifact-real` only after the candidate gates in `mode-lock-runbook.md` pass.

This is not a winner claim. `WINNER_CLAIM_ALLOWED` remains `false` until the full upgrade rules below pass.

## Upgrade Current Claim To `caw-target-real`

This section is for the final/current public claim, not the hour-4 `TARGET_*` candidate block.

Allowed only when all are true:

- `docs/evidence/caw-identity-probe.json` has `mode: real`, `pass: true`, and `winnerClaimAllowed: true`
- CAW policy receipt plus matching tx/audit evidence proves chain, target, selector, expiry, tx-count/request-count limits, and usage
- CAW receipt ingest proves every CAW operation came from raw API/export JSON, not hand-entered fields
- wrong-target bypass has a real CAW deny request id or audit receipt
- clean activation has a real CAW allow receipt
- `SpendTripped` A/B and `SpendSettled` C are real chain events in the same session
- Judge Check rows for CAW boundary, source challenge, A/B trip, and C settlement are `pass`
- `PACTFUSE_EVIDENCE_V1` replay bundle binds the CAW receipts, tx/log refs, source proof, artifact records, Agent Transcript, Judge Check rows, and verifier output under one `sessionId`

Headline: `Contract-enforced source fuse behind a Cobo Pact target allowlist`.

## Upgrade To `caw-stable-params-real`

Allowed only when `caw-target-real` is already true and CAW receipts also prove decoded stable params plus a same-policy wrong-param denial for target/selector/params_match.

Headline: `Cobo param-bound source fuse`.

## Payment Mode Rules

- `gate-paid-artifact-real`: requires same-wallet approve owner, activation payer, `SenderProbe` sender, `SourceBoundSpend.agentWallet`, CAW approve tx, allowance before/after, approved amount equal to quote price, CAW policy digest/usage proof, mode-exclusive `gatePaid` proof, and approve-before-activate ordering.
- `permit-payment-real`: requires CAW `message_sign` receipts for GatePaymentAuthorization and EIP-2612 Permit, plus activation receipt.
- `mocked`: required if neither real payment path is proven by hour 4.

## Token Mode Rules

W1 default order: probe `official-testnet-usdc` (Circle Base Sepolia USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e`) FIRST at hour 0; `mock-test-token` is the fallback rung and the fallback reason must be recorded in `docs/evidence/mock-token.json`.

- `official-testnet-usdc`: requires official/sponsor token evidence for the exact chain/address.
- `mock-test-token`: requires public testnet mock ERC20 deployment evidence in `docs/evidence/mock-token.json` plus the recorded official-USDC probe failure reason.
- `local-mocked`: local only, not a winner claim.

## Identity Mode Rules

W1 default order: attempt `p0-win-separate-identities` (separate CAW wallets/identities for A/B/C) FIRST at hour 0; `p0-floor-one-wallet` is the fallback rung and requires the recorded provisioning failure reason in `docs/evidence/caw-identity-probe.json`. Floor mode copy must say "one owner, three approved Pacts", never "two agents".

## Lease Execution Rules (W1)

- Lease-execution evidence (Beat 4): `/api/lease/execute` output on the pinned target repo + recomputed `leaseRunHash`, Bearer-bound to `(sessionId, spendId, payer, artifactHash)`.
- W3 "agent used what it bought" copy also requires raw MCP Agent Transcript hashes for `tools/list` and `tools/call`, bounded to the pinned manifest.
- The external-workflow chip requires an independent public target repo/commit. Team-owned targets must be labeled and cannot support that chip.
- If missing: UI pane and pitch must say `lease-execution-pending`; no "the agent used what it bought" claim.
- Lease execution is required for the full Economy-track demo story but does not gate `WINNER_CLAIM_ALLOWED` on the payment path itself.

## Downgrade Rules

- Missing CAW deny or allow receipt: `CLAIM_MODE: simulated`
- Missing CAW receipt ingest or manual-only receipts: no CAW proof chip
- Missing same-wallet proof for gate-paid path: `PAYMENT_MODE: mocked` unless `permit-payment-real` is already proven
- Missing approve tx, allowance before/after, approved amount, quote price, policy digest/usage proof, or approve-before-activate order in gate-paid mode: `PAYMENT_MODE: mocked`
- Mixed gate-paid and permit proof branches: `PAYMENT_MODE: mocked`
- Missing mock-token deployment evidence: `TOKEN_MODE: local-mocked`
- Missing artifact preflight or price/source disclosure: no quote signing, no paid-content-unlock claim, no lease-execution claim
- Missing or non-pass Judge Check row: remove that proof chip from the winner claim
- Missing Agent Transcript: no "agent used what it bought" claim
- Missing replay bundle: `WINNER_CLAIM_ALLOWED: false`
- Failed C settlement: no payment-path winner claim
- Real C settlement but missing artifact delivery: `artifact-hash-proof` only
