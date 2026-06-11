# PactFuse Evidence Directory

This folder separates current checked-in status from future winner-claim evidence.

## Current Status

- `caw-identity-probe.json`: pending same-wallet CAW probe; not real evidence yet.
- `mock-token.json`: pending public testnet mock ERC20 deployment evidence; not real evidence yet.
- `caw-policy-receipt.example.json`: template for normalized CAW receipt capture.
- `receipt-pack.pending.example.json`: schema-only example only; not real evidence yet.
- Artifact preflight / Judge Check / runner heartbeat / CAW receipt ingest / Agent Transcript / replay bundle records are API-backed, but checked-in public evidence remains pending until live Cobo identity, deployed token, and external-chain receipts are captured.
- The backend now requires `caw.allowance.verified` before `token.balance_delta.verified`: CAW live approve call evidence, CAW audit allow usage, approve tx receipt, ERC20 `Approval(owner=agentWallet, spender=ProcurementGate)`, and block-level `allowance` state must all match the registered spend.
- Token settlement proof also requires `caw.activation.verified`: the CAW `activate_tool` contract call must have audit allow usage and a tx hash matching the finalized `SpendSettled` event before ERC20 `Transfer` and `balanceOf` deltas can pass.

Current checked-in public modes stay:

```text
CLAIM_MODE: simulated
PAYMENT_MODE: mocked
TOKEN_MODE: local-mocked
WINNER_CLAIM_ALLOWED: false
```

## Upgrade Rules

- `build-slice-checklist.md`: implementation order and stop rules for the minimum P0 vertical slice.
- `claim-mode.md`: authoritative mode-lock, winner-claim, and downgrade rules.
- `mode-lock-runbook.md`: operator runbook for hour-4 candidate mode, final winner gate, and forbidden upgrades.
- `live-vs-fixture.md`: which proof chips may appear in the winner claim.
- `rerun.md`: clean-state re-run expectations and downgrade outcomes.

## Boundaries

- `caw-policy-vs-live-values.md`: what CAW proves versus what `ProcurementGate` proves.
- `custody.md`: fund custody and non-custodial settlement path.

## Reusable Verification

- `receipt-verifier.md`: minimal P0 `pactfuse verify receipt.json` verifier spec and implementation boundary.
- `../../packages/verifier/pactfuse-verify-receipt.mjs`: importable `verifyEvidence()` plus CLI for receipt-pack mode branches, pending markers, A/B/C proof cardinality, and gate-paid CAW allowlist shape; default mode is a proof-chip gate, `--schema-only` is structural preflight, and the scaffold reports `schemaOk`, `proofChipAllowed`, `finalVerifierComplete`, and refuses `winnerClaimAllowed: true`.
- Receipt-pack hashes must bind CAW policy receipts, CAW operations, payment proof, source proof, chain events, artifact hash, and block window into one `PACTFUSE_EVIDENCE_V1` transcript.
- W2 receipt-pack hashes also bind `priceDisclosure`, `deliveryPreflight`, optional `leaseRunHash`, and Judge Check rows through app-level evidence records before any paid-content-unlock or "used what it bought" claim.
- W3 winner rows additionally require raw CAW receipt ingest, MCP Agent Transcript, independent target repo proof, and a `PACTFUSE_EVIDENCE_V1` replay bundle under one `sessionId`.

Pending, fixture, manual, or blocked evidence cannot support a winner claim.
