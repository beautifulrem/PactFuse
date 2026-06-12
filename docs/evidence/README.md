# PactFuse Evidence Directory

This folder separates current checked-in status from future winner-claim evidence.

## Current Status

- `caw-identity-probe.json`: pending same-wallet CAW probe; not real evidence yet.
- `mock-token.json`: pending public testnet mock ERC20 deployment evidence; not real evidence yet.
- `deployment-registry.example.json`: non-authoritative example of the live deployment registry shape; real deployments must be supplied through `PACTFUSE_DEPLOYMENT_REGISTRY_PATH` or `PACTFUSE_DEPLOYMENT_REGISTRY_JSON`.
- `caw-policy-receipt.example.json`: template for normalized CAW receipt capture.
- `receipt-pack.pending.example.json`: schema-only example only; not real evidence yet.
- Artifact preflight / Judge Check / claim readiness / runner heartbeat / CAW receipt ingest / Agent Transcript / replay bundle / public proof bundle records are API-backed. Replay bundles include indexed page roots, embedded page proofs, deployment registry snapshots, and deployment registry hashes, but checked-in public evidence remains pending until live Cobo identity, deployed token, and external-chain receipts are captured.
- The backend now requires an active CAW Pact policy authority binding before proof-bearing contract calls: policy digest, policy snapshot hash, chain allowlist, target allowlist, selector allowlist, request limit, and expiry must be present and consistent.
- Public-claim readiness rechecks the live CAW wallet endpoint for the identity probe and blocks if the current redacted wallet response hash no longer matches the stored proof event. It also re-fetches the CAW API/export source for the stored deny_probe, approve, and activate_tool raw receipt rows before those receipts can support a public claim.
- The backend requires `caw.allowance.verified` before `token.balance_delta.verified`: CAW live approve call evidence, matching Pact policy digest, CAW audit allow usage, approve tx receipt, ERC20 `Approval(owner=agentWallet, spender=ProcurementGate)`, and block-level `allowance` state must all match the registered spend.
- Token settlement proof also requires `caw.activation.verified`: the CAW `activate_tool` contract call must have the same Pact policy digest, audit allow usage, and a tx hash matching the finalized `SpendSettled` event before ERC20 `Transfer` and `balanceOf` deltas can pass.
- Public replay and proof-bundle exports redact chain provider endpoints to public origins before hashing or publishing. The verifier rejects unredacted `chainProviderEndpoint` values and final proof stays closed if chain proof events do not match the trusted provider snapshot.
- Public claim/proof-bundle exports include `tokenSettlementClaim` so mock ERC20 fallback evidence stays labeled as `live-mock-erc20-fallback` instead of being overclaimed as official USDC settlement.
- Proof provider status snapshots redact endpoints and secret-shaped failure text before they are exposed through `/readyz`, verifier raw output, claim readiness, or public proof bundles.
- Source manifest URLs and artifact delivery endpoint URLs are public evidence fields. They must be stable HTTP(S) URLs with public hostnames and without credentials, query strings, or fragments; localhost, private, reserved, internal, signed, and query-token URLs are rejected before replay/proof-bundle export.
- CAW live response payloads are string-redacted before storage and replay/proof-bundle export, including neutral fields that contain URLs, bearer values, api keys, passwords, tokens, or secret-shaped text.

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
- `../../packages/verifier/pactfuse-verify-receipt.mjs`: importable `verifyEvidence()` plus CLI for receipt-pack mode branches, pending markers, A/B/C proof cardinality, replay-page hashes, CAW allowlist shape, and final replay claim blockers; default mode is a proof-chip gate, `--schema-only` is structural preflight, public proof bundles require `PACTFUSE_TRUSTED_PROOF_KEY_HASHES` or `--trusted-proof-key-hash`, and the verifier reports `schemaOk`, `proofChipAllowed`, `finalVerifierComplete`, `winnerClaimAllowed`, and `proofCompletenessErrors`.
- `/api/v1/evidence/claim-readiness`: operator-only derivation of current and target public modes from live evidence gates; it is a readiness report, not a manual mode override.
- `/api/v1/evidence/public-claim`: the operator-only fail-closed public-claim gate; it returns `authorized_public_claim` only when readiness, replay hash, final verifier authority, and a trusted proof signing key all pass together.
- `/api/v1/evidence/proof-bundle`: the operator-only `PACTFUSE_PUBLIC_PROOF_BUNDLE_V1` export for the latest proof-authorized public claim, or for a historical proof-authorized event when `publicClaimEventId=<event_id>` is supplied; it binds the public claim hash, public-claim event hash, frozen replay bundle, verifier run hash, provider status hash, deployment registry hash, server metadata hash, verifier attestation signature, and proof bundle hash. Replay data, provider status, deployment registry, and server metadata are captured in the authorization event and reused on read. Provider endpoints are public-origin redacted before inclusion. `server.generatedAt` is fixed to the proof authorization event timestamp, not the read time. Historical proof-bundle reads survive proof signing private-key rotation, later non-event rows, and later session verification/advisory events as long as the attested public key hash remains trusted.
- Mock-token public claims and final replay verification require a live deployment registry entry binding the payment token address to chain id, non-zero deployment transaction hash, public HTTPS explorer URL, decimals, non-zero code hash, and a recorded failed official-USDC probe reason. Official-USDC public claims require chain id `84532`, a passed official-USDC probe, and a matching live registry entry.
- Receipt-pack hashes must bind CAW policy receipts, CAW operations, payment proof, source proof, chain events, artifact hash, and block window into one `PACTFUSE_EVIDENCE_V1` transcript.
- W2 receipt-pack hashes also bind `priceDisclosure`, `deliveryPreflight`, optional `leaseRunHash`, and Judge Check rows through app-level evidence records before any paid-content-unlock or "used what it bought" claim.
- W3 winner rows additionally require raw CAW receipt ingest, MCP Agent Transcript, independent target repo proof, and a `PACTFUSE_EVIDENCE_V1` replay bundle under one `sessionId`.

Pending, fixture, manual, or blocked evidence cannot support a winner claim.
