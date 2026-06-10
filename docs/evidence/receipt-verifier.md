# PactFuse Receipt Verifier

P0 includes one reusable verification artifact: a receipt-pack verifier command.

```bash
pactfuse verify receipt.json
```

Current local schema-only scaffold:

```bash
node packages/verifier/pactfuse-verify-receipt.mjs --schema-only docs/evidence/receipt-pack.pending.example.json
```

Default CLI mode is a proof-chip gate and exits nonzero unless `proofChipAllowed: true`. Use `--schema-only` only when you want a structural preflight.

The scaffold is intentionally conservative. It exports `verifyEvidence(input, options)` and the CLI prints `schemaOk`, `proofChipAllowed`, `finalVerifierComplete`, and `winnerClaimAllowed`. `schemaOk` only means the receipt is structurally parseable for the selected payment branch. `proofChipAllowed` is false when pending, fixture, manual, blocked, placeholder, unexpected null markers, missing A/B/C proof cardinality, missing dynamic CAW/Gate bindings, or missing final chain/signature/hash recomputation remain. The scaffold refuses `winnerClaimAllowed: true` because it is not the final chain/signature/hash verifier required for `WINNER_CLAIM_ALLOWED: true`.

W1 `rootMode` rule (spec §13): receipts carry `rootMode: "none" | "published"`. In `"none"` (P0 default — no `BlastRadiusRoot` published) the verifier does not require top-level `affectedSpendIdsRoot` or per-spend `membershipBranch` fields; it reconstructs the affected set (and computes the deterministic root) from `SpendRegistered` logs. In `"published"` (P1) all root/branch/publisher fields are required and validated. The scaffold script already gates these structural requirements on `rootMode`.

Final winner-grade verifier checks:

- recompute `sourceRefHash`, canonical source JSON hash, source document hash, and recovered issuer address
- rehash challenge reason JSON and verify the issuer matches the registered source issuer
- recompute sorted `sourceHashesHash`, `sourceSetHash`, affected leaves, and C negative proof; reconstruct the affected set from `SpendRegistered` logs (rootMode "none") or additionally recompute affected root + A/B branches (rootMode "published")
- (when `leaseRun` present) recompute `leaseRunHash` from the JCS lease-run payload and check the pinned target repo/commit
- verify `agentTranscript` hashes from raw MCP JSON-RPC `tools/list` and `tools/call`, and ensure the tool set is bounded to the pinned manifest before any "agent used what it bought" chip
- verify the external target repo is independent for the external-workflow chip; team-owned targets are downgraded even when the scan itself is real
- recompute `priceDisclosure.displayedDisclosureHash` and verify the displayed quote price/source fields match the receipt
- verify `deliveryPreflight.quoteSignedAfterPreflight === true` and fail paid-content-unlock eligibility when preflight rows are absent or blocked
- verify CAW policy receipts for request id, target, selector, policy digest, expiry, tx/request count limits, and usage
- verify `cawReceiptIngest.manualEntry === false`, source is API/export in winner mode, and every CAW operation references a raw ingested receipt hash
- canonicalize only `canonicalReceipt` inside CAW policy receipt files; wrapper/status fields are never part of the hash preimage
- canonicalize each `cawOperation` and the mode-specific `paymentProof`, then bind those hashes with chain events, artifact payload hash, Agent Transcript hash, Judge Check hash, and receipt-pack hash into one `PACTFUSE_EVIDENCE_V1` replay bundle
- require gate-paid payment proof to include `approveTxHash`, `allowanceBefore`, `allowanceAfter`, `approvedAmount`, `quotePrice`, `policyTxCount`, and `approveBeforeActivate: true`
- order A/B `SpendTripped` tx hashes by `(blockNumber, transactionIndex, logIndex, txHash)` before transcript hashing
- fail proof-chip eligibility if any included proof chip is `pending`, `fixture`, `manual`, `blocked`, placeholder, or unexpected null evidence
- fail winner proof-chip eligibility if the app-level Judge Check row for that chip is missing or not `pass`

This can be a local `tsx`/`node` command in P0. It does not need a published SDK. The current script implements structural and fail-closed proof-chip eligibility checks above the final checklist; before a winner claim, it must be extended or paired with the app verifier to perform the full recomputation list and then stop refusing `winnerClaimAllowed: true`.
