# PactFuse

Target demo after evidence lock: one challenged signed MCP manifest trips two Cobo-approved tool leases before payment; a clean third lease settles — **and the purchased lease actually runs**: the agent executes the leased code-scan on a pinned public repo, bounded to exactly the tools in the pinned manifest.

Track: Cobo Agentic Wallet

The 90-second loop (target): (1) bypass attempt → CAW deny; (2) judge challenges the manifest → main-stage diff shows the later version added `write_file` → two dependent leases trip, no token moves; (3) clean lease settles through `ProcurementGate`; (4) the lease executes — scan output on a real repo, "write capability absent per pinned manifest."

One-command judge run (after build): `./demo/run-judge.sh` — starts Fusebox + `pactfuse-api`, prints primary evidence links, Judge Check, replay bundle hash, and runs the receipt verifier.

Winner-corpus hardening now locked (design only): artifact preflight before quote signing, refund/void path for paid-but-undelivered artifacts, agent-visible price/source disclosure, runner heartbeat, one-click Judge Check, CAW receipt ingest, raw MCP Agent Transcript, clean replay bundle, independent target repo proof, and the P0 **PactFuse Guard Kit** packaging. See `docs/strategy/winner-corpus-gap-fix-2026-06-10.md`.

Backend architecture lock: the implementation shape is a single `apps/pactfuse-api` TypeScript service (API + worker + indexer + CAW receipt ingest + lease runner + SSE + verifier adapter) over an append-only evidence store, plus Foundry contracts and an importable verifier. W7 locks the `/api/v1` service contract; W8.1 hardens proof authenticity, finality/reorg handling, fail-closed behavior, and the observed-vs-finalized state split. See `research/pactfuse-backend-w7-winner-parity-technical-plan-2026-06-10.md` and `research/pactfuse-backend-w8-hardening-2026-06-10.md`.

W8.1/W9 frontend/UI lock: Fusebox is a procurement breaker panel, not a generic Web3 dashboard or static proof page. The first viewport is dominated by a live fuse board: Cobo authority enters on the blue rail, challenged A/B cartridges open before payment with cold `0 moved` current, clean C uses green settlement current, and the proof tray/evidence sheets expand only on demand. W9 elevates the rendered surface to the dark machined-instrument prototype in `apps/fusebox/preview/fusebox-v2/index.html`. Motion is event-bound; prototype/fixture visuals are never proof authority and must remain globally stamped as not live evidence. Production frontend calls target the W7.1 `/api/v1` contract. See `research/pactfuse-frontend-w8-winner-parity-ui-plan-2026-06-10.md` and `research/pactfuse-frontend-w9-visual-elevation-2026-06-11.md`.

Current implementation stack lock: hybrid protocol product, not native app, browser extension, pure CLI, or pure web dashboard. Use Node 22, pnpm + turbo, Hono, zod, Drizzle + `node:sqlite` WAL, viem v2, Foundry, Vite + React 19 SPA, Tailwind v4, shadcn/Radix, TanStack Query, `motion`, and a thin MCP adapter. This supersedes older Next.js App Router / `better-sqlite3` recommendations where they conflict. See `research/pactfuse-stack-form-review-v2-2026-06-10.md`.

Backend mutation routes fail closed unless operator role tokens are configured (`PACTFUSE_OPERATOR_TOKEN`, optional `PACTFUSE_CHALLENGE_SUBMITTER_TOKEN`, optional `PACTFUSE_ARTIFACT_SIGNER_TOKEN`). Local-only test/dev runs can explicitly set `PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS=true`; do not use that bypass for public demos or hosted services.

W6 full-stack rereview lock: a fresh winner-corpus pass (twelve closest verified peer winners) closed the defects that survived W1-W5 — deterministic session-create idempotency, an SSE evidence stream with polling fallback and zero proof authority, a binding live-state ladder (CAW-approval/tx-pending/indexing waiting states with timers, error chips, de-energized empty board), a flag-gated advisory manifest drift watcher that can never trip or touch proof rows, issuer-griefing and who-pays hostile-judge answers, deterministic-runner labeling (GLM is P1-only), lease-runner egress and tool-output trust invariants, performance/console acceptance gates, the demo fallback ladder, and a hardened fuse-cartridge visual contract with the fixture redrawn to satisfy it. See `research/pactfuse-w6-fullstack-rereview-2026-06-10.md`.

Current checked-in evidence status:

```text
CLAIM_MODE: simulated
PAYMENT_MODE: mocked
TOKEN_MODE: local-mocked
IDENTITY_MODE: pending
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: false
```

What this blocks right now:

| Current blocker | Blocked public claim |
|---|---|
| `IDENTITY_MODE: pending` | no current Cobo same-wallet or `p0-floor-one-wallet` claim |
| `PAYMENT_MODE: mocked` | no current `gate-paid-artifact-real` or paid-content-unlock claim |
| `TOKEN_MODE: local-mocked` | no current public token settlement claim |
| pending receipt pack / `proofChipAllowed: false` | no receipt-pack proof rail/Judge Check pass |
| no live contracts/API and only a fixture Fusebox preview | differentiation is a target design, not a demonstrated live system |

Mode-lock template only. Do not publish or copy this block as current status until `docs/evidence/mode-lock-runbook.md` candidate gates pass:

```text
TARGET_CLAIM_MODE: caw-target-real
TARGET_PAYMENT_MODE: gate-paid-artifact-real
TARGET_TOKEN_MODE: official-testnet-usdc (fallback rung: mock-test-token, deployment tx shown)
TARGET_IDENTITY_MODE: p0-win-separate-identities (fallback rung: p0-floor-one-wallet)
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: false
```

Final winner banner template only. Do not publish or copy this block until all `docs/evidence/claim-mode.md` upgrade rules pass: identity probe, token evidence, CAW policy receipt, wrong-target deny, clean allow, A/B trips, C settlement, Bearer-token artifact access, lease-execution evidence (or honest `lease-execution-pending`), and receipt-pack verification.

```text
CLAIM_MODE: caw-target-real
PAYMENT_MODE: gate-paid-artifact-real
TOKEN_MODE: <locked at hour 4: official-testnet-usdc | mock-test-token>
IDENTITY_MODE: <locked at hour 4: p0-win-separate-identities | p0-floor-one-wallet>
FUSEREFLEX_MODE: none
WINNER_CLAIM_ALLOWED: true
```

Target protected path after final evidence lock:

```text
Cobo CAW contract_call -> ERC20.approve(ProcurementGate, quote.price)
-> Cobo CAW contract_call -> ProcurementGate.activateTool(..., signedQuote, empty paymentAuth)
-> PaidArtifactMarket
```

Target behavior: PactFuse is a procurement fuse for agent tool leases. A Cobo-approved agent can buy a source-bound code-scan MCP lease only through `ProcurementGate`. If the signed source behind that lease is challenged before settlement, the Gate trips the spend before token movement; a clean-source lease still settles, unlocks the paid artifact receipt pack, and is executed against the pinned target repo (spec §16.2).

Reusable primitive: `SourceFreshGuard` — a ~10-line modifier any settlement contract can adopt against the same `SourceStateRegistry` (spec §14.1); the repo ships a second adopter example (`FreshSourceEscrow`) plus a target-agnostic Pact template renderer.

## Demo Evidence

Winner-claim evidence must be live and re-runnable:

- Cobo Pact boundary receipt pack: deny request id, approve tx, clean allow receipt, policy digest, tx-count/expiry.
- `SourceChallenged` tx from a source issuer key that is visibly separate from owner/runner.
- Two A/B `SpendTripped` events for spends bound to the challenged source.
- Clean C `SpendSettled` tx plus payer/market balance delta.
- Downloaded receipt pack whose artifact hash matches the signed quote, plus Bearer-token access proof bound to `(sessionId, spendId, payer, artifactHash)`.
- Lease execution output on the pinned target repo plus `leaseRunHash` (or honest `lease-execution-pending` label).
- Raw MCP Agent Transcript: `tools/list` + `tools/call` hashes proving the clean lease was consumed through the pinned manifest tool surface.
- CAW receipt ingest bundle: raw API/export receipts, JCS hashes, and operation links; manually edited receipt rows cannot pass proof rail nodes or Judge Check rows.
- Clean replay bundle: one `PACTFUSE_EVIDENCE_V1` `sessionId` tying config, raw CAW receipts, tx/log refs, artifact preflight, agent transcript, lease run, Judge Check, and verifier output.
- Artifact preflight row proving quote signing happened only after source fetch, endpoint reachability, lease dry-run, artifact hash preview, and price/source disclosure hash passed.
- Judge Check row set: CAW boundary, source challenge, A/B trip, C settlement, artifact access, lease execution; the seven proof slots map onto these six rows, and every winner row must be `pass`. Agent Transcript, replay bundle, raw CAW receipts, and verifier output are secondary audit links, not extra proof rows.
- Manifest source pair: real third-party pinned commit as the good source; challenge `evidenceRef` prefers a real later commit (spec §16.1; team-authored deltas must be labeled).

Evidence docs:

- Clean re-run plan: `docs/evidence/rerun.md`
- Evidence directory index: `docs/evidence/README.md`
- P0 build slice checklist: `docs/evidence/build-slice-checklist.md`
- Live vs fixture rules: `docs/evidence/live-vs-fixture.md`
- Claim mode rules: `docs/evidence/claim-mode.md`
- Mode-lock runbook: `docs/evidence/mode-lock-runbook.md`
- CAW vs Gate enforcement boundary: `docs/evidence/caw-policy-vs-live-values.md`
- CAW policy receipt template: `docs/evidence/caw-policy-receipt.example.json`
- Custody boundary: `docs/evidence/custody.md`
- Current CAW identity probe status: `docs/evidence/caw-identity-probe.json`
- First CAW identity probe template: `docs/evidence/caw-identity-probe.example.json`
- Current mock token status: `docs/evidence/mock-token.json`
- Pending receipt-pack example: `docs/evidence/receipt-pack.pending.example.json`
- Reusable receipt verifier spec: `docs/evidence/receipt-verifier.md`
- Local verifier preflight script: `packages/verifier/pactfuse-verify-receipt.mjs`
- Competitive differentiation: `docs/strategy/competitive-differentiation.md`
- Winner-corpus gap fix: `docs/strategy/winner-corpus-gap-fix-2026-06-10.md`
- Evidence-gated judge script: `docs/pitch/90s-script.md`
- Fixture Fusebox preview (legacy W8 static): `apps/fusebox/preview/fusebox/index.html`
- Fusebox v2 visual prototype (W9 motion preview): `apps/fusebox/preview/fusebox-v2/index.html`
- Fusebox v2 rendered screenshot: `docs/evidence/screenshots/fusebox-v2-prototype.fixture.png`
- Fuse Stage SVG prototype: `docs/evidence/fuse-stage-prototype.svg`

Pact templates:

- Target public path template: `pact-template/gate-paid-artifact-real.json`
- A/B/C Pact renderer: `pact-template/render-pact-series.mjs`
- Appendix fallback: `pact-template/permit-payment-real.appendix.json`

Full technical spec: `research/pactfuse-v8-final-technical-spec-2026-06-10.md`

Final backend architecture plan: `research/pactfuse-backend-w8-hardening-2026-06-10.md`

Backend service-contract lock: `research/pactfuse-backend-w7-winner-parity-technical-plan-2026-06-10.md`

Previous W4 backend architecture plan: `research/pactfuse-backend-architecture-final-technical-plan-2026-06-10.md`

Final frontend/UI visual lock: `research/pactfuse-frontend-w9-visual-elevation-2026-06-11.md`

Frontend/UI concept lock: `research/pactfuse-frontend-w8-winner-parity-ui-plan-2026-06-10.md`

Previous W5/W6 frontend/UI plan: `research/pactfuse-frontend-ui-final-technical-plan-2026-06-10.md`

Implementation form and stack lock: `research/pactfuse-stack-form-review-v2-2026-06-10.md`

Previous stack review: `research/pactfuse-implementation-form-stack-review-2026-06-10.md`

Full frontend/backend architecture review: `research/pactfuse-full-architecture-review-2026-06-10.md`

W6 full-stack rereview: `research/pactfuse-w6-fullstack-rereview-2026-06-10.md`

## Boundaries

- A mock token on public testnet must be labeled `public testnet mock ERC20`, never USDC.
- If `docs/evidence/caw-identity-probe.json` does not prove same-wallet approve owner, activation payer, `SenderProbe` sender, and `SourceBoundSpend.agentWallet` by hour 4, the public payment mode must downgrade to `mocked` or to an already-proven `permit-payment-real` fallback.
- CAW constrains target, selector, call count, expiry, and capped stable params. `ProcurementGate` enforces source freshness and exact quote settlement; `PaidArtifactMarket` must preflight delivery before quote signing and refund/void failed delivery paths before any paid-content-unlock claim.
- PactFuse is issuer-declared source freshness, not independent fraud detection. If the issuer refuses to challenge or is compromised, P0 does not detect it.
- Fixture, manual, pending, or blocked proof rail nodes / Judge Check rows cannot appear in the winner claim.
