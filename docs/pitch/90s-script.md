# PactFuse 90-Second Judge Script

Use this only as a script template. The operator must choose the version that matches current evidence modes.

## Current Safe Version

PactFuse is being built as a Cobo Agentic Wallet procurement fuse for agent tool leases.

The current checked-in state is still simulated and mocked. The live proof files are pending, so we are not claiming a winner-grade Cobo path yet.

The differentiation is still a target design until the same-wallet CAW probe, Gate trip/settle events, CAW receipt ingest, artifact preflight, full verifier, Bearer-token artifact proof, MCP Agent Transcript, replay bundle, and Judge Check rows are live.

The target demo is narrow: one signed MCP manifest is challenged, two dependent source-bound tool leases trip before payment, and one clean lease settles through `ProcurementGate`.

The important boundary is that the agent does not pay the tool provider directly. Cobo CAW approves only the ERC20 `approve` and `ProcurementGate.activateTool` path. The Gate then enforces source freshness and exact settlement.

## Final Winner Version

Read this version only after `docs/evidence/mode-lock-runbook.md` final winner gate passes.

PactFuse lets an agent buy a paid MCP tool lease without trusting yesterday's tool source.

This Cobo CAW policy allows exactly two calls: approve the Gate for the quoted amount, then activate the lease through `ProcurementGate`. A direct provider payment or wrong target is denied by CAW.

Now the issuer challenges the signed MCP manifest. Look at why: the manifest we approved had two read-only tools; the version behind the challenge added `write_file`. The Gate checks source freshness at settlement, so two dependent leases trip before token movement — they would have paid for a tool that can now write to your repo. A third lease bound to a clean source still settles, and the artifact API releases only the receipt pack whose hash matches the paid quote.

And the agent uses what it bought: the leased scanner runs on an independent pinned public repo, bounded to exactly the tools in the pinned manifest. The raw MCP transcript shows `tools/list`, then `tools/call`. Paid, delivered, used.

Before the clean payment, the price/source chip shows the quote, cap, token, and pinned manifest source. The quote exists only because artifact preflight passed.

The proof surface is the whole demo: raw-ingested Cobo deny/approve/allow receipts, `SourceChallenged` with the manifest diff, two `SpendTripped` events, one `SpendSettled` plus balance delta, a preflighted verified artifact receipt pack, the MCP Agent Transcript, the live scan output, a replay bundle hash, and the Judge Check page where each row links to raw evidence.

Fusebox should look like an industrial fuse table, not a generic dashboard: the Cobo authority rail feeds three fuse lanes, the challenged source blows A and B before payment, and the clean C lane stays closed through settlement, receipt unlock, and lease execution.

The reusable primitive is small: PactFuse Guard Kit — a ten-line `SourceFreshGuard` modifier any settlement contract can adopt against the same registry, a second adopter example, a Cobo Pact template, a receipt verifier path, an Agent Transcript pattern, and a Judge Check output for source-bound paid tool leases.

## Never Say

- Do not say this is independent fraud detection. It is issuer-declared source freshness at settlement.
- Do not present a manifest drift observation as fraud or tamper detection; it is an advisory-only signal when `DRIFT_WATCH_MODE: advisory` is enabled, and it cannot trip a fuse or change a proof row.
- Do not call a mock token USDC.
- Do not say `schemaOk` or `proofChipAllowed` is winner-grade verification.
- Do not claim paid-content unlock unless Bearer-token artifact delivery is live.
- Do not claim the quote was safe unless artifact preflight and price/source disclosure are live.
- Do not claim a proof chip if the matching Judge Check row is not `pass`.
- Do not claim a CAW proof chip from hand-entered receipts; require raw CAW ingest.
- Do not say "agent used what it bought" without a raw MCP Agent Transcript.
- Do not use a team-owned target repo as an external-workflow proof chip.
- Do not show speculative loss-prevented numbers; show only observed blocked spend amount and denied capability delta.
- Do not present `TARGET_*` candidate values as current public modes.
- Do not claim the lease ran unless the `/api/lease/execute` output is live; say `lease-execution-pending` otherwise.
- Do not say "two agents" in `p0-floor-one-wallet` mode; say "one owner, three approved Pacts."
- Do not present a team-authored manifest delta as a real third-party version history; label it "illustrative delta (team-authored)."
