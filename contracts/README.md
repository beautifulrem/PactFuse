# PactFuse Contracts

Minimal on-chain proof anchor for the backend evidence path.

- `SourceStateRegistry` records issuer-owned source state and emits the backend-indexed `SourceChallenged(bytes32,bytes32,bytes32)` event.
- `ProcurementGate` registers source-bound spends, trips stale-source activations before token movement, and emits backend-indexed `SpendTripped(bytes32,bytes32)` / `SpendSettled(bytes32,bytes32)` events.
- `PaidArtifactMarket` records delivery pending/delivered/refunded state after a clean gate settlement.
- `SourceFreshGuard` is the reusable guard primitive; `examples/FreshSourceEscrow.sol` proves a second adopter outside the PactFuse purchase path.

Run:

```sh
pnpm test:contracts
```
