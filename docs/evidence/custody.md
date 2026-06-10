# Custody Boundary

PactFuse does not custody funds long-term.

Target `gate-paid-artifact-real` path after evidence lock:

1. Agent wallet holds the token.
2. Cobo Pact allows exactly one capped approve to `ProcurementGate`; the verifier and Gate evidence require the observed approved amount to match the settled `quote.price`.
3. Cobo Pact allows exactly one `activateTool` call to `ProcurementGate`.
4. `ProcurementGate` checks registered source state before allowance checks or token transfer.
5. If the source is Active, `ProcurementGate` transfers exactly `quote.price` from agent wallet to market.
6. If the source is Challenged or Revoked, `ProcurementGate` emits `SpendTripped` and no funds move.

Fallback `permit-payment-real` custody rule:

- Only allowed if locked by hour 4 with CAW `message_sign` receipts.
- P0 fallback supports EIP-2612 Permit only.
- `paymentAuthHash`, `gatePaymentAuthorizationHash`, and `tokenAuthHash` must match activation calldata and `SpendSettled`.
- Owner-pre-signed permits outside CAW are fixtures, not a real Cobo payment path.
