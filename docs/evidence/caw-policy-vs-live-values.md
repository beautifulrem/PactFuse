# CAW Policy vs Live Values

This matrix prevents the demo from implying CAW enforces session-fresh values that are actually enforced by `ProcurementGate`.

| Value | CAW policy responsibility | Gate responsibility | Evidence |
|---|---|---|---|
| chain | allow target chain | reject wrong `quote.chainId` | raw-ingested CAW receipt + quote verification |
| target | allow mock/test ERC-20 `approve` where spender is `ProcurementGate`, and allow `ProcurementGate.activateTool` | reject direct market/provider calls by design | raw-ingested CAW bypass-deny receipt + approve/activate receipts |
| selector | allow `approve` and `activateTool` only | decode stable params | raw-ingested CAW policy digest |
| tx count | limit approve + activate count | verifier checks actual order | raw-ingested CAW tx-count/expiry receipt + event timeline |
| pactId/toolId/paymentToken/maxPrice | stable `params_match` when available | calldata/storage cross-check | raw-ingested CAW receipt + `registeredSpend` |
| spendId/sourceSetHash/sourceHashes | not pinned in pre-approved Pact | read registered spend and source registry | `SpendRegistered`, `registeredSpend`, verifier |
| source freshness | CAW does not claim dynamic freshness | check `SourceStateRegistry` inside `activateTool` before funds move | `SourceChallenged`, `SpendTripped`, `SpendSettled` |
| payment amount | cap approve / signed authorization amount at `maxPrice` | enforce `quote.price <= maxPrice`, require observed approval or signed token value to match the settled quote, and transfer exactly `quote.price` | approve tx or permit proof, quote, balance delta |

Claim rule: the public script says CAW constrains where the agent may approve/authorize and spend; `ProcurementGate` constrains whether the source is still live.
