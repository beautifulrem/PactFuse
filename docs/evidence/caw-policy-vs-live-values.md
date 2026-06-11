# CAW Policy vs Live Values

This matrix prevents the demo from implying CAW enforces session-fresh values that are actually enforced by `ProcurementGate`.

| Value | CAW policy responsibility | Gate responsibility | Evidence |
|---|---|---|---|
| chain | allow target chain | reject wrong `quote.chainId` | raw-ingested CAW receipt + quote verification |
| target | allow mock/test ERC-20 `approve` where spender is `ProcurementGate`, and allow `ProcurementGate.activateTool` | reject direct market/provider calls by design | raw-ingested CAW bypass-deny receipt + approve/activate receipts |
| selector | allow ERC20 `approve(address,uint256)` and `ProcurementGate.activateTool(bytes32,bytes)` only | verify registered spend state and finalized gate event | raw-ingested CAW policy digest |
| tx count | limit approve + activate count | verifier checks actual order | raw-ingested CAW tx-count/expiry receipt + event timeline |
| spendId/paymentAuth | match activate calldata when the Pact is created after spend registration | reject wrong spend state or non-empty auth where unsupported | raw-ingested CAW receipt + `registeredSpend` |
| pactId/toolId/paymentToken/maxPrice/sourceSetHash/sourceHashes | CAW does not claim these values from activate calldata | read registered spend and source registry | `SpendRegistered`, `registeredSpend`, verifier |
| source freshness | CAW does not claim dynamic freshness | check `SourceStateRegistry` inside `activateTool` before funds move | `SourceChallenged`, `SpendTripped`, `SpendSettled` |
| payment amount | cap approve / signed authorization amount at `maxPrice` | enforce `quote.price <= maxPrice`, require observed approval or signed token value to match the settled quote, and transfer exactly `quote.price` | approve tx or permit proof, quote, balance delta |

Claim rule: the public script says CAW constrains where the agent may approve/authorize and spend; `ProcurementGate` constrains whether the source is still live.
