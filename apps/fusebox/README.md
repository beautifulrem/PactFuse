# Fusebox — PactFuse Console

`live/` is the PactFuse Console: an interactive, evidence-backed demo of the
procurement gate. It is a zero-build vanilla ES-module app (no framework, no
dependencies) driven by a single demo state machine.

## Run it

```sh
pnpm demo:console
# → http://127.0.0.1:8123/apps/fusebox/live/
```

Any static server rooted at the repository root works; the app fetches the
checked-in signed proof artifacts from `docs/evidence/live/<session>/`.

## What it demonstrates

Three risk scenarios, each replayed from verified evidence rows of the
authorized Base Sepolia session (real tx hashes, block numbers, CAW audit
evidence — never hand-written values):

1. **Unsafe source → auto-interrupt** — a source challenge finalizes on-chain
   and `ProcurementGate` trips every bound spend before payment (`0 moved`).
2. **Fresh source → settle & deliver** — CAW-policied approval, on-chain
   allowance verification, `SpendSettled`, balance delta, artifact delivery,
   bounded MCP lease run.
3. **Wrong target → policy denial** — a contract call outside the Pact
   allowlist is refused by CAW server-side; no transaction ever exists.

The stage machine (`idle → pending → detected → executing →
success | failed → reset`) drives every visual: the topology map, stage rail,
inspector payload, and appending evidence log. `?fail=1` simulates a transport
failure on the executing step to demonstrate the `failed` state and retry.

## Honesty rules

- With reachable artifacts the header shows `verified evidence` and every
  step binds to real evidence (tx links, event seqs, block numbers).
- If artifacts cannot be fetched the app degrades to a clearly stamped
  `fixture fallback`: zeroed metrics, `(fixture)` outcomes, no proof language.
- The console renders evidence; it never creates proof authority. Claim text
  comes from the signed public claim (`tokenSettlementClaim`,
  `winnerClaimAllowed`) and stays session-scoped.

## Structure

```
live/
  index.html            app shell (semantic landmarks, loading state)
  styles/tokens.css     design tokens (color/spacing/radius/type/motion)
  styles/app.css        layout + components (token-driven, flat)
  src/main.mjs          boot: evidence load, machine wiring
  src/machine.mjs       demo stage machine (pluggable step driver)
  src/data.mjs          evidence adapter: proof bundle → scenarios
  src/symbols.mjs       unified SVG symbol sprite (1.5px stroke system)
  src/components/
    scenario.mjs        trigger panel + stage rail + retry/reset
    flowmap.mjs         abstract system topology (breaker, policy wall…)
    inspector.mjs       event inspector + evidence log
    chrome.mjs          header, metric strip, drawers, footer, toast
```

URL parameters: `?session=0x…` (alternate session), `?artifacts=<base-url>`
(alternate artifact source), `?fail=1` (simulated failure), plus full
`prefers-reduced-motion` support (instant final states, no loops).

## Legacy previews

- `preview/fusebox/index.html` — W8 static wireframe fixture.
- `preview/fusebox-v2/index.html` — W9 skeuomorphic motion prototype.

Both are design history, clearly stamped as fixtures, and carry no proof
authority.
