/* Evidence adapter. Loads the signed public proof bundle exported by the
 * backend and derives the three demo scenarios from real evidence rows.
 * When the artifacts are unreachable the adapter degrades to a clearly
 * labelled fixture with the same shape, so the UI never silently fakes
 * verified data. */

import { STAGE } from "./machine.mjs";

export const DEFAULT_SESSION = "0x4686a9d093cce9159d3b38085b7dab31fcf394488d956850bbc533b478c1965c";
export const EXPLORER = "https://sepolia.basescan.org";

export const short = (hex, head = 10, tail = 4) =>
  typeof hex === "string" && hex.length > head + tail + 1
    ? `${hex.slice(0, head)}…${hex.slice(-tail)}`
    : String(hex ?? "—");
export const fmt = (n) => Number(n ?? 0).toLocaleString("en-US");
export const txUrl = (hash) => `${EXPLORER}/tx/${hash}`;
export const addrUrl = (a) => `${EXPLORER}/address/${a}`;
export const blockUrl = (n) => `${EXPLORER}/block/${n}`;

export async function loadEvidence({ session, artifactsBase }) {
  const base = artifactsBase ?? new URL(`../../../../docs/evidence/live/${session}/`, import.meta.url).href;
  const bundle = await fetch(new URL("proof-bundle.json", base)).then((r) => {
    if (!r.ok) throw new Error(`proof-bundle ${r.status}`);
    return r.json();
  });
  return deriveModel(bundle);
}

function deriveModel(pb) {
  const rb = pb.replayBundle;
  const events = [...(rb.events ?? [])].sort((a, b) => a.eventSeq - b.eventSeq);
  const byKind = (k) => events.filter((e) => e.kind === k);
  const first = (k) => byKind(k)[0];
  const pay = (e) => e?.payload ?? {};

  const spends = rb.spends ?? [];
  const settledSpend = spends.find((s) => String(s.status).startsWith("settled"));
  const tripped = spends.filter((s) => String(s.status).startsWith("tripped"));
  const trips = byKind("gate.spend_tripped").map((e) => pay(e));
  const challenge = pay(first("source.challenge.confirmed"));
  const challengePending = first("source.challenge.pending");
  const allowance = pay(byKind("caw.allowance.verified").at(-1));
  const settled = pay(first("gate.spend_settled"));
  const delta = pay(first("token.balance_delta.verified"));
  const identity = pay(first("caw.identity.probed"));
  const denyEvent = events.find((e) => /denied/i.test(String(pay(e).status ?? pay(e).result ?? "")));
  const lease = (rb.leaseRuns ?? [])[0];
  const registry = (rb.deploymentRegistry?.entries ?? []).find((x) => x.contractName === "PaymentToken");
  const auditCount = byKind("caw.live.audit.usage.verified").length;
  const settleAmount = delta.marketAfter && delta.marketBefore ? Number(delta.marketAfter) - Number(delta.marketBefore) : 0;
  const judgeRows = rb.judgeCheck?.rows ?? [];
  const blocks = [challenge.blockNumber, settled.blockNumber, ...trips.map((t) => t.blockNumber)].filter(Boolean);

  const ev = (e) => ({ seq: e?.eventSeq, kind: e?.kind, at: e?.createdAt });
  const gate = settled.contractAddress;

  const scenarios = [
    {
      id: "trip",
      title: "Unsafe source → auto-interrupt",
      lede: "A pinned source turns unsafe after quote. The gate must cut payment before funds move.",
      tone: "danger",
      flow: "trip",
      outcome: {
        label: "protected · 0 moved on the challenged source",
        tone: "success",
        detail: `spends ${short(tripped[0]?.spendId, 6, 4)} and ${short(tripped[1]?.spendId, 6, 4)} tripped on-chain before settlement`,
      },
      steps: [
        {
          stage: STAGE.pending,
          flow: "trip-challenge",
          title: "Issuer submits a source challenge",
          detail: "challenge evidence enters the session ledger",
          evidence: { event: ev(challengePending), source: short(challenge.sourceHash, 8, 6) },
          log: [{ text: `source.challenge.pending · seq ${challengePending?.eventSeq}`, meta: "ledger" }],
        },
        {
          stage: STAGE.detected,
          flow: "trip-detect",
          tone: "warning",
          risk: "chain risk event",
          title: "SourceChallenged finalized on Base Sepolia",
          detail: "the indexer confirms the public-chain risk event",
          evidence: { tx: challenge.txHash, block: challenge.blockNumber },
          log: [
            { text: `SourceChallenged · block ${challenge.blockNumber}`, meta: "chain" },
            { text: `tx ${short(challenge.txHash, 12, 6)}`, meta: "chain", link: challenge.txHash },
          ],
        },
        {
          stage: STAGE.executing,
          flow: "trip-cut",
          tone: "danger",
          title: "ProcurementGate interrupts the bound spends",
          detail: "the payment path for every spend pinned to that source is opened",
          evidence: { gate }, // full ProcurementGate address → /address link in the inspector
          log: trips.map((t) => ({
            text: `SpendTripped · ${short(t.spendId, 8, 4)} · block ${t.blockNumber}`,
            meta: "gate",
            link: t.txHash,
          })),
          holdMs: 1900,
        },
      ],
    },
    {
      id: "settle",
      title: "Fresh source → settle & deliver",
      lede: "The source stays clean, so the same gate settles the lease and releases the artifact.",
      tone: "success",
      flow: "settle",
      outcome: {
        label: `settled · ${fmt(settleAmount)} ${registry?.symbol ?? "mUSD"}-atomic moved`,
        tone: "success",
        detail: `artifact unlocked and consumed through a bounded MCP lease run`,
      },
      steps: [
        {
          stage: STAGE.pending,
          flow: "settle-approve",
          title: "Agent approves the gate through CAW",
          detail: "ERC20 approval signed inside the Pact policy boundary",
          evidence: { owner: allowance.owner, spender: allowance.spender }, // full addresses → /address links
          log: [{ text: `caw approve · owner ${short(allowance.owner, 10, 4)}`, meta: "caw" }],
        },
        {
          stage: STAGE.detected,
          flow: "settle-allow",
          tone: "info",
          title: "Allowance verified on-chain",
          detail: `allowance ${fmt(allowance.allowanceBefore)} → ${fmt(allowance.allowanceAfter)} at block ${allowance.blockNumber}`,
          evidence: { tx: allowance.approveTxHash, block: allowance.blockNumber },
          log: [
            { text: `Approval log + allowance state match policy digest`, meta: "verifier" },
            { text: `tx ${short(allowance.approveTxHash, 12, 6)}`, meta: "chain", link: allowance.approveTxHash },
          ],
        },
        {
          stage: STAGE.executing,
          flow: "settle-pay",
          tone: "success",
          title: "activate_tool settles the clean spend",
          detail: `SpendSettled finalized · market balance ${fmt(delta.marketBefore)} → ${fmt(delta.marketAfter)}`,
          evidence: { tx: settled.txHash, block: settled.blockNumber },
          log: [
            { text: `SpendSettled · ${short(settled.spendId, 8, 4)} · block ${settled.blockNumber}`, meta: "gate", link: settled.txHash },
            { text: `ERC20 Transfer + balanceOf delta verified`, meta: "verifier" },
          ],
          holdMs: 1900,
        },
        {
          stage: STAGE.executing,
          flow: "settle-deliver",
          tone: "success",
          title: "Artifact released, lease executed",
          detail: "bearer-bound access token; MCP transcript pinned to the bought artifact",
          evidence: { artifact: short(lease?.artifactHash, 8, 6), run: short(lease?.leaseRunId, 8, 6) },
          log: [
            { text: `artifact ${short(lease?.artifactHash, 12, 6)} unlocked`, meta: "market" },
            { text: `lease run ${short(lease?.leaseRunId, 12, 6)} · succeeded_live_mcp_transcript`, meta: "mcp" },
          ],
        },
      ],
    },
    {
      id: "deny",
      title: "Wrong target → policy denial",
      lede: "The agent is pointed at a contract outside its Pact. CAW must refuse before anything reaches the chain.",
      tone: "warning",
      flow: "deny",
      outcome: {
        label: "denied · request never reached the chain",
        tone: "warning",
        detail: "structured live_denied evidence recorded against the Pact policy digest",
      },
      steps: [
        {
          stage: STAGE.pending,
          flow: "deny-call",
          title: "Agent submits a wrong-target contract call",
          detail: "target address is not in the Pact allowlist",
          evidence: { wallet: identity.walletAddress }, // full CAW wallet address → /address link
          log: [{ text: `contract_call → unlisted target`, meta: "caw" }],
        },
        {
          stage: STAGE.detected,
          flow: "deny-check",
          tone: "warning",
          title: "Pact policy mismatch detected",
          detail: "CAW evaluates target, selector, and limits server-side",
          evidence: { policy: short(pay(denyEvent).policyDigest ?? "", 10, 6) || "pact policy" },
          log: [{ text: `policy check · target ∉ allowlist`, meta: "caw" }],
        },
        {
          stage: STAGE.executing,
          flow: "deny-block",
          tone: "warning",
          title: "CAW rejects the operation",
          detail: "persisted as live_denied audit evidence; no transaction exists",
          evidence: { op: short(pay(denyEvent).operationId ?? denyEvent?.eventId, 10, 6), event: ev(denyEvent) },
          log: [
            { text: `live_denied · op ${short(pay(denyEvent).operationId ?? "", 12, 6)}`, meta: "caw" },
            { text: `deny receipt re-fetched from Cobo audit export at claim time`, meta: "verifier" },
          ],
          holdMs: 1700,
        },
      ],
    },
  ];

  // Mark each scenario's first executing step as the fragile point a transport
  // drop can hit. Whether it actually fails is decided at run time by the
  // machine's one-shot failure arming (the in-UI toggle or ?fail=1) — the model
  // stays pure input config and is never mutated by a render subscriber.
  for (const s of scenarios) {
    const target = s.steps.find((x) => x.stage === STAGE.executing);
    if (target) {
      target.fragile = true;
      target.failReason = "transport drop before the action completed — retry clears it";
    }
  }

  return {
    source: "verified",
    sessionId: rb.sessionId,
    claim: pb.publicClaim,
    judgeRows,
    attestation: pb.verifierAttestation,
    hashes: {
      "public claim": pb.publicClaimHash,
      "proof bundle": pb.proofBundleHash,
      "replay bundle": pb.replayBundleHash,
      "verifier run": pb.verifierRunHash,
      "deployment registry": pb.deploymentRegistryHash,
      "server metadata": pb.serverHash,
      "attestation key": pb.verifierAttestation?.publicKeyHash,
    },
    metrics: [
      { label: "settled & delivered", value: settleAmount, tone: "success", suffix: "atomic" },
      { label: "blocked before payment", value: tripped.reduce((sum, s) => sum + Number(s.maxPriceAtomic ?? 0), 0), tone: "warning", suffix: "atomic" },
      { label: "ledger seq", value: pb.asOfEventSeq ?? events.length },
      { label: "caw audit rows", value: auditCount },
    ],
    facts: { identity, allowance, settled, delta, challenge, lease, registry, gate, blocks },
    scenarios,
  };
}

export function fixtureModel() {
  const mkStep = (stage, flow, title, detail, tone) => ({
    stage,
    flow,
    title,
    detail,
    tone,
    evidence: { mode: "fixture" },
    log: [{ text: `${title.toLowerCase()} (fixture)`, meta: "fixture" }],
  });
  const model = {
    source: "fixture",
    sessionId: DEFAULT_SESSION,
    claim: null,
    judgeRows: [],
    attestation: null,
    hashes: { note: "serve the repo root so docs/evidence/live artifacts can load" },
    metrics: [
      { label: "settled & delivered", value: 0, tone: "success", suffix: "atomic" },
      { label: "blocked before payment", value: 0, tone: "warning", suffix: "atomic" },
      { label: "evidence events", value: 0 },
      { label: "caw audit rows", value: 0 },
    ],
    facts: {},
    scenarios: [
      {
        id: "trip",
        title: "Unsafe source → auto-interrupt",
        lede: "A pinned source turns unsafe after quote. The gate must cut payment before funds move.",
        tone: "danger",
        flow: "trip",
        outcome: { label: "protected · 0 moved (fixture)", tone: "danger", detail: "fixture outcome — no proof authority" },
        steps: [
          mkStep(STAGE.pending, "trip-challenge", "Issuer submits a source challenge", "fixture event", undefined),
          mkStep(STAGE.detected, "trip-detect", "SourceChallenged finalized", "fixture event", "warning"),
          mkStep(STAGE.executing, "trip-cut", "Gate interrupts the bound spends", "fixture event", "danger"),
        ],
      },
      {
        id: "settle",
        title: "Fresh source → settle & deliver",
        lede: "The source stays clean, so the gate settles the lease and releases the artifact.",
        tone: "success",
        flow: "settle",
        outcome: { label: "settled (fixture)", tone: "success", detail: "fixture outcome — no proof authority" },
        steps: [
          mkStep(STAGE.pending, "settle-approve", "Agent approves the gate through CAW", "fixture event", undefined),
          mkStep(STAGE.detected, "settle-allow", "Allowance verified on-chain", "fixture event", undefined),
          mkStep(STAGE.executing, "settle-pay", "activate_tool settles the clean spend", "fixture event", "success"),
          mkStep(STAGE.executing, "settle-deliver", "Artifact released, lease executed", "fixture event", "success"),
        ],
      },
      {
        id: "deny",
        title: "Wrong target → policy denial",
        lede: "The agent is pointed at a contract outside its Pact. CAW refuses before the chain.",
        tone: "warning",
        flow: "deny",
        outcome: { label: "denied (fixture)", tone: "warning", detail: "fixture outcome — no proof authority" },
        steps: [
          mkStep(STAGE.pending, "deny-call", "Agent submits a wrong-target call", "fixture event", undefined),
          mkStep(STAGE.detected, "deny-check", "Pact policy mismatch detected", "fixture event", "warning"),
          mkStep(STAGE.executing, "deny-block", "CAW rejects the operation", "fixture event", "warning"),
        ],
      },
    ],
  };
  for (const s of model.scenarios) {
    const t = s.steps.find((x) => x.stage === STAGE.executing);
    if (t) {
      t.fragile = true;
      t.failReason = "transport drop before the action completed — retry clears it";
    }
  }
  return model;
}
