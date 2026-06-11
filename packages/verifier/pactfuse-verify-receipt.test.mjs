import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyEvidence } from "./pactfuse-verify-receipt.mjs";

const pendingReceiptPath = new URL("../../docs/evidence/receipt-pack.pending.example.json", import.meta.url);
const verifierPath = new URL("./pactfuse-verify-receipt.mjs", import.meta.url);
const pendingReceiptFile = fileURLToPath(pendingReceiptPath);
const verifierFile = fileURLToPath(verifierPath);

describe("pactfuse receipt verifier contract", () => {
  it("keeps schema-only separate from proof-chip authority", () => {
    const receipt = pendingReceipt();
    const result = verifyEvidence(receipt, { cliMode: "schema-only" });

    expect(result.schemaOk).toBe(true);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.winnerClaimAllowed).toBe(false);

    const schemaOnlyCli = spawnSync(process.execPath, [verifierFile, "--schema-only", pendingReceiptFile], {
      encoding: "utf8",
    });
    const proofCli = spawnSync(process.execPath, [verifierFile, pendingReceiptFile], { encoding: "utf8" });
    const schemaOnlyJson = JSON.parse(schemaOnlyCli.stdout);

    expect(schemaOnlyCli.status).toBe(0);
    expect(schemaOnlyJson.schemaOk).toBe(true);
    expect(schemaOnlyJson.proofChipAllowed).toBe(false);
    expect(schemaOnlyJson.finalVerifierComplete).toBe(false);
    expect(proofCli.status).toBe(1);
  });

  it.each([
    ["root winner flag", (receipt) => void (receipt.winnerClaimAllowed = true)],
    ["status field winner flag", (receipt) => void (receipt.statusFields.winnerClaimAllowed = true)],
    [
      "claim winner flag with real-evidence marker",
      (receipt) => {
        receipt.statusFields.isRealEvidence = true;
        receipt.claim = { winnerClaimAllowed: true };
      },
    ],
  ])("rejects %s", (_label, mutate) => {
    const receipt = pendingReceipt();
    mutate(receipt);
    const result = verifyEvidence(receipt, { cliMode: "proof-chip" });

    expect(result.requestedWinnerClaimAllowed).toBe(true);
    expect(result.winnerClaimAllowed).toBe(false);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.errors).toContain(
      "this scaffold is structural-only and refuses winnerClaimAllowed: true; run the full chain/signature/hash verifier before winner claims",
    );
  });

  it("accepts a structurally bound replay bundle while keeping proof-chip authority closed", () => {
    const bundle = replayBundle();
    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

    expect(result.schemaOk).toBe(true);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.errors).toContain(
      "current replay verifier preflight is structural-only; final chain, signature, CAW policy authority, tx/log, and Judge Check recomputation is incomplete",
    );
    expect(result.schemaErrors).toEqual([]);
  });

  it.each([
    [
      "raw bundle hash",
      (bundle) => {
        bundle.rawCawReceiptBundles[0].rawBundleHash = hex32("bad-raw-bundle");
      },
      "rawBundleHash does not match rawBundle",
    ],
    [
      "canonical receipt hash",
      (bundle) => {
        bundle.canonicalCawReceipts[0].canonicalReceiptHash = hex32("bad-canonical");
      },
      "canonicalReceiptHash does not recompute",
    ],
    [
      "raw receipt membership",
      (bundle) => {
        bundle.canonicalCawReceipts[0].rawReceiptHash = hex32("missing-raw");
      },
      "does not match any raw receipt hash",
    ],
    [
      "missing raw bundle body",
      (bundle) => {
        delete bundle.rawCawReceiptBundles[0].rawBundle;
      },
      "rawBundle cannot be canonicalized",
    ],
  ])("rejects replay bundles with tampered %s", (_label, mutate, expected) => {
    const bundle = replayBundle();
    mutate(bundle);
    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

    expect(result.schemaOk).toBe(false);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.errors.some((error) => error.includes(expected))).toBe(true);
  });
});

function pendingReceipt() {
  return JSON.parse(readFileSync(pendingReceiptPath, "utf8"));
}

function replayBundle() {
  const fetchedAt = "2026-06-11T00:00:00.000Z";
  const createdAt = "2026-06-11T00:00:01.000Z";
  const rawReceipt = {
    operationId: "op-activate",
    operationKind: "activate",
    walletAddress: "0x1111111111111111111111111111111111111111",
    policyDigest: hex32("policy"),
    paramsDigest: hex32("params"),
    requestId: "req-1",
    effect: "allow",
    status: "succeeded",
    target: "0x2222222222222222222222222222222222222222",
    selector: "0x12345678",
    txHash: hex32("tx"),
    txCount: "1",
    expiry: "2026-06-12T00:00:00.000Z",
  };
  const rawBundle = {
    source: "caw-api",
    sourceLabel: "caw-api",
    sessionId: "session-replay-1",
    operationId: "op-activate",
    operationKind: "activate",
    walletId: "wallet-1",
    fetchedAt,
    exportUrl: "https://caw.example.test/audit",
    receipts: [rawReceipt],
    raw: { receipts: [rawReceipt] },
  };
  const rawReceiptHash = hashJson(rawReceipt);
  const rawCawReceiptBundle = {
    bundleId: "bundle-1",
    sessionId: "session-replay-1",
    operationId: "op-activate",
    operationKind: "activate",
    sourceLabel: "caw-api",
    fetchedAt,
    rawBundleHash: hashJson(rawBundle),
    rawBundle,
    createdAt,
  };
  const canonicalBase = {
    bundleId: "bundle-1",
    sessionId: "session-replay-1",
    operationId: "op-activate",
    operationKind: "activate",
    sourceLabel: "caw-api",
    walletAddress: rawReceipt.walletAddress,
    target: rawReceipt.target,
    selector: rawReceipt.selector,
    requestId: rawReceipt.requestId,
    effect: "allow",
    status: "succeeded",
    policyDigest: rawReceipt.policyDigest,
    paramsDigest: rawReceipt.paramsDigest,
    txHash: rawReceipt.txHash,
    txCount: "1",
    expiry: rawReceipt.expiry,
    fetchedAt,
    createdAt,
  };
  const canonicalReceipt = {
    rawReceiptHash,
    canonicalReceiptHash: hashJson(canonicalBase),
    ...canonicalBase,
  };
  const events = [
    {
      seq: 1,
      type: "caw.receipt.ingested.raw",
      eventHash: hex32("event-1"),
    },
  ];

  return {
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId: "session-replay-1",
    summaryMode: "full",
    asOfEventSeq: 1,
    eventRoot: hashJson(events.map((event) => event.eventHash)),
    agentTranscriptHash: hex32("agent-transcript"),
    events,
    mcpAdapterCalls: [],
    cawReceiptOperations: [],
    rawCawReceiptBundles: [rawCawReceiptBundle],
    canonicalCawReceipts: [canonicalReceipt],
    judgeCheck: {
      schema: "PACTFUSE_JUDGE_CHECK_V1",
      sessionId: "session-replay-1",
      createdAt,
      verdict: "blocked",
      checks: [],
    },
  };
}

function canonicalizeJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  return `{${Object.keys(value)
    .filter((key) => value[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`)
    .join(",")}}`;
}

function hashJson(value) {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function hex32(seed) {
  return `0x${createHash("sha256").update(seed).digest("hex")}`;
}
