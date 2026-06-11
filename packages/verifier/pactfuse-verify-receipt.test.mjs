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
	    [
	      "quote hash",
	      (bundle) => {
	        bundle.quotes[0].quoteHash = hex32("bad-quote-hash");
	      },
	      "quoteHash does not recompute",
	    ],
	    [
	      "quote price",
	      (bundle) => {
	        bundle.quotes[0].priceAtomic = "2000";
	      },
	      "quoteHash does not recompute",
	    ],
	    [
	      "quote expiry",
	      (bundle) => {
	        bundle.quotes[0].validUntilBlock = "2";
	      },
	      "quoteHash does not recompute",
	    ],
	    [
	      "artifact token payload",
	      (bundle) => {
	        bundle.artifactAccessTokens[0].artifactPayload.content = "tampered";
	      },
	      "payload hash does not match artifactHash",
	    ],
	  ])("rejects replay bundles with tampered %s", (_label, mutate, expected) => {
    const bundle = replayBundle();
    mutate(bundle);
    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

    expect(result.schemaOk).toBe(false);
    expect(result.proofChipAllowed).toBe(false);
	    expect(result.errors.some((error) => error.includes(expected))).toBe(true);
	  });

	  it("accepts uppercase artifact hex variants after canonical comparison", () => {
	    const bundle = replayBundle();
	    bundle.artifactPreflights[0].artifactHashPreview = uppercaseHexBody(bundle.artifactPreflights[0].artifactHashPreview);
	    bundle.artifactPreflights[0].artifactCid = `sha256:${uppercaseHexBody(bundle.artifactPreflights[0].artifactHashPreview)}`;
	    bundle.quotes[0].artifactCommitment = uppercaseHexBody(bundle.quotes[0].artifactCommitment);
	    bundle.quotes[0].artifactCid = `sha256:${uppercaseHexBody(bundle.quotes[0].artifactCommitment)}`;
	    bundle.artifactAccessTokens[0].artifactHash = uppercaseHexBody(bundle.artifactAccessTokens[0].artifactHash);
	    bundle.artifactAccessTokens[0].artifactCid = `sha256:${uppercaseHexBody(bundle.artifactAccessTokens[0].artifactHash)}`;
	    bundle.artifactAccessTokens[0].artifactPayloadHash = uppercaseHexBody(bundle.artifactAccessTokens[0].artifactPayloadHash);

	    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

	    expect(result.schemaOk).toBe(true);
	    expect(result.errors.some((error) => error.includes("artifact"))).toBe(false);
	  });
	});

function pendingReceipt() {
  return JSON.parse(readFileSync(pendingReceiptPath, "utf8"));
}

function replayBundle() {
  const fetchedAt = "2026-06-11T00:00:00.000Z";
  const createdAt = "2026-06-11T00:00:01.000Z";
  const sessionId = hex32("session-replay-1");
  const operationId = hex32("op-activate");
  const bundleId = hex32("bundle-1");
  const rawReceipt = {
    operationId,
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
    sessionId,
    operationId,
    operationKind: "activate",
    walletId: "wallet-1",
    fetchedAt,
    exportUrl: "https://caw.example.test/audit",
    receipts: [rawReceipt],
    raw: { receipts: [rawReceipt] },
  };
  const rawReceiptHash = hashJson(rawReceipt);
  const rawCawReceiptBundle = {
    bundleId,
    sessionId,
    operationId,
    operationKind: "activate",
    sourceLabel: "caw-api",
    fetchedAt,
    rawBundleHash: hashJson(rawBundle),
    rawBundle,
    createdAt,
  };
  const canonicalBase = {
    bundleId,
    sessionId,
    operationId,
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
	  const spendId = hex32("spend-artifact");
	  const preflightId = hex32("artifact-preflight");
	  const quoteId = hex32("artifact-quote");
	  const tokenId = hex32("artifact-token");
	  const artifactPayload = { artifactType: "source-bound-code-scan-mcp-lease", content: "scan-result" };
	  const artifactHash = hashJson(artifactPayload);
	  const artifactCid = `sha256:${artifactHash}`;
	  const priceDisclosureHash = hex32("price-disclosure");
	  const sourceStateSnapshotHash = hex32("source-state");
	  const quoteHash = hashJson({
	    sessionId,
	    spendId,
	    preflightId,
	    artifactCommitment: artifactHash,
	    priceAtomic: "1000",
	    quoteNonce: "quote-nonce",
	    validUntilBlock: "1000000",
	    artifactCid,
	    priceDisclosureHash,
	    sourceStateSnapshotHash,
	    quoteSignedAfterPreflight: true,
	    modes: lockedRuntimeModes(),
	  });

	  return {
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId,
    summaryMode: true,
    asOfEventSeq: 1,
    asOfMcpAdapterCallCount: 0,
    winnerClaimAllowed: false,
    eventRoot: hashJson(events.map((event) => event.eventHash)),
    agentTranscriptHash: hex32("agent-transcript"),
    events,
    sources: [],
    spends: [],
	    artifactPreflights: [
	      {
	        preflightId,
	        sessionId,
	        spendId,
	        artifactHashPreview: artifactHash,
	        artifactCid,
	        endpointUrl: "https://example.com/artifact.json",
	        priceDisclosureHash,
	        sourceStateSnapshotHash,
	        status: "pending_live_delivery",
	        createdAt,
	      },
	    ],
	    quotes: [
	      {
	        quoteId,
	        sessionId,
	        spendId,
	        preflightId,
	        artifactCommitment: artifactHash,
	        artifactCid,
	        priceDisclosureHash,
	        sourceStateSnapshotHash,
	        priceAtomic: "1000",
	        quoteNonce: "quote-nonce",
	        validUntilBlock: "1000000",
	        quoteHash,
	        status: "mocked_after_preflight_not_chain_settleable",
	        createdAt,
	      },
	    ],
	    artifactAccessTokens: [
	      {
	        tokenId,
	        sessionId,
	        spendId,
	        payer: "0x1234",
	        quoteId,
	        preflightId,
	        artifactHash,
	        artifactCid,
	        artifactPayloadHash: artifactHash,
	        artifactPayload,
	        tokenHash: hex32("artifact-token-hash"),
	        status: "active",
	        issuedByVerifierRunId: hex32("verifier-run"),
	        settlementEventId: hex32("settlement-event"),
	        createdAt,
	      },
	    ],
    mcpAdapterCalls: [],
    cawReceiptOperations: [],
    rawCawReceiptBundles: [rawCawReceiptBundle],
    canonicalCawReceipts: [canonicalReceipt],
    leaseRuns: [],
    judgeCheck: {
      sessionId,
      winnerClaimAllowed: false,
      rows: [
        "caw_boundary",
        "source_challenge",
        "ab_trip",
        "c_settlement",
        "artifact_access",
        "lease_execution",
      ].map((rowId) => ({
        rowId,
        label: rowId,
        status: "pending",
        authority: "proof",
        reason: "pending",
        evidenceEventId: null,
        evidenceUrl: null,
      })),
    },
  };
	}

function lockedRuntimeModes() {
  return {
    CLAIM_MODE: "simulated",
    PAYMENT_MODE: "mocked",
    TOKEN_MODE: "local-mocked",
    IDENTITY_MODE: "pending",
    WINNER_CLAIM_ALLOWED: false,
  };
}

function uppercaseHexBody(value) {
  return `0x${String(value).slice(2).toUpperCase()}`;
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
