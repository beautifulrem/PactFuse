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
const ZERO_HASH = `0x${"0".repeat(64)}`;

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

  it("accepts replay contract state proof markers while keeping final authority closed", () => {
    const bundle = replayBundle();
    appendContractProofEventsForTest(bundle);
    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

    expect(result.schemaOk).toBe(true);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.schemaErrors).toEqual([]);
  });

  it("accepts structurally bound signed source identity rows", () => {
    const bundle = replayBundle();
    appendSignedSourceForTest(bundle);
    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

    expect(result.schemaOk).toBe(true);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
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
	      "CAW operation target",
	      (bundle) => {
	        bundle.cawReceiptOperations[0].target = "0x9999999999999999999999999999999999999999";
	      },
	      "target is not bound to CAW operation target",
	    ],
	    [
	      "CAW operation receipt bundle",
	      (bundle) => {
	        bundle.cawReceiptOperations[0].receiptBundleHash = null;
	      },
	      "requires CAW operation receiptBundleHash",
	    ],
	    [
	      "CAW operation status",
	      (bundle) => {
	        bundle.cawReceiptOperations[0].status = "built_mocked";
	      },
	      "requires structurally verified CAW authority status",
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
	    [
	      "agent transcript hash",
	      (bundle) => {
	        bundle.agentTranscriptHash = hex32("bad-agent-transcript");
	      },
	      "agentTranscriptHash must equal the hash of the replay MCP transcript snapshot",
	    ],
    [
      "gate contract state proof marker",
      (bundle) => {
        const { gateEvent } = appendContractProofEventsForTest(bundle);
        delete gateEvent.payload.contractStateVerified;
      },
      "requires contractStateVerified=true",
    ],
    [
      "gate contract spend state",
      (bundle) => {
        const { gateEvent } = appendContractProofEventsForTest(bundle);
        gateEvent.payload.contractSpendState = "Tripped";
      },
      "contractSpendState must be Settled",
    ],
    [
      "gate contract payment token",
      (bundle) => {
        const { gateEvent } = appendContractProofEventsForTest(bundle);
        gateEvent.payload.contractPaymentToken = "0x9999999999999999999999999999999999999999";
      },
      "contractPaymentToken must match replay spend PaymentToken",
    ],
    [
      "replay spend artifact hash",
      (bundle) => {
        appendContractProofEventsForTest(bundle);
        bundle.spends[0].artifactHash = hex32("tampered-spend-artifact");
      },
      "contractArtifactHash must match replay spend ArtifactHash",
    ],
    [
      "source registry address",
      (bundle) => {
        const { sourceEvent } = appendContractProofEventsForTest(bundle);
        delete sourceEvent.payload.sourceRegistryAddress;
      },
      "requires sourceRegistryAddress",
    ],
    [
      "source identity hash",
      (bundle) => {
        const source = appendSignedSourceForTest(bundle);
        source.sourceHash = hex32("bad-source-identity-hash");
      },
      "sourceHash does not match signed source identity preimage",
    ],
    [
      "source identity partial signature",
      (bundle) => {
        const source = appendSignedSourceForTest(bundle);
        source.signature = null;
      },
      "issuer and signature must be provided together",
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
    bundle.replayPageIndex = replayPageIndexForTest(bundle);

	    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

	    expect(result.schemaOk).toBe(true);
	    expect(result.errors.some((error) => error.includes("artifact"))).toBe(false);
	  });

	  it("accepts replay bundles with MCP lease transcript hashes while keeping proof-chip authority closed", () => {
	    const bundle = replayBundleWithLease();
	    const result = verifyEvidence(bundle, { cliMode: "proof-chip" });

	    expect(result.schemaOk).toBe(true);
	    expect(result.proofChipAllowed).toBe(false);
	    expect(result.schemaErrors).toEqual([]);
	  });

	  it.each([
	    [
	      "MCP response body",
	      (bundle) => {
	        bundle.mcpAdapterCalls[1].response.result.structuredContent.findingCount = 1;
	      },
	      "responseHash does not match response",
	    ],
	    [
	      "lease transcript hash",
	      (bundle) => {
	        bundle.leaseRuns[0].transcriptHash = hex32("bad-lease-transcript");
	      },
	      "transcriptHash does not recompute from MCP transcript",
	    ],
	    [
	      "lease event payload",
	      (bundle) => {
	        const event = bundle.events.find((candidate) => candidate.kind === "lease.execution.succeeded");
	        event.payload.outputHash = hex32("bad-event-output");
	      },
	      "payload.outputHash does not match lease run",
	    ],
    [
      "self-consistent lease event payload",
      (bundle) => {
        const event = bundle.events.find((candidate) => candidate.kind === "lease.execution.succeeded");
        event.payload.outputHash = hex32("self-consistent-bad-event-output");
        sealReplayBundleForTest(bundle);
        bundle.judgeCheck.rows.find((row) => row.rowId === "lease_execution").evidenceEventId = event.eventId;
      },
      "payload.outputHash does not match lease run",
    ],
	    [
	      "judge row event reference",
	      (bundle) => {
	        bundle.judgeCheck.rows.find((row) => row.rowId === "lease_execution").evidenceEventId = hex32("missing-judge-event");
	      },
	      "references missing evidence event",
	    ],
	    [
	      "self-consistent MCP call arguments",
	      (bundle) => {
	        bundle.mcpAdapterCalls[1].request.params.arguments.targetCommit = "deadbeef0000";
	        rehashLeaseTranscriptForTest(bundle);
	      },
	      "tools/call argument targetCommit does not match lease run",
	    ],
	    [
	      "pinned source manifest tools",
	      (bundle) => {
	        bundle.sources[0].capabilityVector.mcpTools = [leaseToolDefinitionForTest("pactfuse_other_scan")];
	      },
	      "tools/list is not bounded to pinned source manifest",
	    ],
    [
      "self-consistent non-read-only pinned tool metadata",
      (bundle) => {
        const badTool = { name: "pactfuse_code_scan" };
        bundle.sources[0].capabilityVector.mcpTools = [badTool];
        bundle.mcpAdapterCalls[0].response.result.tools = [badTool];
        rehashLeaseTranscriptForTest(bundle);
      },
      "must advertise annotations.readOnlyHint=true",
    ],
    [
      "extra MCP frame mixed into a bounded lease transcript",
      (bundle) => {
        bundle.mcpAdapterCalls.push(
          mcpCallForTest({
            callId: hex32("extra-mcp-call"),
            sessionId: bundle.sessionId,
            auditNonce: "audit-extra-frame",
            toolName: "tools/list",
            request: { jsonrpc: "2.0", id: "extra", method: "tools/list", params: {} },
            response: { jsonrpc: "2.0", id: "extra", result: { tools: [leaseToolDefinitionForTest()] } },
            createdAt: "2026-06-11T00:00:03.000Z",
          }),
        );
        bundle.asOfMcpAdapterCallCount = bundle.mcpAdapterCalls.length;
        rehashLeaseTranscriptForTest(bundle, false);
      },
      "agentTranscript with succeeded leases must contain only pinned manifest MCP transcript frames",
    ],
    [
      "post-summary MCP frame hidden behind replay page index",
      (bundle) => {
        bundle.replayPageIndex.collections.mcpAdapterCalls.totalRows = bundle.mcpAdapterCalls.length + 1;
      },
      "agentTranscript with succeeded leases must contain only pinned manifest MCP transcript frames",
    ],
	  ])("rejects replay bundles with tampered %s", (_label, mutate, expected) => {
	    const bundle = replayBundleWithLease();
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
  const sessionId = hex32("session-replay-1");
  const operationId = hex32("op-activate");
  const bundleId = hex32("bundle-1");
  const rawReceipt = {
    operationId,
    operationKind: "activate_tool",
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
    operationKind: "activate_tool",
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
    operationKind: "activate_tool",
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
    operationKind: "activate_tool",
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
      eventSeq: 1,
      authority: "delivery",
      kind: "caw.receipt.ingested.raw",
      payload: {
        operationId,
        rawBundleHash: rawCawReceiptBundle.rawBundleHash,
        winnerClaimAllowed: false,
      },
      createdAt,
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

		  const bundle = {
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId,
    summaryMode: true,
    asOfEventSeq: 1,
    asOfMcpAdapterCallCount: 0,
    winnerClaimAllowed: false,
    eventRoot: ZERO_HASH,
    agentTranscriptHash: hashJson(agentTranscriptForTest(sessionId, [])),
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
    cawLiveInteractions: [],
    cawReceiptOperations: [
      {
        operationId,
        sessionId,
        spendId: hex32("caw-spend"),
        operationKind: "activate_tool",
        target: rawReceipt.target,
        selector: rawReceipt.selector,
        valueAtomic: "0",
        request: {
          spendId: hex32("caw-spend"),
          operationKind: "activate_tool",
          target: rawReceipt.target,
          selector: rawReceipt.selector,
          valueAtomic: "0",
        },
        receiptBundleHash: rawCawReceiptBundle.rawBundleHash,
        status: "verified_policy_authority_structural",
        createdAt: "2026-06-11T00:00:03.000Z",
      },
    ],
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
  sealReplayBundleForTest(bundle);
  return bundle;
		}

function replayBundleWithLease() {
  const bundle = replayBundle();
  const createdAt = "2026-06-11T00:00:02.000Z";
  const leaseRunId = hex32("lease-run-1");
  const listCallId = hex32("lease-list-call");
  const toolCallId = hex32("lease-tool-call");
  const auditPrefix = leaseRunId.slice(2, 22);
  const pinnedTool = leaseToolDefinitionForTest();
  const sourceHash = hex32("source");
  const listRequest = { jsonrpc: "2.0", id: "lease-tools-list", method: "tools/list", params: {} };
  const listResponse = {
    jsonrpc: "2.0",
    id: "lease-tools-list",
    result: { tools: [pinnedTool] },
  };
  const callRequest = {
    jsonrpc: "2.0",
    id: "lease-tools-call",
    method: "tools/call",
    params: {
      name: "pactfuse_code_scan",
      arguments: {
        sessionId: bundle.sessionId,
        leaseRunId,
        spendId: bundle.artifactAccessTokens[0].spendId,
        payer: bundle.artifactAccessTokens[0].payer,
        artifactHash: bundle.artifactAccessTokens[0].artifactHash,
        targetRepo: "https://github.com/example/target",
        targetCommit: "abcdef123456",
      },
    },
  };
  const callResponse = {
    jsonrpc: "2.0",
    id: "lease-tools-call",
    result: {
      content: [{ type: "text", text: "scan:https://github.com/example/target@abcdef123456" }],
      structuredContent: {
        targetRepo: "https://github.com/example/target",
        targetCommit: "abcdef123456",
        findingCount: 0,
      },
    },
  };
  bundle.sources = [
    {
      sourceId: "clean-source",
      sessionId: bundle.sessionId,
      sourceHash,
      manifestUrl: "https://example.com/manifest.json",
      manifestHash: hex32("manifest"),
      issuer: null,
      signature: null,
      capabilityVector: defaultSourceCapabilityForTest(),
      proofStatus: "pending",
      createdAt,
    },
  ];
  bundle.spends = [
    {
      spendId: bundle.artifactAccessTokens[0].spendId,
      sessionId: bundle.sessionId,
      pactId: hex32("pact-c"),
      toolId: hex32("code-scan"),
      payer: bundle.artifactAccessTokens[0].payer,
      agentWallet: "0x1000000000000000000000000000000000000001",
      paymentToken: "0x4000000000000000000000000000000000000004",
      artifactHash: bundle.artifactAccessTokens[0].artifactHash,
      market: "0x5000000000000000000000000000000000000005",
      sourceHashes: [sourceHash],
      sourceSetHash: hex32("source-set"),
      sessionCommitment: hex32("session-commitment"),
      spendPreimage: {},
      maxPriceAtomic: "1000",
      nonce: "nonce-1",
      status: "settled_finalized",
      createdAt,
    },
  ];
  const mcpAdapterCalls = [
    mcpCallForTest({
      callId: listCallId,
      sessionId: bundle.sessionId,
      auditNonce: `lease_${auditPrefix}_tools_list`,
      toolName: "tools/list",
      request: listRequest,
      response: listResponse,
      createdAt,
    }),
    mcpCallForTest({
      callId: toolCallId,
      sessionId: bundle.sessionId,
      auditNonce: `lease_${auditPrefix}_tools_call`,
      toolName: "tools/call",
      request: callRequest,
      response: callResponse,
      createdAt,
    }),
  ];
  const transcriptHash = hashJson({
    format: "mcp-json-rpc",
    sessionId: bundle.sessionId,
    leaseRunId,
    frameCallIds: [listCallId, toolCallId],
    frames: [
      { method: "tools/list", requestHash: mcpAdapterCalls[0].requestHash, responseHash: mcpAdapterCalls[0].responseHash },
      { method: "tools/call", requestHash: mcpAdapterCalls[1].requestHash, responseHash: mcpAdapterCalls[1].responseHash },
    ],
  });
  const toolsListHash = hashJson({ requestHash: mcpAdapterCalls[0].requestHash, responseHash: mcpAdapterCalls[0].responseHash });
  const toolsCallHash = hashJson({ requestHash: mcpAdapterCalls[1].requestHash, responseHash: mcpAdapterCalls[1].responseHash });
  const outputHash = hashJson(callResponse);
  const leaseRun = {
    leaseRunId,
    sessionId: bundle.sessionId,
    spendId: bundle.artifactAccessTokens[0].spendId,
    payer: bundle.artifactAccessTokens[0].payer,
    artifactHash: bundle.artifactAccessTokens[0].artifactHash,
    targetRepo: "https://github.com/example/target",
    targetCommit: "abcdef123456",
    status: "succeeded_live_mcp_transcript",
    transcriptHash,
    toolsListHash,
    toolsCallHash,
    outputHash,
    leaseRunHash: null,
    settlementEventId: bundle.artifactAccessTokens[0].settlementEventId,
    artifactTokenId: bundle.artifactAccessTokens[0].tokenId,
    createdAt,
    completedAt: createdAt,
  };
  leaseRun.leaseRunHash = hashJson({
    sessionId: bundle.sessionId,
    leaseRunId,
    spendId: leaseRun.spendId,
    payer: leaseRun.payer,
    artifactHash: leaseRun.artifactHash,
    targetRepo: leaseRun.targetRepo,
    targetCommit: leaseRun.targetCommit,
    settlementEventId: leaseRun.settlementEventId,
    artifactTokenId: leaseRun.artifactTokenId,
    transcriptHash,
    outputHash,
  });
  const manifestBinding = leaseManifestBindingForTest(bundle, leaseRun, toolsListHash, toolsCallHash);
  const leaseEvent = {
    eventSeq: bundle.events.length + 1,
    authority: "delivery",
    kind: "lease.execution.succeeded",
    payload: {
      leaseRunId,
      spendId: leaseRun.spendId,
      payer: leaseRun.payer,
      artifactHash: leaseRun.artifactHash,
      targetRepo: leaseRun.targetRepo,
      targetCommit: leaseRun.targetCommit,
      settlementEventId: leaseRun.settlementEventId,
      artifactTokenId: leaseRun.artifactTokenId,
      transcriptHash,
      toolsListHash,
      toolsCallHash,
      outputHash,
      leaseRunHash: leaseRun.leaseRunHash,
      mcpToolName: "pactfuse_code_scan",
      boundedToPinnedManifest: true,
      pinnedManifestToolsHash: manifestBinding.pinnedManifestToolsHash,
      pinnedManifestHashes: manifestBinding.manifestHashes,
      manifestBindingHash: manifestBinding.manifestBindingHash,
      bearerBound: true,
      status: "succeeded_live_mcp_transcript",
      proofAuthority: false,
      winnerClaimAllowed: false,
    },
    createdAt,
  };
  bundle.mcpAdapterCalls = mcpAdapterCalls;
  bundle.asOfMcpAdapterCallCount = mcpAdapterCalls.length;
  bundle.leaseRuns = [leaseRun];
  bundle.agentTranscriptHash = hashJson(agentTranscriptForTest(bundle.sessionId, mcpAdapterCalls, true));
  bundle.events = [...bundle.events, leaseEvent];
  sealReplayBundleForTest(bundle);
  const leaseRow = bundle.judgeCheck.rows.find((row) => row.rowId === "lease_execution");
  leaseRow.status = "pass";
  leaseRow.authority = "delivery";
  leaseRow.reason = "MCP transcript recorded";
  leaseRow.evidenceEventId = leaseEvent.eventId;
  return bundle;
}

function appendContractProofEventsForTest(bundle) {
  if (!Array.isArray(bundle.spends) || bundle.spends.length === 0) {
    bundle.spends = [
      {
        spendId: bundle.artifactAccessTokens[0].spendId,
        sessionId: bundle.sessionId,
        pactId: hex32("pact-c"),
        toolId: hex32("code-scan"),
        payer: bundle.artifactAccessTokens[0].payer,
        agentWallet: "0x1000000000000000000000000000000000000001",
        paymentToken: "0x4000000000000000000000000000000000000004",
        artifactHash: bundle.artifactAccessTokens[0].artifactHash,
        market: "0x5000000000000000000000000000000000000005",
        sourceHashes: [hex32("source")],
        sourceSetHash: hex32("source-set"),
        sessionCommitment: hex32("session-commitment"),
        spendPreimage: {},
        maxPriceAtomic: "1000",
        nonce: "nonce-1",
        status: "settled_finalized",
        createdAt: "2026-06-11T00:00:03.000Z",
      },
    ];
  }
  const gateEvent = {
    eventId: hex32("contract-gate-event"),
    sessionId: bundle.sessionId,
    authority: "proof",
    kind: "gate.spend_settled",
    eventHash: hex32("contract-gate-event-hash"),
    payload: {
      gateEventId: hex32("contract-gate-event-id"),
      event: "SpendSettled",
      spendId: bundle.artifactAccessTokens[0].spendId,
      txHash: hex32("contract-gate-tx"),
      logIndex: 0,
      chainId: "84532",
      blockNumber: 100,
      currentBlockNumber: 102,
      rawLogHash: hex32("contract-gate-log"),
      confirmations: 3,
      finalityDepth: 2,
      finalityStatus: "finalized",
      observedEventId: hex32("contract-gate-observed"),
      indexedLogId: hex32("contract-gate-indexed-log"),
      cursorId: "gate:indexer",
      indexedRawLogHash: hex32("contract-gate-indexed-raw"),
      finalizedHeadBlock: 102,
      latestHeadBlock: 102,
      contractStateVerified: true,
      contractAddress: "0x1111111111111111111111111111111111111111",
      contractFunction: "registeredSpend",
      contractSessionId: bundle.sessionId,
      contractPactId: bundle.spends[0].pactId,
      contractToolId: bundle.spends[0].toolId,
      contractSourceSetHash: bundle.spends[0].sourceSetHash,
      contractAgentWallet: bundle.spends[0].agentWallet,
      contractPaymentToken: bundle.spends[0].paymentToken,
      contractPrice: bundle.spends[0].maxPriceAtomic,
      contractArtifactHash: bundle.spends[0].artifactHash,
      contractMarket: bundle.spends[0].market,
      contractSpendState: "Settled",
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
  };
  const sourceEvent = {
    eventId: hex32("contract-source-event"),
    sessionId: bundle.sessionId,
    authority: "proof",
    kind: "source.challenge.confirmed",
    eventHash: hex32("contract-source-event-hash"),
    payload: {
      challengeId: hex32("contract-source-challenge"),
      sourceHash: hex32("contract-source"),
      reasonHash: hex32("contract-source-reason"),
      txHash: hex32("contract-source-tx"),
      logIndex: 1,
      chainId: "84532",
      blockNumber: 101,
      indexedLogId: hex32("contract-source-indexed-log"),
      cursorId: "gate:indexer",
      indexedRawLogHash: hex32("contract-source-indexed-raw"),
      finalizedHeadBlock: 103,
      latestHeadBlock: 103,
      finalityStatus: "finalized",
      contractStateVerified: true,
      sourceRegistryAddress: "0x1111111111111111111111111111111111111111",
      contractFunction: "sourceState",
      contractSourceState: "Challenged",
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
  };
  bundle.events = [...bundle.events, gateEvent, sourceEvent];
  sealReplayBundleForTest(bundle);
  return { gateEvent, sourceEvent };
}

function appendSignedSourceForTest(bundle) {
  const sourceBase = {
    sourceId: "signed-source",
    manifestUrl: "https://example.com/signed-source.json",
    manifestHash: hex32("signed-source-manifest"),
    capabilityVector: defaultSourceCapabilityForTest(),
  };
  const sourceHash = hashJson({
    version: "pactfuse-source-identity-v1",
    sourceId: sourceBase.sourceId,
    manifestUrl: sourceBase.manifestUrl,
    manifestHash: sourceBase.manifestHash.toLowerCase(),
    capabilityVector: sourceBase.capabilityVector,
  });
  const source = {
    ...sourceBase,
    sessionId: bundle.sessionId,
    sourceHash,
    issuer: "0x1111111111111111111111111111111111111111",
    signature: hex32("signed-source-signature"),
    proofStatus: "pending",
    createdAt: "2026-06-11T00:00:03.000Z",
  };
  bundle.sources = [...bundle.sources, source];
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
  return source;
}

function defaultSourceCapabilityForTest(toolName = "pactfuse_code_scan") {
  return {
    has_write_file: false,
    mcpTools: [leaseToolDefinitionForTest(toolName)],
  };
}

function leaseToolDefinitionForTest(name = "pactfuse_code_scan") {
  const properties = Object.fromEntries(
    ["sessionId", "leaseRunId", "spendId", "payer", "artifactHash", "targetRepo", "targetCommit"].map((field) => [
      field,
      { type: "string" },
    ]),
  );
  return {
    name,
    description: "Deterministic read-only code scan",
    inputSchema: {
      type: "object",
      properties,
      required: Object.keys(properties),
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
  };
}

function sealReplayBundleForTest(bundle) {
  let previousProofEventHash = ZERO_HASH;
  bundle.events.forEach((event, index) => {
    const eventSeq = Number.isInteger(event.eventSeq) ? event.eventSeq : index + 1;
    const authority = event.authority ?? "operator";
    const kind = event.kind ?? event.type;
    const payload = event.payload ?? { winnerClaimAllowed: false };
    const prevProofEventHash = authority === "proof" ? previousProofEventHash : null;
    const payloadHash = hashJson(payload);
    const eventHash = hashJson({
      sessionId: bundle.sessionId,
      eventSeq,
      authority,
      kind,
      payloadHash,
      prevProofEventHash,
    });
    delete event.seq;
    delete event.type;
    Object.assign(event, {
      eventId: eventHash,
      sessionId: bundle.sessionId,
      eventSeq,
      eventHash,
      prevProofEventHash,
      authority,
      kind,
      payloadHash,
      payload,
      createdAt: event.createdAt ?? `2026-06-11T00:00:${String(index + 1).padStart(2, "0")}.000Z`,
    });
    if (authority === "proof") {
      previousProofEventHash = eventHash;
    }
  });
  bundle.asOfEventSeq = bundle.events.length;
  bundle.eventRoot = hashJson(bundle.events.map((event) => event.eventHash));
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
}

function leaseManifestBindingForTest(bundle, leaseRun, toolsListHash, toolsCallHash) {
  const sourceHashes = [...bundle.spends.find((spend) => spend.spendId === leaseRun.spendId).sourceHashes]
    .map((sourceHash) => sourceHash.toLowerCase())
    .sort();
  const sourcesByHash = new Map(bundle.sources.map((source) => [source.sourceHash.toLowerCase(), source]));
  const manifestHashes = [];
  const tools = [];
  for (const sourceHash of sourceHashes) {
    const source = sourcesByHash.get(sourceHash);
    manifestHashes.push(source.manifestHash.toLowerCase());
    tools.push(...source.capabilityVector.mcpTools);
  }
  const pinnedManifestToolsHash = hashJson(tools);
  const manifestBindingHash = hashJson({
    sessionId: bundle.sessionId,
    leaseRunId: leaseRun.leaseRunId,
    spendId: leaseRun.spendId,
    sourceHashes,
    manifestHashes,
    pinnedManifestToolsHash,
    toolsListHash,
    toolsCallHash,
  });
  return { sourceHashes, manifestHashes, pinnedManifestToolsHash, manifestBindingHash };
}

function replayPageIndexForTest(bundle) {
  const collections = Object.fromEntries(
    [
      "artifactAccessTokens",
      "artifactPreflights",
      "canonicalCawReceipts",
      "cawLiveInteractions",
      "cawReceiptOperations",
      "events",
      "leaseRuns",
      "mcpAdapterCalls",
      "quotes",
      "rawCawReceiptBundles",
      "sources",
      "spends",
    ].map((name) => [name, replayPageCollectionForTest(bundle.sessionId, name, bundle[name] ?? [])]),
  );
  return {
    pageSize: 200,
    pageRoot: hashJson(Object.entries(collections).map(([name, collection]) => ({ name, pageRoot: collection.pageRoot }))),
    collections,
  };
}

function replayPageCollectionForTest(sessionId, collection, rows) {
  const pageHashes = [];
  const orderBy = replayCollectionOrderByForTest(collection);
  for (let offset = 0; offset < rows.length; offset += 200) {
    pageHashes.push(replayPageHashForTest(sessionId, collection, offset / 200, orderBy, rows.slice(offset, offset + 200)));
  }
  return {
    totalRows: rows.length,
    pageCount: pageHashes.length,
    orderBy,
    firstPageHash: pageHashes[0] ?? replayPageHashForTest(sessionId, collection, 0, orderBy, []),
    pageRoot: hashJson(pageHashes),
    pageHashes,
  };
}

function replayPageHashForTest(sessionId, collection, pageIndex, orderBy, rows) {
  return hashJson({ sessionId, collection, pageIndex, pageSize: 200, orderBy, rows });
}

function replayCollectionOrderByForTest(collection) {
  return {
    artifactAccessTokens: ["createdAt ASC", "tokenId ASC"],
    artifactPreflights: ["createdAt ASC", "preflightId ASC"],
    canonicalCawReceipts: ["createdAt ASC", "rawReceiptHash ASC"],
    cawLiveInteractions: ["createdAt ASC", "interactionId ASC"],
    cawReceiptOperations: ["createdAt ASC", "operationId ASC"],
    events: ["eventSeq ASC"],
    leaseRuns: ["createdAt DESC", "leaseRunId ASC"],
    mcpAdapterCalls: ["createdAt ASC", "toolName tools/list before tools/call", "callId ASC"],
    quotes: ["createdAt ASC", "quoteId ASC"],
    rawCawReceiptBundles: ["createdAt ASC", "bundleId ASC"],
    sources: ["createdAt ASC", "sourceHash ASC"],
    spends: ["createdAt ASC", "spendId ASC"],
  }[collection];
}

function mcpCallForTest({ callId, sessionId, auditNonce, toolName, request, response, createdAt }) {
  return {
    callId,
    sessionId,
    auditNonce,
    toolName,
    requestHash: hashJson(request),
    responseHash: hashJson(response),
    request,
    response,
    status: "succeeded",
    createdAt,
    proofAuthority: false,
  };
}

function rehashLeaseTranscriptForTest(bundle, boundedToPinnedManifest = true) {
  for (const call of bundle.mcpAdapterCalls) {
    call.requestHash = hashJson(call.request);
    call.responseHash = hashJson(call.response);
  }
  const leaseRun = bundle.leaseRuns[0];
  const listCall = bundle.mcpAdapterCalls[0];
  const toolCall = bundle.mcpAdapterCalls[1];
  leaseRun.toolsListHash = hashJson({ requestHash: listCall.requestHash, responseHash: listCall.responseHash });
  leaseRun.toolsCallHash = hashJson({ requestHash: toolCall.requestHash, responseHash: toolCall.responseHash });
  leaseRun.transcriptHash = hashJson({
    format: "mcp-json-rpc",
    sessionId: bundle.sessionId,
    leaseRunId: leaseRun.leaseRunId,
    frameCallIds: [listCall.callId, toolCall.callId],
    frames: [
      { method: "tools/list", requestHash: listCall.requestHash, responseHash: listCall.responseHash },
      { method: "tools/call", requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
    ],
  });
  leaseRun.outputHash = hashJson(toolCall.response);
  leaseRun.leaseRunHash = hashJson({
    sessionId: bundle.sessionId,
    leaseRunId: leaseRun.leaseRunId,
    spendId: leaseRun.spendId,
    payer: leaseRun.payer,
    artifactHash: leaseRun.artifactHash,
    targetRepo: leaseRun.targetRepo,
    targetCommit: leaseRun.targetCommit,
    settlementEventId: leaseRun.settlementEventId,
    artifactTokenId: leaseRun.artifactTokenId,
    transcriptHash: leaseRun.transcriptHash,
    outputHash: leaseRun.outputHash,
  });
  const event = bundle.events.find((candidate) => candidate.kind === "lease.execution.succeeded");
  const manifestBinding = leaseManifestBindingForTest(bundle, leaseRun, leaseRun.toolsListHash, leaseRun.toolsCallHash);
  event.payload.transcriptHash = leaseRun.transcriptHash;
  event.payload.toolsListHash = leaseRun.toolsListHash;
  event.payload.toolsCallHash = leaseRun.toolsCallHash;
  event.payload.outputHash = leaseRun.outputHash;
  event.payload.leaseRunHash = leaseRun.leaseRunHash;
  event.payload.pinnedManifestToolsHash = manifestBinding.pinnedManifestToolsHash;
  event.payload.pinnedManifestHashes = manifestBinding.manifestHashes;
  event.payload.manifestBindingHash = manifestBinding.manifestBindingHash;
  bundle.agentTranscriptHash = hashJson(agentTranscriptForTest(bundle.sessionId, bundle.mcpAdapterCalls, boundedToPinnedManifest));
  sealReplayBundleForTest(bundle);
  const leaseRow = bundle.judgeCheck.rows.find((row) => row.rowId === "lease_execution");
  if (leaseRow) {
    leaseRow.evidenceEventId = event.eventId;
  }
}

function agentTranscriptForTest(sessionId, calls, boundedToPinnedManifest = false) {
  const callSummaries = calls.map((call) => ({
    callId: call.callId,
    auditNonce: call.auditNonce,
    toolName: call.toolName,
    requestHash: call.requestHash,
    responseHash: call.responseHash,
    status: call.status,
    createdAt: call.createdAt,
  }));
  const toolsListHash = calls.length > 0 ? hashJson([...new Set(calls.map((call) => call.toolName))].sort()) : null;
  const toolsCallHash = calls.length > 0 ? hashJson(callSummaries) : null;
  const transcriptHash =
    calls.length > 0
      ? hashJson({
          format: "mcp-json-rpc",
          sessionId,
          toolsListHash,
          toolsCallHash,
          boundedToPinnedManifest,
          callCount: calls.length,
        })
      : null;
  return {
    sessionId,
    status: calls.length > 0 ? "summarized" : "pending",
    format: "mcp-json-rpc",
    toolsListHash,
    toolsCallHash,
    transcriptHash,
    boundedToPinnedManifest,
    callCount: calls.length,
    calls: callSummaries,
    winnerClaimAllowed: false,
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
