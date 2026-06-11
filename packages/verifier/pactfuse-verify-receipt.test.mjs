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
const ERC20_APPROVE_SELECTOR = "0x095ea7b3";
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR = "0xb14620f9";

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

  it("accepts structurally bound CAW live contract calls while keeping final authority closed", () => {
    const bundle = replayBundle();
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
      "CAW activate selector",
      (bundle) => {
        bundle.rawCawReceiptBundles[0].rawBundle.receipts[0].selector = "0xca255603";
        rehashFirstCawReceiptForTest(bundle);
      },
      "selector must be ProcurementGate.activateTool(bytes32,bytes)",
    ],
    [
      "CAW activate target split from finalized gate contract",
      (bundle) => {
        bundle.rawCawReceiptBundles[0].rawBundle.receipts[0].target = "0x9999999999999999999999999999999999999999";
        rehashFirstCawReceiptForTest(bundle);
      },
      "target does not match finalized ProcurementGate contractAddress",
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
      "CAW operation spend split from finalized settlement",
      (bundle) => {
        bundle.cawReceiptOperations[0].spendId = hex32("split-caw-spend");
        bundle.cawReceiptOperations[0].request.spendId = hex32("split-caw-spend");
      },
      "does not match a finalized SpendSettled proof event by spendId and txHash",
    ],
    [
      "CAW receipt tx split from finalized settlement",
      (bundle) => {
        const gateEvent = bundle.events.find((candidate) => candidate.kind === "gate.spend_settled");
        gateEvent.payload.txHash = hex32("split-gate-tx");
        sealReplayBundleForTest(bundle);
      },
      "does not match a finalized SpendSettled proof event by spendId and txHash",
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
      "self-consistent quote price drift from registered spend",
      (bundle) => {
        bundle.quotes[0].priceAtomic = "999";
        rehashFirstQuoteForTest(bundle);
      },
      "priceAtomic does not match registered spend price",
    ],
	    [
	      "quote expiry",
	      (bundle) => {
	        bundle.quotes[0].validUntilBlock = "2";
	      },
	      "quoteHash does not recompute",
	    ],
    [
      "self-consistent artifact drift from registered spend",
      (bundle) => {
        retargetArtifactForTest(bundle, { artifactType: "source-bound-code-scan-mcp-lease", content: "drifted-scan-result" });
      },
      "artifactHashPreview does not match registered spend artifactHash",
    ],
	    [
	      "artifact token payload",
	      (bundle) => {
	        bundle.artifactAccessTokens[0].artifactPayload.content = "tampered";
	      },
	      "payload hash does not match artifactHash",
	    ],
    [
      "missing registered spend",
      (bundle) => {
        bundle.spends = [];
        bundle.replayPageIndex = replayPageIndexForTest(bundle);
      },
      "references missing registered spend",
    ],
    [
      "self-consistent CAW live transfer amount drift from registered spend",
      (bundle) => {
        const { transfer } = appendCawLiveTransferForTest(bundle);
        transfer.request.amount = "999";
        transfer.requestHash = hashJson(transfer.request);
        const event = bundle.events.find((candidate) => candidate.kind === "caw.live.transfer.submitted");
        event.payload.requestHash = transfer.requestHash;
        event.payload.amount = "999";
        sealReplayBundleForTest(bundle);
      },
      "request.amount does not match registered spend",
    ],
    [
      "self-consistent CAW live transfer token id drift from registered spend",
      (bundle) => {
        const { transfer } = appendCawLiveTransferForTest(bundle);
        transfer.request.token_id = "0x9999999999999999999999999999999999999999";
        transfer.requestHash = hashJson(transfer.request);
        const event = bundle.events.find((candidate) => candidate.kind === "caw.live.transfer.submitted");
        event.payload.requestHash = transfer.requestHash;
        sealReplayBundleForTest(bundle);
      },
      "request.token_id does not match registered spend payment token",
    ],
    [
      "self-consistent CAW live approve amount drift from registered spend",
      (bundle) => {
        const { approve } = appendCawLiveContractCallsForTest(bundle);
        approve.request.amount = "999";
        approve.request.calldata = expectedApproveCalldata(approve.request.procurement_gate_addr, "999");
        resealCawLiveContractCallForTest(bundle, approve);
      },
      "request.amount does not match registered spend price",
    ],
    [
      "self-consistent CAW live approve spender drift from ProcurementGate",
      (bundle) => {
        const { approve } = appendCawLiveContractCallsForTest(bundle);
        approve.request.spender_addr = bundle.spends[0].market.toLowerCase();
        approve.request.calldata = expectedApproveCalldata(bundle.spends[0].market, bundle.spends[0].maxPriceAtomic);
        resealCawLiveContractCallForTest(bundle, approve);
      },
      "request.spender_addr must match procurement_gate_addr",
    ],
    [
      "self-consistent CAW live activate calldata spend drift",
      (bundle) => {
        const { activate } = appendCawLiveContractCallsForTest(bundle);
        activate.request.calldata = expectedActivateToolCalldata(hex32("wrong-live-activate-spend"));
        resealCawLiveContractCallForTest(bundle, activate);
      },
      "calldata must call activateTool(spendId, 0x)",
    ],
    [
      "self-consistent CAW live activate gate split from finalized settlement",
      (bundle) => {
        const { activate } = appendCawLiveContractCallsForTest(bundle);
        activate.request.contract_addr = "0x9999999999999999999999999999999999999999";
        activate.request.procurement_gate_addr = "0x9999999999999999999999999999999999999999";
        resealCawLiveContractCallForTest(bundle, activate);
      },
      "does not match a finalized SpendSettled proof event by spendId and contractAddress",
    ],
    [
      "CAW active Pact missing policy authority binding",
      (bundle) => {
        const pactEvent = bundle.events.find((event) => event.kind === "caw.live.pact.synced");
        delete pactEvent.payload.policyDigest;
        sealReplayBundleForTest(bundle);
      },
      "requires policy digest, snapshot hash, chain/target/selector allowlists, request limit, and expiry",
    ],
    [
      "CAW audit usage policy digest split from Pact",
      (bundle) => {
        const auditUsage = bundle.events.find((event) => event.kind === "caw.live.audit.usage.verified");
        auditUsage.payload.pactPolicyDigest = hex32("wrong-pact-policy");
        sealReplayBundleForTest(bundle);
      },
      "pactPolicyDigest must match policyDigest",
    ],
    [
      "CAW contract event policy digest split from active Pact",
      (bundle) => {
        const contractEvent = bundle.events.find((event) => event.kind === "caw.live.contract_call.submitted");
        contractEvent.payload.pactPolicyDigest = hex32("wrong-contract-policy");
        sealReplayBundleForTest(bundle);
      },
      "payload.pactPolicyDigest does not match contract call request",
    ],
    [
      "token balance agent delta",
      (bundle) => {
        const tokenEvent = bundle.events.find((event) => event.kind === "token.balance_delta.verified");
        tokenEvent.payload.agentWalletAfter = "3999";
        resealTokenBalanceEventForTest(bundle);
      },
      "agent wallet balance delta does not match amountAtomic",
    ],
    [
      "token balance transfer value",
      (bundle) => {
        const tokenEvent = bundle.events.find((event) => event.kind === "token.balance_delta.verified");
        tokenEvent.payload.transferData = `0x${uint256Word("999")}`;
        resealTokenBalanceEventForTest(bundle);
      },
      "transferData does not encode amountAtomic",
    ],
    [
      "token balance settlement event link",
      (bundle) => {
        const tokenEvent = bundle.events.find((event) => event.kind === "token.balance_delta.verified");
        tokenEvent.payload.settlementEventId = hex32("missing-token-settlement");
        resealTokenBalanceEventForTest(bundle);
      },
      "references missing finalized proof-authority gate.spend_settled event",
    ],
    [
      "c settlement pass row without token balance proof",
      (bundle) => {
        const gateEvent = bundle.events.find((event) => event.kind === "gate.spend_settled");
        const row = bundle.judgeCheck.rows.find((candidate) => candidate.rowId === "c_settlement");
        row.status = "pass";
        row.authority = "proof";
        row.evidenceEventId = gateEvent.eventId;
        bundle.replayPageIndex = replayPageIndexForTest(bundle);
      },
      "judgeCheck pass row c_settlement must reference token.balance_delta.verified",
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
      "lease registered spend artifact",
      (bundle) => {
        bundle.spends[0].artifactHash = hex32("lease-spend-artifact-drift");
        bundle.replayPageIndex = replayPageIndexForTest(bundle);
      },
      "artifactHash does not match registered spend artifactHash",
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
    selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
  const agentWallet = "0x1000000000000000000000000000000000000001";
  const paymentToken = "0x4000000000000000000000000000000000000004";
  const market = "0x5000000000000000000000000000000000000005";
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
    spends: [
      {
        spendId,
        sessionId,
        pactId: hex32("pact-c"),
        toolId: hex32("code-scan"),
        payer: agentWallet,
        agentWallet,
        paymentToken,
        artifactHash,
        market,
        sourceHashes: [hex32("source")],
        sourceSetHash: hex32("source-set"),
        sessionCommitment: hex32("session-commitment"),
        spendPreimage: {},
        maxPriceAtomic: "1000",
        nonce: "nonce-1",
        status: "settled_finalized",
        createdAt,
      },
    ],
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
	        payer: agentWallet,
	        quoteId,
	        preflightId,
	        artifactHash,
	        artifactCid,
	        artifactPayloadHash: artifactHash,
	        artifactPayload,
	        tokenHash: hex32("artifact-token-hash"),
	        status: "active",
	        issuedByVerifierRunId: hex32("verifier-run"),
	        settlementEventId: ZERO_HASH,
	        createdAt,
	      },
    ],
    mcpAdapterCalls: [],
    cawLiveInteractions: [],
    cawReceiptOperations: [
      {
        operationId,
        sessionId,
        spendId,
        operationKind: "activate_tool",
        target: rawReceipt.target,
        selector: rawReceipt.selector,
        valueAtomic: "0",
        request: {
          spendId,
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
  bundle.events = [
    ...bundle.events,
    {
      eventSeq: bundle.events.length + 1,
      authority: "proof",
      kind: "gate.spend_settled",
      payload: {
        gateEventId: hex32("base-contract-gate-event-id"),
        event: "SpendSettled",
        spendId,
        txHash: rawReceipt.txHash,
        logIndex: 0,
        chainId: "84532",
        blockNumber: 100,
        currentBlockNumber: 102,
        rawLogHash: hex32("base-contract-gate-log"),
        confirmations: 3,
        finalityDepth: 2,
        finalityStatus: "finalized",
        observedEventId: hex32("base-contract-gate-observed"),
        indexedLogId: hex32("base-contract-gate-indexed-log"),
        cursorId: "gate:indexer",
        indexedRawLogHash: hex32("base-contract-gate-indexed-raw"),
        finalizedHeadBlock: 102,
        latestHeadBlock: 102,
        contractStateVerified: true,
        contractAddress: rawReceipt.target,
        contractFunction: "registeredSpend",
        contractSessionId: sessionId,
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
      createdAt,
    },
  ];
  sealReplayBundleForTest(bundle);
  const gateEvent = bundle.events.find((event) => event.kind === "gate.spend_settled");
  const cawCalls = appendCawLiveContractCallsForTest(bundle);
  const auditUsage = appendCawLiveAuditUsageEventsForTest(bundle, cawCalls);
  const allowanceEvent = appendCawAllowanceEventForTest(bundle, cawCalls.approve, auditUsage.approveUsage);
  const activationEvent = appendCawActivationEventForTest(bundle, cawCalls.activate, auditUsage.activateUsage, gateEvent);
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "token.balance_delta.verified",
    payload: {
      spendId,
      allowanceEventId: allowanceEvent.eventId,
      approveInteractionId: cawCalls.approve.interactionId,
      approveTxHash: cawCalls.approve.response.result.transaction_hash,
      activationEventId: activationEvent.eventId,
      activateInteractionId: cawCalls.activate.interactionId,
      activateTxHash: cawCalls.activate.response.result.transaction_hash,
      settlementEventId: gateEvent.eventId,
      gateEventId: gateEvent.payload.gateEventId,
      txHash: gateEvent.payload.txHash,
      chainId: gateEvent.payload.chainId,
      blockNumber: gateEvent.payload.blockNumber,
      preBlockNumber: gateEvent.payload.blockNumber - 1,
      transferLogIndex: 2,
      transferRawLogHash: hex32("base-token-transfer-log"),
      transferTopics: [ERC20_TRANSFER_TOPIC, evmAddressTopic(agentWallet), evmAddressTopic(market)],
      transferData: `0x${uint256Word("1000")}`,
      paymentToken,
      payer: agentWallet,
      agentWallet,
      payerAgentWalletSame: true,
      market,
      amountAtomic: "1000",
      agentDeltaAtomic: "-1000",
      marketDeltaAtomic: "1000",
      agentWalletBefore: "5000",
      agentWalletAfter: "4000",
      marketBefore: "10",
      marketAfter: "1010",
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt,
  });
  sealReplayBundleForTest(bundle);
  const tokenBalanceEvent = bundle.events.find((event) => event.kind === "token.balance_delta.verified");
  bundle.artifactAccessTokens[0].settlementEventId = tokenBalanceEvent.eventId;
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
  return bundle;
		}

function rehashFirstQuoteForTest(bundle) {
  const quote = bundle.quotes[0];
  quote.quoteHash = hashJson({
    sessionId: bundle.sessionId,
    spendId: quote.spendId,
    preflightId: quote.preflightId,
    artifactCommitment: quote.artifactCommitment.toLowerCase(),
    priceAtomic: quote.priceAtomic,
    quoteNonce: quote.quoteNonce,
    validUntilBlock: quote.validUntilBlock,
    artifactCid: quote.artifactCid.toLowerCase(),
    priceDisclosureHash: quote.priceDisclosureHash,
    sourceStateSnapshotHash: quote.sourceStateSnapshotHash,
    quoteSignedAfterPreflight: true,
    modes: lockedRuntimeModes(),
  });
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
}

function rehashFirstCawReceiptForTest(bundle) {
  const rawBundle = bundle.rawCawReceiptBundles[0];
  const rawReceipt = rawBundle.rawBundle.receipts[0];
  const mirroredRawReceipt = rawBundle.rawBundle.raw?.receipts?.[0];
  if (mirroredRawReceipt && mirroredRawReceipt !== rawReceipt) {
    Object.assign(mirroredRawReceipt, rawReceipt);
  }
  rawBundle.rawBundleHash = hashJson(rawBundle.rawBundle);

  const canonical = bundle.canonicalCawReceipts[0];
  canonical.target = rawReceipt.target;
  canonical.selector = rawReceipt.selector;
  canonical.rawReceiptHash = hashJson(rawReceipt);
  const { rawReceiptHash: _rawReceiptHash, canonicalReceiptHash: _canonicalReceiptHash, ...canonicalBase } = canonical;
  canonical.canonicalReceiptHash = hashJson(canonicalBase);

  const operation = bundle.cawReceiptOperations[0];
  operation.target = rawReceipt.target;
  operation.selector = rawReceipt.selector;
  operation.request.target = rawReceipt.target;
  operation.request.selector = rawReceipt.selector;
  operation.receiptBundleHash = rawBundle.rawBundleHash;
  sealReplayBundleForTest(bundle);
}

function retargetArtifactForTest(bundle, artifactPayload) {
  const artifactHash = hashJson(artifactPayload);
  const artifactCid = `sha256:${artifactHash}`;
  bundle.artifactPreflights[0].artifactHashPreview = artifactHash;
  bundle.artifactPreflights[0].artifactCid = artifactCid;
  bundle.quotes[0].artifactCommitment = artifactHash;
  bundle.quotes[0].artifactCid = artifactCid;
  bundle.artifactAccessTokens[0].artifactHash = artifactHash;
  bundle.artifactAccessTokens[0].artifactCid = artifactCid;
  bundle.artifactAccessTokens[0].artifactPayloadHash = artifactHash;
  bundle.artifactAccessTokens[0].artifactPayload = artifactPayload;
  rehashFirstQuoteForTest(bundle);
}

function appendCawLiveTransferForTest(bundle) {
  const createdAt = "2026-06-11T00:00:02.000Z";
  const walletId = "wallet-live-1";
  const pactId = "pact-live-1";
  const authKeyHash = hashJson("pact-scoped-secret");
  const spend = bundle.spends[0];
  const pactRequest = { pact_id: pactId };
  const pactResponse = {
    result: {
      pact_id: pactId,
      wallet_id: walletId,
      status: "ACTIVE",
    },
  };
  const pactSync = {
    interactionId: hex32("caw-live-pact-sync"),
    sessionId: bundle.sessionId,
    kind: "pact_sync",
    walletId,
    pactId,
    cawRequestId: null,
    requestHash: hashJson(pactRequest),
    request: pactRequest,
    responseHash: hashJson(pactResponse),
    response: pactResponse,
    status: "live_active",
    authKeyHash,
    proofAuthority: true,
    winnerClaimAllowed: false,
    createdAt,
  };
  const transferRequest = {
    spend_id: spend.spendId,
    pact_id: pactId,
    wallet_id: walletId,
    dst_addr: spend.market.toLowerCase(),
    amount: spend.maxPriceAtomic,
    payment_token: spend.paymentToken.toLowerCase(),
    token_id: spend.paymentToken.toLowerCase(),
    request_id: "pf-live-transfer-test",
  };
  const transferResponse = {
    result: {
      id: "tx-live-1",
      wallet_id: walletId,
      request_id: "pf-live-transfer-test",
      status: "submitted",
    },
  };
  const transfer = {
    interactionId: hex32("caw-live-transfer"),
    sessionId: bundle.sessionId,
    kind: "transfer_submit",
    walletId,
    pactId,
    cawRequestId: "pf-live-transfer-test",
    requestHash: hashJson(transferRequest),
    request: transferRequest,
    responseHash: hashJson(transferResponse),
    response: transferResponse,
    status: "live_pending",
    authKeyHash,
    proofAuthority: true,
    winnerClaimAllowed: false,
    createdAt,
  };
  bundle.cawLiveInteractions = [pactSync, transfer];
  bundle.events = [
    ...bundle.events,
    {
      eventSeq: bundle.events.length + 1,
      authority: "proof",
      kind: "caw.live.pact.synced",
      payload: {
        interactionId: pactSync.interactionId,
        walletId,
        pactId,
        pactScopedApiKeyHash: authKeyHash,
        requestHash: pactSync.requestHash,
        responseHash: pactSync.responseHash,
        status: "live_active",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
      createdAt,
    },
    {
      eventSeq: bundle.events.length + 2,
      authority: "proof",
      kind: "caw.live.transfer.submitted",
      payload: {
        interactionId: transfer.interactionId,
        walletId,
        pactId,
        spendId: spend.spendId,
        cawRequestId: transfer.cawRequestId,
        tokenId: spend.paymentToken.toLowerCase(),
        paymentToken: spend.paymentToken.toLowerCase(),
        amount: spend.maxPriceAtomic,
        destinationAddress: spend.market,
        requestHash: transfer.requestHash,
        responseHash: transfer.responseHash,
        pactScopedApiKeyHash: authKeyHash,
        status: "live_pending",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
      createdAt,
    },
  ];
  sealReplayBundleForTest(bundle);
  return { pactSync, transfer };
}

function appendCawLiveContractCallsForTest(bundle) {
  const createdAt = "2026-06-11T00:00:02.000Z";
  const walletId = "wallet-live-1";
  const pactId = "pact-live-1";
  const authKeyHash = hashJson("pact-scoped-secret");
  const spend = bundle.spends[0];
  const gateEvent = bundle.events.find((candidate) => candidate.kind === "gate.spend_settled");
  const gateAddress = gateEvent.payload.contractAddress.toLowerCase();
  const policyDigest = hex32("pact-live-policy");
  const policy = {
    chain_ids: ["84532"],
    target_addresses: [spend.paymentToken.toLowerCase(), gateAddress],
    selectors: [ERC20_APPROVE_SELECTOR, PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR],
    request_limit: "2",
    expiry: "2026-06-12T00:00:00.000Z",
  };
  const policySnapshotHash = hashJson({ policy });
  const pactRequest = { pact_id: pactId };
  const pactResponse = {
    result: {
      pact_id: pactId,
      wallet_id: walletId,
      status: "ACTIVE",
      policy_digest: policyDigest,
      policy,
    },
  };
  const pactSync = {
    interactionId: hex32("caw-live-contract-pact-sync"),
    sessionId: bundle.sessionId,
    kind: "pact_sync",
    walletId,
    pactId,
    cawRequestId: null,
    requestHash: hashJson(pactRequest),
    request: pactRequest,
    responseHash: hashJson(pactResponse),
    response: pactResponse,
    status: "live_active",
    authKeyHash,
    proofAuthority: true,
    winnerClaimAllowed: false,
    createdAt,
  };
  const approveRequest = {
    operation_kind: "approve",
    spend_id: spend.spendId,
    pact_id: pactId,
    wallet_id: walletId,
    chain_id: "84532",
    contract_addr: spend.paymentToken.toLowerCase(),
    calldata: expectedApproveCalldata(gateAddress, spend.maxPriceAtomic),
    selector: ERC20_APPROVE_SELECTOR,
    value: "0",
    procurement_gate_addr: gateAddress,
    spender_addr: gateAddress,
    amount: spend.maxPriceAtomic,
    request_id: "pf-live-approve-test",
  };
  const activateRequest = {
    operation_kind: "activate_tool",
    spend_id: spend.spendId,
    pact_id: pactId,
    wallet_id: walletId,
    chain_id: "84532",
    contract_addr: gateAddress,
    calldata: expectedActivateToolCalldata(spend.spendId),
    selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
    value: "0",
    procurement_gate_addr: gateAddress,
    payment_auth: "0x",
    request_id: "pf-live-activate-test",
  };
  const approve = cawLiveContractInteractionForTest({
    seed: "approve",
    bundle,
    walletId,
    pactId,
    authKeyHash,
    request: approveRequest,
    createdAt,
  });
  const activate = cawLiveContractInteractionForTest({
    seed: "activate",
    bundle,
    walletId,
    pactId,
    authKeyHash,
    request: activateRequest,
    createdAt,
  });
  bundle.cawLiveInteractions = [...bundle.cawLiveInteractions, pactSync, approve, activate];
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "caw.live.pact.synced",
    payload: {
      interactionId: pactSync.interactionId,
      walletId,
      pactId,
      pactScopedApiKeyHash: authKeyHash,
      policyDigest,
      policySnapshotHash,
      policyChainIds: policy.chain_ids,
      policyContractAddresses: policy.target_addresses,
      policySelectors: policy.selectors,
      policyRequestLimit: policy.request_limit,
      policyExpiry: policy.expiry,
      requestHash: pactSync.requestHash,
      responseHash: pactSync.responseHash,
      status: "live_active",
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt,
  });
  sealReplayBundleForTest(bundle);
  bundle.events.push(cawLiveContractEventForTest(bundle, approve, createdAt), cawLiveContractEventForTest(bundle, activate, createdAt));
  sealReplayBundleForTest(bundle);
  return { pactSync, approve, activate };
}

function appendCawLiveAuditUsageEventsForTest(bundle, cawCalls) {
  const createdAt = "2026-06-11T00:00:02.250Z";
  const auditRequest = {
    wallet_id: cawCalls.approve.walletId,
    result: "allowed",
    limit: 20,
  };
  const approveItem = cawLiveAuditItemForTest(cawCalls.approve, "contract_call.approve");
  const activateItem = cawLiveAuditItemForTest(cawCalls.activate, "contract_call.activate_tool");
  const auditResponse = {
    items: [approveItem, activateItem],
  };
  const auditSync = {
    interactionId: hex32("caw-live-audit-sync"),
    sessionId: bundle.sessionId,
    kind: "audit_sync",
    walletId: cawCalls.approve.walletId,
    pactId: null,
    cawRequestId: null,
    requestHash: hashJson(auditRequest),
    request: auditRequest,
    responseHash: hashJson(auditResponse),
    response: auditResponse,
    status: "live_synced",
    authKeyHash: null,
    proofAuthority: true,
    winnerClaimAllowed: false,
    createdAt,
  };
  bundle.cawLiveInteractions = [...bundle.cawLiveInteractions, auditSync];
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "caw.live.audit.synced",
    payload: {
      interactionId: auditSync.interactionId,
      walletId: auditSync.walletId,
      requestHash: auditSync.requestHash,
      responseHash: auditSync.responseHash,
      status: "live_synced",
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt,
  });
  sealReplayBundleForTest(bundle);
  const auditEvent = bundle.events.find((candidate) => candidate.kind === "caw.live.audit.synced" && candidate.payload.interactionId === auditSync.interactionId);
  const approveUsage = appendCawAuditUsageEventForTest(bundle, auditSync, auditEvent, cawCalls.approve, approveItem, 0, createdAt);
  const activateUsage = appendCawAuditUsageEventForTest(bundle, auditSync, auditEvent, cawCalls.activate, activateItem, 1, createdAt);
  sealReplayBundleForTest(bundle);
  return { auditSync, approveUsage, activateUsage };
}

function cawLiveAuditItemForTest(interaction, action) {
  return {
    id: `audit-${interaction.cawRequestId}`,
    action,
    result: "allowed",
    request_id: interaction.cawRequestId,
    transaction_hash: interaction.response.result.transaction_hash,
    policy_digest: hex32("pact-live-policy"),
  };
}

function appendCawAuditUsageEventForTest(bundle, auditSync, auditEvent, interaction, auditItem, auditLogIndex, createdAt) {
  const contractEvent = bundle.events.find((candidate) => candidate.kind === "caw.live.contract_call.submitted" && candidate.payload.interactionId === interaction.interactionId);
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "caw.live.audit.usage.verified",
    payload: {
      auditInteractionId: auditSync.interactionId,
      auditEventId: auditEvent.eventId,
      cawContractCallEventId: contractEvent.eventId,
      interactionId: interaction.interactionId,
      walletId: interaction.walletId,
      pactId: interaction.pactId,
      cawRequestId: interaction.cawRequestId,
      operationKind: interaction.request.operation_kind,
      action: auditItem.action,
      result: "allowed",
      policyDigest: auditItem.policy_digest,
      pactPolicyDigest: contractEvent.payload.pactPolicyDigest,
      pactSyncInteractionId: contractEvent.payload.pactSyncInteractionId,
      pactSyncEventId: contractEvent.payload.pactSyncEventId,
      txHash: auditItem.transaction_hash,
      auditLogHash: hashJson(auditItem),
      auditLogIndex,
      auditLogId: auditItem.id,
      requestHash: interaction.requestHash,
      responseHash: interaction.responseHash,
      auditRequestHash: auditSync.requestHash,
      auditResponseHash: auditSync.responseHash,
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt,
  });
  sealReplayBundleForTest(bundle);
  return bundle.events.find(
    (candidate) => candidate.kind === "caw.live.audit.usage.verified" && candidate.payload.interactionId === interaction.interactionId,
  );
}

function appendCawAllowanceEventForTest(bundle, approve, auditUsage) {
  const spend = bundle.spends[0];
  const cawEvent = bundle.events.find((candidate) => candidate.payload?.interactionId === approve.interactionId);
  const gateAddress = approve.request.procurement_gate_addr.toLowerCase();
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "caw.allowance.verified",
    payload: {
      spendId: spend.spendId,
      approveInteractionId: approve.interactionId,
      cawContractCallEventId: cawEvent.eventId,
      walletId: approve.walletId,
      pactId: approve.pactId,
      cawRequestId: approve.cawRequestId,
      approveTxHash: approve.response.result.transaction_hash,
      auditUsageEventId: auditUsage.eventId,
      auditInteractionId: auditUsage.payload.auditInteractionId,
      auditPolicyDigest: auditUsage.payload.policyDigest,
      auditLogHash: auditUsage.payload.auditLogHash,
      chainId: approve.request.chain_id,
      blockNumber: 99,
      preBlockNumber: 98,
      approvalLogIndex: 1,
      approvalRawLogHash: hex32("base-caw-approval-log"),
      approvalTopics: [ERC20_APPROVAL_TOPIC, evmAddressTopic(spend.agentWallet), evmAddressTopic(gateAddress)],
      approvalData: `0x${uint256Word(spend.maxPriceAtomic)}`,
      paymentToken: spend.paymentToken,
      payer: spend.agentWallet,
      agentWallet: spend.agentWallet,
      owner: spend.agentWallet,
      payerAgentWalletSame: true,
      procurementGateAddress: gateAddress,
      spender: gateAddress,
      amountAtomic: spend.maxPriceAtomic,
      allowanceBefore: "0",
      allowanceAfter: spend.maxPriceAtomic,
      requestHash: approve.requestHash,
      responseHash: approve.responseHash,
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt: "2026-06-11T00:00:02.500Z",
  });
  sealReplayBundleForTest(bundle);
  const allowanceEvent = bundle.events.find((candidate) => candidate.kind === "caw.allowance.verified" && candidate.payload.approveInteractionId === approve.interactionId);
  const row = bundle.judgeCheck.rows.find((candidate) => candidate.rowId === "caw_boundary");
  row.status = "pass";
  row.authority = "proof";
  row.reason = "CAW approve tx, ERC20 Approval log, and allowance state verified";
  row.evidenceEventId = allowanceEvent.eventId;
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
  return allowanceEvent;
}

function appendCawActivationEventForTest(bundle, activate, auditUsage, gateEvent) {
  const cawEvent = bundle.events.find((candidate) => candidate.payload?.interactionId === activate.interactionId);
  bundle.events.push({
    eventSeq: bundle.events.length + 1,
    authority: "proof",
    kind: "caw.activation.verified",
    payload: {
      spendId: activate.request.spend_id,
      activateInteractionId: activate.interactionId,
      cawContractCallEventId: cawEvent.eventId,
      auditUsageEventId: auditUsage.eventId,
      auditInteractionId: auditUsage.payload.auditInteractionId,
      auditPolicyDigest: auditUsage.payload.policyDigest,
      auditLogHash: auditUsage.payload.auditLogHash,
      walletId: activate.walletId,
      pactId: activate.pactId,
      cawRequestId: activate.cawRequestId,
      activateTxHash: activate.response.result.transaction_hash,
      settlementEventId: gateEvent.eventId,
      gateEventId: gateEvent.payload.gateEventId,
      procurementGateAddress: activate.request.contract_addr,
      chainId: activate.request.chain_id,
      requestHash: activate.requestHash,
      responseHash: activate.responseHash,
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt: "2026-06-11T00:00:02.750Z",
  });
  sealReplayBundleForTest(bundle);
  return bundle.events.find((candidate) => candidate.kind === "caw.activation.verified" && candidate.payload.activateInteractionId === activate.interactionId);
}

function cawLiveContractInteractionForTest({ seed, bundle, walletId, pactId, authKeyHash, request, createdAt }) {
  const gateEvent = bundle.events.find((candidate) => candidate.kind === "gate.spend_settled");
  const txHash = request.operation_kind === "activate_tool" && gateEvent ? gateEvent.payload.txHash : hex32(`caw-live-contract-${seed}-tx`);
  const response = {
    result: {
      id: `contract-live-${seed}`,
      wallet_id: walletId,
      request_id: request.request_id,
      status: "submitted",
      transaction_hash: txHash,
    },
  };
  return {
    interactionId: hex32(`caw-live-contract-${seed}`),
    sessionId: bundle.sessionId,
    kind: "contract_call",
    walletId,
    pactId,
    cawRequestId: request.request_id,
    requestHash: hashJson(request),
    request,
    responseHash: hashJson(response),
    response,
    status: "live_pending",
    authKeyHash,
    proofAuthority: true,
    winnerClaimAllowed: false,
    createdAt,
  };
}

function cawLiveContractEventForTest(bundle, interaction, createdAt) {
  const pactSyncEvent = bundle.events.find(
    (candidate) => candidate.kind === "caw.live.pact.synced" && candidate.payload?.pactId === interaction.pactId && candidate.payload?.walletId === interaction.walletId,
  );
  return {
    authority: "proof",
    kind: "caw.live.contract_call.submitted",
    payload: {
      interactionId: interaction.interactionId,
      walletId: interaction.walletId,
      pactId: interaction.pactId,
      spendId: interaction.request.spend_id,
      operationKind: interaction.request.operation_kind,
      contractAddress: interaction.request.contract_addr,
      selector: interaction.request.selector,
      cawRequestId: interaction.cawRequestId,
      pactSyncInteractionId: pactSyncEvent?.payload.interactionId,
      pactSyncEventId: pactSyncEvent?.eventId,
      pactPolicyDigest: pactSyncEvent?.payload.policyDigest,
      pactPolicySnapshotHash: pactSyncEvent?.payload.policySnapshotHash,
      chainId: interaction.request.chain_id,
      valueAtomic: interaction.request.value,
      txHash: interaction.response.result.transaction_hash,
      requestHash: interaction.requestHash,
      responseHash: interaction.responseHash,
      pactScopedApiKeyHash: interaction.authKeyHash,
      status: interaction.status,
      proofAuthority: true,
      winnerClaimAllowed: false,
    },
    createdAt,
  };
}

function resealCawLiveContractCallForTest(bundle, interaction) {
  interaction.requestHash = hashJson(interaction.request);
  const event = bundle.events.find((candidate) => candidate.payload?.interactionId === interaction.interactionId);
  event.payload.spendId = interaction.request.spend_id;
  event.payload.operationKind = interaction.request.operation_kind;
  event.payload.contractAddress = interaction.request.contract_addr;
  event.payload.selector = interaction.request.selector;
  event.payload.chainId = interaction.request.chain_id;
  event.payload.valueAtomic = interaction.request.value;
  event.payload.requestHash = interaction.requestHash;
  sealReplayBundleForTest(bundle);
}

function resealTokenBalanceEventForTest(bundle) {
  sealReplayBundleForTest(bundle);
  const tokenEvent = bundle.events.find((event) => event.kind === "token.balance_delta.verified");
  if (bundle.artifactAccessTokens[0] && tokenEvent) {
    bundle.artifactAccessTokens[0].settlementEventId = tokenEvent.eventId;
  }
  bundle.replayPageIndex = replayPageIndexForTest(bundle);
}

function expectedApproveCalldata(spender, amount) {
  return `${ERC20_APPROVE_SELECTOR}${evmAddressWord(spender)}${uint256Word(amount)}`;
}

function expectedActivateToolCalldata(spendId) {
  return `${PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR}${spendId.slice(2).toLowerCase()}${uint256Word("64")}${uint256Word("0")}`;
}

function evmAddressWord(address) {
  return address.slice(2).toLowerCase().padStart(64, "0");
}

function evmAddressTopic(address) {
  return `0x${evmAddressWord(address)}`;
}

function uint256Word(value) {
  return BigInt(value).toString(16).padStart(64, "0");
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
