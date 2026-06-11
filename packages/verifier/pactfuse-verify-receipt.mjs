#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const BAD_EVIDENCE_VALUES = new Set(["pending", "fixture", "manual", "blocked"]);
const INACTIVE_BRANCH_NULL_PATHS = new Set(["paymentProof.permit", "paymentProof.gatePaid"]);
const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;

function usage() {
  console.error("Usage: node packages/verifier/pactfuse-verify-receipt.mjs [--schema-only] <receipt-pack.json>");
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`failed to read JSON from ${path}: ${error.message}`);
  }
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalizeJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS canonicalization rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`)
      .join(",")}}`;
  }
  throw new Error(`JCS canonicalization rejects ${typeof value}`);
}

function hashJson(value) {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function safeHashJson(value, label, errors) {
  try {
    return hashJson(value);
  } catch (error) {
    errors.push(`${label} cannot be canonicalized: ${error instanceof Error ? error.message : "unknown error"}`);
    return null;
  }
}

function at(root, path) {
  return path.reduce((value, key) => (value == null ? undefined : value[key]), root);
}

function pathLabel(path) {
  return path.length === 0 ? "$" : path.join(".");
}

function collectEvidenceMarkers(value, path, markers) {
  const label = pathLabel(path);

  if (typeof value === "string") {
    const lower = value.toLowerCase();
    if ([...BAD_EVIDENCE_VALUES].some((marker) => lower === marker || lower.includes(marker))) {
      markers.badEvidence.push({ path: label, value });
    }
    if (value.includes("...") || lower.includes("pending") || value === "0x0" || /^0x0+$/.test(value)) {
      markers.placeholders.push({ path: label, value });
    }
    return;
  }

  if (value === null) {
    if (!INACTIVE_BRANCH_NULL_PATHS.has(label)) {
      markers.nulls.push({ path: label });
    }
    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => collectEvidenceMarkers(item, [...path, String(index)], markers));
    return;
  }

  if (isObject(value)) {
    Object.entries(value).forEach(([key, item]) => collectEvidenceMarkers(item, [...path, key], markers));
  }
}

function requirePath(root, path, errors) {
  const value = at(root, path);
  if (value === undefined || value === null || value === "") {
    errors.push(`missing required field: ${pathLabel(path)}`);
  }
  return value;
}

function requireObject(root, path, errors) {
  const value = requirePath(root, path, errors);
  if (value !== undefined && value !== null && !isObject(value)) {
    errors.push(`field must be an object: ${pathLabel(path)}`);
  }
  return value;
}

function requireArray(root, path, errors) {
  const value = requirePath(root, path, errors);
  if (value !== undefined && value !== null && !Array.isArray(value)) {
    errors.push(`field must be an array: ${pathLabel(path)}`);
  }
  return value;
}

function requireNull(root, path, errors) {
  const value = at(root, path);
  if (value !== null) {
    errors.push(`field must be null: ${pathLabel(path)}`);
  }
}

function asText(value) {
  return value == null ? "" : String(value);
}

function isEvmAddress(value) {
  return /^0x[a-fA-F0-9]{40}$/.test(value);
}

function isHex32(value) {
  return typeof value === "string" && HEX32_RE.test(value);
}

function lowerHex(value) {
  return typeof value === "string" ? value.toLowerCase() : value;
}

function decimal(value) {
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  const text = asText(value);
  return /^[0-9]+$/.test(text) ? BigInt(text) : null;
}

function checkGatePaid(root, errors) {
  const gatePaid = requireObject(root, ["paymentProof", "gatePaid"], errors);
  requireNull(root, ["paymentProof", "permit"], errors);

  for (const field of [
    "approveTxHash",
    "allowanceBefore",
    "allowanceAfter",
    "approvedAmount",
    "quotePrice",
    "policyTxCount",
    "approveBeforeActivate",
  ]) {
    requirePath(root, ["paymentProof", "gatePaid", field], errors);
  }

  if (!isObject(gatePaid)) {
    return;
  }

  if (asText(gatePaid.approvedAmount) !== asText(gatePaid.quotePrice)) {
    errors.push("gate-paid proof requires approvedAmount to equal quotePrice");
  }
  if (gatePaid.approveBeforeActivate !== true) {
    errors.push("gate-paid proof requires approveBeforeActivate: true");
  }
  if (asText(gatePaid.policyTxCount) !== "2") {
    errors.push("gate-paid target path requires policyTxCount to be 2");
  }

  const allowedCalls = at(root, ["checks", "recommendedCawPolicy", "allowedCalls"]);
  if (!Array.isArray(allowedCalls)) {
    errors.push("recommendedCawPolicy.allowedCalls must list CAW approve and activateTool calls");
    return;
  }

  if (allowedCalls.length !== 2) {
    errors.push("recommendedCawPolicy.allowedCalls must contain exactly one approve call and one activateTool call");
  }
  if (asText(at(root, ["checks", "recommendedCawPolicy", "txCount"])) !== "2") {
    errors.push("recommendedCawPolicy.txCount must be 2 for gate-paid path");
  }

  const approveCalls = allowedCalls.filter((call) => {
    const target = asText(call.target);
    return (
      (target === "PUBLIC_TESTNET_MOCK_ERC20" || isEvmAddress(target)) &&
      asText(call.selector).includes("approve") &&
      at(call, ["constraints", "spender"]) === "ProcurementGate"
    );
  });
  const activateCalls = allowedCalls.filter((call) => {
    return asText(call.target) === "ProcurementGate" && asText(call.selector).includes("activateTool");
  });

  if (approveCalls.length !== 1) {
    errors.push("recommendedCawPolicy.allowedCalls must include exactly one ERC20 approve(spender=ProcurementGate)");
  }
  if (activateCalls.length !== 1) {
    errors.push("recommendedCawPolicy.allowedCalls must include exactly one ProcurementGate.activateTool");
  }

  const approve = approveCalls[0];
  const activate = activateCalls[0];
  const amountMax = decimal(at(approve, ["constraints", "amountMax"]));
  const quotePrice = decimal(gatePaid.quotePrice);
  const approvedAmount = decimal(gatePaid.approvedAmount);

  if (amountMax === null) {
    errors.push("approve allowed call requires decimal constraints.amountMax");
  }
  if (quotePrice === null) {
    errors.push("gate-paid proof requires decimal quotePrice");
  }
  if (approvedAmount === null) {
    errors.push("gate-paid proof requires decimal approvedAmount");
  }
  if (amountMax !== null && quotePrice !== null && quotePrice > amountMax) {
    errors.push("gate-paid quotePrice must be <= approve amountMax");
  }
  if (amountMax !== null && approvedAmount !== null && approvedAmount > amountMax) {
    errors.push("gate-paid approvedAmount must be <= approve amountMax");
  }
  if (activate && at(activate, ["constraints", "paymentAuth"]) !== "empty") {
    errors.push("activateTool allowed call must require paymentAuth: empty for gate-paid path");
  }
}

function checkPermit(root, errors) {
  requireNull(root, ["paymentProof", "gatePaid"], errors);
  const permit = requireObject(root, ["paymentProof", "permit"], errors);
  if (!isObject(permit)) {
    return;
  }

  for (const field of [
    "gatePaymentAuthorization",
    "gatePaymentAuthorizationCawReceiptHash",
    "eip2612Permit",
    "eip2612PermitCawReceiptHash",
    "activationTxHash",
  ]) {
    requirePath(root, ["paymentProof", "permit", field], errors);
  }
}

function checkTripProofCompleteness(root, errors) {
  const tripProof = requireObject(root, ["tripProof"], errors);
  if (!isObject(tripProof)) {
    return;
  }

  // W1 rootMode rule (spec section 13): "published" requires root/branch fields;
  // "none" (P0 default) reconstructs the affected set from SpendRegistered logs,
  // so per-spend root/branch fields are not required. Receipts must carry the
  // rootMode key explicitly for proof-chip eligibility; on-chain consistency
  // (rootMode vs BlastRadiusRoot events, publisher validation) is final-verifier
  // work and stays inside the standing not-final error below.
  const rootMode = root.rootMode === "published" ? "published" : "none";
  if (root.rootMode === undefined) {
    errors.push('missing required field: rootMode ("none" | "published")');
  } else if (root.rootMode !== "none" && root.rootMode !== "published") {
    errors.push('rootMode must be "none" or "published"');
  }
  const rootRequired = rootMode === "published";

  const keys = Object.keys(tripProof).sort().join(",");
  if (keys !== "pactA,pactB,pactC") {
    errors.push("tripProof must contain exactly pactA, pactB, and pactC");
  }

  const baseTripFields = [
    "txHash",
    "event",
    "blockNumber",
    "transactionIndex",
    "logIndex",
    "spendId",
    "sourceSetHash",
  ];
  const rootTripFields = ["affectedSpendIdsRoot", "membershipBranch"];

  for (const label of ["pactA", "pactB"]) {
    const proof = requireObject(root, ["tripProof", label], errors);
    for (const field of rootRequired ? [...baseTripFields, ...rootTripFields] : baseTripFields) {
      requirePath(root, ["tripProof", label, field], errors);
    }
    if (rootRequired) {
      const branch = requireArray(root, ["tripProof", label, "membershipBranch"], errors);
      if (Array.isArray(branch) && branch.length === 0) {
        errors.push(`tripProof.${label}.membershipBranch must not be empty`);
      }
    }
    if (isObject(proof) && proof.event !== "SpendTripped") {
      errors.push(`tripProof.${label}.event must be SpendTripped`);
    }
  }

  const pactC = requireObject(root, ["tripProof", "pactC"], errors);
  const pactCFields = rootRequired
    ? ["negativeProof", "spendId", "sourceSetHash", "affectedSpendIdsRoot"]
    : ["negativeProof", "spendId", "sourceSetHash"];
  for (const field of pactCFields) {
    requirePath(root, ["tripProof", "pactC", field], errors);
  }
  if (isObject(pactC) && pactC.event && pactC.event !== "SpendSettled") {
    errors.push("tripProof.pactC.event must be SpendSettled when present");
  }

  const spendIds = ["pactA", "pactB", "pactC"]
    .map((label) => at(root, ["tripProof", label, "spendId"]))
    .filter(Boolean)
    .map(String);
  if (spendIds.length === 3 && new Set(spendIds).size !== 3) {
    errors.push("tripProof pactA, pactB, and pactC spendId values must be distinct");
  }
}

function checkGatePaidProofBinding(root, errors) {
  for (const field of [
    "activateTxHash",
    "approveTarget",
    "approveSelector",
    "activateTarget",
    "activateSelector",
    "activatePactId",
    "activateSpendId",
    "activateToolId",
    "activatePaymentToken",
    "activateMaxPrice",
    "gateStorageRegistrationHash",
    "cawPolicyReceiptHash",
    "cawOperationHashesHash",
    "paymentProofHash",
  ]) {
    requirePath(root, ["paymentProof", "gatePaid", field], errors);
  }

  const expected = [
    ["pactId", "activatePactId"],
    ["spendId", "activateSpendId"],
    ["toolId", "activateToolId"],
    ["paymentToken", "activatePaymentToken"],
  ];
  for (const [rootField, proofField] of expected) {
    const a = at(root, [rootField]);
    const b = at(root, ["paymentProof", "gatePaid", proofField]);
    if (a !== undefined && b !== undefined && asText(a) !== asText(b)) {
      errors.push(`gate-paid proof ${proofField} must match receipt ${rootField}`);
    }
  }

  const quotePrice = decimal(at(root, ["paymentProof", "gatePaid", "quotePrice"]));
  const maxPrice = decimal(at(root, ["paymentProof", "gatePaid", "activateMaxPrice"]));
  if (quotePrice !== null && maxPrice !== null && quotePrice > maxPrice) {
    errors.push("gate-paid quotePrice must be <= activateMaxPrice");
  }
}

function checkPermitProofBinding(root, errors) {
  for (const field of [
    "sessionId",
    "spendId",
    "validUntil",
    "sourceSetHash",
    "quoteHash",
    "paymentAuthNonce",
    "tokenAuthHash",
  ]) {
    requirePath(root, ["paymentProof", "permit", "gatePaymentAuthorization", field], errors);
  }
  for (const field of ["typedDataHash", "recoveredSigner", "cawRequestId"]) {
    requirePath(root, ["paymentProof", "permit", "gatePaymentAuthorizationReceipt", field], errors);
    requirePath(root, ["paymentProof", "permit", "eip2612PermitReceipt", field], errors);
  }
  for (const [rootPath, proofPath] of [
    [["sessionId"], ["paymentProof", "permit", "gatePaymentAuthorization", "sessionId"]],
    [["spendId"], ["paymentProof", "permit", "gatePaymentAuthorization", "spendId"]],
    [["sourceSetHash"], ["paymentProof", "permit", "gatePaymentAuthorization", "sourceSetHash"]],
    [["quoteHash"], ["paymentProof", "permit", "gatePaymentAuthorization", "quoteHash"]],
  ]) {
    const a = at(root, rootPath);
    const b = at(root, proofPath);
    if (a !== undefined && b !== undefined && asText(a) !== asText(b)) {
      errors.push(`${pathLabel(proofPath)} must match receipt ${pathLabel(rootPath)}`);
    }
  }
}

function checkPriceDisclosure(root, errors) {
  const disclosure = requireObject(root, ["priceDisclosure"], errors);
  for (const field of [
    "price",
    "maxPrice",
    "paymentToken",
    "tokenMode",
    "sourceFreshnessRequired",
    "sourceRef",
    "displayedDisclosureHash",
  ]) {
    requirePath(root, ["priceDisclosure", field], errors);
  }
  if (!isObject(disclosure)) {
    return;
  }

  const price = decimal(disclosure.price);
  const maxPrice = decimal(disclosure.maxPrice);
  if (price === null) {
    errors.push("priceDisclosure.price must be a decimal string");
  }
  if (maxPrice === null) {
    errors.push("priceDisclosure.maxPrice must be a decimal string");
  }
  if (price !== null && maxPrice !== null && price > maxPrice) {
    errors.push("priceDisclosure.price must be <= priceDisclosure.maxPrice");
  }
  if (disclosure.sourceFreshnessRequired !== true) {
    errors.push("priceDisclosure.sourceFreshnessRequired must be true");
  }

  const gateQuotePrice = at(root, ["paymentProof", "gatePaid", "quotePrice"]);
  if (gateQuotePrice !== undefined && asText(disclosure.price) !== asText(gateQuotePrice)) {
    errors.push("priceDisclosure.price must match paymentProof.gatePaid.quotePrice");
  }
  const permitQuotePrice = at(root, ["paymentProof", "permit", "gatePaymentAuthorization", "price"]);
  if (permitQuotePrice !== undefined && asText(disclosure.price) !== asText(permitQuotePrice)) {
    errors.push("priceDisclosure.price must match paymentProof.permit.gatePaymentAuthorization.price");
  }
  const rootSourceRef = at(root, ["sourceRef"]);
  if (rootSourceRef !== undefined && asText(disclosure.sourceRef) !== asText(rootSourceRef)) {
    errors.push("priceDisclosure.sourceRef must match receipt sourceRef");
  }
}

function checkDeliveryPreflight(root, errors) {
  const preflight = requireObject(root, ["deliveryPreflight"], errors);
  for (const field of [
    "manifestFetch",
    "endpointReachability",
    "leaseDryRun",
    "artifactPayloadHashReady",
    "quoteSignedAfterPreflight",
  ]) {
    requirePath(root, ["deliveryPreflight", field], errors);
  }
  if (!isObject(preflight)) {
    return;
  }
  for (const field of ["manifestFetch", "endpointReachability", "leaseDryRun", "artifactPayloadHashReady"]) {
    if (preflight[field] !== "ok") {
      errors.push(`deliveryPreflight.${field} must be ok for proof-chip eligibility`);
    }
  }
  if (preflight.quoteSignedAfterPreflight !== true) {
    errors.push("deliveryPreflight.quoteSignedAfterPreflight must be true for proof-chip eligibility");
  }
}

function checkAgentTranscript(root, errors) {
  const transcript = requireObject(root, ["agentTranscript"], errors);
  for (const field of [
    "format",
    "toolsListHash",
    "toolsCallHash",
    "transcriptHash",
    "boundedToPinnedManifest",
  ]) {
    requirePath(root, ["agentTranscript", field], errors);
  }
  const target = requireObject(root, ["agentTranscript", "externalTarget"], errors);
  for (const field of ["repoUrl", "commit", "ownerIsTeam", "expectedFindingClass", "observedFindingHash"]) {
    requirePath(root, ["agentTranscript", "externalTarget", field], errors);
  }
  if (!isObject(transcript)) {
    return;
  }
  if (transcript.format !== "mcp-json-rpc") {
    errors.push("agentTranscript.format must be mcp-json-rpc");
  }
  if (transcript.boundedToPinnedManifest !== true) {
    errors.push("agentTranscript.boundedToPinnedManifest must be true for proof-chip eligibility");
  }
  if (isObject(target) && target.ownerIsTeam === true) {
    errors.push("agentTranscript.externalTarget.ownerIsTeam must be false for external-workflow proof-chip eligibility");
  }
}

function checkCawReceiptIngest(root, errors) {
  const ingest = requireObject(root, ["cawReceiptIngest"], errors);
  for (const field of ["source", "fetchedAt", "rawReceiptBundleHash", "operationCount", "manualEntry"]) {
    requirePath(root, ["cawReceiptIngest", field], errors);
  }
  if (!isObject(ingest)) {
    return;
  }
  if (ingest.manualEntry !== false) {
    errors.push("cawReceiptIngest.manualEntry must be false for proof-chip eligibility");
  }
  if (ingest.source === "fixture") {
    errors.push("cawReceiptIngest.source must be caw-api or caw-export for proof-chip eligibility");
  }
  const operationCount = decimal(ingest.operationCount);
  if (operationCount === null || operationCount <= 0n) {
    errors.push("cawReceiptIngest.operationCount must be a positive decimal value");
  }
}

function checkReplayBundle(root, errors) {
  const bundle = requireObject(root, ["replayBundle"], errors);
  for (const field of [
    "schema",
    "sessionId",
    "runConfigHash",
    "rawCawReceiptBundleHash",
    "sourceProofHash",
    "txLogRefsHash",
    "artifactPreflightHash",
    "agentTranscriptHash",
    "judgeCheckHash",
    "verifierOutputHash",
    "replayBundleHash",
  ]) {
    requirePath(root, ["replayBundle", field], errors);
  }
  if (!isObject(bundle)) {
    return;
  }
  if (bundle.schema !== "PACTFUSE_EVIDENCE_V1") {
    errors.push("replayBundle.schema must be PACTFUSE_EVIDENCE_V1");
  }
  const sessionId = at(root, ["sessionId"]);
  if (sessionId !== undefined && bundle.sessionId !== undefined && asText(sessionId) !== asText(bundle.sessionId)) {
    errors.push("replayBundle.sessionId must match receipt sessionId");
  }
}

function checkProofChipCompleteness(root, errors, options = {}) {
  for (const path of [
    ["sessionId"],
    ["pactId"],
    ["spendId"],
    ["toolId"],
    ["paymentToken"],
    ["allowedAgentWallet"],
    ["sourceSetHash"],
    ["quoteHash"],
    ["cawPolicyDigest"],
    ["artifactPayloadHash"],
    ["receiptPackHash"],
  ]) {
    requirePath(root, path, errors);
  }

  // W1: top-level affectedSpendIdsRoot is required only in rootMode "published";
  // in "none" the verifier computes it from SpendRegistered logs (spec section 13).
  if (root.rootMode === "published") {
    requirePath(root, ["affectedSpendIdsRoot"], errors);
  }

  checkTripProofCompleteness(root, errors);
  checkPriceDisclosure(root, errors);
  checkDeliveryPreflight(root, errors);
  checkAgentTranscript(root, errors);
  checkCawReceiptIngest(root, errors);
  checkReplayBundle(root, errors);
  checkPactTemplateBinding(root, errors, options);

  const proofMode = at(root, ["paymentProof", "mode"]);
  if (proofMode === "gate-paid-artifact-real") {
    checkGatePaidProofBinding(root, errors);
  } else if (proofMode === "permit-payment-real") {
    checkPermitProofBinding(root, errors);
  }

  errors.push(
    "current scaffold is not a final proof-chip verifier; it has not recomputed chain events, CAW typed-data hashes, recovered signers, CAW policy authority, priceDisclosure/displayed hash, delivery preflight hash, MCP Agent Transcript hashes, Judge Check rows, or rootMode-vs-BlastRadiusRoot on-chain consistency (incl. publisher validation in published mode)",
  );
}

function checkPactTemplateBinding(root, errors, options) {
  const proofMode = at(root, ["paymentProof", "mode"]);
  if (!proofMode) {
    return;
  }
  const templateHash = at(root, ["pactTemplateHash"]) ?? at(root, ["pactTemplate", "templateHash"]);
  if (!templateHash) {
    errors.push("missing required field: pactTemplateHash");
    return;
  }
  const templates = Array.isArray(options.pactTemplates) ? options.pactTemplates : [];
  const expected = templates.find((template) => isObject(template) && template.mode === proofMode);
  if (!expected) {
    errors.push(`no pinned Pact template hash provided for paymentProof.mode ${proofMode}`);
    return;
  }
  if (asText(templateHash) !== asText(expected.templateHash)) {
    errors.push(`pactTemplateHash must match pinned ${proofMode} template hash`);
  }
}

const JUDGE_ROW_IDS = ["caw_boundary", "source_challenge", "ab_trip", "c_settlement", "artifact_access", "lease_execution"];

const JUDGE_ROW_EVENT_KINDS = {
  caw_boundary: new Set(["caw.receipt.ingested.raw", "caw.receipt.ingested.fixture"]),
  source_challenge: new Set(["source.challenge.confirmed"]),
  ab_trip: new Set(["gate.spend_tripped", "reorg.invalidated"]),
  c_settlement: new Set(["gate.spend_settled", "reorg.invalidated"]),
  artifact_access: new Set(["artifact.access_token.issued"]),
  lease_execution: new Set(["lease.execution.succeeded", "lease.execution.blocked"]),
};

function buildAgentTranscriptSnapshot(sessionId, calls) {
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
    boundedToPinnedManifest: false,
    callCount: calls.length,
    calls: callSummaries,
    winnerClaimAllowed: false,
  };
}

function verifyMcpAdapterCalls(bundle, calls, errors) {
  const callsByAuditNonce = new Map();
  for (const call of calls) {
    if (!isObject(call)) {
      errors.push("mcpAdapterCalls entries must be objects");
      continue;
    }
    if (call.sessionId !== null && call.sessionId !== bundle.sessionId) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} sessionId is not bound to replay bundle session`);
    }
    if (call.proofAuthority !== false) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} must carry proofAuthority=false`);
    }
    const requestHash = safeHashJson(call.request, `MCP adapter call ${call.callId ?? "-"} request`, errors);
    const responseHash = safeHashJson(call.response, `MCP adapter call ${call.callId ?? "-"} response`, errors);
    if (requestHash && lowerHex(call.requestHash) !== requestHash) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} requestHash does not match request`);
    }
    if (responseHash && lowerHex(call.responseHash) !== responseHash) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} responseHash does not match response`);
    }
    if (typeof call.auditNonce === "string") {
      callsByAuditNonce.set(call.auditNonce, call);
    }
  }
  const transcript = buildAgentTranscriptSnapshot(bundle.sessionId, calls.filter(isObject));
  const transcriptHash = safeHashJson(transcript, "agent transcript snapshot", errors);
  if (transcriptHash && lowerHex(bundle.agentTranscriptHash) !== transcriptHash) {
    errors.push("agentTranscriptHash must equal the hash of the replay MCP transcript snapshot");
  }
  return callsByAuditNonce;
}

function requireLeaseHashField(lease, field, errors) {
  if (!isHex32(lease[field])) {
    errors.push(`succeeded lease run ${lease.leaseRunId ?? "-"} requires ${field}`);
    return null;
  }
  return lowerHex(lease[field]);
}

function jsonPath(root, path) {
  return path.reduce((value, key) => (value == null ? undefined : value[key]), root);
}

function verifyLeaseMcpCallBinding(lease, listCall, toolCall, bundle, errors) {
  if (listCall.sessionId !== bundle.sessionId || toolCall.sessionId !== bundle.sessionId) {
    errors.push(`succeeded lease run ${lease.leaseRunId} MCP transcript frames must be bound to replay bundle session`);
  }
  if (listCall.toolName !== "tools/list" || jsonPath(listCall, ["request", "method"]) !== "tools/list") {
    errors.push(`succeeded lease run ${lease.leaseRunId} tools/list transcript frame has unexpected method`);
  }
  if (toolCall.toolName !== "tools/call" || jsonPath(toolCall, ["request", "method"]) !== "tools/call") {
    errors.push(`succeeded lease run ${lease.leaseRunId} tools/call transcript frame has unexpected method`);
  }
  const argumentsObject = jsonPath(toolCall, ["request", "params", "arguments"]);
  if (!isObject(argumentsObject)) {
    errors.push(`succeeded lease run ${lease.leaseRunId} tools/call request is missing arguments`);
    return;
  }
  const expectedArguments = {
    sessionId: bundle.sessionId,
    leaseRunId: lease.leaseRunId,
    spendId: lease.spendId,
    payer: lease.payer,
    artifactHash: lease.artifactHash,
    targetRepo: lease.targetRepo,
    targetCommit: lease.targetCommit,
  };
  for (const [field, expected] of Object.entries(expectedArguments)) {
    if (argumentsObject[field] !== expected) {
      errors.push(`succeeded lease run ${lease.leaseRunId} tools/call argument ${field} does not match lease run`);
    }
  }
}

function verifyLeaseRuns(bundle, callsByAuditNonce, eventsById, errors) {
  const artifactTokensById = new Map(
    (Array.isArray(bundle.artifactAccessTokens) ? bundle.artifactAccessTokens : []).filter(isObject).map((token) => [token.tokenId, token]),
  );
  for (const lease of Array.isArray(bundle.leaseRuns) ? bundle.leaseRuns : []) {
    if (!isObject(lease)) {
      errors.push("leaseRuns entries must be objects");
      continue;
    }
    if (lease.sessionId !== bundle.sessionId) {
      errors.push(`lease run ${lease.leaseRunId ?? "-"} sessionId is not bound to replay bundle session`);
    }
    if (lease.status !== "succeeded_live_mcp_transcript") {
      continue;
    }
    for (const field of ["leaseRunId", "spendId", "payer", "artifactHash", "targetRepo", "targetCommit", "settlementEventId", "artifactTokenId"]) {
      requirePath(lease, [field], errors);
    }
    const transcriptHash = requireLeaseHashField(lease, "transcriptHash", errors);
    const toolsListHash = requireLeaseHashField(lease, "toolsListHash", errors);
    const toolsCallHash = requireLeaseHashField(lease, "toolsCallHash", errors);
    const outputHash = requireLeaseHashField(lease, "outputHash", errors);
    const leaseRunHash = requireLeaseHashField(lease, "leaseRunHash", errors);
    if (!transcriptHash || !toolsListHash || !toolsCallHash || !outputHash || !leaseRunHash || typeof lease.leaseRunId !== "string") {
      continue;
    }
    const prefix = lease.leaseRunId.slice(2, 22);
    const listCall = callsByAuditNonce.get(`lease_${prefix}_tools_list`);
    const toolCall = callsByAuditNonce.get(`lease_${prefix}_tools_call`);
    if (!listCall || !toolCall) {
      errors.push(`succeeded lease run ${lease.leaseRunId} is missing bound MCP tools/list or tools/call transcript frames`);
      continue;
    }
    verifyLeaseMcpCallBinding(lease, listCall, toolCall, bundle, errors);
    const expectedToolsListHash = safeHashJson(
      { requestHash: listCall.requestHash, responseHash: listCall.responseHash },
      `lease run ${lease.leaseRunId} tools/list hash body`,
      errors,
    );
    const expectedToolsCallHash = safeHashJson(
      { requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
      `lease run ${lease.leaseRunId} tools/call hash body`,
      errors,
    );
    const expectedTranscriptHash = safeHashJson(
      {
        format: "mcp-json-rpc",
        sessionId: bundle.sessionId,
        leaseRunId: lease.leaseRunId,
        frameCallIds: [listCall.callId, toolCall.callId],
        frames: [
          { method: "tools/list", requestHash: listCall.requestHash, responseHash: listCall.responseHash },
          { method: "tools/call", requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
        ],
      },
      `lease run ${lease.leaseRunId} transcript hash body`,
      errors,
    );
    const expectedOutputHash = safeHashJson(toolCall.response, `lease run ${lease.leaseRunId} MCP output`, errors);
    if (expectedToolsListHash && toolsListHash !== expectedToolsListHash) {
      errors.push(`succeeded lease run ${lease.leaseRunId} toolsListHash does not recompute from MCP transcript`);
    }
    if (expectedToolsCallHash && toolsCallHash !== expectedToolsCallHash) {
      errors.push(`succeeded lease run ${lease.leaseRunId} toolsCallHash does not recompute from MCP transcript`);
    }
    if (expectedTranscriptHash && transcriptHash !== expectedTranscriptHash) {
      errors.push(`succeeded lease run ${lease.leaseRunId} transcriptHash does not recompute from MCP transcript`);
    }
    if (expectedOutputHash && outputHash !== expectedOutputHash) {
      errors.push(`succeeded lease run ${lease.leaseRunId} outputHash does not match MCP tools/call response`);
    }
    const token = artifactTokensById.get(lease.artifactTokenId);
    if (!token) {
      errors.push(`succeeded lease run ${lease.leaseRunId} references missing artifact token`);
    } else if (token.spendId !== lease.spendId || lowerHex(token.artifactHash) !== lowerHex(lease.artifactHash)) {
      errors.push(`succeeded lease run ${lease.leaseRunId} does not match referenced artifact token`);
    }
    const expectedLeaseRunHash = safeHashJson(
      {
        sessionId: bundle.sessionId,
        leaseRunId: lease.leaseRunId,
        spendId: lease.spendId,
        payer: lease.payer,
        artifactHash: lowerHex(lease.artifactHash),
        targetRepo: lease.targetRepo,
        targetCommit: lease.targetCommit,
        settlementEventId: lease.settlementEventId,
        artifactTokenId: lease.artifactTokenId,
        transcriptHash: lease.transcriptHash,
        outputHash: lease.outputHash,
      },
      `lease run ${lease.leaseRunId} leaseRunHash body`,
      errors,
    );
    if (expectedLeaseRunHash && leaseRunHash !== expectedLeaseRunHash) {
      errors.push(`succeeded lease run ${lease.leaseRunId} leaseRunHash does not recompute`);
    }
    const event = [...eventsById.values()].find(
      (candidate) => isObject(candidate) && candidate.kind === "lease.execution.succeeded" && candidate.payload?.leaseRunId === lease.leaseRunId,
    );
    if (!event) {
      errors.push(`succeeded lease run ${lease.leaseRunId} has no lease.execution.succeeded event`);
    } else {
      for (const field of [
        "spendId",
        "payer",
        "artifactHash",
        "targetRepo",
        "targetCommit",
        "settlementEventId",
        "artifactTokenId",
        "transcriptHash",
        "toolsListHash",
        "toolsCallHash",
        "outputHash",
        "leaseRunHash",
      ]) {
        if (event.payload?.[field] !== lease[field]) {
          errors.push(`lease execution event ${event.eventId ?? "-"} payload.${field} does not match lease run`);
        }
      }
    }
  }
}

function verifyJudgeCheck(bundle, eventsById, errors) {
  const judge = bundle.judgeCheck;
  if (!isObject(judge) || judge.sessionId !== bundle.sessionId || judge.winnerClaimAllowed !== false) {
    errors.push("judgeCheck must be bound to the replay bundle session and winnerClaimAllowed=false");
    return;
  }
  if (!Array.isArray(judge.rows) || judge.rows.length !== 6) {
    errors.push("judgeCheck.rows must contain six rows");
    return;
  }
  const seen = new Set();
  for (const expectedRowId of JUDGE_ROW_IDS) {
    if (!judge.rows.some((row) => isObject(row) && row.rowId === expectedRowId)) {
      errors.push(`judgeCheck.rows is missing ${expectedRowId}`);
    }
  }
  for (const row of judge.rows) {
    if (!isObject(row)) {
      errors.push("judgeCheck.rows entries must be objects");
      continue;
    }
    if (seen.has(row.rowId)) {
      errors.push(`judgeCheck row ${row.rowId} is duplicated`);
    }
    seen.add(row.rowId);
    if (!JUDGE_ROW_IDS.includes(row.rowId)) {
      errors.push(`judgeCheck row ${row.rowId ?? "-"} is not recognized`);
    }
    if (row.status === "pass" && !row.evidenceEventId) {
      errors.push(`judgeCheck pass row ${row.rowId} requires evidenceEventId`);
    }
    if (!row.evidenceEventId) {
      continue;
    }
    const event = eventsById.get(row.evidenceEventId);
    if (!event) {
      errors.push(`judgeCheck row ${row.rowId} references missing evidence event ${row.evidenceEventId}`);
      continue;
    }
    if (event.sessionId && event.sessionId !== bundle.sessionId) {
      errors.push(`judgeCheck row ${row.rowId} evidence event is not bound to replay bundle session`);
    }
    const allowedKinds = JUDGE_ROW_EVENT_KINDS[row.rowId];
    if (allowedKinds && event.kind && !allowedKinds.has(event.kind)) {
      errors.push(`judgeCheck row ${row.rowId} references unexpected event kind ${event.kind}`);
    }
    if (row.status === "pass" && row.authority === "proof" && event.authority && event.authority !== "proof") {
      errors.push(`judgeCheck proof pass row ${row.rowId} references non-proof event ${row.evidenceEventId}`);
    }
    if (row.status === "pass" && row.authority === "delivery" && event.authority && event.authority !== "delivery") {
      errors.push(`judgeCheck delivery pass row ${row.rowId} references non-delivery event ${row.evidenceEventId}`);
    }
  }
}

function verifyContractStateProofEvents(bundle, events, errors) {
  for (const event of events) {
    if (!isObject(event)) {
      continue;
    }
    if (event.kind === "gate.spend_tripped" || event.kind === "gate.spend_settled") {
      verifyGateContractStateProofEvent(bundle, event, errors);
    } else if (event.kind === "source.challenge.confirmed") {
      verifySourceContractStateProofEvent(bundle, event, errors);
    }
  }
}

function verifySourceIdentityBindings(bundle, errors) {
  for (const source of Array.isArray(bundle.sources) ? bundle.sources : []) {
    if (!isObject(source)) {
      errors.push("sources entries must be objects");
      continue;
    }
    const hasIssuer = typeof source.issuer === "string" && source.issuer.length > 0;
    const hasSignature = typeof source.signature === "string" && source.signature.length > 0;
    if (hasIssuer !== hasSignature) {
      errors.push(`source ${source.sourceHash ?? "-"} issuer and signature must be provided together`);
      continue;
    }
    if (!hasIssuer || !hasSignature) {
      continue;
    }
    const expectedSourceHash = hashJson({
      version: "pactfuse-source-identity-v1",
      sourceId: source.sourceId,
      manifestUrl: source.manifestUrl,
      manifestHash: lowerHex(source.manifestHash),
      capabilityVector: source.capabilityVector,
    });
    if (lowerHex(source.sourceHash) !== expectedSourceHash) {
      errors.push(`source ${source.sourceHash ?? "-"} sourceHash does not match signed source identity preimage`);
    }
  }
}

function verifyGateContractStateProofEvent(bundle, event, errors) {
  const payload = isObject(event.payload) ? event.payload : null;
  const label = `gate proof event ${event.eventId ?? "-"}`;
  if (!payload) {
    errors.push(`${label} requires payload`);
    return;
  }
  if (event.authority !== "proof") {
    errors.push(`${label} must carry proof authority`);
  }
  if (event.sessionId && event.sessionId !== bundle.sessionId) {
    errors.push(`${label} sessionId is not bound to replay bundle session`);
  }
  if (payload.finalityStatus !== "finalized" || payload.proofAuthority !== true) {
    errors.push(`${label} must be finalized proofAuthority=true`);
  }
  if (payload.contractStateVerified !== true) {
    errors.push(`${label} requires contractStateVerified=true`);
  }
  if (!isEvmAddress(payload.contractAddress)) {
    errors.push(`${label} requires contractAddress`);
  }
  if (payload.contractFunction !== "registeredSpend") {
    errors.push(`${label} contractFunction must be registeredSpend`);
  }
  if (!isHex32(payload.contractSessionId)) {
    errors.push(`${label} requires contractSessionId`);
  } else if (lowerHex(payload.contractSessionId) !== lowerHex(bundle.sessionId)) {
    errors.push(`${label} contractSessionId must match replay bundle sessionId`);
  }
  if (!isHex32(payload.contractSourceSetHash)) {
    errors.push(`${label} requires contractSourceSetHash`);
  }
  const expectedState = event.kind === "gate.spend_tripped" ? "Tripped" : "Settled";
  if (payload.contractSpendState !== expectedState) {
    errors.push(`${label} contractSpendState must be ${expectedState}`);
  }
}

function verifySourceContractStateProofEvent(bundle, event, errors) {
  const payload = isObject(event.payload) ? event.payload : null;
  const label = `source challenge proof event ${event.eventId ?? "-"}`;
  if (!payload) {
    errors.push(`${label} requires payload`);
    return;
  }
  if (event.authority !== "proof") {
    errors.push(`${label} must carry proof authority`);
  }
  if (event.sessionId && event.sessionId !== bundle.sessionId) {
    errors.push(`${label} sessionId is not bound to replay bundle session`);
  }
  if (payload.finalityStatus !== "finalized" || payload.proofAuthority !== true) {
    errors.push(`${label} must be finalized proofAuthority=true`);
  }
  if (payload.contractStateVerified !== true) {
    errors.push(`${label} requires contractStateVerified=true`);
  }
  if (!isEvmAddress(payload.sourceRegistryAddress)) {
    errors.push(`${label} requires sourceRegistryAddress`);
  }
  if (payload.contractFunction !== "sourceState") {
    errors.push(`${label} contractFunction must be sourceState`);
  }
  if (payload.contractSourceState !== "Challenged") {
    errors.push(`${label} contractSourceState must be Challenged`);
  }
}

function sameNullableLowerHex(left, right) {
  const normalizedLeft = left == null ? null : asText(left).toLowerCase();
  const normalizedRight = right == null ? null : asText(right).toLowerCase();
  return normalizedLeft === normalizedRight;
}

function verifyCawOperationBinding(canonical, operation, rawBundle, errors) {
  if (operation.sessionId !== canonical.sessionId) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} is not bound to the CAW operation session`);
  }
  if (operation.operationKind !== canonical.operationKind) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} operationKind does not match CAW operation`);
  }
  if (!sameNullableLowerHex(operation.target, canonical.target)) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} target is not bound to CAW operation target`);
  }
  if (!sameNullableLowerHex(operation.selector, canonical.selector)) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} selector is not bound to CAW operation selector`);
  }
  if (operation.status !== "verified_policy_authority_structural") {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} requires structurally verified CAW authority status`);
  }
  if (!operation.receiptBundleHash) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} requires CAW operation receiptBundleHash`);
  } else if (operation.receiptBundleHash !== rawBundle.rawBundleHash) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} raw bundle hash does not match CAW operation receiptBundleHash`);
  }
  const request = isObject(operation.request) ? operation.request : null;
  if (!request) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} requires CAW operation request body`);
    return;
  }
  if (request.operationKind !== canonical.operationKind) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} request.operationKind does not match canonical receipt`);
  }
  if (!sameNullableLowerHex(request.target, canonical.target)) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} request.target does not match canonical receipt`);
  }
  if (!sameNullableLowerHex(request.selector, canonical.selector)) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} request.selector does not match canonical receipt`);
  }
  if (String(request.valueAtomic ?? "0") !== String(operation.valueAtomic ?? "0")) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} request.valueAtomic does not match CAW operation`);
  }
  if (operation.spendId && request.spendId !== operation.spendId) {
    errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} request.spendId does not match CAW operation`);
  }
}

function verifyReplayBundleEvidence(bundle, options = {}) {
  const errors = [];
  const warnings = [];
  for (const field of [
    "bundleType",
    "sessionId",
    "summaryMode",
    "asOfEventSeq",
    "eventRoot",
    "agentTranscriptHash",
    "events",
    "sources",
    "spends",
    "artifactPreflights",
    "quotes",
    "artifactAccessTokens",
    "mcpAdapterCalls",
    "cawReceiptOperations",
    "rawCawReceiptBundles",
    "canonicalCawReceipts",
    "leaseRuns",
    "judgeCheck",
  ]) {
    requirePath(bundle, [field], errors);
  }
  if (bundle.bundleType !== "PACTFUSE_EVIDENCE_V1") {
    errors.push("bundleType must be PACTFUSE_EVIDENCE_V1");
  }
  if (!isHex32(bundle.sessionId)) {
    errors.push("sessionId must be a 32-byte hex string");
  }
  if (bundle.summaryMode !== true) {
    errors.push("summaryMode must be true");
  }
  if (!Number.isInteger(bundle.asOfEventSeq) || bundle.asOfEventSeq < 0 || bundle.asOfEventSeq > 200) {
    errors.push("asOfEventSeq must be an integer in [0,200]");
  }
  if (!Number.isInteger(bundle.asOfMcpAdapterCallCount) || bundle.asOfMcpAdapterCallCount < 0 || bundle.asOfMcpAdapterCallCount > 200) {
    errors.push("asOfMcpAdapterCallCount must be an integer in [0,200]");
  }
  if (bundle.winnerClaimAllowed !== false) {
    errors.push("replay bundle winnerClaimAllowed must be false unless the final verifier is complete");
  }
  let eventsById = new Map();
  if (!Array.isArray(bundle.events)) {
    errors.push("events must be an array");
  } else {
    const eventRoot = safeHashJson(
      bundle.events.map((event) => (isObject(event) ? event.eventHash : undefined)),
      "eventRoot",
      errors,
    );
    if (eventRoot && bundle.eventRoot !== eventRoot) {
      errors.push("eventRoot must equal the hash of ordered event hashes");
    }
    eventsById = new Map(
      bundle.events
        .filter((event) => isObject(event) && typeof event.eventId === "string")
        .map((event) => [event.eventId, event]),
    );
  }
  const rawBundles = Array.isArray(bundle.rawCawReceiptBundles) ? bundle.rawCawReceiptBundles : [];
  const canonicalReceipts = Array.isArray(bundle.canonicalCawReceipts) ? bundle.canonicalCawReceipts : [];
  const cawReceiptOperations = Array.isArray(bundle.cawReceiptOperations) ? bundle.cawReceiptOperations : [];
  const preflights = Array.isArray(bundle.artifactPreflights) ? bundle.artifactPreflights : [];
  const quotes = Array.isArray(bundle.quotes) ? bundle.quotes : [];
  const accessTokens = Array.isArray(bundle.artifactAccessTokens) ? bundle.artifactAccessTokens : [];
  const cawOperationsById = new Map(cawReceiptOperations.filter(isObject).map((operation) => [operation.operationId, operation]));
  const mcpCalls = Array.isArray(bundle.mcpAdapterCalls) ? bundle.mcpAdapterCalls : [];
  if (!Array.isArray(bundle.mcpAdapterCalls)) {
    errors.push("mcpAdapterCalls must be an array");
  }
  if (Array.isArray(bundle.mcpAdapterCalls) && bundle.asOfMcpAdapterCallCount !== bundle.mcpAdapterCalls.length) {
    errors.push("asOfMcpAdapterCallCount must equal mcpAdapterCalls.length in the replay summary");
  }
  const callsByAuditNonce = verifyMcpAdapterCalls(bundle, mcpCalls, errors);
  verifyLeaseRuns(bundle, callsByAuditNonce, eventsById, errors);
  verifyJudgeCheck(bundle, eventsById, errors);
  verifyContractStateProofEvents(bundle, Array.isArray(bundle.events) ? bundle.events : [], errors);
  verifySourceIdentityBindings(bundle, errors);
  const preflightsById = new Map(preflights.filter(isObject).map((preflight) => [preflight.preflightId, preflight]));
  const quotesById = new Map(quotes.filter(isObject).map((quote) => [quote.quoteId, quote]));
  for (const preflight of preflights) {
    if (!isObject(preflight)) {
      errors.push("artifactPreflights entries must be objects");
      continue;
    }
    if (lowerHex(preflight.artifactCid) !== `sha256:${asText(preflight.artifactHashPreview).toLowerCase()}`) {
      errors.push(`artifact preflight ${preflight.preflightId ?? "-"} artifactCid does not match artifactHashPreview`);
    }
  }
  for (const quote of quotes) {
    if (!isObject(quote)) {
      errors.push("quotes entries must be objects");
      continue;
    }
    const preflight = preflightsById.get(quote.preflightId);
    if (!preflight) {
      errors.push(`quote ${quote.quoteId ?? "-"} references missing artifact preflight`);
      continue;
    }
    if (quote.spendId !== preflight.spendId) {
      errors.push(`quote ${quote.quoteId ?? "-"} spendId does not match preflight`);
    }
    if (
      lowerHex(quote.artifactCommitment) !== lowerHex(preflight.artifactHashPreview) ||
      lowerHex(quote.artifactCid) !== lowerHex(preflight.artifactCid)
    ) {
      errors.push(`quote ${quote.quoteId ?? "-"} artifact commitment does not match preflight`);
    }
    const expectedQuoteHash = safeHashJson(
      {
        sessionId: bundle.sessionId,
        spendId: quote.spendId,
        preflightId: quote.preflightId,
        artifactCommitment: lowerHex(quote.artifactCommitment),
        priceAtomic: quote.priceAtomic,
        quoteNonce: quote.quoteNonce,
        validUntilBlock: quote.validUntilBlock,
        artifactCid: lowerHex(quote.artifactCid),
        priceDisclosureHash: quote.priceDisclosureHash,
        sourceStateSnapshotHash: quote.sourceStateSnapshotHash,
	        quoteSignedAfterPreflight: true,
	        modes: {
	          CLAIM_MODE: "simulated",
	          PAYMENT_MODE: "mocked",
	          TOKEN_MODE: "local-mocked",
	          IDENTITY_MODE: "pending",
	          WINNER_CLAIM_ALLOWED: false,
	        },
      },
      `quote ${quote.quoteId ?? "-"} quoteHash body`,
      errors,
    );
    if (expectedQuoteHash && lowerHex(quote.quoteHash) !== expectedQuoteHash) {
      errors.push(`quote ${quote.quoteId ?? "-"} quoteHash does not recompute`);
    }
  }
  for (const token of accessTokens) {
    if (!isObject(token)) {
      errors.push("artifactAccessTokens entries must be objects");
      continue;
    }
    const payloadHash = safeHashJson(token.artifactPayload, `artifact access token ${token.tokenId ?? "-"} payload`, errors);
    if (payloadHash && (payloadHash !== lowerHex(token.artifactPayloadHash) || payloadHash !== lowerHex(token.artifactHash))) {
      errors.push(`artifact access token ${token.tokenId ?? "-"} payload hash does not match artifactHash`);
    }
    if (lowerHex(token.artifactCid) !== `sha256:${asText(token.artifactHash).toLowerCase()}`) {
      errors.push(`artifact access token ${token.tokenId ?? "-"} artifactCid does not match artifactHash`);
    }
    const quote = quotesById.get(token.quoteId);
    if (!quote) {
      errors.push(`artifact access token ${token.tokenId ?? "-"} references missing quote`);
      continue;
    }
    if (
      token.spendId !== quote.spendId ||
      token.preflightId !== quote.preflightId ||
      lowerHex(token.artifactHash) !== lowerHex(quote.artifactCommitment) ||
      lowerHex(token.artifactCid) !== lowerHex(quote.artifactCid)
    ) {
      errors.push(`artifact access token ${token.tokenId ?? "-"} is not bound to quote/preflight artifact`);
    }
  }
  const rawReceiptsByHash = new Map();
  for (const rawBundle of rawBundles) {
    if (!isObject(rawBundle)) {
      errors.push("rawCawReceiptBundles entries must be objects");
      continue;
    }
    const rawBundleHash = safeHashJson(rawBundle.rawBundle, `rawCawReceiptBundle ${rawBundle.bundleId ?? "-"} rawBundle`, errors);
    if (rawBundleHash && rawBundle.rawBundleHash !== rawBundleHash) {
      errors.push(`rawCawReceiptBundle ${rawBundle.bundleId ?? "-"} rawBundleHash does not match rawBundle`);
    }
    const receipts = Array.isArray(rawBundle.rawBundle?.receipts) ? rawBundle.rawBundle.receipts : [];
    for (const receipt of receipts) {
      const receiptHash = safeHashJson(receipt, "raw CAW receipt", errors);
      if (receiptHash) {
        rawReceiptsByHash.set(receiptHash, { rawBundle, receipt });
      }
    }
  }
  for (const canonical of canonicalReceipts) {
    if (!isObject(canonical)) {
      errors.push("canonicalCawReceipts entries must be objects");
      continue;
    }
    const rawMatch = rawReceiptsByHash.get(canonical.rawReceiptHash);
    if (!rawMatch) {
      errors.push(`canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"} does not match any raw receipt hash`);
      continue;
    }
    const { rawReceiptHash, canonicalReceiptHash, ...canonicalBase } = canonical;
    const recomputedRawReceiptHash = safeHashJson(rawMatch.receipt, `canonical CAW receipt ${canonicalReceiptHash ?? "-"} raw receipt`, errors);
    if (recomputedRawReceiptHash && rawReceiptHash !== recomputedRawReceiptHash) {
      errors.push(`canonical CAW receipt ${canonicalReceiptHash ?? "-"} rawReceiptHash does not recompute`);
    }
    const recomputedCanonicalReceiptHash = safeHashJson(canonicalBase, `canonical CAW receipt ${canonicalReceiptHash ?? "-"} canonical body`, errors);
    if (recomputedCanonicalReceiptHash && canonicalReceiptHash !== recomputedCanonicalReceiptHash) {
      errors.push(`canonical CAW receipt ${canonicalReceiptHash ?? "-"} canonicalReceiptHash does not recompute`);
    }
    if (canonical.bundleId !== rawMatch.rawBundle.bundleId || canonical.operationId !== rawMatch.rawBundle.operationId) {
      errors.push(`canonical CAW receipt ${canonicalReceiptHash ?? "-"} is not bound to its raw bundle operation`);
    }
    const operation = cawOperationsById.get(canonical.operationId);
    if (!operation) {
      errors.push(`canonical CAW receipt ${canonicalReceiptHash ?? "-"} references missing CAW operation`);
    } else {
      verifyCawOperationBinding(canonical, operation, rawMatch.rawBundle, errors);
    }
    if (canonical.effect === "allow" && !canonical.txHash) {
      errors.push(`canonical CAW allow receipt ${canonicalReceiptHash ?? "-"} requires txHash`);
    }
  }
  errors.push(
    "current replay verifier preflight is structural-only; final chain, signature, CAW policy authority, tx/log, and Judge Check recomputation is incomplete",
  );
  return {
    schemaOk: errors.length === 1,
    proofChipAllowed: false,
    winnerClaimAllowed: false,
    requestedWinnerClaimAllowed: bundle.winnerClaimAllowed === true,
    finalVerifierComplete: false,
    file: options.file ?? null,
    cliMode: options.cliMode ?? null,
    paymentProofMode: null,
    warnings,
    schemaErrors: errors.filter((error) => !error.startsWith("current replay verifier preflight")),
    proofCompletenessErrors: errors.filter((error) => error.startsWith("current replay verifier preflight")),
    proofChipErrors: errors,
    winnerClaimErrors: [],
    errors,
  };
}

export function verifyEvidence(receipt, options = {}) {
  if (isObject(receipt) && receipt.bundleType === "PACTFUSE_EVIDENCE_V1") {
    return verifyReplayBundleEvidence(receipt, options);
  }
  const schemaErrors = [];
  const winnerClaimErrors = [];
  const warnings = [];
  const file = options.file ?? null;

  for (const path of [
    ["artifactType"],
    ["pactId"],
    ["spendId"],
    ["toolId"],
    ["paymentProof", "mode"],
    ["payment", "mode"],
  ]) {
    requirePath(receipt, path, schemaErrors);
  }

  const proofMode = at(receipt, ["paymentProof", "mode"]);
  const paymentMode = at(receipt, ["payment", "mode"]);
  if (proofMode && paymentMode && proofMode !== paymentMode) {
    schemaErrors.push(`paymentProof.mode (${proofMode}) must match payment.mode (${paymentMode})`);
  }

  if (proofMode === "gate-paid-artifact-real") {
    checkGatePaid(receipt, schemaErrors);
  } else if (proofMode === "permit-payment-real") {
    checkPermit(receipt, schemaErrors);
  } else if (proofMode !== undefined) {
    schemaErrors.push(`unsupported paymentProof.mode: ${proofMode}`);
  }

  const requestedWinnerClaimAllowed =
    at(receipt, ["winnerClaimAllowed"]) === true ||
    at(receipt, ["statusFields", "winnerClaimAllowed"]) === true ||
    at(receipt, ["claim", "winnerClaimAllowed"]) === true;

  if (requestedWinnerClaimAllowed) {
    winnerClaimErrors.push(
      "this scaffold is structural-only and refuses winnerClaimAllowed: true; run the full chain/signature/hash verifier before winner claims",
    );
  }
  if (requestedWinnerClaimAllowed && at(receipt, ["statusFields", "isRealEvidence"]) !== true) {
    winnerClaimErrors.push("winnerClaimAllowed requires statusFields.isRealEvidence: true");
  }

  const markers = { badEvidence: [], placeholders: [], nulls: [] };
  collectEvidenceMarkers(receipt, [], markers);

  const proofChipErrors = [
    ...markers.badEvidence.map((marker) => `proof chip contains ${marker.value} evidence at ${marker.path}`),
    ...markers.placeholders.map((marker) => `proof chip contains placeholder value at ${marker.path}`),
    ...markers.nulls.map((marker) => `proof chip contains null at ${marker.path}`),
  ];
  const proofCompletenessErrors = [];
  checkProofChipCompleteness(receipt, proofCompletenessErrors, options);
  proofChipErrors.push(...proofCompletenessErrors);

  if (!requestedWinnerClaimAllowed) {
    if (markers.badEvidence.length > 0) {
      warnings.push(`non-winner receipt contains ${markers.badEvidence.length} pending/fixture/manual/blocked marker(s)`);
    }
    if (markers.placeholders.length > 0) {
      warnings.push(`non-winner receipt contains ${markers.placeholders.length} placeholder value(s)`);
    }
    if (markers.nulls.length > 0) {
      warnings.push(`non-winner receipt contains ${markers.nulls.length} non-branch null value(s)`);
    }
  }

  const schemaOk = schemaErrors.length === 0;
  const proofChipAllowed = schemaOk && proofChipErrors.length === 0 && !requestedWinnerClaimAllowed;

  return {
    schemaOk,
    proofChipAllowed,
    winnerClaimAllowed: false,
    requestedWinnerClaimAllowed,
    finalVerifierComplete: false,
    file,
    cliMode: options.cliMode ?? null,
    paymentProofMode: proofMode ?? null,
    warnings,
    schemaErrors,
    proofCompletenessErrors,
    proofChipErrors,
    winnerClaimErrors,
    errors: [...schemaErrors, ...winnerClaimErrors],
  };
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }
  const schemaOnly = args.includes("--schema-only") || args.includes("--preflight");
  const positional = args.filter((arg) => arg !== "--schema-only" && arg !== "--preflight");
  const unknownFlags = positional.filter((arg) => arg.startsWith("-"));
  const [receiptPath] = positional;
  if (unknownFlags.length > 0) {
    usage();
    console.error(`unknown option(s): ${unknownFlags.join(", ")}`);
    process.exit(1);
  }
  if (!receiptPath) {
    usage();
    process.exit(1);
  }

  let receipt;
  try {
    receipt = readJson(receiptPath);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }

  const result = verifyEvidence(receipt, { file: receiptPath, cliMode: schemaOnly ? "schema-only" : "proof-chip" });
  console.log(JSON.stringify(result, null, 2));
  if (schemaOnly) {
    process.exit(result.schemaOk && !result.requestedWinnerClaimAllowed ? 0 : 1);
  }
  process.exit(result.proofChipAllowed ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
