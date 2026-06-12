#!/usr/bin/env node

import { secp256k1 } from "@noble/curves/secp256k1";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { hashMessage } from "viem";
import { publicKeyToAddress } from "viem/accounts";

const BAD_EVIDENCE_VALUES = new Set(["pending", "fixture", "manual", "blocked"]);
const INACTIVE_BRANCH_NULL_PATHS = new Set(["paymentProof.permit", "paymentProof.gatePaid"]);
const HEX32_RE = /^0x[0-9a-fA-F]{64}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const ERC20_APPROVE_SELECTOR = "0x095ea7b3";
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR = "0xb14620f9";
const MOCK_QUOTE_STATUS = "mocked_after_preflight_not_chain_settleable";
const CHAIN_SETTLEABLE_QUOTE_STATUS = "chain_settleable_after_preflight";
const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const PUBLIC_EXPLORER_HOST_PATTERNS = [
  /(^|\.)basescan\.org$/,
  /(^|\.)etherscan\.io$/,
  /(^|\.)etherscan\.org$/,
  /(^|\.)arbiscan\.io$/,
  /(^|\.)optimistic\.etherscan\.io$/,
  /(^|\.)polygonscan\.com$/,
  /(^|\.)blockscout\.com$/,
  /(^|\.)routescan\.io$/,
];
const REQUIRED_LEASE_TOOL_ARGUMENTS = [
  "sessionId",
  "leaseRunId",
  "spendId",
  "payer",
  "artifactHash",
  "artifactPayloadHash",
  "artifactPayload",
  "targetRepo",
  "targetCommit",
];
const SERVER_RUNTIME_PROOF_PROVIDER_TOKENS = new WeakSet();
const CAW_POLICY_CHAIN_KEYS = ["chain_ids", "chainIds", "allowed_chain_ids", "allowedChainIds", "chains", "chain_in", "chain_id", "chainId"];
const CAW_POLICY_CONTRACT_KEYS = [
  "contract_addresses",
  "contractAddresses",
  "target_addresses",
  "targetAddresses",
  "targets",
  "target_in",
  "contract_addr",
  "contractAddress",
  "allowed_contracts",
  "allowedContracts",
];
const CAW_POLICY_SELECTOR_KEYS = ["selectors", "function_selectors", "functionSelectors", "function_id", "functionId", "allowed_selectors", "allowedSelectors"];
const DANGEROUS_TOOL_NAME_PATTERN =
  /(write|edit|delete|remove|shell|exec|terminal|command|commit|push|deploy|transfer|send|apply|patch|modify|create|move|copy|rename|upload|download|file|fs|process|subprocess)/;

function usage() {
  console.error(
    "Usage: node packages/verifier/pactfuse-verify-receipt.mjs [--schema-only] [--trusted-proof-key-hash 0x...] <receipt-pack.json>",
  );
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

function sha256Hex(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
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

function rejectUnexpectedKeys(value, allowedKeys, label, errors) {
  if (!isObject(value)) {
    return;
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      errors.push(`${label} has unexpected field: ${key}`);
    }
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

function artifactPayloadRedactionHash(value) {
  if (!isObject(value) || value.redacted !== true || value.reason !== "artifact_bearer_required") {
    return null;
  }
  return isHex32(value.artifactPayloadHash) ? lowerHex(value.artifactPayloadHash) : null;
}

function hasRedactedField(value, field) {
  return Array.isArray(value?.redactedFields) && value.redactedFields.includes(field);
}

function lowerHex(value) {
  return typeof value === "string" ? value.toLowerCase() : value;
}

function normalizedHex32List(values) {
  return values
    .flatMap((value) => (typeof value === "string" ? value.split(",") : []))
    .map((value) => value.trim().toLowerCase())
    .filter((value) => HEX32_RE.test(value));
}

function publicProofEndpoint(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  try {
    const url = new URL(asText(value));
    url.username = "";
    url.password = "";
    url.pathname = "/";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return "[redacted-endpoint]";
  }
}

function verifyPublicChainProviderEndpoint(label, payload, errors) {
  const endpoint = payload.chainProviderEndpoint ?? null;
  if (endpoint !== null && endpoint !== publicProofEndpoint(endpoint)) {
    errors.push(`${label} chainProviderEndpoint must be a redacted public origin`);
  }
}

function verifyPublicReplayUrl(label, value, errors) {
  if (typeof value !== "string" || value.length === 0) {
    errors.push(`${label} must be a URL string`);
    return;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    errors.push(`${label} must be a valid URL`);
    return;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    errors.push(`${label} must use HTTP or HTTPS`);
  }
  if (url.username || url.password || url.search || url.hash) {
    errors.push(`${label} must not contain credentials, query strings, or fragments`);
  }
  if (!isPublicReplayHostname(url.hostname)) {
    errors.push(`${label} must use a public hostname`);
  }
}

function isPublicReplayHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".test") ||
    host.endsWith(".local") ||
    host.endsWith(".lan") ||
    host.endsWith(".internal")
  ) {
    return false;
  }
  if (host.includes(":")) {
    return false;
  }
  if (isPrivateOrReservedIpv4(host)) {
    return false;
  }
  return host.includes(".");
}

function isPrivateOrReservedIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet, index) => !Number.isInteger(octet) || octet < 0 || octet > 255 || String(octet) !== parts[index])) {
    return false;
  }
  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;
  const c = octets[2] ?? -1;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function trustedProofKeyHashes(options) {
  return new Set(
    normalizedHex32List([
      options.trustedProofKeyHash,
      ...(Array.isArray(options.trustedProofKeyHashes) ? options.trustedProofKeyHashes : []),
    ]),
  );
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
  if (activate && at(activate, ["constraints", "paymentAuth"]) !== "0x") {
    errors.push("activateTool allowed call must require paymentAuth: 0x for gate-paid path");
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
  caw_boundary: new Set([
    "caw.receipt.ingested.raw",
    "caw.receipt.ingested.fixture",
    "caw.live.pact.submitted",
    "caw.live.pact.synced",
    "caw.live.transfer.submitted",
    "caw.live.audit.synced",
    "caw.allowance.verified",
  ]),
  source_challenge: new Set(["source.challenge.confirmed"]),
  ab_trip: new Set(["gate.spend_tripped", "reorg.invalidated"]),
  c_settlement: new Set(["gate.spend_settled", "token.balance_delta.verified", "reorg.invalidated"]),
  artifact_access: new Set(["artifact.access_token.issued"]),
  lease_execution: new Set(["lease.execution.succeeded", "lease.execution.blocked"]),
};

const REPLAY_PAGE_SIZE = 200;
const REPLAY_COLLECTIONS = [
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
];

function buildAgentTranscriptSnapshot(bundle, calls) {
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
  const boundedToPinnedManifest = agentTranscriptBoundedToPinnedManifest(bundle, calls);
  const transcriptHash =
    calls.length > 0
      ? hashJson({
          format: "mcp-json-rpc",
          sessionId: bundle.sessionId,
          toolsListHash,
          toolsCallHash,
          boundedToPinnedManifest,
          callCount: calls.length,
        })
      : null;
  return {
    sessionId: bundle.sessionId,
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

function replayPageTotalRows(bundle, collectionName) {
  const totalRows = bundle?.replayPageIndex?.collections?.[collectionName]?.totalRows;
  return Number.isInteger(totalRows) ? totalRows : null;
}

function agentTranscriptBoundedToPinnedManifest(bundle, calls) {
  const leaseRows = replayRowsForCollection(bundle, "leaseRuns");
  const successfulLeases = leaseRows.filter(
    (lease) => isObject(lease) && lease.status === "succeeded_live_mcp_transcript",
  );
  if (successfulLeases.length === 0) {
    return false;
  }
  if (replayPageTotalRows(bundle, "leaseRuns") !== leaseRows.length) {
    return false;
  }
  const expectedAuditNonces = new Set();
  for (const lease of successfulLeases) {
    if (typeof lease.leaseRunId !== "string") {
      return false;
    }
    const prefix = lease.leaseRunId.slice(2, 22);
    expectedAuditNonces.add(`lease_${prefix}_tools_list`);
    expectedAuditNonces.add(`lease_${prefix}_tools_call`);
  }
  if (replayPageTotalRows(bundle, "mcpAdapterCalls") !== expectedAuditNonces.size) {
    return false;
  }
  if (calls.length !== expectedAuditNonces.size) {
    return false;
  }
  if (calls.some((call) => !isObject(call) || !expectedAuditNonces.has(call.auditNonce))) {
    return false;
  }
  const callsByAuditNonce = new Map(calls.filter(isObject).map((call) => [call.auditNonce, call]));
  return successfulLeases.every((lease) => {
    const prefix = typeof lease.leaseRunId === "string" ? lease.leaseRunId.slice(2, 22) : "";
    const listCall = callsByAuditNonce.get(`lease_${prefix}_tools_list`);
    const toolCall = callsByAuditNonce.get(`lease_${prefix}_tools_call`);
    const binding = pinnedMcpManifestBindingForLease(bundle, lease, listCall, toolCall);
    return binding.ok;
  });
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
    const requestRedacted = hasRedactedField(call, "request.params.arguments.artifactPayload");
    const requestHash = requestRedacted ? null : safeHashJson(call.request, `MCP adapter call ${call.callId ?? "-"} request`, errors);
    const responseHash = safeHashJson(call.response, `MCP adapter call ${call.callId ?? "-"} response`, errors);
    if (requestRedacted && !isHex32(call.requestHash)) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} redacted request requires a recorded requestHash`);
    } else if (requestHash && lowerHex(call.requestHash) !== requestHash) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} requestHash does not match request`);
    }
    if (responseHash && lowerHex(call.responseHash) !== responseHash) {
      errors.push(`MCP adapter call ${call.callId ?? "-"} responseHash does not match response`);
    }
    if (typeof call.auditNonce === "string") {
      callsByAuditNonce.set(call.auditNonce, call);
    }
  }
  const transcript = buildAgentTranscriptSnapshot(bundle, calls.filter(isObject));
  const transcriptHash = safeHashJson(transcript, "agent transcript snapshot", errors);
  if (transcriptHash && lowerHex(bundle.agentTranscriptHash) !== transcriptHash) {
    errors.push("agentTranscriptHash must equal the hash of the replay MCP transcript snapshot");
  }
  const successfulLeaseCount = (Array.isArray(bundle.leaseRuns) ? bundle.leaseRuns : []).filter(
    (lease) => isObject(lease) && lease.status === "succeeded_live_mcp_transcript",
  ).length;
  if (successfulLeaseCount > 0 && transcript.boundedToPinnedManifest !== true) {
    errors.push("agentTranscript with succeeded leases must contain only pinned manifest MCP transcript frames");
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

function validateLeaseToolDefinition(tool, label, errors = null) {
  const fail = (message) => {
    if (errors) {
      errors.push(`${label} ${message}`);
    }
    return false;
  };
  if (!isObject(tool)) {
    return fail("must be an object");
  }
  if (typeof tool.name !== "string" || !/^pactfuse_[a-z0-9_:-]{1,80}$/.test(tool.name)) {
    return fail("name must be a controlled pactfuse_* capability");
  }
  if (DANGEROUS_TOOL_NAME_PATTERN.test(tool.name.toLowerCase())) {
    return fail("name must not describe write, execution, transfer, or file capabilities");
  }
  const annotations = tool.annotations;
  if (!isObject(annotations) || annotations.readOnlyHint !== true) {
    return fail("must advertise annotations.readOnlyHint=true");
  }
  const schema = tool.inputSchema;
  if (!isObject(schema)) {
    return fail("must expose an inputSchema object");
  }
  if (schema.type !== "object") {
    return fail("inputSchema.type must be object");
  }
  if (schema.additionalProperties !== false) {
    return fail("inputSchema must set additionalProperties=false");
  }
  if (!isObject(schema.properties)) {
    return fail("inputSchema must declare properties");
  }
  if (!Array.isArray(schema.required)) {
    return fail("inputSchema must declare required fields");
  }
  const propertyNames = new Set(Object.keys(schema.properties));
  const requiredNames = new Set(schema.required.filter((field) => typeof field === "string"));
  const missing = REQUIRED_LEASE_TOOL_ARGUMENTS.filter((field) => !propertyNames.has(field) || !requiredNames.has(field));
  if (missing.length > 0) {
    return fail(`inputSchema is missing required PactFuse fields: ${missing.join(",")}`);
  }
  return true;
}

function sourceManifestHashesForSpend(sourceHashes, sourcesByHash, leaseRunId, errors) {
  const manifestHashes = [];
  for (const sourceHash of sourceHashes) {
    const source = sourcesByHash.get(lowerHex(sourceHash));
    if (!source) {
      errors.push(`succeeded lease run ${leaseRunId} source ${sourceHash} is missing from replay sources`);
      continue;
    }
    if (!isHex32(source.manifestHash)) {
      errors.push(`succeeded lease run ${leaseRunId} source ${sourceHash} is missing manifestHash`);
      continue;
    }
    manifestHashes.push(lowerHex(source.manifestHash));
  }
  return manifestHashes;
}

function pinnedMcpManifestBindingForLease(bundle, lease, listCall, toolCall, errors = null) {
  const fail = (message) => {
    if (errors) {
      errors.push(message);
    }
    return { ok: false };
  };
  if (!isObject(listCall) || !isObject(toolCall)) {
    return fail(`succeeded lease run ${lease?.leaseRunId ?? "-"} is missing bound MCP tools/list or tools/call transcript frames`);
  }
  const spend = replayRowsForCollection(bundle, "spends").find((candidate) => isObject(candidate) && candidate.spendId === lease.spendId);
  if (!spend) {
    return fail(`succeeded lease run ${lease.leaseRunId} references a spend without pinned source manifest data`);
  }
  if (!Array.isArray(spend.sourceHashes) || spend.sourceHashes.length === 0) {
    return fail(`succeeded lease run ${lease.leaseRunId} spend is missing source hashes`);
  }
  const sourceHashes = [];
  for (const sourceHash of spend.sourceHashes) {
    if (typeof sourceHash !== "string") {
      return fail(`succeeded lease run ${lease.leaseRunId} spend contains a non-string source hash`);
    }
    sourceHashes.push(lowerHex(sourceHash));
  }
  sourceHashes.sort();
  const sourcesByHash = new Map(
    replayRowsForCollection(bundle, "sources")
      .filter((source) => isObject(source) && typeof source.sourceHash === "string")
      .map((source) => [lowerHex(source.sourceHash), source]),
  );
  const expectedTools = [];
  for (const sourceHash of sourceHashes) {
    const source = sourcesByHash.get(lowerHex(sourceHash));
    if (!source) {
      return fail(`succeeded lease run ${lease.leaseRunId} source ${sourceHash} is missing from replay sources`);
    }
    const capabilityVector = source.capabilityVector;
    if (!isObject(capabilityVector)) {
      return fail(`succeeded lease run ${lease.leaseRunId} source ${sourceHash} has invalid capabilityVector`);
    }
    if (capabilityVector.has_write_file === true) {
      return fail(`succeeded lease run ${lease.leaseRunId} source ${sourceHash} advertises write-file capability`);
    }
    if (!Array.isArray(capabilityVector.mcpTools) || capabilityVector.mcpTools.length === 0) {
      return fail(`succeeded lease run ${lease.leaseRunId} source ${sourceHash} is missing pinned MCP tools`);
    }
    for (const tool of capabilityVector.mcpTools) {
      if (!isObject(tool) || typeof tool.name !== "string") {
        return fail(`succeeded lease run ${lease.leaseRunId} source ${sourceHash} has invalid pinned MCP tool`);
      }
      validateLeaseToolDefinition(tool, `succeeded lease run ${lease.leaseRunId} pinned MCP tool`, errors);
      expectedTools.push(tool);
    }
  }
  if (expectedTools.length !== 1) {
    return fail(`succeeded lease run ${lease.leaseRunId} pinned manifest must expose exactly one MCP tool`);
  }
  const actualTools = jsonPath(listCall, ["response", "result", "tools"]);
  if (!Array.isArray(actualTools) || actualTools.some((tool) => !isObject(tool))) {
    return fail(`succeeded lease run ${lease.leaseRunId} tools/list response is missing tool definitions`);
  }
  for (const tool of actualTools) {
    validateLeaseToolDefinition(tool, `succeeded lease run ${lease.leaseRunId} tools/list tool`, errors);
  }
  const expectedToolsHash = safeHashJson(expectedTools, `lease run ${lease.leaseRunId} pinned MCP tools`, errors ?? []);
  const actualToolsHash = safeHashJson(actualTools, `lease run ${lease.leaseRunId} actual MCP tools`, errors ?? []);
  if (expectedToolsHash && actualToolsHash && expectedToolsHash !== actualToolsHash) {
    return fail(`succeeded lease run ${lease.leaseRunId} tools/list is not bounded to pinned source manifest`);
  }
  const requestedToolName = jsonPath(toolCall, ["request", "params", "name"]);
  if (requestedToolName !== expectedTools[0].name) {
    return fail(`succeeded lease run ${lease.leaseRunId} tools/call name does not match pinned source manifest`);
  }
  const manifestHashes = sourceManifestHashesForSpend(sourceHashes, sourcesByHash, lease.leaseRunId, errors ?? []);
  if (manifestHashes.length !== sourceHashes.length) {
    return { ok: false };
  }
  return { ok: true, expectedToolsHash, actualToolsHash, spend, sourceHashes, manifestHashes };
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
    return { ok: false };
  }
  const manifestBinding = pinnedMcpManifestBindingForLease(bundle, lease, listCall, toolCall, errors);
  const expectedArguments = {
    sessionId: bundle.sessionId,
    leaseRunId: lease.leaseRunId,
    spendId: lease.spendId,
    payer: lease.payer,
    artifactHash: lease.artifactHash,
    artifactPayloadHash: lease.consumedArtifactPayloadHash,
    targetRepo: lease.targetRepo,
    targetCommit: lease.targetCommit,
  };
  for (const [field, expected] of Object.entries(expectedArguments)) {
    if (argumentsObject[field] !== expected) {
      errors.push(`succeeded lease run ${lease.leaseRunId} tools/call argument ${field} does not match lease run`);
    }
  }
  const redactedArtifactPayloadHash = artifactPayloadRedactionHash(argumentsObject.artifactPayload);
  const argumentPayloadHash =
    redactedArtifactPayloadHash ?? safeHashJson(argumentsObject.artifactPayload, `lease run ${lease.leaseRunId} tools/call artifactPayload`, errors);
  if (argumentPayloadHash && lowerHex(lease.consumedArtifactPayloadHash) !== argumentPayloadHash) {
    errors.push(`succeeded lease run ${lease.leaseRunId} tools/call artifactPayload hash does not match consumedArtifactPayloadHash`);
  }
  return manifestBinding;
}

function verifyLeaseRuns(bundle, callsByAuditNonce, eventsById, errors) {
  const artifactTokensById = new Map(
    replayRowsForCollection(bundle, "artifactAccessTokens").filter(isObject).map((token) => [token.tokenId, token]),
  );
  const spendsById = new Map(
    replayRowsForCollection(bundle, "spends").filter(isObject).map((spend) => [lowerHex(spend.spendId), spend]),
  );
  const leaseRuns = replayRowsForCollection(bundle, "leaseRuns");
  for (const lease of leaseRuns) {
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
    for (const field of [
      "leaseRunId",
      "spendId",
      "payer",
      "artifactHash",
      "consumedArtifactPayloadHash",
      "targetRepo",
      "targetCommit",
      "settlementEventId",
      "artifactTokenId",
    ]) {
      requirePath(lease, [field], errors);
    }
    const spend = spendsById.get(lowerHex(lease.spendId));
    if (!spend) {
      errors.push(`succeeded lease run ${lease.leaseRunId} references missing registered spend`);
    } else {
      if (lowerHex(lease.artifactHash) !== lowerHex(spend.artifactHash)) {
        errors.push(`succeeded lease run ${lease.leaseRunId} artifactHash does not match registered spend artifactHash`);
      }
      if (typeof spend.payer === "string" && lease.payer !== spend.payer) {
        errors.push(`succeeded lease run ${lease.leaseRunId} payer does not match registered spend payer`);
      }
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
    const manifestBinding = verifyLeaseMcpCallBinding(lease, listCall, toolCall, bundle, errors);
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
    let expectedManifestBindingHash = null;
    if (manifestBinding?.ok) {
      expectedManifestBindingHash = safeHashJson(
        {
          sessionId: bundle.sessionId,
          leaseRunId: lease.leaseRunId,
          spendId: lease.spendId,
          sourceHashes: manifestBinding.sourceHashes,
          manifestHashes: manifestBinding.manifestHashes,
          pinnedManifestToolsHash: manifestBinding.expectedToolsHash,
          toolsListHash: lease.toolsListHash,
          toolsCallHash: lease.toolsCallHash,
        },
        `lease run ${lease.leaseRunId} manifest binding hash body`,
        errors,
      );
    }
    const token = artifactTokensById.get(lease.artifactTokenId);
    if (!token) {
      errors.push(`succeeded lease run ${lease.leaseRunId} references missing artifact token`);
    } else if (
      token.spendId !== lease.spendId ||
      lowerHex(token.artifactHash) !== lowerHex(lease.artifactHash) ||
      lowerHex(token.artifactPayloadHash) !== lowerHex(lease.consumedArtifactPayloadHash)
    ) {
      errors.push(`succeeded lease run ${lease.leaseRunId} does not match referenced artifact token`);
    }
    const expectedLeaseRunHash = safeHashJson(
      {
        sessionId: bundle.sessionId,
        leaseRunId: lease.leaseRunId,
        spendId: lease.spendId,
        payer: lease.payer,
        artifactHash: lowerHex(lease.artifactHash),
        consumedArtifactPayloadHash: lowerHex(lease.consumedArtifactPayloadHash),
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
        "consumedArtifactPayloadHash",
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
      if (event.payload?.boundedToPinnedManifest !== true) {
        errors.push(`lease execution event ${event.eventId ?? "-"} payload.boundedToPinnedManifest must be true`);
      }
      if (manifestBinding?.ok) {
        if (event.payload?.pinnedManifestToolsHash !== manifestBinding.expectedToolsHash) {
          errors.push(`lease execution event ${event.eventId ?? "-"} payload.pinnedManifestToolsHash does not match pinned manifest`);
        }
        if (JSON.stringify(event.payload?.pinnedManifestHashes) !== JSON.stringify(manifestBinding.manifestHashes)) {
          errors.push(`lease execution event ${event.eventId ?? "-"} payload.pinnedManifestHashes does not match pinned manifest`);
        }
        if (expectedManifestBindingHash && event.payload?.manifestBindingHash !== expectedManifestBindingHash) {
          errors.push(`lease execution event ${event.eventId ?? "-"} payload.manifestBindingHash does not recompute`);
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
    if (row.rowId === "caw_boundary" && row.status === "pass" && event.kind !== "caw.allowance.verified") {
      errors.push("judgeCheck pass row caw_boundary must reference caw.allowance.verified");
    }
    if (row.rowId === "c_settlement" && row.status === "pass" && event.kind !== "token.balance_delta.verified") {
      errors.push("judgeCheck pass row c_settlement must reference token.balance_delta.verified");
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

function verifyCawAuditUsageEvents(eventsById, interactionsById, errors) {
  for (const event of eventsById.values()) {
    if (!isObject(event) || event.kind !== "caw.live.audit.usage.verified") {
      continue;
    }
    const payload = isObject(event.payload) ? event.payload : null;
    const label = `CAW audit usage event ${event.eventId ?? "-"}`;
    if (!payload) {
      errors.push(`${label} requires payload`);
      continue;
    }
    if (event.authority !== "proof" || payload.proofAuthority !== true || payload.winnerClaimAllowed !== false) {
      errors.push(`${label} must carry proofAuthority=true and winnerClaimAllowed=false`);
    }
    if (!isHex32(payload.policyDigest)) {
      errors.push(`${label} requires policyDigest`);
    }
    if (payload.pactPolicyDigest !== payload.policyDigest) {
      errors.push(`${label} pactPolicyDigest must match policyDigest`);
    }
    if (!isHex32(payload.auditLogHash)) {
      errors.push(`${label} requires auditLogHash`);
    }
    if (payload.result !== "allowed" && payload.result !== "denied") {
      errors.push(`${label} result must be allowed or denied`);
    }
    if (payload.result === "allowed" && !isHex32(payload.txHash)) {
      errors.push(`${label} allowed result requires txHash`);
    }
    const auditEvent = eventsById.get(payload.auditEventId);
    if (!isObject(auditEvent) || auditEvent.kind !== "caw.live.audit.synced" || auditEvent.authority !== "proof") {
      errors.push(`${label} references missing caw.live.audit.synced event`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.auditInteractionId],
        ["requestHash", payload.auditRequestHash],
        ["responseHash", payload.auditResponseHash],
      ]) {
        if ((auditEvent.payload?.[field] ?? null) !== expected) {
          errors.push(`${label} audit event payload.${field} does not match usage proof`);
        }
      }
    }
    const contractEvent = eventsById.get(payload.cawContractCallEventId);
    if (!isObject(contractEvent) || contractEvent.kind !== "caw.live.contract_call.submitted" || contractEvent.authority !== "proof") {
      errors.push(`${label} references missing CAW contract call event`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.interactionId],
        ["operationKind", payload.operationKind],
        ["pactPolicyDigest", payload.policyDigest],
        ["requestHash", payload.requestHash],
        ["responseHash", payload.responseHash],
      ]) {
        if (asText(contractEvent.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
          errors.push(`${label} contract call event payload.${field} does not match usage proof`);
        }
      }
      if (payload.result === "allowed" && asText(contractEvent.payload?.txHash).toLowerCase() !== asText(payload.txHash).toLowerCase()) {
        errors.push(`${label} contract call event payload.txHash does not match usage proof`);
      }
    }
    const pactSyncEvent = eventsById.get(payload.pactSyncEventId);
    if (!isObject(pactSyncEvent) || pactSyncEvent.kind !== "caw.live.pact.synced" || pactSyncEvent.authority !== "proof") {
      errors.push(`${label} references missing CAW Pact sync event`);
    } else if (
      pactSyncEvent.payload?.interactionId !== payload.pactSyncInteractionId ||
      pactSyncEvent.payload?.policyDigest !== payload.policyDigest ||
      pactSyncEvent.payload?.proofAuthority !== true
    ) {
      errors.push(`${label} Pact sync event does not match audit policy proof`);
    }
    const interaction = interactionsById.get(payload.interactionId);
    if (!isObject(interaction) || interaction.kind !== "contract_call") {
      errors.push(`${label} references missing CAW contract call interaction`);
      continue;
    }
    if (interaction.requestHash !== payload.requestHash || interaction.responseHash !== payload.responseHash) {
      errors.push(`${label} requestHash/responseHash do not match CAW contract call interaction`);
    }
    if (interaction.request?.operation_kind !== payload.operationKind || interaction.request?.request_id !== payload.cawRequestId) {
      errors.push(`${label} request operation_kind/request_id do not match audit usage`);
    }
  }
}

function verifyCawAllowanceEvents(eventsById, spendsById, interactionsById, errors) {
  for (const event of eventsById.values()) {
    if (!isObject(event) || event.kind !== "caw.allowance.verified") {
      continue;
    }
    const payload = isObject(event.payload) ? event.payload : null;
    const label = `CAW allowance event ${event.eventId ?? "-"}`;
    if (!payload) {
      errors.push(`${label} requires payload`);
      continue;
    }
    if (event.authority !== "proof" || payload.proofAuthority !== true || payload.winnerClaimAllowed !== false) {
      errors.push(`${label} must carry proofAuthority=true and winnerClaimAllowed=false`);
    }
    if (payload.chainProviderMode !== "live") {
      errors.push(`${label} requires chainProviderMode=live`);
    }
    verifyPublicChainProviderEndpoint(label, payload, errors);
    const spend = spendsById.get(lowerHex(payload.spendId));
    if (!spend) {
      errors.push(`${label} references missing registered spend`);
      continue;
    }
    const amount = decimal(payload.amountAtomic);
    const spendAmount = decimal(spend.maxPriceAtomic);
    if (amount === null || spendAmount === null || amount !== spendAmount) {
      errors.push(`${label} amountAtomic does not match registered spend price`);
    }
    for (const [field, expected] of [
      ["paymentToken", spend.paymentToken],
      ["payer", spend.payer],
      ["agentWallet", spend.agentWallet],
      ["owner", spend.agentWallet],
    ]) {
      if (lowerHex(payload[field]) !== lowerHex(expected)) {
        errors.push(`${label} payload.${field} does not match registered spend`);
      }
    }
    if (lowerHex(spend.payer) !== lowerHex(spend.agentWallet) || payload.payerAgentWalletSame !== true) {
      errors.push(`${label} requires payerAgentWalletSame=true until wallet ownership proof exists`);
    }
    const spender = lowerHex(payload.spender);
    const gate = lowerHex(payload.procurementGateAddress);
    if (!isEvmAddress(spender) || spender !== gate) {
      errors.push(`${label} spender must equal ProcurementGate address`);
    }
    if (decimal(payload.allowanceAfter) !== spendAmount) {
      errors.push(`${label} allowanceAfter must equal registered spend price`);
    }
    if (decimal(payload.allowanceBefore) === null) {
      errors.push(`${label} allowanceBefore must be a decimal uint string`);
    }
    if (Number(payload.preBlockNumber) !== Number(payload.blockNumber) - 1) {
      errors.push(`${label} preBlockNumber must equal blockNumber - 1`);
    }
    if (!isHex32(payload.approveTxHash)) {
      errors.push(`${label} requires approveTxHash`);
    }
    if (!isHex32(payload.auditPolicyDigest)) {
      errors.push(`${label} requires auditPolicyDigest`);
    }
    if (!isHex32(payload.auditLogHash)) {
      errors.push(`${label} requires auditLogHash`);
    }
    if (!isHex32(payload.approvalRawLogHash)) {
      errors.push(`${label} requires approvalRawLogHash`);
    }
    const topics = Array.isArray(payload.approvalTopics) ? payload.approvalTopics.map((topic) => asText(topic).toLowerCase()) : [];
    if (
      topics[0] !== ERC20_APPROVAL_TOPIC ||
      topics[1] !== evmAddressTopic(spend.agentWallet) ||
      topics[2] !== evmAddressTopic(gate)
    ) {
      errors.push(`${label} approvalTopics do not bind ERC20 Approval(owner=agentWallet,spender=ProcurementGate)`);
    }
    if (amount !== null && asText(payload.approvalData).toLowerCase() !== `0x${uint256Word(amount)}`) {
      errors.push(`${label} approvalData does not encode amountAtomic`);
    }
    const cawEvent = eventsById.get(payload.cawContractCallEventId);
    if (!isObject(cawEvent) || cawEvent.kind !== "caw.live.contract_call.submitted" || cawEvent.authority !== "proof") {
      errors.push(`${label} references missing proof-authority CAW contract call event`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.approveInteractionId],
        ["spendId", payload.spendId],
        ["operationKind", "approve"],
        ["contractAddress", spend.paymentToken],
        ["selector", ERC20_APPROVE_SELECTOR],
        ["txHash", payload.approveTxHash],
        ["pactPolicyDigest", payload.auditPolicyDigest],
        ["requestHash", payload.requestHash],
        ["responseHash", payload.responseHash],
      ]) {
        if (lowerHex(cawEvent.payload?.[field]) !== lowerHex(expected)) {
          errors.push(`${label} CAW contract call event payload.${field} does not match allowance proof`);
        }
      }
    }
    const interaction = interactionsById.get(payload.approveInteractionId);
    if (!interaction || interaction.kind !== "contract_call") {
      errors.push(`${label} references missing CAW live approve interaction`);
      continue;
    }
    if (interaction.status === "live_denied" || interaction.status === "live_failed") {
      errors.push(`${label} cannot reference denied or failed CAW live approve interaction`);
    }
    if (interaction.requestHash !== payload.requestHash || interaction.responseHash !== payload.responseHash) {
      errors.push(`${label} requestHash/responseHash do not match CAW live interaction`);
    }
    if (interaction.request?.operation_kind !== "approve") {
      errors.push(`${label} CAW interaction must be an approve contract call`);
    }
    const expectedCalldata = expectedApproveCalldata(gate, asText(spend.maxPriceAtomic));
    for (const [field, expected] of [
      ["spend_id", payload.spendId],
      ["contract_addr", spend.paymentToken],
      ["selector", ERC20_APPROVE_SELECTOR],
      ["spender_addr", gate],
      ["procurement_gate_addr", gate],
      ["amount", asText(spend.maxPriceAtomic)],
      ["calldata", expectedCalldata],
    ]) {
      const actual = field === "amount" ? (decimal(interaction.request?.[field]) ?? -1n).toString() : asText(interaction.request?.[field]).toLowerCase();
      if (actual !== asText(expected).toLowerCase()) {
        errors.push(`${label} CAW approve request.${field} does not match allowance proof`);
      }
    }
    const auditUsageEvent = eventsById.get(payload.auditUsageEventId);
    if (!isObject(auditUsageEvent) || auditUsageEvent.kind !== "caw.live.audit.usage.verified" || auditUsageEvent.authority !== "proof") {
      errors.push(`${label} references missing CAW live audit usage proof`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.approveInteractionId],
        ["txHash", payload.approveTxHash],
        ["operationKind", "approve"],
        ["result", "allowed"],
        ["policyDigest", payload.auditPolicyDigest],
        ["pactPolicyDigest", payload.auditPolicyDigest],
        ["auditLogHash", payload.auditLogHash],
      ]) {
        if (asText(auditUsageEvent.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
          errors.push(`${label} audit usage payload.${field} does not match allowance proof`);
        }
      }
    }
  }
}

function verifyCawActivationEvents(eventsById, errors) {
  for (const event of eventsById.values()) {
    if (!isObject(event) || event.kind !== "caw.activation.verified") {
      continue;
    }
    const payload = isObject(event.payload) ? event.payload : null;
    const label = `CAW activation event ${event.eventId ?? "-"}`;
    if (!payload) {
      errors.push(`${label} requires payload`);
      continue;
    }
    if (event.authority !== "proof" || payload.proofAuthority !== true || payload.winnerClaimAllowed !== false) {
      errors.push(`${label} must carry proofAuthority=true and winnerClaimAllowed=false`);
    }
    if (payload.chainProviderMode !== "live") {
      errors.push(`${label} requires chainProviderMode=live`);
    }
    verifyPublicChainProviderEndpoint(label, payload, errors);
    if (!isHex32(payload.activateTxHash)) {
      errors.push(`${label} requires activateTxHash`);
    }
    if (!isHex32(payload.auditPolicyDigest)) {
      errors.push(`${label} requires auditPolicyDigest`);
    }
    if (!isHex32(payload.auditLogHash)) {
      errors.push(`${label} requires auditLogHash`);
    }
    const contractEvent = eventsById.get(payload.cawContractCallEventId);
    if (!isObject(contractEvent) || contractEvent.kind !== "caw.live.contract_call.submitted" || contractEvent.authority !== "proof") {
      errors.push(`${label} references missing CAW activate contract call event`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.activateInteractionId],
        ["operationKind", "activate_tool"],
        ["txHash", payload.activateTxHash],
        ["pactPolicyDigest", payload.auditPolicyDigest],
        ["spendId", payload.spendId],
        ["requestHash", payload.requestHash],
        ["responseHash", payload.responseHash],
      ]) {
        if (asText(contractEvent.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
          errors.push(`${label} contract call event payload.${field} does not match activation proof`);
        }
      }
    }
    const auditUsageEvent = eventsById.get(payload.auditUsageEventId);
    if (!isObject(auditUsageEvent) || auditUsageEvent.kind !== "caw.live.audit.usage.verified" || auditUsageEvent.authority !== "proof") {
      errors.push(`${label} references missing CAW audit usage proof`);
    } else {
      for (const [field, expected] of [
        ["interactionId", payload.activateInteractionId],
        ["operationKind", "activate_tool"],
        ["result", "allowed"],
        ["txHash", payload.activateTxHash],
        ["policyDigest", payload.auditPolicyDigest],
        ["pactPolicyDigest", payload.auditPolicyDigest],
        ["auditLogHash", payload.auditLogHash],
      ]) {
        if (asText(auditUsageEvent.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
          errors.push(`${label} audit usage payload.${field} does not match activation proof`);
        }
      }
    }
    const settlementEvent = eventsById.get(payload.settlementEventId);
    if (!isObject(settlementEvent) || settlementEvent.kind !== "gate.spend_settled" || settlementEvent.authority !== "proof") {
      errors.push(`${label} references missing finalized SpendSettled event`);
    } else if (
      settlementEvent.payload?.finalityStatus !== "finalized" ||
      settlementEvent.payload?.proofAuthority !== true ||
      lowerHex(settlementEvent.payload?.txHash) !== lowerHex(payload.activateTxHash) ||
      settlementEvent.payload?.spendId !== payload.spendId
    ) {
      errors.push(`${label} settlement event does not match activation tx/spend`);
    }
  }
}

function verifyTokenBalanceDeltaEvents(eventsById, spendsById, errors) {
  for (const event of eventsById.values()) {
    if (!isObject(event) || event.kind !== "token.balance_delta.verified") {
      continue;
    }
    const payload = isObject(event.payload) ? event.payload : null;
    const label = `token balance delta event ${event.eventId ?? "-"}`;
    if (!payload) {
      errors.push(`${label} requires payload`);
      continue;
    }
    if (event.authority !== "proof" || payload.proofAuthority !== true || payload.winnerClaimAllowed !== false) {
      errors.push(`${label} must carry proofAuthority=true and winnerClaimAllowed=false`);
    }
    if (payload.chainProviderMode !== "live") {
      errors.push(`${label} requires chainProviderMode=live`);
    }
    verifyPublicChainProviderEndpoint(label, payload, errors);
    const spend = spendsById.get(lowerHex(payload.spendId));
    if (!spend) {
      errors.push(`${label} references missing registered spend`);
      continue;
    }
    const amount = decimal(payload.amountAtomic);
    const spendAmount = decimal(spend.maxPriceAtomic);
    if (amount === null || spendAmount === null || amount !== spendAmount) {
      errors.push(`${label} amountAtomic does not match registered spend price`);
    }
    for (const [field, expected] of [
      ["paymentToken", spend.paymentToken],
      ["payer", spend.payer],
      ["agentWallet", spend.agentWallet],
      ["market", spend.market],
    ]) {
      if (lowerHex(payload[field]) !== lowerHex(expected)) {
        errors.push(`${label} payload.${field} does not match registered spend`);
      }
    }
    if (lowerHex(spend.payer) !== lowerHex(spend.agentWallet) || payload.payerAgentWalletSame !== true) {
      errors.push(`${label} requires payerAgentWalletSame=true until wallet ownership proof exists`);
    }
    const allowanceEvent = eventsById.get(payload.allowanceEventId);
    const allowancePayload = isObject(allowanceEvent?.payload) ? allowanceEvent.payload : null;
    if (
      !isObject(allowanceEvent) ||
      allowanceEvent.kind !== "caw.allowance.verified" ||
      allowanceEvent.authority !== "proof" ||
      !allowancePayload ||
      allowancePayload.spendId !== payload.spendId ||
      allowancePayload.proofAuthority !== true
    ) {
      errors.push(`${label} references missing proof-authority caw.allowance.verified allowanceEventId`);
    } else {
      for (const [field, expected] of [
        ["approveInteractionId", allowancePayload.approveInteractionId],
        ["approveTxHash", allowancePayload.approveTxHash],
        ["paymentToken", allowancePayload.paymentToken],
        ["payer", allowancePayload.payer],
        ["agentWallet", allowancePayload.agentWallet],
        ["amountAtomic", allowancePayload.amountAtomic],
      ]) {
        if (lowerHex(payload[field]) !== lowerHex(expected)) {
          errors.push(`${label} payload.${field} does not match allowance proof`);
        }
      }
    }
    const activationEvent = eventsById.get(payload.activationEventId);
    const activationPayload = isObject(activationEvent?.payload) ? activationEvent.payload : null;
    if (
      !isObject(activationEvent) ||
      activationEvent.kind !== "caw.activation.verified" ||
      activationEvent.authority !== "proof" ||
      !activationPayload ||
      activationPayload.spendId !== payload.spendId ||
      activationPayload.proofAuthority !== true
    ) {
      errors.push(`${label} references missing proof-authority caw.activation.verified activationEventId`);
    } else {
      for (const [field, expected] of [
        ["activateInteractionId", activationPayload.activateInteractionId],
        ["activateTxHash", activationPayload.activateTxHash],
        ["settlementEventId", activationPayload.settlementEventId],
        ["gateEventId", activationPayload.gateEventId],
      ]) {
        if (lowerHex(payload[field]) !== lowerHex(expected)) {
          errors.push(`${label} payload.${field} does not match activation proof`);
        }
      }
      if (lowerHex(payload.txHash) !== lowerHex(activationPayload.activateTxHash)) {
        errors.push(`${label} activateTxHash must match settlement txHash`);
      }
    }
    const settlementEvent = eventsById.get(payload.settlementEventId);
    const settlementPayload = isObject(settlementEvent?.payload) ? settlementEvent.payload : null;
    if (
      !isObject(settlementEvent) ||
      settlementEvent.kind !== "gate.spend_settled" ||
      settlementEvent.authority !== "proof" ||
      !settlementPayload ||
      settlementPayload.finalityStatus !== "finalized" ||
      settlementPayload.proofAuthority !== true
    ) {
      errors.push(`${label} references missing finalized proof-authority gate.spend_settled event`);
    } else {
      for (const field of ["gateEventId", "spendId", "txHash", "chainId", "blockNumber"]) {
        if (payload[field] !== settlementPayload[field]) {
          errors.push(`${label} payload.${field} does not match settlement event`);
        }
      }
    }
    if (Number(payload.preBlockNumber) !== Number(payload.blockNumber) - 1) {
      errors.push(`${label} preBlockNumber must equal blockNumber - 1`);
    }
    if (amount !== null) {
      const agentBefore = decimal(payload.agentWalletBefore);
      const agentAfter = decimal(payload.agentWalletAfter);
      const marketBefore = decimal(payload.marketBefore);
      const marketAfter = decimal(payload.marketAfter);
      if (agentBefore === null || agentAfter === null || agentBefore - agentAfter !== amount) {
        errors.push(`${label} agent wallet balance delta does not match amountAtomic`);
      }
      if (marketBefore === null || marketAfter === null || marketAfter - marketBefore !== amount) {
        errors.push(`${label} market balance delta does not match amountAtomic`);
      }
      if (payload.agentDeltaAtomic !== `-${amount.toString()}` || payload.marketDeltaAtomic !== amount.toString()) {
        errors.push(`${label} signed delta fields do not match amountAtomic`);
      }
      const topics = Array.isArray(payload.transferTopics) ? payload.transferTopics.map((topic) => asText(topic).toLowerCase()) : [];
      if (
        topics[0] !== ERC20_TRANSFER_TOPIC ||
        topics[1] !== evmAddressTopic(spend.agentWallet) ||
        topics[2] !== evmAddressTopic(spend.market)
      ) {
        errors.push(`${label} transferTopics do not bind ERC20 Transfer(from=agentWallet,to=market)`);
      }
      if (asText(payload.transferData).toLowerCase() !== `0x${uint256Word(amount)}`) {
        errors.push(`${label} transferData does not encode amountAtomic`);
      }
    }
    if (!Number.isInteger(Number(payload.transferLogIndex)) || Number(payload.transferLogIndex) < 0) {
      errors.push(`${label} requires transferLogIndex`);
    }
    if (!isHex32(payload.transferRawLogHash)) {
      errors.push(`${label} requires transferRawLogHash`);
    }
    const expectedTransferLogBindingHash = tokenTransferLogBindingHash(payload);
    if (!isHex32(payload.transferLogBindingHash) || lowerHex(payload.transferLogBindingHash) !== expectedTransferLogBindingHash) {
      errors.push(`${label} transferLogBindingHash does not recompute`);
    }
    const expectedBalanceReadHash = tokenBalanceReadHash(payload);
    if (!isHex32(payload.balanceReadHash) || lowerHex(payload.balanceReadHash) !== expectedBalanceReadHash) {
      errors.push(`${label} balanceReadHash does not recompute`);
    }
    const expectedChainReadProofHash = tokenBalanceDeltaChainReadProofHash(payload);
    if (!isHex32(payload.chainReadProofHash) || lowerHex(payload.chainReadProofHash) !== expectedChainReadProofHash) {
      errors.push(`${label} chainReadProofHash does not recompute`);
    }
  }
}

function tokenTransferLogBindingHash(payload) {
  return hashJson({
    mode: "erc20_transfer_log_binding_v1",
    chainId: asText(payload.chainId),
    txHash: lowerHex(payload.txHash),
    blockNumber: Number(payload.blockNumber),
    logIndex: Number(payload.transferLogIndex),
    address: lowerHex(payload.paymentToken),
    rawLogHash: lowerHex(payload.transferRawLogHash),
    topics: Array.isArray(payload.transferTopics) ? payload.transferTopics.map((topic) => asText(topic).toLowerCase()) : [],
    data: asText(payload.transferData).toLowerCase(),
  });
}

function tokenBalanceReadHash(payload) {
  return hashJson({
    mode: "erc20_balance_read_v1",
    chainId: asText(payload.chainId),
    blockNumber: Number(payload.blockNumber),
    preBlockNumber: Number(payload.preBlockNumber),
    paymentToken: lowerHex(payload.paymentToken),
    agentWallet: lowerHex(payload.agentWallet),
    market: lowerHex(payload.market),
    amountAtomic: asText(payload.amountAtomic),
    agentWalletBefore: asText(payload.agentWalletBefore),
    agentWalletAfter: asText(payload.agentWalletAfter),
    marketBefore: asText(payload.marketBefore),
    marketAfter: asText(payload.marketAfter),
  });
}

function tokenBalanceDeltaChainReadProofHash(payload) {
  return hashJson({
    mode: "token_balance_delta_chain_read_proof_v1",
    chainProviderMode: asText(payload.chainProviderMode),
    chainProviderEndpoint: payload.chainProviderEndpoint === null || payload.chainProviderEndpoint === undefined ? null : asText(payload.chainProviderEndpoint),
    settlementEventId: asText(payload.settlementEventId),
    gateEventId: asText(payload.gateEventId),
    transferLogBindingHash: lowerHex(payload.transferLogBindingHash),
    balanceReadHash: lowerHex(payload.balanceReadHash),
  });
}

function verifySourceIdentityBindings(bundle, errors) {
  for (const source of replayRowsForCollection(bundle, "sources")) {
    if (!isObject(source)) {
      errors.push("sources entries must be objects");
      continue;
    }
    verifyPublicReplayUrl(`source ${source.sourceHash ?? "-"} manifestUrl`, source.manifestUrl, errors);
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
      continue;
    }
    if (!isEvmAddress(source.issuer)) {
      errors.push(`source ${source.sourceHash ?? "-"} issuer must be an EVM address`);
      continue;
    }
    try {
      const recovered = recoverSourceIssuerAddress(sourceIdentityMessage(expectedSourceHash), source.signature);
      if (lowerHex(recovered) !== lowerHex(source.issuer)) {
        errors.push(`source ${source.sourceHash ?? "-"} signature does not recover issuer`);
      }
    } catch (error) {
      errors.push(`source ${source.sourceHash ?? "-"} signature cannot be recovered: ${error instanceof Error ? error.message : "unknown error"}`);
    }
  }
}

function sourceIdentityMessage(sourceIdentityHash) {
  return `PactFuse source identity v1:${sourceIdentityHash}`;
}

function recoverSourceIssuerAddress(message, signature) {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new Error("signature must be 65-byte hex");
  }
  const recoveryBit = signatureRecoveryBit(Number.parseInt(signature.slice(130, 132), 16));
  const compactSignature = signature.slice(2, 130);
  const messageHash = hashMessage(message);
  const publicKey = secp256k1.Signature.fromCompact(compactSignature)
    .addRecoveryBit(recoveryBit)
    .recoverPublicKey(messageHash.slice(2))
    .toHex(false);
  return publicKeyToAddress(`0x${publicKey}`);
}

function signatureRecoveryBit(yParityOrV) {
  if (yParityOrV === 0 || yParityOrV === 1) {
    return yParityOrV;
  }
  if (yParityOrV === 27) {
    return 0;
  }
  if (yParityOrV === 28) {
    return 1;
  }
  throw new Error("invalid recovery bit");
}

function verifyCawLiveInteractions(interactions, spendsById, eventsById, errors) {
  const activePacts = new Map();
  const contractCallCounts = new Map();
  for (const interaction of interactions) {
    if (
      isObject(interaction) &&
      interaction.kind === "pact_sync" &&
      interaction.status === "live_active" &&
      interaction.walletId &&
      interaction.pactId &&
      interaction.authKeyHash
    ) {
      const event = [...eventsById.values()].find(
        (candidate) => isObject(candidate) && candidate.kind === "caw.live.pact.synced" && candidate.payload?.interactionId === interaction.interactionId,
      );
      const binding = cawPactPolicyBindingFromInteraction(interaction, event, errors);
      if (binding) {
        activePacts.set(`${interaction.walletId}:${interaction.pactId}:${lowerHex(interaction.authKeyHash)}`, binding);
      }
    }
  }
  for (const interaction of interactions) {
    if (!isObject(interaction)) {
      errors.push("cawLiveInteractions entries must be objects");
      continue;
    }
    if (!isObject(interaction.request)) {
      errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} requires request`);
      continue;
    }
    if (!isObject(interaction.response)) {
      errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} requires response`);
      continue;
    }
    const requestHash = safeHashJson(interaction.request, `CAW live interaction ${interaction.interactionId ?? "-"} request`, errors);
    const responseHash = safeHashJson(interaction.response, `CAW live interaction ${interaction.interactionId ?? "-"} response`, errors);
    if (requestHash && requestHash !== lowerHex(interaction.requestHash)) {
      errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} requestHash does not match request`);
    }
    if (responseHash && responseHash !== lowerHex(interaction.responseHash)) {
      errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} responseHash does not match response`);
    }
    const expectedEventKind = cawLiveEventKindForInteraction(interaction.kind);
    const event = [...eventsById.values()].find(
      (candidate) =>
        isObject(candidate) &&
        candidate.kind === expectedEventKind &&
        candidate.payload?.interactionId === interaction.interactionId,
    );
    if (!event) {
      errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} has no matching evidence event`);
    } else {
      if (expectedEventKind && event.kind !== expectedEventKind) {
        errors.push(`CAW live interaction ${interaction.interactionId ?? "-"} event kind does not match interaction kind`);
      }
      for (const [field, expected] of [
        ["walletId", interaction.walletId ?? null],
        ["pactId", interaction.pactId ?? null],
        ["requestHash", interaction.requestHash],
        ["responseHash", interaction.responseHash],
        ["status", interaction.status],
      ]) {
        if ((event.payload?.[field] ?? null) !== expected) {
          errors.push(`CAW live event ${event.eventId ?? "-"} payload.${field} does not match interaction`);
        }
      }
      if (event.authority !== "proof" || event.payload?.proofAuthority !== true || event.payload?.winnerClaimAllowed !== false) {
        errors.push(`CAW live event ${event.eventId ?? "-"} must carry fail-closed proof payload`);
      }
    }
    if (interaction.kind === "contract_call") {
      verifyCawLiveContractCallInteraction(interaction, spendsById, eventsById, activePacts, event, errors);
      const key = `${interaction.walletId}:${interaction.pactId}:${lowerHex(interaction.authKeyHash)}`;
      if (interaction.status !== "live_denied" && interaction.status !== "live_failed") {
        contractCallCounts.set(key, (contractCallCounts.get(key) ?? 0) + 1);
      }
      continue;
    }
    if (interaction.kind !== "transfer_submit") {
      continue;
    }
    const spendId = typeof interaction.request.spend_id === "string" ? interaction.request.spend_id : null;
    if (!spendId) {
      errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} is missing spend_id`);
      continue;
    }
    const spend = spendsById.get(lowerHex(spendId));
    if (!spend) {
      errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} references missing registered spend`);
      continue;
    }
    for (const [field, expected] of [
      ["payment_token", lowerHex(spend.paymentToken)],
      ["dst_addr", lowerHex(spend.market)],
      ["amount", asText(spend.maxPriceAtomic)],
    ]) {
      const actual =
        field === "amount"
          ? (decimal(interaction.request[field]) ?? -1n).toString()
          : asText(interaction.request[field]).toLowerCase();
      if (actual !== asText(expected).toLowerCase()) {
        errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} request.${field} does not match registered spend`);
      }
    }
    if (typeof interaction.request.token_id === "string" && lowerHex(interaction.request.token_id) !== lowerHex(spend.paymentToken)) {
      errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} request.token_id does not match registered spend payment token`);
    }
    if (typeof interaction.request.src_addr === "string" && lowerHex(interaction.request.src_addr) !== lowerHex(spend.payer)) {
      errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} request.src_addr does not match registered spend payer`);
    }
    const activePact = activePacts.get(`${interaction.walletId}:${interaction.pactId}:${lowerHex(interaction.authKeyHash)}`);
    if (!activePact) {
      errors.push(`CAW live transfer ${interaction.interactionId ?? "-"} is not bound to an active synced CAW Pact and key hash`);
    }
    if (event) {
      for (const [field, expected] of [
        ["spendId", spendId],
        ["paymentToken", lowerHex(spend.paymentToken)],
        ["amount", asText(spend.maxPriceAtomic)],
        ["destinationAddress", lowerHex(spend.market)],
        ["pactSyncInteractionId", activePact?.pactSyncInteractionId],
        ["pactSyncEventId", activePact?.pactSyncEventId],
        ["pactPolicyDigest", activePact?.policyDigest],
        ["pactPolicySnapshotHash", activePact?.policySnapshotHash],
      ]) {
        if (expected !== undefined && asText(event.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
          errors.push(`CAW live event ${event.eventId ?? "-"} payload.${field} does not match registered spend transfer`);
        }
      }
    }
  }
  for (const [key, count] of contractCallCounts.entries()) {
    const activePact = activePacts.get(key);
    if (activePact && count > Number(activePact.policyRequestLimit)) {
      errors.push(`CAW live Pact ${key} contract call count exceeds policyRequestLimit`);
    }
  }
}

function cawPactPolicyBindingFromInteraction(interaction, event, errors) {
  const label = `CAW live active Pact ${interaction.interactionId ?? "-"}`;
  if (!isObject(event) || event.kind !== "caw.live.pact.synced" || event.authority !== "proof") {
    errors.push(`${label} has no proof-authority pact sync event`);
    return null;
  }
  const policyRoot = cawPactPolicyRoot(interaction.response);
  const policySnapshotHash = hashJson(policyRoot);
  const policyDigest =
    cawOptionalString(interaction.response, ["policy_digest", "policyDigest", "policy_hash", "policyHash", "pact_digest", "pactDigest"]) ??
    policySnapshotHash;
  const policyChainIds = arrayText(event.payload?.policyChainIds);
  const policyContractAddresses = arrayText(event.payload?.policyContractAddresses).map((value) => value.toLowerCase()).filter(isEvmAddress);
  const policySelectors = arrayText(event.payload?.policySelectors).map((value) => value.toLowerCase()).filter((value) => /^0x[0-9a-f]{8}$/.test(value));
  const policyRules = cawPactPolicyRules(policyRoot);
  const policyRequestLimit = asText(event.payload?.policyRequestLimit);
  const policyExpiry = asText(event.payload?.policyExpiry);
  if (
    !isHex32(policyDigest) ||
    event.payload?.policyDigest !== policyDigest ||
    !isHex32(event.payload?.policySnapshotHash) ||
    event.payload?.policySnapshotHash !== policySnapshotHash ||
    policyChainIds.length === 0 ||
    policyContractAddresses.length === 0 ||
    policySelectors.length === 0 ||
    policyRules.length === 0 ||
    decimal(policyRequestLimit) === null ||
    !policyExpiry
  ) {
    errors.push(`${label} requires policy digest, snapshot hash, chain/target/selector rules, request limit, and expiry`);
    return null;
  }
  if (event.payload?.policyRules !== undefined && hashJson(event.payload.policyRules) !== hashJson(policyRules)) {
    errors.push(`${label} policyRules evidence does not match response`);
    return null;
  }
  return {
    pactSyncInteractionId: interaction.interactionId,
    pactSyncEventId: event.eventId,
    policyDigest,
    policySnapshotHash,
    policyChainIds,
    policyContractAddresses,
    policySelectors,
    policyRules,
    policyRequestLimit,
    policyExpiry,
  };
}

function cawPactPolicyRoot(response) {
  const result = isObject(response?.result) ? response.result : null;
  const pact = isObject(result?.pact) ? result.pact : null;
  for (const root of [pact, result, response].filter(isObject)) {
    for (const key of ["policy", "policies", "policy_spec", "policySpec", "spec", "limits", "authorization", "rules"]) {
      if (root[key] !== undefined && root[key] !== null) {
        return { [key]: root[key] };
      }
    }
  }
  return result ?? response;
}

function cawOptionalString(response, keys) {
  const result = isObject(response?.result) ? response.result : null;
  const pact = isObject(result?.pact) ? result.pact : null;
  for (const root of [response, result, pact].filter(isObject)) {
    for (const key of keys) {
      if (typeof root[key] === "string" && root[key].length > 0) {
        return root[key];
      }
    }
  }
  return null;
}

function arrayText(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === "string") : [];
}

function policyDirectStringArray(root, keys) {
  const collected = [];
  for (const key of keys) {
    collectPolicyStrings(root?.[key], collected);
  }
  return [...new Set(collected)];
}

function collectPolicyStrings(value, collected) {
  if (typeof value === "string" && value.length > 0) {
    collected.push(value);
    return;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    collected.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectPolicyStrings(item, collected);
    }
  }
}

function cawPactPolicyRules(root) {
  const rules = [];
  const seen = new Set();
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item);
      }
      return;
    }
    if (!isObject(value)) {
      return;
    }
    const chainIds = policyDirectStringArray(value, CAW_POLICY_CHAIN_KEYS);
    const contractAddresses = policyDirectStringArray(value, CAW_POLICY_CONTRACT_KEYS)
      .map((candidate) => candidate.toLowerCase())
      .filter(isEvmAddress);
    const selectors = policyDirectStringArray(value, CAW_POLICY_SELECTOR_KEYS)
      .map((candidate) => candidate.toLowerCase())
      .filter((candidate) => /^0x[0-9a-f]{8}$/.test(candidate));
    if (chainIds.length > 0 && contractAddresses.length > 0 && selectors.length > 0) {
      const rule = {
        chainIds: [...new Set(chainIds)],
        contractAddresses: [...new Set(contractAddresses)],
        selectors: [...new Set(selectors)],
      };
      const key = canonicalizeJson(rule);
      if (!seen.has(key)) {
        seen.add(key);
        rules.push(rule);
      }
    }
    for (const child of Object.values(value)) {
      visit(child);
    }
  };
  visit(root);
  return rules;
}

function cawPactPolicyAllowsContractCall(activePact, payload) {
  return activePact.policyRules.some(
    (rule) =>
      rule.chainIds.includes(payload.chainId) &&
      rule.contractAddresses.includes(payload.contractAddress) &&
      rule.selectors.includes(payload.selector),
  );
}

function cawLiveEventKindForInteraction(kind) {
  return {
    pact_submit: "caw.live.pact.submitted",
    pact_sync: "caw.live.pact.synced",
    transfer_submit: "caw.live.transfer.submitted",
    contract_call: "caw.live.contract_call.submitted",
    audit_sync: "caw.live.audit.synced",
  }[kind];
}

function verifyCawLiveContractCallInteraction(interaction, spendsById, eventsById, activePacts, event, errors) {
  const label = `CAW live contract call ${interaction.interactionId ?? "-"}`;
  const spendId = typeof interaction.request.spend_id === "string" ? interaction.request.spend_id : null;
  if (!spendId) {
    errors.push(`${label} is missing spend_id`);
    return;
  }
  const spend = spendsById.get(lowerHex(spendId));
  if (!spend) {
    errors.push(`${label} references missing registered spend`);
    return;
  }
  const activePact = activePacts.get(`${interaction.walletId}:${interaction.pactId}:${lowerHex(interaction.authKeyHash)}`);
  if (!activePact) {
    errors.push(`${label} is not bound to an active synced CAW Pact and key hash`);
  }
  if (interaction.request.wallet_id !== interaction.walletId || interaction.request.pact_id !== interaction.pactId) {
    errors.push(`${label} request wallet_id/pact_id does not match interaction`);
  }
  if (event) {
    for (const [field, expected] of [
      ["spendId", spendId],
      ["operationKind", interaction.request.operation_kind],
      ["contractAddress", interaction.request.contract_addr],
      ["selector", interaction.request.selector],
      ["chainId", interaction.request.chain_id],
      ["valueAtomic", interaction.request.value],
      ["pactSyncInteractionId", activePact?.pactSyncInteractionId],
      ["pactSyncEventId", activePact?.pactSyncEventId],
      ["pactPolicyDigest", activePact?.policyDigest],
      ["pactPolicySnapshotHash", activePact?.policySnapshotHash],
    ]) {
      if (expected !== undefined && asText(event.payload?.[field]).toLowerCase() !== asText(expected).toLowerCase()) {
        errors.push(`CAW live event ${event.eventId ?? "-"} payload.${field} does not match contract call request`);
      }
    }
  }
  const operationKind = asText(interaction.request.operation_kind);
  const contractAddress = asText(interaction.request.contract_addr).toLowerCase();
  const selector = asText(interaction.request.selector).toLowerCase();
  const calldata = asText(interaction.request.calldata).toLowerCase();
  if (activePact) {
    const policyTuple = {
      chainId: asText(interaction.request.chain_id),
      contractAddress,
      selector,
    };
    const tupleAllowed = cawPactPolicyAllowsContractCall(activePact, policyTuple);
    if (operationKind === "deny_probe") {
      if (tupleAllowed) {
        errors.push(`${label} deny_probe chain/target/selector tuple is unexpectedly allowed by active Pact policy`);
      }
      if (interaction.status !== "live_denied" || event?.payload?.status !== "live_denied") {
        errors.push(`${label} deny_probe must be recorded as live_denied`);
      }
    } else {
      if (!activePact.policyChainIds.includes(policyTuple.chainId)) {
        errors.push(`${label} chain_id is not allowed by active Pact policy`);
      }
      if (!activePact.policyContractAddresses.includes(contractAddress)) {
        errors.push(`${label} contract_addr is not allowed by active Pact policy`);
      }
      if (!activePact.policySelectors.includes(selector)) {
        errors.push(`${label} selector is not allowed by active Pact policy`);
      }
      if (!tupleAllowed) {
        errors.push(`${label} chain/target/selector tuple is not allowed by active Pact policy`);
      }
    }
  }
  if (operationKind === "deny_probe") {
    return;
  }
  if (operationKind === "approve") {
    verifyCawLiveApproveCall(interaction, spend, contractAddress, selector, calldata, errors);
    return;
  }
  if (operationKind === "activate_tool") {
    verifyCawLiveActivateToolCall(interaction, spend, spendId, eventsById, event, contractAddress, selector, calldata, errors);
    return;
  }
  errors.push(`${label} has unsupported operation_kind`);
}

function verifyCawLiveApproveCall(interaction, spend, contractAddress, selector, calldata, errors) {
  const label = `CAW live approve ${interaction.interactionId ?? "-"}`;
  const expectedAmount = asText(spend.maxPriceAtomic);
  const procurementGateAddress = asText(interaction.request.procurement_gate_addr).toLowerCase();
  if (contractAddress !== lowerHex(spend.paymentToken)) {
    errors.push(`${label} request.contract_addr does not match registered spend payment token`);
  }
  if (!isEvmAddress(procurementGateAddress)) {
    errors.push(`${label} requires procurement_gate_addr`);
    return;
  }
  if (selector !== ERC20_APPROVE_SELECTOR) {
    errors.push(`${label} selector must be ERC20.approve(address,uint256)`);
  }
  if (asText(interaction.request.spender_addr).toLowerCase() !== procurementGateAddress) {
    errors.push(`${label} request.spender_addr must match procurement_gate_addr`);
  }
  if ((decimal(interaction.request.amount) ?? -1n).toString() !== expectedAmount) {
    errors.push(`${label} request.amount does not match registered spend price`);
  }
  const expectedCalldata = expectedApproveCalldata(procurementGateAddress, expectedAmount);
  if (!expectedCalldata || calldata !== expectedCalldata) {
    errors.push(`${label} calldata must approve ProcurementGate for the registered spend price`);
  }
}

function verifyCawLiveActivateToolCall(interaction, spend, spendId, eventsById, event, contractAddress, selector, calldata, errors) {
  const label = `CAW live activate_tool ${interaction.interactionId ?? "-"}`;
  if (!isEvmAddress(contractAddress)) {
    errors.push(`${label} requires contract_addr`);
    return;
  }
  if (contractAddress === lowerHex(spend.market)) {
    errors.push(`${label} contract_addr cannot be the PaidArtifactMarket`);
  }
  if (
    typeof interaction.request.procurement_gate_addr === "string" &&
    interaction.request.procurement_gate_addr.toLowerCase() !== contractAddress
  ) {
    errors.push(`${label} procurement_gate_addr must match contract_addr`);
  }
  if (selector !== PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR) {
    errors.push(`${label} selector must be ProcurementGate.activateTool(bytes32,bytes)`);
  }
  if ((decimal(interaction.request.value) ?? -1n).toString() !== "0") {
    errors.push(`${label} value must be zero`);
  }
  if (interaction.request.payment_auth !== "0x") {
    errors.push(`${label} payment_auth must be 0x`);
  }
  const expectedCalldata = expectedActivateToolCalldata(spendId);
  if (!expectedCalldata || calldata !== expectedCalldata) {
    errors.push(`${label} calldata must call activateTool(spendId, 0x)`);
  }
  const settled = [...eventsById.values()].find((candidate) => {
    const payload = isObject(candidate?.payload) ? candidate.payload : {};
    return (
      isObject(candidate) &&
      candidate.kind === "gate.spend_settled" &&
      lowerHex(payload.spendId) === lowerHex(spendId) &&
      lowerHex(payload.contractAddress) === contractAddress &&
      payload.finalityStatus === "finalized" &&
      payload.proofAuthority === true
    );
  });
  if (!settled) {
    errors.push(`${label} does not match a finalized SpendSettled proof event by spendId and contractAddress`);
    return;
  }
  const settledPayload = isObject(settled.payload) ? settled.payload : {};
  const txEvent = cawLiveContractCallEventWithTxHash(eventsById, event, interaction);
  if (!txEvent || !isHex32(txEvent.payload?.txHash)) {
    errors.push(`${label} requires CAW contract call event txHash`);
  } else if (lowerHex(txEvent.payload.txHash) !== lowerHex(settledPayload.txHash)) {
    errors.push(`${label} txHash must match finalized SpendSettled txHash`);
  }
}

function cawLiveContractCallEventWithTxHash(eventsById, event, interaction) {
  if (isObject(event) && isHex32(event.payload?.txHash)) {
    return event;
  }
  const requestId = asText(interaction.request?.request_id ?? interaction.cawRequestId);
  if (!requestId) {
    return event;
  }
  const operationKind = asText(interaction.request?.operation_kind);
  const contractAddress = asText(interaction.request?.contract_addr).toLowerCase();
  const selector = asText(interaction.request?.selector).toLowerCase();
  const candidates = [...eventsById.values()]
    .filter((candidate) => {
      const payload = isObject(candidate?.payload) ? candidate.payload : {};
      return (
        candidate?.kind === "caw.live.contract_call.submitted" &&
        payload.cawRequestId === requestId &&
        payload.operationKind === operationKind &&
        asText(payload.contractAddress).toLowerCase() === contractAddress &&
        asText(payload.selector).toLowerCase() === selector &&
        isHex32(payload.txHash)
      );
    })
    .sort((a, b) => Number(a.eventSeq ?? 0) - Number(b.eventSeq ?? 0));
  return candidates.at(-1) ?? event;
}

function expectedApproveCalldata(spender, amount) {
  const addressWord = evmAddressWord(spender);
  const amountWord = uint256Word(amount);
  if (!addressWord || !amountWord) {
    return null;
  }
  return `${ERC20_APPROVE_SELECTOR}${addressWord}${amountWord}`;
}

function expectedActivateToolCalldata(spendId) {
  if (!isHex32(spendId)) {
    return null;
  }
  return `${PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR}${spendId.slice(2).toLowerCase()}${uint256Word("64")}${uint256Word("0")}`;
}

function evmAddressWord(address) {
  return isEvmAddress(address) ? address.slice(2).toLowerCase().padStart(64, "0") : null;
}

function evmAddressTopic(address) {
  const word = evmAddressWord(address);
  return word ? `0x${word}` : null;
}

function uint256Word(value) {
  const parsed = decimal(value);
  if (parsed === null || parsed < 0n || parsed > (1n << 256n) - 1n) {
    return null;
  }
  return parsed.toString(16).padStart(64, "0");
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
  const spend = replayRowsForCollection(bundle, "spends").find(
    (candidate) => isObject(candidate) && lowerHex(candidate.spendId) === lowerHex(payload.spendId),
  );
  if (!spend) {
    errors.push(`${label} requires a matching replay spend row`);
  } else {
    const expected = {
      contractSessionId: lowerHex(spend.sessionId),
      contractPactId: lowerHex(spend.pactId),
      contractToolId: lowerHex(spend.toolId),
      contractSourceSetHash: lowerHex(spend.sourceSetHash),
      contractAgentWallet: lowerHex(spend.agentWallet),
      contractPaymentToken: lowerHex(spend.paymentToken),
      contractPrice: asText(spend.maxPriceAtomic),
      contractArtifactHash: lowerHex(spend.artifactHash),
      contractMarket: lowerHex(spend.market),
    };
    for (const [field, expectedValue] of Object.entries(expected)) {
      const actualValue = field === "contractPrice" ? asText(payload[field]) : lowerHex(payload[field]);
      if (actualValue !== expectedValue) {
        errors.push(`${label} ${field} must match replay spend ${field.replace(/^contract/, "")}`);
      }
    }
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

function verifyCawReceiptSettlementBinding(canonical, operation, bundle, errors) {
  if (canonical.operationKind !== "activate_tool" || canonical.effect !== "allow") {
    return;
  }
  const label = `canonical CAW receipt ${canonical.canonicalReceiptHash ?? "-"}`;
  if (!operation.spendId) {
    errors.push(`${label} activate_tool allow receipt requires CAW operation spendId`);
    return;
  }
  if (!canonical.txHash) {
    errors.push(`${label} activate_tool allow receipt requires txHash`);
    return;
  }
  if (!isEvmAddress(canonical.target)) {
    errors.push(`${label} activate_tool allow receipt requires ProcurementGate target address`);
  }
  if (lowerHex(canonical.selector) !== PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR) {
    errors.push(`${label} activate_tool allow receipt selector must be ProcurementGate.activateTool(bytes32,bytes)`);
  }
  const settled = replayRowsForCollection(bundle, "events").find((event) => {
    const payload = isObject(event?.payload) ? event.payload : {};
    return (
      isObject(event) &&
      event.kind === "gate.spend_settled" &&
      lowerHex(payload.spendId) === lowerHex(operation.spendId) &&
      lowerHex(payload.txHash) === lowerHex(canonical.txHash) &&
      payload.finalityStatus === "finalized" &&
      payload.proofAuthority === true
    );
  });
  if (!settled) {
    errors.push(`${label} activate_tool allow receipt does not match a finalized SpendSettled proof event by spendId and txHash`);
    return;
  }
  const settledPayload = isObject(settled.payload) ? settled.payload : {};
  if (!isEvmAddress(settledPayload.contractAddress)) {
    errors.push(`${label} matching SpendSettled proof event requires ProcurementGate contractAddress`);
    return;
  }
  if (lowerHex(canonical.target) !== lowerHex(settledPayload.contractAddress)) {
    errors.push(`${label} activate_tool allow receipt target does not match finalized ProcurementGate contractAddress`);
  }
}

function verifyReplayPageIndex(bundle, errors, warnings) {
  const index = bundle.replayPageIndex;
  if (!isObject(index)) {
    errors.push("replayPageIndex must be an object");
    return;
  }
  if (index.pageSize !== REPLAY_PAGE_SIZE) {
    errors.push(`replayPageIndex.pageSize must be ${REPLAY_PAGE_SIZE}`);
  }
  if (!isObject(index.collections)) {
    errors.push("replayPageIndex.collections must be an object");
    return;
  }
  const replayPages = bundle.replayPages;
  if (!isObject(replayPages)) {
    errors.push("replayPages must be an object with every indexed replay page");
  }
  const rootEntries = [];
  for (const name of REPLAY_COLLECTIONS) {
    const collection = index.collections[name];
    if (!isObject(collection)) {
      errors.push(`replayPageIndex.collections.${name} must be an object`);
      continue;
    }
    const rows = Array.isArray(bundle[name]) ? bundle[name] : [];
    const canonicalOrderBy = replayCollectionOrderBy(name);
    const collectionOrderByOk =
      Array.isArray(collection.orderBy) &&
      collection.orderBy.length === canonicalOrderBy.length &&
      collection.orderBy.every((field) => typeof field === "string") &&
      hashJson(collection.orderBy) === hashJson(canonicalOrderBy);
    if (!collectionOrderByOk) {
      errors.push(`replayPageIndex.collections.${name}.orderBy must match the canonical replay order`);
    }
    if (!Number.isInteger(collection.totalRows) || collection.totalRows < rows.length) {
      errors.push(`replayPageIndex.collections.${name}.totalRows must cover the summary rows`);
    }
    if (!Array.isArray(collection.pageHashes) || collection.pageHashes.some((hash) => !isHex32(hash))) {
      errors.push(`replayPageIndex.collections.${name}.pageHashes must be 32-byte hex hashes`);
      continue;
    }
    const expectedPageCount = Math.ceil(Number(collection.totalRows ?? 0) / REPLAY_PAGE_SIZE);
    if (collection.pageCount !== expectedPageCount || collection.pageHashes.length !== expectedPageCount) {
      errors.push(`replayPageIndex.collections.${name}.pageCount must match totalRows/pageSize`);
    }
    const expectedFirstPageHash = replayPageHash(bundle.sessionId, name, 0, canonicalOrderBy, rows.slice(0, REPLAY_PAGE_SIZE));
    if (collection.firstPageHash !== expectedFirstPageHash) {
      errors.push(`replayPageIndex.collections.${name}.firstPageHash does not match summary rows`);
    }
    const expectedPageRoot = hashJson(collection.pageHashes);
    if (collection.pageRoot !== expectedPageRoot) {
      errors.push(`replayPageIndex.collections.${name}.pageRoot does not match pageHashes`);
    }
    if (isObject(replayPages)) {
      verifyReplayPagesForCollection(bundle, name, collection, canonicalOrderBy, rows, errors);
    }
    rootEntries.push({ name, pageRoot: collection.pageRoot });
  }
  if (index.pageRoot !== hashJson(rootEntries)) {
    errors.push("replayPageIndex.pageRoot does not match collection page roots");
  }
  if (bundle.fullReplayRoot !== index.pageRoot) {
    errors.push("fullReplayRoot must match replayPageIndex.pageRoot");
  }
}

function verifyReplayPagesForCollection(bundle, name, collection, canonicalOrderBy, summaryRows, errors) {
  const pages = bundle.replayPages[name];
  const expectedPageCount = Math.ceil(Number(collection.totalRows ?? 0) / REPLAY_PAGE_SIZE);
  if (!Array.isArray(pages)) {
    errors.push(`replayPages.${name} must be an array`);
    return;
  }
  if (pages.length !== expectedPageCount) {
    errors.push(`replayPages.${name} must contain exactly ${expectedPageCount} page(s)`);
  }
  const flattenedRows = [];
  const recomputedPageHashes = [];
  const seenPageIndexes = new Set();
  for (let index = 0; index < pages.length; index += 1) {
    const page = pages[index];
    if (!isObject(page)) {
      errors.push(`replayPages.${name}.${index} must be an object`);
      continue;
    }
    if (seenPageIndexes.has(page.pageIndex)) {
      errors.push(`replayPages.${name} contains duplicate pageIndex ${page.pageIndex}`);
    }
    seenPageIndexes.add(page.pageIndex);
    if (page.bundleType !== "PACTFUSE_REPLAY_PAGE_V1") {
      errors.push(`replayPages.${name}.${index}.bundleType must be PACTFUSE_REPLAY_PAGE_V1`);
    }
    if (page.sessionId !== bundle.sessionId) {
      errors.push(`replayPages.${name}.${index}.sessionId must match the replay bundle sessionId`);
    }
    if (page.collection !== name) {
      errors.push(`replayPages.${name}.${index}.collection must match its replayPages key`);
    }
    if (page.pageIndex !== index) {
      errors.push(`replayPages.${name}.${index}.pageIndex must match its position`);
    }
    if (page.pageSize !== REPLAY_PAGE_SIZE) {
      errors.push(`replayPages.${name}.${index}.pageSize must be ${REPLAY_PAGE_SIZE}`);
    }
    if (
      !Array.isArray(page.orderBy) ||
      page.orderBy.some((field) => typeof field !== "string") ||
      hashJson(page.orderBy) !== hashJson(canonicalOrderBy)
    ) {
      errors.push(`replayPages.${name}.${index}.orderBy must match the canonical replay order`);
    }
    const pageRows = Array.isArray(page.rows) ? page.rows : null;
    if (!pageRows) {
      errors.push(`replayPages.${name}.${index}.rows must be an array`);
      continue;
    }
    if (pageRows.length > REPLAY_PAGE_SIZE) {
      errors.push(`replayPages.${name}.${index}.rows exceeds page size`);
    }
    if (index < expectedPageCount - 1 && pageRows.length !== REPLAY_PAGE_SIZE) {
      errors.push(`replayPages.${name}.${index}.rows must be full before the final page`);
    }
    const expectedPageHash = replayPageHash(bundle.sessionId, name, index, canonicalOrderBy, pageRows);
    if (page.pageHash !== expectedPageHash) {
      errors.push(`replayPages.${name}.${index}.pageHash does not match page rows`);
    }
    if (collection.pageHashes[index] !== page.pageHash) {
      errors.push(`replayPageIndex.collections.${name}.pageHashes.${index} does not match replayPages.${name}.${index}.pageHash`);
    }
    recomputedPageHashes.push(expectedPageHash);
    flattenedRows.push(...pageRows);
  }
  if (flattenedRows.length !== collection.totalRows) {
    errors.push(`replayPages.${name} row count must match replayPageIndex.collections.${name}.totalRows`);
  }
  if (hashJson(recomputedPageHashes) !== collection.pageRoot) {
    errors.push(`replayPageIndex.collections.${name}.pageRoot does not match replayPages.${name}`);
  }
  if (hashJson(flattenedRows.slice(0, summaryRows.length)) !== hashJson(summaryRows)) {
    errors.push(`replayPages.${name} must have the summary rows as its prefix`);
  }
}

function replayPageHash(sessionId, collection, pageIndex, orderBy, rows) {
  return hashJson({ sessionId, collection, pageIndex, pageSize: REPLAY_PAGE_SIZE, orderBy, rows });
}

function replayCollectionOrderBy(collection) {
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

function verifyReplayEvents(bundle, events, errors) {
  let previousEventSeq = 0;
  let previousProofEventHash = ZERO_HASH;
  for (const event of events) {
    if (!isObject(event)) {
      errors.push("events entries must be objects");
      continue;
    }
    for (const field of ["eventId", "sessionId", "eventSeq", "eventHash", "authority", "kind", "payloadHash", "payload"]) {
      requirePath(event, [field], errors);
    }
    if (event.sessionId !== bundle.sessionId) {
      errors.push(`event ${event.eventId ?? "-"} sessionId is not bound to replay bundle session`);
    }
    if (!Number.isInteger(event.eventSeq) || event.eventSeq <= previousEventSeq) {
      errors.push(`event ${event.eventId ?? "-"} eventSeq must be strictly increasing`);
    }
    previousEventSeq = Number.isInteger(event.eventSeq) ? event.eventSeq : previousEventSeq;
    const expectedPayloadHash = safeHashJson(event.payload, `event ${event.eventId ?? "-"} payload`, errors);
    if (expectedPayloadHash && lowerHex(event.payloadHash) !== expectedPayloadHash) {
      errors.push(`event ${event.eventId ?? "-"} payloadHash does not match payload`);
    }
    const expectedPrevProofEventHash = event.authority === "proof" ? previousProofEventHash : null;
    if ((event.prevProofEventHash ?? null) !== expectedPrevProofEventHash) {
      errors.push(`event ${event.eventId ?? "-"} prevProofEventHash does not match proof authority chain`);
    }
    const expectedEventHash = expectedPayloadHash
      ? safeHashJson(
          {
            sessionId: event.sessionId,
            eventSeq: event.eventSeq,
            authority: event.authority,
            kind: event.kind,
            payloadHash: event.payloadHash,
            prevProofEventHash: event.prevProofEventHash ?? null,
          },
          `event ${event.eventId ?? "-"} hash body`,
          errors,
        )
      : null;
    if (expectedEventHash && lowerHex(event.eventHash) !== expectedEventHash) {
      errors.push(`event ${event.eventId ?? "-"} eventHash does not recompute`);
    }
    if (expectedEventHash && lowerHex(event.eventId) !== expectedEventHash) {
      errors.push(`event ${event.eventId ?? "-"} eventId must equal eventHash`);
    }
    if (event.authority === "proof" && isHex32(event.eventHash)) {
      previousProofEventHash = lowerHex(event.eventHash);
    }
  }
}

function replayProvider(options, name) {
  const providers = Array.isArray(options.proofProviders) ? options.proofProviders : [];
  return providers.find((provider) => provider?.name === name && provider.ready === true && provider.mode === "live") ?? null;
}

function replayProviderReady(options, name) {
  return Boolean(replayProvider(options, name));
}

function replayProviderAuthorityLocked(options) {
  return (
    options.proofProviderAuthority === "server-runtime" &&
    isObject(options.proofProviderAuthorityToken) &&
    SERVER_RUNTIME_PROOF_PROVIDER_TOKENS.has(options.proofProviderAuthorityToken)
  );
}

export function createServerRuntimeVerifierOptions(options = {}) {
  const proofProviderAuthorityToken = {};
  SERVER_RUNTIME_PROOF_PROVIDER_TOKENS.add(proofProviderAuthorityToken);
  return {
    ...options,
    proofProviderAuthority: "server-runtime",
    proofProviderAuthorityToken,
  };
}

function deploymentRegistryEntryHasLiveFields(entry, options = {}) {
  return (
    isObject(entry) &&
    isHex32(entry.deploymentTxHash) &&
    entry.deploymentTxHash !== ZERO_HASH &&
    isPublicExplorerUrl(entry.explorerUrl) &&
    explorerUrlContainsTxHash(entry.explorerUrl, entry.deploymentTxHash) &&
    isHex32(entry.codeHash) &&
    entry.codeHash !== ZERO_HASH &&
    (!options.requireErc20Metadata || Number.isInteger(entry.decimals))
  );
}

function explorerUrlContainsTxHash(explorerUrl, txHash) {
  if (typeof explorerUrl !== "string" || typeof txHash !== "string") {
    return false;
  }
  try {
    const url = new URL(explorerUrl);
    const segments = url.pathname.toLowerCase().split("/").filter(Boolean);
    const txIndex = segments.indexOf("tx");
    return txIndex >= 0 && segments[txIndex + 1] === txHash.toLowerCase();
  } catch {
    return false;
  }
}

function isPublicExplorerUrl(value) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") {
      return false;
    }
    const host = url.hostname.toLowerCase();
    return PUBLIC_EXPLORER_HOST_PATTERNS.some((pattern) => pattern.test(host));
  } catch {
    return false;
  }
}

function deploymentRegistryBlockersForPaymentToken(registry, paymentToken, chainId) {
  if (!isObject(registry) || registry.mode !== "live") {
    return ["final verifier requires live deployment registry evidence for the payment token"];
  }
  if (asText(registry.chainId) !== asText(chainId)) {
    return ["final verifier requires deployment registry chainId to match the chain-settleable quote"];
  }
  const tokenMode = tokenModeForPaymentToken(paymentToken);
  if (tokenMode === "local-mocked") {
    return ["final verifier refuses local-mocked token mode for chain-settleable quotes"];
  }
  const entries = Array.isArray(registry.entries) ? registry.entries : [];
  const paymentTokenAddress = lowerHex(paymentToken);
  const entry = entries.find(
    (candidate) =>
      candidate?.contractName === "PaymentToken" &&
      asText(candidate.chainId) === asText(chainId) &&
      lowerHex(candidate.address) === paymentTokenAddress &&
      candidate.tokenMode === tokenMode,
  );
  if (!entry || !deploymentRegistryEntryHasLiveFields(entry, { requireErc20Metadata: true })) {
    return ["final verifier requires a live PaymentToken deployment registry entry for the chain-settleable payment token"];
  }
  const probeStatus = registry.officialUsdcProbe?.status;
  if (tokenMode === "official-testnet-usdc") {
    if (paymentTokenAddress !== BASE_SEPOLIA_USDC || asText(chainId) !== "84532") {
      return ["final verifier only accepts official Base Sepolia USDC on chain 84532"];
    }
    if (probeStatus !== "passed") {
      return ["final verifier requires official Base Sepolia USDC to include a passed official-USDC probe"];
    }
    return [];
  }
  if (probeStatus !== "failed" || asText(registry.officialUsdcProbe?.reason).length === 0) {
    return ["final verifier requires mock token fallback to include a failed official-USDC probe reason"];
  }
  return [];
}

function deploymentRegistryEntryForContract(registry, contractName, address, chainId) {
  const entries = Array.isArray(registry?.entries) ? registry.entries : [];
  const normalizedAddress = lowerHex(address);
  return entries.find(
    (candidate) =>
      candidate?.contractName === contractName &&
      asText(candidate.chainId) === asText(chainId) &&
      lowerHex(candidate.address) === normalizedAddress,
  );
}

function deploymentRegistryBlockersForLiveContracts(registry, bundle, eventsById) {
  if (!isObject(registry) || registry.mode !== "live") {
    return ["final verifier requires live deployment registry evidence for chain proof contracts"];
  }
  const requirements = new Map();
  const addRequirement = (contractName, address, chainId) => {
    if (!isEvmAddress(address) || asText(chainId).length === 0) {
      return;
    }
    const key = `${contractName}:${asText(chainId)}:${lowerHex(address)}`;
    requirements.set(key, { contractName, address: lowerHex(address), chainId: asText(chainId) });
  };

  for (const event of eventsById.values()) {
    const payload = isObject(event?.payload) ? event.payload : {};
    if ((event.kind === "gate.spend_tripped" || event.kind === "gate.spend_settled") && replayGateFinalized(event)) {
      addRequirement("ProcurementGate", payload.contractAddress, payload.chainId);
    }
    if (event.kind === "source.challenge.confirmed" && replayGateFinalized(event)) {
      addRequirement("SourceStateRegistry", payload.sourceRegistryAddress, payload.chainId);
    }
  }

  const spendsById = new Map(replayRowsForCollection(bundle, "spends").filter(isObject).map((spend) => [lowerHex(spend.spendId), spend]));
  for (const quote of replayRowsForCollection(bundle, "quotes").filter(isObject)) {
    if (quote.status !== CHAIN_SETTLEABLE_QUOTE_STATUS) {
      continue;
    }
    const spend = spendsById.get(lowerHex(quote.spendId));
    addRequirement("PaidArtifactMarket", spend?.market, quote.chainId);
  }

  const blockers = [];
  for (const requirement of requirements.values()) {
    if (asText(registry.chainId) !== requirement.chainId) {
      blockers.push(`final verifier requires deployment registry chainId to match ${requirement.contractName} chain proof`);
      continue;
    }
    const entry = deploymentRegistryEntryForContract(registry, requirement.contractName, requirement.address, requirement.chainId);
    if (!entry || !deploymentRegistryEntryHasLiveFields(entry)) {
      blockers.push(
        `final verifier requires a live ${requirement.contractName} deployment registry entry for ${requirement.address} on chain ${requirement.chainId}`,
      );
    }
  }
  return blockers;
}

function latestReplayEvent(eventsById, kind, predicate = () => true) {
  return [...eventsById.values()]
    .filter((event) => isObject(event) && event.kind === kind && predicate(event))
    .sort((a, b) => (Number(a.eventSeq) || 0) - (Number(b.eventSeq) || 0))
    .at(-1);
}

function replayRowsForCollection(bundle, collection) {
  const pages = bundle?.replayPages?.[collection];
  if (!Array.isArray(pages)) {
    return Array.isArray(bundle?.[collection]) ? bundle[collection] : [];
  }
  return pages.flatMap((page) => (Array.isArray(page?.rows) ? page.rows : []));
}

function replayEventsByIdForFinalGate(bundle, summaryEventsById) {
  const rows = replayRowsForCollection(bundle, "events");
  if (rows.length === 0) {
    return summaryEventsById;
  }
  return new Map(rows.filter((event) => isObject(event) && typeof event.eventId === "string").map((event) => [event.eventId, event]));
}

function replayEventHasProofAuthority(event, winnerClaimAllowed = false) {
  const payload = isObject(event?.payload) ? event.payload : {};
  return event?.authority === "proof" && payload.proofAuthority === true && payload.winnerClaimAllowed === winnerClaimAllowed;
}

function replayEventHasLiveChainProofAuthority(event, winnerClaimAllowed = false) {
  const payload = isObject(event?.payload) ? event.payload : {};
  return replayEventHasProofAuthority(event, winnerClaimAllowed) && payload.chainProviderMode === "live";
}

function replayGateFinalized(event) {
  const payload = isObject(event?.payload) ? event.payload : {};
  return replayEventHasProofAuthority(event, false) && payload.finalityStatus === "finalized" && payload.contractStateVerified === true;
}

function replayChainProviderBindingBlockers(events, options) {
  const blockers = [];
  const chainProvider = replayProvider(options, "chain");
  if (!chainProvider) {
    return blockers;
  }
  const expectedChainId = typeof chainProvider.chainId === "string" ? chainProvider.chainId : null;
  const expectedEndpoint = publicProofEndpoint(chainProvider.endpoint);
  if (!expectedChainId || !expectedEndpoint) {
    blockers.push("final verifier requires chain proof provider chainId and redacted endpoint");
    return blockers;
  }
  const chainProofEventsByKey = latestChainProofEventsByKey(events);
  for (const event of chainProofEventsByKey.values()) {
    const payload = isObject(event.payload) ? event.payload : {};
    const label = `event ${event.eventId ?? "-"} ${event.kind}`;
    if (expectedChainId !== null && asText(payload.chainId) !== expectedChainId) {
      blockers.push(`${label} chainId does not match trusted chain proof provider`);
    }
    if (expectedEndpoint !== null && publicProofEndpoint(payload.chainProviderEndpoint) !== expectedEndpoint) {
      blockers.push(`${label} chainProviderEndpoint does not match trusted chain proof provider`);
    }
  }
  return blockers;
}

function latestChainProofEventsByKey(events) {
  const chainProofEventKinds = new Set(["caw.allowance.verified", "caw.activation.verified", "token.balance_delta.verified"]);
  const byKey = new Map();
  for (const event of events) {
    if (!chainProofEventKinds.has(event?.kind) || !isObject(event.payload)) {
      continue;
    }
    const key = `${event.kind}:${asText(event.payload.spendId) || asText(event.payload.txHash) || asText(event.eventId)}`;
    const current = byKey.get(key);
    if (!current || Number(event.eventSeq ?? 0) > Number(current.eventSeq ?? 0)) {
      byKey.set(key, event);
    }
  }
  return byKey;
}

function replayWrongTargetDenyPayload(payload) {
  const operationKind = asText(payload.operationKind).toLowerCase();
  const action = asText(payload.action).toLowerCase();
  return operationKind === "deny_probe" || action.includes("wrong") || action.includes("bypass") || action.includes("deny_probe");
}

function tokenModeForPaymentToken(paymentToken) {
  const normalized = asText(paymentToken).toLowerCase();
  if (normalized === BASE_SEPOLIA_USDC) {
    return "official-testnet-usdc";
  }
  return normalized ? "mock-test-token" : "local-mocked";
}

function tokenSettlementClaimForTokenMode(tokenMode) {
  if (tokenMode === "official-testnet-usdc") {
    return "official-testnet-usdc";
  }
  if (tokenMode === "mock-test-token") {
    return "live-mock-erc20-fallback";
  }
  return null;
}

function quoteRuntimeModesForStatus(status, spend) {
  if (status === MOCK_QUOTE_STATUS) {
    return {
      CLAIM_MODE: "simulated",
      PAYMENT_MODE: "mocked",
      TOKEN_MODE: "local-mocked",
      IDENTITY_MODE: "pending",
      WINNER_CLAIM_ALLOWED: false,
    };
  }
  if (status === CHAIN_SETTLEABLE_QUOTE_STATUS) {
    return {
      CLAIM_MODE: "caw-target-real",
      PAYMENT_MODE: "gate-paid-artifact-real",
      TOKEN_MODE: tokenModeForPaymentToken(spend?.paymentToken),
      IDENTITY_MODE: "p0-floor-one-wallet",
      WINNER_CLAIM_ALLOWED: false,
    };
  }
  return null;
}

function replayJudgeRowsById(bundle) {
  return new Map((Array.isArray(bundle.judgeCheck?.rows) ? bundle.judgeCheck.rows : []).filter(isObject).map((row) => [row.rowId, row]));
}

function replayJudgeRowPasses(rowsById, rowId, allowedAuthorities) {
  const row = rowsById.get(rowId);
  return row?.status === "pass" && allowedAuthorities.has(row.authority) && typeof row.evidenceEventId === "string";
}

function verifyFinalReplayClaimGate(bundle, eventsById, options) {
  const blockers = [];
  if (!replayProviderAuthorityLocked(options)) {
    blockers.push("final verifier requires proofProviders from server-runtime authority, not caller-supplied live flags");
  }
  for (const name of ["chain", "caw", "caw_live", "mcp_lease"]) {
    if (!replayProviderReady(options, name)) {
      blockers.push(`final verifier requires live ${name} proof provider`);
    }
  }

  const rowsById = replayJudgeRowsById(bundle);
  const finalEvents = [...eventsById.values()];
  blockers.push(...replayChainProviderBindingBlockers(finalEvents, options));
  if (finalEvents.some((event) => event.kind === "reorg.invalidated")) {
    blockers.push("final verifier refuses replay bundles containing reorg.invalidated events");
  }
  if (finalEvents.some((event) => event.kind === "caw.receipt.ingested.fixture")) {
    blockers.push("final verifier refuses fixture CAW receipt evidence");
  }
  blockers.push(...finalCawReceiptCoverageBlockers(bundle));

  const proofRows = ["caw_boundary", "source_challenge", "ab_trip", "c_settlement"];
  const deliveryRows = ["artifact_access", "lease_execution"];
  for (const rowId of proofRows) {
    if (!replayJudgeRowPasses(rowsById, rowId, new Set(["proof"]))) {
      blockers.push(`final verifier requires Judge Check row ${rowId} to pass with proof authority`);
    }
  }
  for (const rowId of deliveryRows) {
    if (!replayJudgeRowPasses(rowsById, rowId, new Set(["delivery", "proof"]))) {
      blockers.push(`final verifier requires Judge Check row ${rowId} to pass with delivery or proof authority`);
    }
  }

  const cawIdentityProbe = latestReplayEvent(eventsById, "caw.identity.probed", (event) => {
    const payload = isObject(event.payload) ? event.payload : {};
    return (
      event.authority === "proof" &&
      payload.mode === "real" &&
      payload.pass === true &&
      payload.proofAuthority === true &&
      payload.winnerClaimAllowed === false &&
      typeof payload.walletId === "string" &&
      typeof payload.walletAddress === "string"
    );
  });
  if (!cawIdentityProbe) {
    blockers.push(
      "final verifier requires caw.identity.probed with mode=real, pass=true, walletAddress, proofAuthority=true, and winnerClaimAllowed=false",
    );
  }

  const cawWrongTargetDeny = latestReplayEvent(eventsById, "caw.live.audit.usage.verified", (event) => {
    const payload = isObject(event.payload) ? event.payload : {};
    return replayEventHasProofAuthority(event, false) && payload.result === "denied" && replayWrongTargetDenyPayload(payload);
  });
  if (!cawWrongTargetDeny) {
    blockers.push("final verifier requires denied caw.live.audit.usage.verified wrong-target proof");
  }

  if (!latestReplayEvent(eventsById, "caw.allowance.verified", (event) => replayEventHasLiveChainProofAuthority(event, false))) {
    blockers.push("final verifier requires caw.allowance.verified proof event from a live chain provider");
  }
  if (!latestReplayEvent(eventsById, "caw.activation.verified", (event) => replayEventHasLiveChainProofAuthority(event, false))) {
    blockers.push("final verifier requires caw.activation.verified proof event from a live chain provider");
  }
  if (!latestReplayEvent(eventsById, "gate.spend_tripped", replayGateFinalized)) {
    blockers.push("final verifier requires finalized gate.spend_tripped proof event");
  }
  if (!latestReplayEvent(eventsById, "gate.spend_settled", replayGateFinalized)) {
    blockers.push("final verifier requires finalized gate.spend_settled proof event");
  }
  if (!latestReplayEvent(eventsById, "source.challenge.confirmed", replayGateFinalized)) {
    blockers.push("final verifier requires finalized source.challenge.confirmed proof event");
  }
  if (!latestReplayEvent(eventsById, "token.balance_delta.verified", (event) => replayEventHasLiveChainProofAuthority(event, false))) {
    blockers.push("final verifier requires token.balance_delta.verified proof event from a live chain provider");
  }
  if (!latestReplayEvent(eventsById, "artifact.access_token.issued", (event) => event.authority === "delivery")) {
    blockers.push("final verifier requires artifact.access_token.issued delivery event");
  }
  const leaseSucceeded = latestReplayEvent(eventsById, "lease.execution.succeeded", (event) => {
    const payload = isObject(event.payload) ? event.payload : {};
    return (
      event.authority === "delivery" &&
      payload.status === "succeeded_live_mcp_transcript" &&
      payload.boundedToPinnedManifest === true &&
      payload.bearerBound === true &&
      payload.winnerClaimAllowed === false
    );
  });
  if (!leaseSucceeded) {
    blockers.push("final verifier requires bearer-bound lease.execution.succeeded with a pinned MCP transcript");
  }

  const quotes = replayRowsForCollection(bundle, "quotes");
  const quotesById = new Map(quotes.filter(isObject).map((quote) => [quote.quoteId, quote]));
  const spends = replayRowsForCollection(bundle, "spends");
  const spendsById = new Map(spends.filter(isObject).map((spend) => [spend.spendId, spend]));
  const accessTokens = replayRowsForCollection(bundle, "artifactAccessTokens");
  const serverLiveFetchPreflightIds = new Set(
    finalEvents
      .filter((event) => {
        const payload = isObject(event.payload) ? event.payload : {};
        return (
          event.kind === "artifact.preflight.verified" &&
          event.authority === "delivery" &&
          typeof payload.preflightId === "string" &&
          payload.deliveryVerificationAuthority === "server_live_fetch" &&
          isHex32(payload.artifactDeliveryEvidenceHash) &&
          payload.winnerClaimAllowed === false
        );
      })
      .map((event) => event.payload.preflightId),
  );
  const liveTokenRegistryBlockerSet = new Set();
  for (const quote of quotes.filter((candidate) => candidate?.status === CHAIN_SETTLEABLE_QUOTE_STATUS)) {
    const spend = spendsById.get(quote.spendId);
    const tokenBlockers = deploymentRegistryBlockersForPaymentToken(bundle.deploymentRegistry, spend?.paymentToken, quote.chainId);
    for (const blocker of tokenBlockers) {
      liveTokenRegistryBlockerSet.add(blocker);
    }
  }
  blockers.push(...liveTokenRegistryBlockerSet);
  blockers.push(...deploymentRegistryBlockersForLiveContracts(bundle.deploymentRegistry, bundle, eventsById));
  if (quotes.length === 0) {
    blockers.push("final verifier requires at least one artifact quote bound to the payment");
  } else if (quotes.some((quote) => quote?.status === MOCK_QUOTE_STATUS)) {
    blockers.push("final verifier refuses mocked_after_preflight_not_chain_settleable quotes");
  } else if (!quotes.some((quote) => quote?.status === CHAIN_SETTLEABLE_QUOTE_STATUS)) {
    blockers.push("final verifier requires chain_settleable_after_preflight quote status");
  }
  if (accessTokens.length === 0) {
    blockers.push("final verifier requires at least one artifact access token");
  }
  const finalArtifactPreflightIds = new Set();
  for (const token of accessTokens) {
    const quote = quotesById.get(token?.quoteId);
    if (!quote || quote.status !== CHAIN_SETTLEABLE_QUOTE_STATUS) {
      blockers.push(`final verifier requires artifact access token ${token?.tokenId ?? "-"} to reference a chain-settleable quote`);
      break;
    }
    if (typeof quote.preflightId === "string") {
      finalArtifactPreflightIds.add(quote.preflightId);
    }
    if (typeof token?.preflightId === "string" && typeof quote.preflightId === "string" && token.preflightId !== quote.preflightId) {
      blockers.push(`final verifier requires artifact access token ${token.tokenId ?? "-"} preflightId to match its quote`);
      break;
    }
  }
  for (const preflightId of finalArtifactPreflightIds) {
    if (!serverLiveFetchPreflightIds.has(preflightId)) {
      blockers.push(`final verifier requires server_live_fetch artifact.preflight.verified delivery event for preflight ${preflightId}`);
    }
  }
  const finalizedTrips = finalEvents.filter((event) => event.kind === "gate.spend_tripped" && replayGateFinalized(event));
  const finalizedTripSpendIds = [...new Set(finalizedTrips.map((event) => event.payload?.spendId).filter((spendId) => typeof spendId === "string"))];
  if (finalizedTripSpendIds.length < 2) {
    blockers.push("final verifier requires two distinct finalized gate.spend_tripped proof spends for A/B");
  }
  const settledSpendIds = new Set(
    finalEvents
      .filter((event) => event.kind === "gate.spend_settled" && replayGateFinalized(event))
      .map((event) => event.payload?.spendId)
      .filter((spendId) => typeof spendId === "string"),
  );
  const tokenDeltaSpendIds = new Set(
    finalEvents
      .filter((event) => event.kind === "token.balance_delta.verified" && replayEventHasProofAuthority(event, false))
      .map((event) => event.payload?.spendId)
      .filter((spendId) => typeof spendId === "string"),
  );
  const liveQuoteSpendIds = new Set(quotes.filter((quote) => quote?.status === CHAIN_SETTLEABLE_QUOTE_STATUS).map((quote) => quote.spendId));
  const liveArtifactSpendIds = new Set(
    accessTokens
      .filter((token) => quotesById.get(token?.quoteId)?.status === CHAIN_SETTLEABLE_QUOTE_STATUS)
      .map((token) => token.spendId),
  );
  const leaseSpendIds = new Set(
    finalEvents
      .filter((event) => event.kind === "lease.execution.succeeded" && event.authority === "delivery")
      .map((event) => event.payload?.spendId)
      .filter((spendId) => typeof spendId === "string"),
  );
  const closedLoopSpendIds = [...settledSpendIds].filter(
    (spendId) =>
      tokenDeltaSpendIds.has(spendId) &&
      liveQuoteSpendIds.has(spendId) &&
      liveArtifactSpendIds.has(spendId) &&
      leaseSpendIds.has(spendId),
  );
  if (closedLoopSpendIds.length !== 1) {
    blockers.push("final verifier requires exactly one settled spend bound to token delta, live quote, artifact access, and lease execution");
  } else if (finalizedTripSpendIds.includes(closedLoopSpendIds[0])) {
    blockers.push("final verifier requires A/B tripped spends to be distinct from the settled C spend");
  } else if (cawIdentityProbe) {
    const closedLoopSpend = spendsById.get(closedLoopSpendIds[0]);
    const walletAddress = lowerHex(cawIdentityProbe.payload?.walletAddress);
    if (
      !closedLoopSpend ||
      !walletAddress ||
      walletAddress !== lowerHex(closedLoopSpend.payer) ||
      walletAddress !== lowerHex(closedLoopSpend.agentWallet)
    ) {
      blockers.push("final verifier requires CAW identity walletAddress to match the settled spend payer and agentWallet");
    }
  }

  if (bundle.winnerClaimAllowed === true && blockers.length > 0) {
    blockers.push("replay bundle requested winnerClaimAllowed=true before every final verifier gate passed");
  }
  return blockers;
}

function finalCawReceiptCoverageBlockers(bundle) {
  const blockers = [];
  const rawBundles = replayRowsForCollection(bundle, "rawCawReceiptBundles").filter(isObject);
  const canonicalReceipts = replayRowsForCollection(bundle, "canonicalCawReceipts").filter(isObject);
  if (rawBundles.length === 0 || canonicalReceipts.length === 0) {
    return ["final verifier requires raw and canonical CAW receipts for deny_probe, approve, and activate_tool"];
  }
  const sourceOk = rawBundles.some((bundleRow) => ["caw-api", "caw-export"].includes(asText(bundleRow.sourceLabel)) && Number(bundleRow.receiptCount) > 0);
  if (!sourceOk) {
    blockers.push("final verifier requires raw CAW receipts from caw-api or caw-export");
  }
  const hasReceipt = (operationKind, effect) =>
    canonicalReceipts.some(
      (receipt) =>
        receipt.operationKind === operationKind &&
        receipt.effect === effect &&
        ["caw-api", "caw-export"].includes(asText(receipt.sourceLabel)) &&
        (effect !== "allow" || isHex32(receipt.txHash)),
    );
  if (!hasReceipt("deny_probe", "deny")) {
    blockers.push("final verifier requires canonical CAW deny_probe deny receipt");
  }
  if (!hasReceipt("approve", "allow")) {
    blockers.push("final verifier requires canonical CAW approve allow receipt with txHash");
  }
  if (!hasReceipt("activate_tool", "allow")) {
    blockers.push("final verifier requires canonical CAW activate_tool allow receipt with txHash");
  }
  blockers.push(...finalCawReceiptLiveBindingBlockers(bundle, canonicalReceipts));
  return blockers;
}

function finalCawReceiptLiveBindingBlockers(bundle, canonicalReceipts) {
  const blockers = [];
  const events = replayRowsForCollection(bundle, "events").filter(isObject);
  const eventsById = new Map(events.filter((event) => typeof event.eventId === "string").map((event) => [event.eventId, event]));
  const spendsById = new Map(replayRowsForCollection(bundle, "spends").filter(isObject).map((spend) => [lowerHex(spend.spendId), spend]));
  const receipts = canonicalReceipts.filter((receipt) => ["caw-api", "caw-export"].includes(asText(receipt.sourceLabel)));

  const receiptMatchesDeny = receipts.some((receipt) =>
    events.some((event) => finalCawDenyReceiptMatchesEvent(receipt, event, eventsById)),
  );
  if (!receiptMatchesDeny) {
    blockers.push("final verifier requires canonical CAW deny_probe receipt to match denied live CAW audit usage");
  }

  const receiptMatchesApprove = receipts.some((receipt) =>
    events.some((event) => finalCawApproveReceiptMatchesEvent(receipt, event)),
  );
  if (!receiptMatchesApprove) {
    blockers.push("final verifier requires canonical CAW approve receipt to match the live allowance proof");
  }

  const receiptMatchesActivate = receipts.some((receipt) =>
    events.some((event) => finalCawActivateReceiptMatchesEvent(receipt, event, spendsById)),
  );
  if (!receiptMatchesActivate) {
    blockers.push("final verifier requires canonical CAW activate_tool receipt to match the live activation proof");
  }
  return blockers;
}

function finalCawDenyReceiptMatchesEvent(receipt, event, eventsById) {
  if (receipt.operationKind !== "deny_probe" || receipt.effect !== "deny" || receipt.status !== "denied") {
    return false;
  }
  const payload = isObject(event?.payload) ? event.payload : {};
  if (
    event.kind !== "caw.live.audit.usage.verified" ||
    !replayEventHasProofAuthority(event, false) ||
    payload.operationKind !== "deny_probe" ||
    payload.result !== "denied" ||
    asText(receipt.requestId) !== asText(payload.cawRequestId) ||
    lowerHex(receipt.policyDigest) !== lowerHex(payload.policyDigest)
  ) {
    return false;
  }
  const contractEvent = eventsById.get(payload.cawContractCallEventId);
  const contractPayload = isObject(contractEvent?.payload) ? contractEvent.payload : {};
  return (
    contractEvent?.kind === "caw.live.contract_call.submitted" &&
    lowerHex(receipt.target) === lowerHex(contractPayload.contractAddress) &&
    lowerHex(receipt.selector) === lowerHex(contractPayload.selector)
  );
}

function finalCawApproveReceiptMatchesEvent(receipt, event) {
  if (receipt.operationKind !== "approve" || receipt.effect !== "allow" || receipt.status !== "succeeded") {
    return false;
  }
  const payload = isObject(event?.payload) ? event.payload : {};
  return (
    event.kind === "caw.allowance.verified" &&
    replayEventHasProofAuthority(event, false) &&
    asText(receipt.requestId) === asText(payload.cawRequestId) &&
    lowerHex(receipt.policyDigest) === lowerHex(payload.auditPolicyDigest) &&
    lowerHex(receipt.txHash) === lowerHex(payload.approveTxHash) &&
    lowerHex(receipt.target) === lowerHex(payload.paymentToken) &&
    lowerHex(receipt.selector) === ERC20_APPROVE_SELECTOR &&
    lowerHex(receipt.walletAddress) === lowerHex(payload.agentWallet)
  );
}

function finalCawActivateReceiptMatchesEvent(receipt, event, spendsById) {
  if (receipt.operationKind !== "activate_tool" || receipt.effect !== "allow" || receipt.status !== "succeeded") {
    return false;
  }
  const payload = isObject(event?.payload) ? event.payload : {};
  const spend = spendsById.get(lowerHex(payload.spendId));
  return (
    event.kind === "caw.activation.verified" &&
    replayEventHasLiveChainProofAuthority(event, false) &&
    asText(receipt.requestId) === asText(payload.cawRequestId) &&
    lowerHex(receipt.policyDigest) === lowerHex(payload.auditPolicyDigest) &&
    lowerHex(receipt.txHash) === lowerHex(payload.activateTxHash) &&
    lowerHex(receipt.target) === lowerHex(payload.procurementGateAddress) &&
    lowerHex(receipt.selector) === PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR &&
    isObject(spend) &&
    lowerHex(receipt.walletAddress) === lowerHex(spend.agentWallet)
  );
}

function verifyReplayBundleEvidence(bundle, options = {}) {
  const errors = [];
  const warnings = [];
  for (const field of [
    "bundleType",
    "sessionId",
    "summaryMode",
    "asOfEventSeq",
    "asOfMcpAdapterCallCount",
    "eventRoot",
    "agentTranscriptHash",
    "fullReplayRoot",
    "events",
    "sources",
    "spends",
    "artifactPreflights",
    "quotes",
    "artifactAccessTokens",
    "mcpAdapterCalls",
    "cawReceiptOperations",
    "cawLiveInteractions",
    "rawCawReceiptBundles",
    "canonicalCawReceipts",
    "leaseRuns",
    "judgeCheck",
    "replayPageIndex",
    "replayPages",
  ]) {
    requirePath(bundle, [field], errors);
  }
  for (const field of ["deploymentRegistry", "deploymentRegistryHash"]) {
    if (!Object.prototype.hasOwnProperty.call(bundle, field)) {
      errors.push(`missing required field: ${field}`);
    }
  }
  if (Object.prototype.hasOwnProperty.call(bundle, "deploymentRegistry") && bundle.deploymentRegistry !== null && !isObject(bundle.deploymentRegistry)) {
    errors.push("deploymentRegistry must be an object or null");
  }
  if (
    Object.prototype.hasOwnProperty.call(bundle, "deploymentRegistryHash") &&
    bundle.deploymentRegistryHash !== null &&
    !isHex32(bundle.deploymentRegistryHash)
  ) {
    errors.push("deploymentRegistryHash must be a 32-byte hash or null");
  }
  if (isObject(bundle.deploymentRegistry)) {
    const deploymentRegistryHash = safeHashJson(bundle.deploymentRegistry, "deploymentRegistry", errors);
    if (deploymentRegistryHash && bundle.deploymentRegistryHash !== deploymentRegistryHash) {
      errors.push("deploymentRegistryHash must equal the hash of deploymentRegistry");
    }
  } else if (Object.prototype.hasOwnProperty.call(bundle, "deploymentRegistryHash") && bundle.deploymentRegistryHash !== null) {
    errors.push("deploymentRegistryHash must be null when deploymentRegistry is null");
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
  if (!Number.isInteger(bundle.asOfEventSeq) || bundle.asOfEventSeq < 0) {
    errors.push("asOfEventSeq must be a non-negative integer");
  }
  if (!Number.isInteger(bundle.asOfMcpAdapterCallCount) || bundle.asOfMcpAdapterCallCount < 0) {
    errors.push("asOfMcpAdapterCallCount must be a non-negative integer");
  }
  const requestedWinnerClaimAllowed = bundle.winnerClaimAllowed === true;
  if (bundle.winnerClaimAllowed !== false && bundle.winnerClaimAllowed !== true) {
    errors.push("replay bundle winnerClaimAllowed must be boolean");
  }
  verifyReplayPageIndex(bundle, errors, warnings);
  const eventRows = replayRowsForCollection(bundle, "events");
  if (Array.isArray(bundle.events) && eventRows.length > bundle.events.length) {
    verifyReplayEvents(bundle, eventRows, errors);
  }
  let eventsById = new Map();
  if (!Array.isArray(bundle.events)) {
    errors.push("events must be an array");
  } else {
    verifyReplayEvents(bundle, bundle.events, errors);
    const eventRoot = safeHashJson(
      bundle.events.map((event) => (isObject(event) ? event.eventHash : undefined)),
      "eventRoot",
      errors,
    );
    if (eventRoot && bundle.eventRoot !== eventRoot) {
      errors.push("eventRoot must equal the hash of ordered event hashes");
    }
    eventsById = new Map(eventRows.filter((event) => isObject(event) && typeof event.eventId === "string").map((event) => [event.eventId, event]));
  }
  const rawBundles = replayRowsForCollection(bundle, "rawCawReceiptBundles");
  const canonicalReceipts = replayRowsForCollection(bundle, "canonicalCawReceipts");
  const cawReceiptOperations = replayRowsForCollection(bundle, "cawReceiptOperations");
  const cawLiveInteractions = replayRowsForCollection(bundle, "cawLiveInteractions");
  const preflights = replayRowsForCollection(bundle, "artifactPreflights");
  const quotes = replayRowsForCollection(bundle, "quotes");
  const accessTokens = replayRowsForCollection(bundle, "artifactAccessTokens");
  const spends = replayRowsForCollection(bundle, "spends");
  const cawOperationsById = new Map(cawReceiptOperations.filter(isObject).map((operation) => [operation.operationId, operation]));
  const replayPageMcpCalls = replayRowsForCollection(bundle, "mcpAdapterCalls");
  const mcpCalls = replayPageMcpCalls.length > 0 ? replayPageMcpCalls : Array.isArray(bundle.mcpAdapterCalls) ? bundle.mcpAdapterCalls : [];
  if (!Array.isArray(bundle.mcpAdapterCalls)) {
    errors.push("mcpAdapterCalls must be an array");
  }
  if (Array.isArray(bundle.mcpAdapterCalls) && bundle.asOfMcpAdapterCallCount !== mcpCalls.length) {
    errors.push("asOfMcpAdapterCallCount must equal the replay MCP adapter call count");
  }
  const callsByAuditNonce = verifyMcpAdapterCalls(bundle, mcpCalls, errors);
  verifyLeaseRuns(bundle, callsByAuditNonce, eventsById, errors);
  verifyJudgeCheck(bundle, eventsById, errors);
  verifyContractStateProofEvents(bundle, eventRows, errors);
  verifySourceIdentityBindings(bundle, errors);
  const spendsById = new Map(spends.filter(isObject).map((spend) => [lowerHex(spend.spendId), spend]));
  const cawLiveInteractionsById = new Map(cawLiveInteractions.filter(isObject).map((interaction) => [interaction.interactionId, interaction]));
  verifyCawAuditUsageEvents(eventsById, cawLiveInteractionsById, errors);
  verifyCawAllowanceEvents(eventsById, spendsById, cawLiveInteractionsById, errors);
  verifyCawActivationEvents(eventsById, errors);
  verifyTokenBalanceDeltaEvents(eventsById, spendsById, errors);
  verifyCawLiveInteractions(cawLiveInteractions, spendsById, eventsById, errors);
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
    verifyPublicReplayUrl(`artifact preflight ${preflight.preflightId ?? "-"} endpointUrl`, preflight.endpointUrl, errors);
    const spend = spendsById.get(lowerHex(preflight.spendId));
    if (!spend) {
      errors.push(`artifact preflight ${preflight.preflightId ?? "-"} references missing registered spend`);
    } else if (lowerHex(preflight.artifactHashPreview) !== lowerHex(spend.artifactHash)) {
      errors.push(`artifact preflight ${preflight.preflightId ?? "-"} artifactHashPreview does not match registered spend artifactHash`);
    }
    if (preflight.status !== "pending_live_delivery" && preflight.status !== "passed_live_delivery") {
      errors.push(`artifact preflight ${preflight.preflightId ?? "-"} has unsupported status ${preflight.status ?? "-"}`);
    }
    if (preflight.status === "passed_live_delivery") {
      for (const field of [
        "deliveryProofHash",
        "manifestFetchHash",
        "endpointResponseHash",
        "leaseDryRunHash",
        "verifiedEventId",
      ]) {
        if (!isHex32(preflight[field])) {
          errors.push(`artifact preflight ${preflight.preflightId ?? "-"} ${field} must be a 32-byte hash after delivery verification`);
        }
      }
      if (typeof preflight.verifiedAt !== "string" || preflight.verifiedAt.length === 0) {
        errors.push(`artifact preflight ${preflight.preflightId ?? "-"} verifiedAt is required after delivery verification`);
      }
      const verifiedEvent = [...eventsById.values()].find(
        (event) => event.kind === "artifact.preflight.verified" && event.payload?.preflightId === preflight.preflightId,
      );
      const proofHashBody = {
        sessionId: bundle.sessionId,
        preflightId: preflight.preflightId,
        spendId: preflight.spendId,
        artifactPayloadHash: lowerHex(preflight.artifactHashPreview),
        artifactCid: lowerHex(preflight.artifactCid),
        endpointUrl: asText(preflight.endpointUrl),
        priceDisclosureHash: asText(preflight.priceDisclosureHash),
        sourceStateSnapshotHash: asText(preflight.sourceStateSnapshotHash),
        manifestFetchHash: lowerHex(preflight.manifestFetchHash),
        endpointResponseHash: lowerHex(preflight.endpointResponseHash),
        leaseDryRunHash: lowerHex(preflight.leaseDryRunHash),
        ...(typeof verifiedEvent?.payload?.deliveryVerificationAuthority === "string"
          ? { deliveryVerificationAuthority: verifiedEvent.payload.deliveryVerificationAuthority }
          : {}),
        ...(isHex32(verifiedEvent?.payload?.artifactDeliveryEvidenceHash)
          ? { artifactDeliveryEvidenceHash: lowerHex(verifiedEvent.payload.artifactDeliveryEvidenceHash) }
          : {}),
      };
      const expectedDeliveryProofHash = safeHashJson(
        proofHashBody,
        `artifact preflight ${preflight.preflightId ?? "-"} delivery proof hash body`,
        errors,
      );
      if (expectedDeliveryProofHash && lowerHex(preflight.deliveryProofHash) !== expectedDeliveryProofHash) {
        errors.push(`artifact preflight ${preflight.preflightId ?? "-"} deliveryProofHash does not recompute`);
      }
      if (!verifiedEvent || verifiedEvent.authority !== "delivery") {
        errors.push(`artifact preflight ${preflight.preflightId ?? "-"} requires delivery-authority artifact.preflight.verified event`);
      } else {
        if (preflight.verifiedEventId && verifiedEvent.eventId !== preflight.verifiedEventId) {
          errors.push(`artifact preflight ${preflight.preflightId ?? "-"} verifiedEventId does not match verified event`);
        }
        for (const [field, expected] of [
          ["spendId", preflight.spendId],
          ["artifactPayloadHash", lowerHex(preflight.artifactHashPreview)],
          ["artifactCid", lowerHex(preflight.artifactCid)],
          ["endpointUrl", preflight.endpointUrl],
          ["priceDisclosureHash", preflight.priceDisclosureHash],
          ["sourceStateSnapshotHash", preflight.sourceStateSnapshotHash],
          ["manifestFetchHash", lowerHex(preflight.manifestFetchHash)],
          ["endpointResponseHash", lowerHex(preflight.endpointResponseHash)],
          ["leaseDryRunHash", lowerHex(preflight.leaseDryRunHash)],
          ["deliveryProofHash", lowerHex(preflight.deliveryProofHash)],
          ["status", "passed_live_delivery"],
          ...(typeof verifiedEvent.payload?.deliveryVerificationAuthority === "string"
            ? [["deliveryVerificationAuthority", verifiedEvent.payload.deliveryVerificationAuthority]]
            : []),
          ...(isHex32(verifiedEvent.payload?.artifactDeliveryEvidenceHash)
            ? [["artifactDeliveryEvidenceHash", lowerHex(verifiedEvent.payload.artifactDeliveryEvidenceHash)]]
            : []),
        ]) {
          if (lowerHex(verifiedEvent.payload?.[field]) !== lowerHex(expected)) {
            errors.push(`artifact preflight ${preflight.preflightId ?? "-"} verified event payload.${field} does not match preflight`);
          }
        }
        if (verifiedEvent.payload?.proofAuthority !== false || verifiedEvent.payload?.winnerClaimAllowed !== false) {
          errors.push(`artifact preflight ${preflight.preflightId ?? "-"} verified event must be delivery-only and winnerClaimAllowed=false`);
        }
      }
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
    if (preflight.status !== "passed_live_delivery") {
      errors.push(`quote ${quote.quoteId ?? "-"} references preflight that has not passed live delivery`);
    }
    if (
      lowerHex(quote.artifactCommitment) !== lowerHex(preflight.artifactHashPreview) ||
      lowerHex(quote.artifactCid) !== lowerHex(preflight.artifactCid)
    ) {
      errors.push(`quote ${quote.quoteId ?? "-"} artifact commitment does not match preflight`);
    }
    const spend = spendsById.get(lowerHex(quote.spendId));
    if (!spend) {
      errors.push(`quote ${quote.quoteId ?? "-"} references missing registered spend`);
    } else {
      if (lowerHex(quote.artifactCommitment) !== lowerHex(spend.artifactHash)) {
        errors.push(`quote ${quote.quoteId ?? "-"} artifactCommitment does not match registered spend artifactHash`);
      }
      const quotePrice = decimal(quote.priceAtomic);
      const spendPrice = decimal(spend.maxPriceAtomic);
      if (quotePrice === null || spendPrice === null || quotePrice !== spendPrice) {
        errors.push(`quote ${quote.quoteId ?? "-"} priceAtomic does not match registered spend price`);
      }
    }
    const quoteModes = quoteRuntimeModesForStatus(quote.status, spend);
    if (!quoteModes) {
      errors.push(`quote ${quote.quoteId ?? "-"} has unsupported status ${quote.status ?? "-"}`);
    }
    const expectedQuoteHash = safeHashJson(
      {
        sessionId: bundle.sessionId,
        spendId: quote.spendId,
        preflightId: quote.preflightId,
        artifactCommitment: lowerHex(quote.artifactCommitment),
        status: quote.status,
        chainId: quote.chainId ?? null,
        payer: lowerHex(spend?.payer),
        agentWallet: lowerHex(spend?.agentWallet),
        paymentToken: lowerHex(spend?.paymentToken),
        market: lowerHex(spend?.market),
        priceAtomic: quote.priceAtomic,
        quoteNonce: quote.quoteNonce,
        validUntilBlock: quote.validUntilBlock,
        artifactCid: lowerHex(quote.artifactCid),
        priceDisclosureHash: quote.priceDisclosureHash,
        sourceStateSnapshotHash: quote.sourceStateSnapshotHash,
        quoteSignedAfterPreflight: true,
        modes: quoteModes ?? {},
      },
      `quote ${quote.quoteId ?? "-"} quoteHash body`,
      errors,
    );
    if (expectedQuoteHash && lowerHex(quote.quoteHash) !== expectedQuoteHash) {
      errors.push(`quote ${quote.quoteId ?? "-"} quoteHash does not recompute`);
    }
    if (quote.status === CHAIN_SETTLEABLE_QUOTE_STATUS) {
      const quoteEvent = [...eventsById.values()].find(
        (event) => event.kind === "quote.signed.chain_settleable" && event.payload?.quoteId === quote.quoteId,
      );
      if (!quoteEvent || quoteEvent.authority !== "delivery") {
        errors.push(`quote ${quote.quoteId ?? "-"} requires delivery-authority quote.signed.chain_settleable event`);
      } else {
        for (const [field, expected] of [
          ["quoteHash", quote.quoteHash],
          ["spendId", quote.spendId],
          ["preflightId", quote.preflightId],
          ["artifactCommitment", lowerHex(quote.artifactCommitment)],
          ["artifactCid", lowerHex(quote.artifactCid)],
          ["payer", lowerHex(spend?.payer)],
          ["agentWallet", lowerHex(spend?.agentWallet)],
          ["paymentToken", lowerHex(spend?.paymentToken)],
          ["market", lowerHex(spend?.market)],
          ["priceAtomic", quote.priceAtomic],
          ["validUntilBlock", quote.validUntilBlock],
          ["status", CHAIN_SETTLEABLE_QUOTE_STATUS],
          ["chainId", quote.chainId],
        ]) {
          if (lowerHex(quoteEvent.payload?.[field]) !== lowerHex(expected)) {
            errors.push(`quote ${quote.quoteId ?? "-"} event payload.${field} does not match quote/payment binding`);
          }
        }
        if (quoteEvent.payload?.proofAuthority !== false || quoteEvent.payload?.winnerClaimAllowed !== false) {
          errors.push(`quote ${quote.quoteId ?? "-"} live quote event must be delivery-only and winnerClaimAllowed=false`);
        }
      }
    } else if (quote.status === MOCK_QUOTE_STATUS) {
      const quoteEvent = [...eventsById.values()].find((event) => event.kind === "quote.signed.mocked" && event.payload?.quoteId === quote.quoteId);
      if (!quoteEvent || quoteEvent.authority !== "advisory") {
        errors.push(`quote ${quote.quoteId ?? "-"} requires advisory quote.signed.mocked event`);
      } else {
        for (const [field, expected] of [
          ["quoteHash", quote.quoteHash],
          ["spendId", quote.spendId],
          ["preflightId", quote.preflightId],
          ["artifactCommitment", lowerHex(quote.artifactCommitment)],
          ["artifactCid", lowerHex(quote.artifactCid)],
          ["payer", lowerHex(spend?.payer)],
          ["agentWallet", lowerHex(spend?.agentWallet)],
          ["paymentToken", lowerHex(spend?.paymentToken)],
          ["market", lowerHex(spend?.market)],
          ["priceAtomic", quote.priceAtomic],
          ["validUntilBlock", quote.validUntilBlock],
          ["status", MOCK_QUOTE_STATUS],
        ]) {
          if (lowerHex(quoteEvent.payload?.[field]) !== lowerHex(expected)) {
            errors.push(`quote ${quote.quoteId ?? "-"} mocked event payload.${field} does not match quote/payment binding`);
          }
        }
        if (quoteEvent.payload?.proofAuthority !== false || quoteEvent.payload?.winnerClaimAllowed !== false) {
          errors.push(`quote ${quote.quoteId ?? "-"} mocked quote event must be advisory and winnerClaimAllowed=false`);
        }
      }
    }
  }
  for (const token of accessTokens) {
    if (!isObject(token)) {
      errors.push("artifactAccessTokens entries must be objects");
      continue;
    }
    const redactedPayloadHash = artifactPayloadRedactionHash(token.artifactPayload);
    const payloadHash =
      redactedPayloadHash ?? safeHashJson(token.artifactPayload, `artifact access token ${token.tokenId ?? "-"} payload`, errors);
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
    const spend = spendsById.get(lowerHex(token.spendId));
    if (!spend) {
      errors.push(`artifact access token ${token.tokenId ?? "-"} references missing registered spend`);
    } else {
      if (lowerHex(token.artifactHash) !== lowerHex(spend.artifactHash)) {
        errors.push(`artifact access token ${token.tokenId ?? "-"} artifactHash does not match registered spend artifactHash`);
      }
      if (typeof spend.payer === "string" && token.payer !== spend.payer) {
        errors.push(`artifact access token ${token.tokenId ?? "-"} payer does not match registered spend payer`);
      }
    }
    const settlementEvent = eventsById.get(token.settlementEventId);
    const settlementPayload = isObject(settlementEvent?.payload) ? settlementEvent.payload : null;
    if (
      !isObject(settlementEvent) ||
      settlementEvent.kind !== "token.balance_delta.verified" ||
      settlementEvent.authority !== "proof" ||
      !settlementPayload ||
      settlementPayload.spendId !== token.spendId ||
      settlementPayload.proofAuthority !== true
	    ) {
	      errors.push(`artifact access token ${token.tokenId ?? "-"} must reference token.balance_delta.verified settlementEventId`);
	    } else if (quote.status === CHAIN_SETTLEABLE_QUOTE_STATUS) {
	      if (!quote.chainId) {
	        errors.push(`artifact access token ${token.tokenId ?? "-"} chain-settleable quote requires chainId`);
	      } else if (asText(quote.chainId) !== asText(settlementPayload.chainId)) {
	        errors.push(`artifact access token ${token.tokenId ?? "-"} chain-settleable quote chainId does not match token settlement`);
	      }
	      const validUntilBlock = decimal(quote.validUntilBlock);
	      const settlementBlock = decimal(settlementPayload.blockNumber);
	      if (validUntilBlock === null || settlementBlock === null || validUntilBlock < settlementBlock) {
	        errors.push(`artifact access token ${token.tokenId ?? "-"} chain-settleable quote expired before token settlement`);
	      }
	    }
	  }
  const rawReceiptsByOperationAndHash = new Map();
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
        rawReceiptsByOperationAndHash.set(`${asText(rawBundle.operationId)}:${receiptHash}`, { rawBundle, receipt });
      }
    }
  }
  for (const canonical of canonicalReceipts) {
    if (!isObject(canonical)) {
      errors.push("canonicalCawReceipts entries must be objects");
      continue;
    }
    const rawMatch = rawReceiptsByOperationAndHash.get(`${asText(canonical.operationId)}:${canonical.rawReceiptHash}`);
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
      verifyCawReceiptSettlementBinding(canonical, operation, bundle, errors);
    }
    if (canonical.effect === "allow" && !canonical.txHash) {
      errors.push(`canonical CAW allow receipt ${canonicalReceiptHash ?? "-"} requires txHash`);
    }
  }
  const schemaErrors = [...errors];
  const finalEventsById = replayEventsByIdForFinalGate(bundle, eventsById);
  const proofCompletenessErrors = schemaErrors.length === 0 ? verifyFinalReplayClaimGate(bundle, finalEventsById, options) : [];
  const finalVerifierComplete = options.cliMode !== "schema-only" && schemaErrors.length === 0 && proofCompletenessErrors.length === 0;
  const proofChipAllowed = finalVerifierComplete;
  const winnerClaimAllowed = finalVerifierComplete && requestedWinnerClaimAllowed;
  const allErrors = [...schemaErrors, ...proofCompletenessErrors];
  return {
    schemaOk: schemaErrors.length === 0,
    proofChipAllowed,
    winnerClaimAllowed,
    requestedWinnerClaimAllowed,
    finalVerifierComplete,
    file: options.file ?? null,
    cliMode: options.cliMode ?? null,
    paymentProofMode: null,
    warnings,
    schemaErrors,
    proofCompletenessErrors,
    proofChipErrors: allErrors,
    winnerClaimErrors: [],
    errors: allErrors,
  };
}

function publicProofBundleVerifierAttestationInput(bundle, attestation) {
  return {
    attestationType: "PACTFUSE_PUBLIC_PROOF_VERIFIER_ATTESTATION_V1",
    scheme: attestation.scheme,
    keyId: attestation.keyId,
    publicKeyHash: attestation.publicKeyHash,
    bundleType: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
    sessionId: bundle.sessionId,
    publicClaimHash: bundle.publicClaimHash,
    publicClaimEventSeq: bundle.publicClaimEventSeq,
    snapshotScope: "authorization_event",
    providerSnapshotOnly: true,
    authorizedAt: bundle.authorizedAt,
    asOfEventSeq: bundle.asOfEventSeq,
    claimInputReplayBundleHash: bundle.claimInputReplayBundleHash,
    replayBundleHash: bundle.replayBundleHash,
    verifierRunHash: bundle.verifierRunHash,
    providerStatusHash: bundle.providerStatusHash,
    deploymentRegistryHash: bundle.deploymentRegistryHash,
    serverHash: bundle.serverHash,
    winnerClaimAllowed: true,
  };
}

function verifyPublicProofBundleVerifierAttestation(bundle, errors) {
  const attestation = isObject(bundle.verifierAttestation) ? bundle.verifierAttestation : null;
  if (!attestation) {
    errors.push("public proof bundle verifierAttestation must be an object");
    return false;
  }
  for (const field of ["scheme", "keyId", "publicKeyPem", "publicKeyHash", "signedPayloadHash", "signature"]) {
    requirePath(attestation, [field], errors);
  }
  if (attestation.scheme !== "ed25519") {
    errors.push("public proof bundle verifierAttestation.scheme must be ed25519");
  }
  if (typeof attestation.keyId !== "string" || attestation.keyId.length < 1) {
    errors.push("public proof bundle verifierAttestation.keyId must be a non-empty string");
  }
  if (typeof attestation.publicKeyPem !== "string" || attestation.publicKeyPem.length < 1) {
    errors.push("public proof bundle verifierAttestation.publicKeyPem must be a PEM string");
  }
  if (!isHex32(attestation.publicKeyHash)) {
    errors.push("public proof bundle verifierAttestation.publicKeyHash must be a 32-byte hash");
  }
  if (!isHex32(attestation.signedPayloadHash)) {
    errors.push("public proof bundle verifierAttestation.signedPayloadHash must be a 32-byte hash");
  }
  if (typeof attestation.signature !== "string" || attestation.signature.length < 1) {
    errors.push("public proof bundle verifierAttestation.signature must be a base64 signature");
  }
  const publicKeyHash = typeof attestation.publicKeyPem === "string" ? sha256Hex(attestation.publicKeyPem) : null;
  if (publicKeyHash && isHex32(attestation.publicKeyHash) && lowerHex(attestation.publicKeyHash) !== publicKeyHash) {
    errors.push("public proof bundle verifierAttestation.publicKeyHash does not match publicKeyPem");
  }
  const signedPayloadHash = safeHashJson(
    publicProofBundleVerifierAttestationInput(bundle, attestation),
    "public proof bundle verifierAttestation signed payload",
    errors,
  );
  if (signedPayloadHash && isHex32(attestation.signedPayloadHash) && lowerHex(attestation.signedPayloadHash) !== signedPayloadHash) {
    errors.push("public proof bundle verifierAttestation.signedPayloadHash does not recompute");
  }
  if (
    attestation.scheme !== "ed25519" ||
    !publicKeyHash ||
    !signedPayloadHash ||
    !isHex32(attestation.publicKeyHash) ||
    !isHex32(attestation.signedPayloadHash) ||
    typeof attestation.signature !== "string"
  ) {
    return false;
  }
  try {
    const publicKey = createPublicKey(attestation.publicKeyPem);
    const signature = Buffer.from(attestation.signature, "base64");
    const ok = cryptoVerify(null, Buffer.from(attestation.signedPayloadHash.slice(2), "hex"), publicKey, signature);
    if (!ok) {
      errors.push("public proof bundle verifierAttestation signature is invalid");
    }
    return ok && lowerHex(attestation.signedPayloadHash) === signedPayloadHash && lowerHex(attestation.publicKeyHash) === publicKeyHash;
  } catch (error) {
    errors.push(`public proof bundle verifierAttestation signature cannot be verified: ${error instanceof Error ? error.message : "unknown error"}`);
    return false;
  }
}

function publicProofBundleAttestationTrustErrors(attestation, options) {
  const trusted = trustedProofKeyHashes(options);
  if (trusted.size === 0) {
    return ["public proof bundle verifierAttestation trusted proof key hash is not configured"];
  }
  const keyHash = lowerHex(attestation?.publicKeyHash);
  if (!trusted.has(keyHash)) {
    return ["public proof bundle verifierAttestation publicKeyHash is not trusted"];
  }
  return [];
}

function verifyPublicProofBundleEvidence(bundle, options = {}) {
  const schemaErrors = [];
  const warnings = [];
  const publicProofBundleFields = [
    "bundleType",
    "sessionId",
    "proofBundleHash",
    "publicClaimHash",
    "publicClaimEventId",
    "publicClaimEventHash",
    "publicClaimEventSeq",
    "snapshotScope",
    "providerSnapshotOnly",
    "authorizedAt",
    "asOfEventSeq",
    "claimInputReplayBundleHash",
    "replayBundleHash",
    "verifierRunHash",
    "providerStatusHash",
    "deploymentRegistryHash",
    "serverHash",
    "publicClaim",
    "replayBundle",
    "providerStatuses",
    "deploymentRegistry",
    "server",
    "verifierAttestation",
    "winnerClaimAllowed",
  ];
  rejectUnexpectedKeys(bundle, publicProofBundleFields, "public proof bundle", schemaErrors);
  for (const field of publicProofBundleFields) {
    requirePath(bundle, [field], schemaErrors);
  }
  if (bundle.bundleType !== "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1") {
    schemaErrors.push("public proof bundle bundleType must be PACTFUSE_PUBLIC_PROOF_BUNDLE_V1");
  }
  if (!isHex32(bundle.sessionId)) {
    schemaErrors.push("public proof bundle sessionId must be a 32-byte hex string");
  }
  for (const field of [
    "proofBundleHash",
    "publicClaimHash",
    "publicClaimEventId",
    "publicClaimEventHash",
    "claimInputReplayBundleHash",
    "replayBundleHash",
    "verifierRunHash",
    "providerStatusHash",
    "serverHash",
  ]) {
    if (!isHex32(bundle[field])) {
      schemaErrors.push(`public proof bundle ${field} must be a 32-byte hash`);
    }
  }
  if (bundle.deploymentRegistryHash !== null && !isHex32(bundle.deploymentRegistryHash)) {
    schemaErrors.push("public proof bundle deploymentRegistryHash must be a 32-byte hash or null");
  }
  if (bundle.snapshotScope !== "authorization_event" || bundle.providerSnapshotOnly !== true) {
    schemaErrors.push("public proof bundle must use authorization_event provider snapshot");
  }
  if (bundle.winnerClaimAllowed !== true) {
    schemaErrors.push("public proof bundle winnerClaimAllowed must be true");
  }
  if (!Number.isInteger(bundle.publicClaimEventSeq) || bundle.publicClaimEventSeq < 1) {
    schemaErrors.push("public proof bundle publicClaimEventSeq must be a positive integer");
  }
  if (!Number.isInteger(bundle.asOfEventSeq) || bundle.asOfEventSeq < 0) {
    schemaErrors.push("public proof bundle asOfEventSeq must be a non-negative integer");
  }
  if (Number.isInteger(bundle.publicClaimEventSeq) && Number.isInteger(bundle.asOfEventSeq) && bundle.asOfEventSeq !== bundle.publicClaimEventSeq - 1) {
    schemaErrors.push("public proof bundle asOfEventSeq must immediately precede publicClaimEventSeq");
  }
  const replayBundle = isObject(bundle.replayBundle) ? bundle.replayBundle : null;
  const publicClaim = isObject(bundle.publicClaim) ? bundle.publicClaim : null;
  if (!replayBundle) {
    schemaErrors.push("public proof bundle requires replayBundle object");
  }
  if (!publicClaim) {
    schemaErrors.push("public proof bundle requires publicClaim object");
  }
  if (replayBundle && replayBundle.sessionId !== bundle.sessionId) {
    schemaErrors.push("public proof bundle replayBundle.sessionId must match bundle.sessionId");
  }
  if (replayBundle && Number.isInteger(bundle.asOfEventSeq) && replayBundle.asOfEventSeq !== bundle.asOfEventSeq) {
    schemaErrors.push("public proof bundle replayBundle.asOfEventSeq must match bundle.asOfEventSeq");
  }
  const replayBundleHash = replayBundle ? safeHashJson(replayBundle, "public proof bundle replayBundle", schemaErrors) : null;
  if (replayBundleHash && lowerHex(bundle.replayBundleHash) !== replayBundleHash) {
    schemaErrors.push("public proof bundle replayBundleHash does not recompute");
  }
  if (bundle.claimInputReplayBundleHash !== bundle.replayBundleHash) {
    schemaErrors.push("public proof bundle claimInputReplayBundleHash must equal replayBundleHash");
  }
  const verifierRunHash = publicClaim?.verifierRun ? safeHashJson(publicClaim.verifierRun, "public proof bundle verifierRun", schemaErrors) : null;
  if (verifierRunHash && lowerHex(bundle.verifierRunHash) !== verifierRunHash) {
    schemaErrors.push("public proof bundle verifierRunHash does not recompute");
  }
  const providerStatusHash = Array.isArray(bundle.providerStatuses)
    ? safeHashJson(bundle.providerStatuses, "public proof bundle providerStatuses", schemaErrors)
    : null;
  if (!Array.isArray(bundle.providerStatuses)) {
    schemaErrors.push("public proof bundle providerStatuses must be an array");
  } else if (providerStatusHash && lowerHex(bundle.providerStatusHash) !== providerStatusHash) {
    schemaErrors.push("public proof bundle providerStatusHash does not recompute");
  }
  const deploymentRegistryHash = bundle.deploymentRegistry === null
    ? null
    : isObject(bundle.deploymentRegistry)
      ? safeHashJson(bundle.deploymentRegistry, "public proof bundle deploymentRegistry", schemaErrors)
      : undefined;
  if (deploymentRegistryHash === undefined) {
    schemaErrors.push("public proof bundle deploymentRegistry must be an object or null");
  } else if (bundle.deploymentRegistryHash !== deploymentRegistryHash) {
    schemaErrors.push("public proof bundle deploymentRegistryHash does not recompute");
  }
  const serverHash = isObject(bundle.server) ? safeHashJson(bundle.server, "public proof bundle server", schemaErrors) : null;
  if (!isObject(bundle.server)) {
    schemaErrors.push("public proof bundle server must be an object");
  } else if (serverHash && lowerHex(bundle.serverHash) !== serverHash) {
    schemaErrors.push("public proof bundle serverHash does not recompute");
  }
  if (publicClaim) {
    verifyPublicClaimBinding(bundle, publicClaim, schemaErrors);
  }
  const verifierAttestationOk = verifyPublicProofBundleVerifierAttestation(bundle, schemaErrors);
  const verifierAttestationTrustErrors = verifierAttestationOk
    ? publicProofBundleAttestationTrustErrors(bundle.verifierAttestation, options)
    : [];
  if (replayBundle && publicClaim) {
    const publicClaimPayload = {
      claim: publicClaim,
      publicClaimHash: bundle.publicClaimHash,
      replayBundle,
      replayBundleHash: bundle.claimInputReplayBundleHash,
      verifierRunHash: bundle.verifierRunHash,
      verifierAttestation: bundle.verifierAttestation,
      asOfEventSeq: publicClaim.asOfEventSeq,
      providerStatuses: bundle.providerStatuses,
      providerStatusHash: bundle.providerStatusHash,
      deploymentRegistry: bundle.deploymentRegistry,
      deploymentRegistryHash: bundle.deploymentRegistryHash,
      server: bundle.server,
      serverHash: bundle.serverHash,
      proofAuthority: true,
      winnerClaimAllowed: true,
    };
    const publicClaimPayloadHash = safeHashJson(publicClaimPayload, "public proof bundle public claim event payload", schemaErrors);
    const previousProofEventHash = latestProofEventHashForPublicClaim(replayBundle, bundle.asOfEventSeq);
    const publicClaimEventHash = publicClaimPayloadHash
      ? safeHashJson(
          {
            sessionId: bundle.sessionId,
            eventSeq: bundle.publicClaimEventSeq,
            authority: "proof",
            kind: "public.claim.authorized",
            payloadHash: publicClaimPayloadHash,
            prevProofEventHash: previousProofEventHash,
          },
          "public proof bundle public claim event hash body",
          schemaErrors,
        )
      : null;
    if (publicClaimEventHash && lowerHex(bundle.publicClaimEventHash) !== publicClaimEventHash) {
      schemaErrors.push("public proof bundle publicClaimEventHash does not recompute");
    }
    if (publicClaimEventHash && lowerHex(bundle.publicClaimEventId) !== publicClaimEventHash) {
      schemaErrors.push("public proof bundle publicClaimEventId must equal publicClaimEventHash");
    }
  }
  const proofBundleBase = { ...bundle };
  delete proofBundleBase.proofBundleHash;
  const proofBundleHash = safeHashJson(proofBundleBase, "public proof bundle body", schemaErrors);
  if (proofBundleHash && lowerHex(bundle.proofBundleHash) !== proofBundleHash) {
    schemaErrors.push("public proof bundle proofBundleHash does not recompute");
  }

  const replayOptions = verifierAttestationOk && verifierAttestationTrustErrors.length === 0
    ? createServerRuntimeVerifierOptions({
        ...options,
        proofProviders: Array.isArray(bundle.providerStatuses) ? bundle.providerStatuses : [],
      })
    : { ...options, proofProviders: [] };
  const replayResult = replayBundle ? verifyReplayBundleEvidence(replayBundle, replayOptions) : null;
  if (replayResult) {
    schemaErrors.push(...replayResult.schemaErrors.map((error) => `replayBundle: ${error}`));
  }
  const proofCompletenessErrors =
    options.cliMode === "schema-only" || schemaErrors.length > 0 || !replayResult
      ? []
      : [
          ...verifierAttestationTrustErrors,
          ...replayResult.proofCompletenessErrors.map((error) => `replayBundle: ${error}`),
          ...(replayResult.finalVerifierComplete ? [] : ["public proof bundle embedded replay did not pass final verifier"]),
          ...(publicClaim?.verifierRun?.finalVerifierComplete === true &&
          publicClaim?.verifierRun?.proofChipAllowed === true &&
          publicClaim?.verifierRun?.winnerClaimAllowed === true
            ? []
            : ["public proof bundle embedded publicClaim verifierRun does not authorize winner claim"]),
        ];
  const finalVerifierComplete =
    options.cliMode !== "schema-only" &&
    schemaErrors.length === 0 &&
    proofCompletenessErrors.length === 0 &&
    Boolean(replayResult?.finalVerifierComplete);
  const proofChipAllowed = finalVerifierComplete;
  const requestedWinnerClaimAllowed = bundle.winnerClaimAllowed === true || publicClaim?.winnerClaimAllowed === true;
  const winnerClaimAllowed = finalVerifierComplete && requestedWinnerClaimAllowed;
  const allErrors = [...schemaErrors, ...proofCompletenessErrors];
  return {
    schemaOk: schemaErrors.length === 0,
    proofChipAllowed,
    winnerClaimAllowed,
    requestedWinnerClaimAllowed,
    finalVerifierComplete,
    file: options.file ?? null,
    cliMode: options.cliMode ?? null,
    paymentProofMode: null,
    warnings: [...warnings, ...(replayResult?.warnings ?? [])],
    schemaErrors,
    proofCompletenessErrors,
    proofChipErrors: allErrors,
    winnerClaimErrors: [],
    errors: allErrors,
  };
}

function verifyPublicClaimBinding(bundle, publicClaim, errors) {
  const expectedTokenSettlementClaim = tokenSettlementClaimForTokenMode(publicClaim.tokenMode);
  if (!expectedTokenSettlementClaim || publicClaim.tokenSettlementClaim !== expectedTokenSettlementClaim) {
    errors.push("public proof bundle publicClaim.tokenSettlementClaim does not match tokenMode");
  }
  for (const field of ["claimMode", "paymentMode", "tokenMode", "identityMode"]) {
    if (publicClaim.verifierRun?.[field] !== publicClaim[field]) {
      errors.push(`public proof bundle publicClaim.verifierRun.${field} does not match publicClaim.${field}`);
    }
  }
  for (const [field, expected] of [
    ["sessionId", bundle.sessionId],
    ["snapshotScope", "authorization_event"],
    ["providerSnapshotOnly", true],
    ["authorizedAt", bundle.authorizedAt],
    ["authorizedEventSeq", bundle.publicClaimEventSeq],
    ["asOfEventSeq", bundle.asOfEventSeq],
    ["replayBundleHash", bundle.replayBundleHash],
    ["providerStatusHash", bundle.providerStatusHash],
    ["deploymentRegistryHash", bundle.deploymentRegistryHash],
    ["serverHash", bundle.serverHash],
    ["proofChipAllowed", true],
    ["finalVerifierComplete", true],
    ["winnerClaimAllowed", true],
  ]) {
    if (publicClaim[field] !== expected) {
      errors.push(`public proof bundle publicClaim.${field} does not match bundle`);
    }
  }
  const expectedPublicClaimHash = safeHashJson(
    {
      sessionId: publicClaim.sessionId,
      snapshotScope: publicClaim.snapshotScope,
      providerSnapshotOnly: publicClaim.providerSnapshotOnly,
      authorizedAt: publicClaim.authorizedAt,
      authorizedEventSeq: publicClaim.authorizedEventSeq,
      asOfEventSeq: publicClaim.asOfEventSeq,
      claimMode: publicClaim.claimMode,
      paymentMode: publicClaim.paymentMode,
      tokenMode: publicClaim.tokenMode,
      tokenSettlementClaim: publicClaim.tokenSettlementClaim,
      identityMode: publicClaim.identityMode,
      replayBundleHash: publicClaim.replayBundleHash,
      providerStatusHash: publicClaim.providerStatusHash,
      deploymentRegistryHash: publicClaim.deploymentRegistryHash,
      serverHash: publicClaim.serverHash,
      verifierRun: {
        claimMode: publicClaim.verifierRun?.claimMode,
        paymentMode: publicClaim.verifierRun?.paymentMode,
        tokenMode: publicClaim.verifierRun?.tokenMode,
        identityMode: publicClaim.verifierRun?.identityMode,
        proofLevel: publicClaim.verifierRun?.proofLevel,
        proofChipAllowed: publicClaim.verifierRun?.proofChipAllowed,
        finalVerifierComplete: publicClaim.verifierRun?.finalVerifierComplete,
        winnerClaimAllowed: publicClaim.verifierRun?.winnerClaimAllowed,
      },
    },
    "public proof bundle publicClaimHash body",
    errors,
  );
  if (expectedPublicClaimHash && lowerHex(bundle.publicClaimHash) !== expectedPublicClaimHash) {
    errors.push("public proof bundle publicClaimHash does not recompute");
  }
  if (lowerHex(publicClaim.publicClaimHash) !== lowerHex(bundle.publicClaimHash)) {
    errors.push("public proof bundle publicClaim.publicClaimHash does not match bundle");
  }
}

function latestProofEventHashForPublicClaim(replayBundle, asOfEventSeq) {
  const events = replayRowsForCollection(replayBundle, "events");
  const proofEvents = events
    .filter((event) => isObject(event) && event.authority === "proof" && Number(event.eventSeq) <= Number(asOfEventSeq))
    .sort((left, right) => Number(left.eventSeq) - Number(right.eventSeq));
  return proofEvents.at(-1)?.eventHash ?? ZERO_HASH;
}

export function verifyEvidence(receipt, options = {}) {
  if (isObject(receipt) && receipt.bundleType === "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1") {
    return verifyPublicProofBundleEvidence(receipt, options);
  }
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
  const trustedProofKeyHashes = normalizedHex32List([process.env.PACTFUSE_TRUSTED_PROOF_KEY_HASHES]);
  const positional = [];
  let schemaOnly = false;
  const unknownFlags = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--schema-only" || arg === "--preflight") {
      schemaOnly = true;
      continue;
    }
    if (arg === "--trusted-proof-key-hash") {
      const value = args[index + 1];
      if (!isHex32(value)) {
        unknownFlags.push(`${arg} requires a 32-byte hex hash`);
      } else {
        trustedProofKeyHashes.push(lowerHex(value));
      }
      index += 1;
      continue;
    }
    if (arg.startsWith("--trusted-proof-key-hash=")) {
      const value = arg.slice("--trusted-proof-key-hash=".length);
      if (!isHex32(value)) {
        unknownFlags.push("--trusted-proof-key-hash requires a 32-byte hex hash");
      } else {
        trustedProofKeyHashes.push(lowerHex(value));
      }
      continue;
    }
    if (arg.startsWith("-")) {
      unknownFlags.push(arg);
      continue;
    }
    positional.push(arg);
  }
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

  const result = verifyEvidence(receipt, {
    file: receiptPath,
    cliMode: schemaOnly ? "schema-only" : "proof-chip",
    trustedProofKeyHashes,
  });
  console.log(JSON.stringify(result, null, 2));
  if (schemaOnly) {
    process.exit(result.schemaOk && !result.requestedWinnerClaimAllowed ? 0 : 1);
  }
  process.exit(result.proofChipAllowed ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
