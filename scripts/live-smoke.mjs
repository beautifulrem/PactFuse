#!/usr/bin/env node

import { createHash } from "node:crypto";

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;

const baseUrl = stripTrailingSlash(process.env.PACTFUSE_API_BASE_URL ?? "http://127.0.0.1:8787");
const operatorToken = process.env.PACTFUSE_OPERATOR_TOKEN;
const sessionId = process.env.PACTFUSE_LIVE_SMOKE_SESSION_ID;
const requirePublicClaim = booleanEnv("PACTFUSE_LIVE_SMOKE_REQUIRE_PUBLIC_CLAIM", true);
const requiredProviders = listEnv("PACTFUSE_LIVE_SMOKE_REQUIRED_PROVIDERS", ["chain", "caw_live", "caw", "mcp_lease"]);

try {
  assert(operatorToken, "PACTFUSE_OPERATOR_TOKEN is required");
  assert(sessionId && HEX32.test(sessionId), "PACTFUSE_LIVE_SMOKE_SESSION_ID must be a 32-byte hex session id");

  const ready = await requestJson("/readyz");
  assert(ready.ok === true, "/readyz did not return ok=true", ready);
  assert(ready.proofProviderCheck?.checked === true, "/readyz did not run deep proof-provider checks", ready.proofProviderCheck);
  assert(ready.apiSecurity?.operatorTokenConfigured === true, "operator token is not configured", ready.apiSecurity);
  assert(ready.apiSecurity?.allowInsecureMissingRoleTokens === false, "insecure missing-role-token bypass is enabled", ready.apiSecurity);
  assert(ready.mcpAudit?.configured === true, "PACTFUSE_MCP_AUDIT_TOKEN is not configured", ready.mcpAudit);
  assert(ready.gateIngest?.configured === true, "PACTFUSE_GATE_INGEST_TOKEN is not configured", ready.gateIngest);

  const providers = new Map((ready.proofProviders ?? []).map((provider) => [provider.name, provider]));
  for (const providerName of requiredProviders) {
    const provider = providers.get(providerName);
    assert(provider?.ready === true, `proof provider ${providerName} is not ready`, provider ?? { name: providerName, ready: false });
  }

  const preflight = await requestJson(`/api/v1/evidence/live-preflight?sessionId=${encodeURIComponent(sessionId)}`);
  const preflightData = preflight.data;
  assert(preflight.ok === true && preflightData, "live-preflight did not return data", preflight);
  assert(preflightData.status === "ready", "live-preflight status is not ready", preflightData);
  assert(preflightData.readyForPublicClaim === true, "live-preflight is not ready for public claim", preflightData);
  assert(preflightData.winnerClaimAllowed === true, "live-preflight winnerClaimAllowed is not true", preflightData);
  assert((preflightData.blockingReasons ?? []).length === 0, "live-preflight still has blockers", preflightData.blockingReasons);
  assert((preflightData.requiredExternalInputs ?? []).length === 0, "live-preflight still requires external inputs", preflightData.requiredExternalInputs);
  for (const check of preflightData.checks ?? []) {
    assert(check.status === "pass", `live-preflight check ${check.checkId} did not pass`, check);
  }
  assert(preflightData.security?.cawIngestTokenConfigured === true, "PACTFUSE_CAW_INGEST_TOKEN is not configured", preflightData.security);

  let claimData = null;
  let proofBundleData = null;
  if (requirePublicClaim) {
    const claim = await requestJson(`/api/v1/evidence/public-claim?sessionId=${encodeURIComponent(sessionId)}`);
    claimData = claim.data;
    assert(claim.ok === true && claimData, "public-claim did not return data", claim);
    assert(claimData.claimStatus === "authorized_public_claim", "public-claim is not authorized", claimData);
    assert(claimData.proofChipAllowed === true, "public-claim proofChipAllowed is not true", claimData);
    assert(claimData.finalVerifierComplete === true, "public-claim finalVerifierComplete is not true", claimData);
    assert(claimData.winnerClaimAllowed === true, "public-claim winnerClaimAllowed is not true", claimData);
    assert(claimData.sessionId === sessionId, "public-claim sessionId does not match PACTFUSE_LIVE_SMOKE_SESSION_ID", {
      expected: sessionId,
      actual: claimData.sessionId,
    });
    assert(HEX32.test(claimData.publicClaimHash), "public-claim hash is missing or invalid", claimData);

    const proofBundle = await requestJson(`/api/v1/evidence/proof-bundle?sessionId=${encodeURIComponent(sessionId)}`);
    proofBundleData = proofBundle.data;
    assert(proofBundle.ok === true && proofBundleData, "proof-bundle did not return data", proofBundle);
    assert(proofBundleData.bundleType === "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1", "proof-bundle has the wrong bundle type", proofBundleData);
    assert(proofBundleData.winnerClaimAllowed === true, "proof-bundle winnerClaimAllowed is not true", proofBundleData);
    assert(proofBundleData.sessionId === sessionId, "proof-bundle sessionId does not match PACTFUSE_LIVE_SMOKE_SESSION_ID", {
      expected: sessionId,
      actual: proofBundleData.sessionId,
    });
    assert(proofBundleData.publicClaim?.sessionId === sessionId, "proof-bundle embedded publicClaim sessionId does not match", {
      expected: sessionId,
      actual: proofBundleData.publicClaim?.sessionId,
    });
    assert(proofBundleData.replayBundle?.sessionId === sessionId, "proof-bundle embedded replayBundle sessionId does not match", {
      expected: sessionId,
      actual: proofBundleData.replayBundle?.sessionId,
    });
    assert(proofBundleData.publicClaimHash === claimData.publicClaimHash, "proof-bundle public claim hash does not match public-claim", {
      proofBundlePublicClaimHash: proofBundleData.publicClaimHash,
      publicClaimHash: claimData.publicClaimHash,
    });
    assert(proofBundleData.claimInputReplayBundleHash === claimData.replayBundleHash, "proof-bundle claim input replay hash does not match public-claim", {
      claimInputReplayBundleHash: proofBundleData.claimInputReplayBundleHash,
      publicClaimReplayBundleHash: claimData.replayBundleHash,
    });
    assert(proofBundleData.replayBundleHash === claimData.replayBundleHash, "proof-bundle final replay hash does not match public-claim", {
      proofBundleReplayBundleHash: proofBundleData.replayBundleHash,
      publicClaimReplayBundleHash: claimData.replayBundleHash,
    });
    assert(HEX32.test(proofBundleData.proofBundleHash), "proof-bundle hash is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.publicClaimEventId), "proof-bundle public claim event id is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.publicClaimEventHash), "proof-bundle public claim event hash is missing or invalid", proofBundleData);
    assert(
      Number.isInteger(proofBundleData.publicClaimEventSeq) && proofBundleData.publicClaimEventSeq > 1,
      "proof-bundle public claim event seq is missing or invalid",
      proofBundleData,
    );
    assert(HEX32.test(proofBundleData.providerStatusHash), "proof-bundle provider status hash is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.serverHash), "proof-bundle server hash is missing or invalid", proofBundleData);
    verifyProofBundleHashes(proofBundleData, claimData);
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        baseUrl,
        sessionId,
        requiredProviders,
        livePreflightStatus: preflightData.status,
        publicClaimHash: claimData?.publicClaimHash ?? null,
        proofBundleHash: proofBundleData?.proofBundleHash ?? null,
      },
      null,
      2,
    ),
  );
} catch (error) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        baseUrl,
        sessionId: sessionId ?? null,
        error: error instanceof Error ? error.message : String(error),
        details: error && typeof error === "object" && "details" in error ? error.details : undefined,
      },
      null,
      2,
    ),
  );
  process.exit(1);
}

async function requestJson(path) {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: {
      authorization: `Bearer ${operatorToken}`,
      accept: "application/json",
    },
  });
  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw withDetails(new Error(`${path} returned non-JSON response`), { status: response.status, body: text.slice(0, 500) });
  }
  if (!response.ok) {
    throw withDetails(new Error(`${path} returned HTTP ${response.status}`), json);
  }
  return json;
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function booleanEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  return !["0", "false", "no", "off"].includes(raw.trim().toLowerCase());
}

function listEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const values = raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return values.length > 0 ? values : fallback;
}

function verifyProofBundleHashes(proofBundle, claim) {
  assert(canonicalizeJson(proofBundle.publicClaim) === canonicalizeJson(claim), "proof-bundle publicClaim does not match public-claim response", {
    proofBundlePublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
    publicClaimHash: claim?.publicClaimHash,
  });
  assert(proofBundle.publicClaim?.publicClaimHash === proofBundle.publicClaimHash, "proof-bundle publicClaimHash does not match embedded publicClaim", {
    proofBundlePublicClaimHash: proofBundle.publicClaimHash,
    embeddedPublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
  });
  assert(
    hashJson(publicClaimHashInput(proofBundle.publicClaim)) === proofBundle.publicClaimHash,
    "proof-bundle publicClaimHash does not recompute from embedded publicClaim",
    {
      expected: proofBundle.publicClaimHash,
      actual: hashJson(publicClaimHashInput(proofBundle.publicClaim)),
    },
  );
  assert(hashJson(proofBundle.replayBundle) === proofBundle.replayBundleHash, "proof-bundle replayBundleHash does not recompute", {
    expected: proofBundle.replayBundleHash,
    actual: hashJson(proofBundle.replayBundle),
  });
  assert(hashJson(proofBundle.publicClaim.verifierRun) === proofBundle.verifierRunHash, "proof-bundle verifierRunHash does not recompute", {
    expected: proofBundle.verifierRunHash,
    actual: hashJson(proofBundle.publicClaim.verifierRun),
  });
  assert(hashJson(proofBundle.providerStatuses) === proofBundle.providerStatusHash, "proof-bundle providerStatusHash does not recompute", {
    expected: proofBundle.providerStatusHash,
    actual: hashJson(proofBundle.providerStatuses),
  });
  const deploymentRegistryHash = proofBundle.deploymentRegistry === null ? null : hashJson(proofBundle.deploymentRegistry);
  assert(deploymentRegistryHash === proofBundle.deploymentRegistryHash, "proof-bundle deploymentRegistryHash does not recompute", {
    expected: proofBundle.deploymentRegistryHash,
    actual: deploymentRegistryHash,
  });
  assert(hashJson(proofBundle.server) === proofBundle.serverHash, "proof-bundle serverHash does not recompute", {
    expected: proofBundle.serverHash,
    actual: hashJson(proofBundle.server),
  });
  const previousProofEventHash = verifyReplayBundleEvents(proofBundle.replayBundle, proofBundle.publicClaimEventSeq - 1);
  verifyPublicClaimEventHash(proofBundle, previousProofEventHash);
  const bundleBase = { ...proofBundle };
  delete bundleBase.proofBundleHash;
  assert(hashJson(bundleBase) === proofBundle.proofBundleHash, "proof-bundle hash does not recompute", {
    expected: proofBundle.proofBundleHash,
    actual: hashJson(bundleBase),
  });
}

function verifyReplayBundleEvents(replayBundle, expectedAsOfEventSeq) {
  const events = replayBundle?.events;
  assert(Array.isArray(events) && events.length > 0, "proof-bundle replayBundle.events is missing or empty", replayBundle);
  assert(replayBundle.asOfEventSeq === expectedAsOfEventSeq, "proof-bundle replay asOfEventSeq does not precede public claim event", {
    expected: expectedAsOfEventSeq,
    actual: replayBundle.asOfEventSeq,
  });
  let previousEventSeq = 0;
  let previousProofEventHash = ZERO_HASH;
  for (const event of events) {
    assert(isObject(event), "proof-bundle replayBundle.events entries must be objects", event);
    for (const field of ["eventId", "sessionId", "eventSeq", "eventHash", "authority", "kind", "payloadHash", "payload"]) {
      assert(event[field] !== undefined, `proof-bundle replay event is missing ${field}`, event);
    }
    assert(event.sessionId === replayBundle.sessionId, "proof-bundle replay event sessionId does not match replay bundle", event);
    assert(Number.isInteger(event.eventSeq) && event.eventSeq > previousEventSeq, "proof-bundle replay eventSeq is not strictly increasing", event);
    previousEventSeq = event.eventSeq;
    const expectedPayloadHash = hashJson(event.payload);
    assert(sameHex(event.payloadHash, expectedPayloadHash), "proof-bundle replay event payloadHash does not recompute", {
      eventId: event.eventId,
      expected: event.payloadHash,
      actual: expectedPayloadHash,
    });
    const expectedPrevProofEventHash = event.authority === "proof" ? previousProofEventHash : null;
    assert(
      (event.prevProofEventHash ?? null) === expectedPrevProofEventHash,
      "proof-bundle replay event prevProofEventHash does not match proof chain",
      { eventId: event.eventId, expected: expectedPrevProofEventHash, actual: event.prevProofEventHash ?? null },
    );
    const expectedEventHash = hashJson({
      sessionId: event.sessionId,
      eventSeq: event.eventSeq,
      authority: event.authority,
      kind: event.kind,
      payloadHash: event.payloadHash,
      prevProofEventHash: event.prevProofEventHash ?? null,
    });
    assert(sameHex(event.eventHash, expectedEventHash), "proof-bundle replay eventHash does not recompute", {
      eventId: event.eventId,
      expected: event.eventHash,
      actual: expectedEventHash,
    });
    assert(sameHex(event.eventId, expectedEventHash), "proof-bundle replay eventId does not equal eventHash", {
      eventId: event.eventId,
      expected: expectedEventHash,
    });
    if (event.authority === "proof") {
      previousProofEventHash = event.eventHash.toLowerCase();
    }
  }
  const expectedEventRoot = hashJson(events.map((event) => event.eventHash));
  assert(sameHex(replayBundle.eventRoot, expectedEventRoot), "proof-bundle replay eventRoot does not recompute", {
    expected: replayBundle.eventRoot,
    actual: expectedEventRoot,
  });
  return previousProofEventHash;
}

function verifyPublicClaimEventHash(proofBundle, previousProofEventHash) {
  const asOfEventSeq = proofBundle.publicClaimEventSeq - 1;
  const payload = {
    claim: proofBundle.publicClaim,
    publicClaimHash: proofBundle.publicClaimHash,
    replayBundleHash: proofBundle.claimInputReplayBundleHash,
    verifierRunHash: proofBundle.verifierRunHash,
    asOfEventSeq,
    providerStatuses: proofBundle.providerStatuses,
    providerStatusHash: proofBundle.providerStatusHash,
    deploymentRegistry: proofBundle.deploymentRegistry,
    deploymentRegistryHash: proofBundle.deploymentRegistryHash,
    server: proofBundle.server,
    serverHash: proofBundle.serverHash,
    proofAuthority: true,
    winnerClaimAllowed: true,
  };
  const payloadHash = hashJson(payload);
  const eventHash = hashJson({
    sessionId: proofBundle.sessionId,
    eventSeq: proofBundle.publicClaimEventSeq,
    authority: "proof",
    kind: "public.claim.authorized",
    payloadHash,
    prevProofEventHash: previousProofEventHash,
  });
  assert(sameHex(proofBundle.publicClaimEventHash, eventHash), "proof-bundle public claim event hash does not recompute", {
    expected: proofBundle.publicClaimEventHash,
    actual: eventHash,
  });
  assert(sameHex(proofBundle.publicClaimEventId, eventHash), "proof-bundle public claim event id does not equal event hash", {
    expected: proofBundle.publicClaimEventId,
    actual: eventHash,
  });
}

function publicClaimHashInput(claim) {
  return {
    sessionId: claim.sessionId,
    claimMode: claim.claimMode,
    paymentMode: claim.paymentMode,
    tokenMode: claim.tokenMode,
    identityMode: claim.identityMode,
    replayBundleHash: claim.replayBundleHash,
    verifierRun: {
      proofLevel: claim.verifierRun.proofLevel,
      proofChipAllowed: claim.verifierRun.proofChipAllowed,
      finalVerifierComplete: claim.verifierRun.finalVerifierComplete,
      winnerClaimAllowed: claim.verifierRun.winnerClaimAllowed,
    },
  };
}

function hashJson(value) {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function canonicalizeJson(value) {
  return JSON.stringify(sortForJcs(value));
}

function sortForJcs(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS canonicalization rejects non-finite numbers");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sortForJcs(item));
  }
  if (typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      if (child !== undefined) {
        sorted[key] = sortForJcs(child);
      }
    }
    return sorted;
  }
  return value;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function sameHex(left, right) {
  return typeof left === "string" && typeof right === "string" && left.toLowerCase() === right.toLowerCase();
}

function assert(condition, message, details) {
  if (!condition) {
    throw withDetails(new Error(message), details);
  }
}

function withDetails(error, details) {
  Object.defineProperty(error, "details", { value: details, enumerable: true });
  return error;
}
