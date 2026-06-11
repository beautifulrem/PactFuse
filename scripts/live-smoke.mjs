#!/usr/bin/env node

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

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
  if (requirePublicClaim) {
    const claim = await requestJson(`/api/v1/evidence/public-claim?sessionId=${encodeURIComponent(sessionId)}`);
    claimData = claim.data;
    assert(claim.ok === true && claimData, "public-claim did not return data", claim);
    assert(claimData.claimStatus === "authorized_public_claim", "public-claim is not authorized", claimData);
    assert(claimData.proofChipAllowed === true, "public-claim proofChipAllowed is not true", claimData);
    assert(claimData.finalVerifierComplete === true, "public-claim finalVerifierComplete is not true", claimData);
    assert(claimData.winnerClaimAllowed === true, "public-claim winnerClaimAllowed is not true", claimData);
    assert(HEX32.test(claimData.publicClaimHash), "public-claim hash is missing or invalid", claimData);
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
  return !["0", "false", "no", "off"].includes(raw.toLowerCase());
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

function assert(condition, message, details) {
  if (!condition) {
    throw withDetails(new Error(message), details);
  }
}

function withDetails(error, details) {
  Object.defineProperty(error, "details", { value: details, enumerable: true });
  return error;
}
