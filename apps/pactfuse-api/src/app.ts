import { createHmac, timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import {
  HexSchema,
  Hex32Schema,
  ChainIndexerBackfillInputSchema,
  McpAdapterAuditPayloadSchema,
  SessionScopedEnvelopeSchema,
  CreateSessionInputSchema,
  canonicalizeJson,
} from "@pactfuse/evidence-schema";
import type { Context } from "hono";
import type { ServiceCtx, ServiceResult } from "./types.js";
import {
  assembleReplayBundle,
  buildCawOperation,
  challengeSource,
  createSession,
  executeLease,
  getSession,
  ingestGateEvent,
  ingestCawReceiptBundle,
  indexChainWindow,
  issueArtifactAccessToken,
  listEventsAfterEventId,
  readAgentTranscript,
  readArtifactAccess,
  readChainIndexerStatus,
  readClaimReadiness,
  readJudgeCheck,
  readProofProviderStatus,
  readReplayPage,
  readRunnerHeartbeat,
  recordMcpAdapterAudit,
  previewVerifyEvidenceForSession,
  probeCawLiveIdentity,
  refundUndeliveredArtifact,
  registerSignedSource,
  registerSourceBoundSpends,
  runArtifactPreflight,
  signArtifactQuote,
  submitCawLivePact,
  submitCawLiveContractCall,
  submitCawLiveTransfer,
  syncCawLiveAudit,
  syncCawLivePact,
  verifyCawAllowance,
  verifyTokenBalanceDelta,
  verifyEvidenceForSession,
} from "./services/service.js";
import { badRequestError, forbiddenError, newRequestId, rateLimitedError, toApiError } from "./util.js";

const MAX_JSON_BODY_BYTES = 2 * 1024 * 1024;
type ApiRole = "operator" | "challenge_submitter" | "artifact_signer";

const ROUTES = [
  { method: "GET", path: "/healthz", okStatus: 200 },
  { method: "GET", path: "/readyz", okStatus: 200 },
  { method: "GET", path: "/api/v1/openapi.json", okStatus: 200 },
  { method: "POST", path: "/api/v1/sessions", okStatus: 201 },
  { method: "GET", path: "/api/v1/sessions/{sessionId}", okStatus: 200 },
  { method: "POST", path: "/api/v1/sources/register", okStatus: 201 },
  { method: "POST", path: "/api/v1/sources/challenge", okStatus: 202 },
  { method: "POST", path: "/api/v1/spends/register-batch", okStatus: 201 },
  { method: "POST", path: "/api/v1/caw/operations/build", okStatus: 201 },
  { method: "GET", path: "/api/v1/caw/live/status", okStatus: 200 },
  { method: "POST", path: "/api/v1/caw/live/identity/probe", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/pacts/submit", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/pacts/sync", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/transfers/submit", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/contracts/call", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/allowances/verify", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/live/audit/sync", okStatus: 202 },
  { method: "POST", path: "/api/v1/caw/receipts/ingest", okStatus: 202 },
  { method: "POST", path: "/api/v1/gate/events/ingest", okStatus: 202 },
  { method: "POST", path: "/api/v1/token/balance-deltas/verify", okStatus: 202 },
  { method: "POST", path: "/api/v1/indexer/backfill", okStatus: 202 },
  { method: "POST", path: "/api/v1/artifacts/preflight", okStatus: 202 },
  { method: "POST", path: "/api/v1/quotes", okStatus: 201 },
  { method: "POST", path: "/api/v1/artifacts/access-token", okStatus: 202 },
  { method: "GET", path: "/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}", okStatus: 200 },
  { method: "POST", path: "/api/v1/artifacts/refund", okStatus: 202 },
  { method: "POST", path: "/api/v1/lease/execute", okStatus: 202 },
  { method: "POST", path: "/api/v1/mcp/audit", okStatus: 202 },
  { method: "POST", path: "/api/v1/evidence/verify", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/{sessionId}/verify", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/judge-check", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/claim-readiness", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/replay-bundle", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/replay-page", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/indexer-status", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/runner-heartbeat", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/agent-transcript", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/stream", okStatus: 200 },
] as const;

const PROOF_FIELD_ROUTES: Record<string, string[]> = {
  "/api/v1/caw/receipts/ingest": ["proofAuthority", "winnerClaimAllowed"],
  "/api/v1/caw/live/pacts/submit": ["interactionId", "pactId", "requestHash", "responseHash", "proofAuthority", "winnerClaimAllowed"],
  "/api/v1/caw/live/identity/probe": ["walletId", "walletAddress", "identityMode", "pass", "proofAuthority", "winnerClaimAllowed"],
  "/api/v1/caw/live/pacts/sync": [
    "interactionId",
    "pactId",
    "policyDigest",
    "policySnapshotHash",
    "policyChainIds",
    "policyContractAddresses",
    "policySelectors",
    "policyRequestLimit",
    "policyExpiry",
    "requestHash",
    "responseHash",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/caw/live/transfers/submit": [
    "interactionId",
    "pactId",
    "spendId",
    "cawRequestId",
    "pactScopedApiKeyHash",
    "pactSyncInteractionId",
    "pactSyncEventId",
    "pactPolicyDigest",
    "pactPolicySnapshotHash",
    "paymentToken",
    "requestHash",
    "responseHash",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/caw/live/contracts/call": [
    "interactionId",
    "pactId",
    "spendId",
    "operationKind",
    "contractAddress",
    "selector",
    "cawRequestId",
    "txHash",
    "pactScopedApiKeyHash",
    "pactSyncInteractionId",
    "pactSyncEventId",
    "pactPolicyDigest",
    "pactPolicySnapshotHash",
    "requestHash",
    "responseHash",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/caw/live/allowances/verify": [
    "spendId",
    "approveInteractionId",
    "cawContractCallEventId",
    "approveTxHash",
    "auditUsageEventId",
    "auditInteractionId",
    "auditPolicyDigest",
    "auditLogHash",
    "paymentToken",
    "owner",
    "spender",
    "amountAtomic",
    "allowanceBefore",
    "allowanceAfter",
    "approvalRawLogHash",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/caw/live/audit/sync": [
    "interactionId",
    "requestHash",
    "responseHash",
    "usageEventIds",
    "usageCount",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/gate/events/ingest": ["finalityStatus", "confirmations", "finalityDepth", "proofAuthority", "winnerClaimAllowed"],
  "/api/v1/token/balance-deltas/verify": [
    "spendId",
    "allowanceEventId",
    "approveInteractionId",
    "approveTxHash",
    "activationEventId",
    "activateInteractionId",
    "activateTxHash",
	    "settlementEventId",
	    "txHash",
	    "chainProviderMode",
	    "chainProviderEndpoint",
	    "paymentToken",
    "agentWallet",
    "market",
    "amountAtomic",
    "agentWalletBefore",
    "agentWalletAfter",
    "marketBefore",
    "marketAfter",
    "proofAuthority",
    "winnerClaimAllowed",
  ],
  "/api/v1/indexer/backfill": ["cursor.status", "cursor.lastIndexedBlock", "insertedLogCount", "proofAuthority", "winnerClaimAllowed"],
  "/api/v1/artifacts/preflight": ["preflightId", "artifactHashPreview", "artifactCid", "priceDisclosureHash", "winnerClaimAllowed"],
  "/api/v1/quotes": ["preflightId", "artifactCid", "quoteSignedAfterPreflight", "priceDisclosureHash", "status", "chainId", "winnerClaimAllowed"],
  "/api/v1/artifacts/access-token": [
    "tokenId",
    "tokenHash",
    "quoteId",
    "preflightId",
    "artifactCid",
    "artifactPayloadHash",
    "verifierRunId",
    "settlementEventId",
    "bearerBound",
    "accessProofLevel",
    "proofChipAllowed",
    "finalVerifierComplete",
    "winnerClaimAllowed",
  ],
  "/api/v1/artifacts/refund": ["spendId", "quoteId", "status", "winnerClaimAllowed"],
  "/api/v1/lease/execute": [
    "leaseRunId",
    "bearerBound",
    "artifactHash",
    "transcriptHash",
    "leaseRunHash",
    "boundedToPinnedManifest",
    "manifestBindingHash",
    "winnerClaimAllowed",
  ],
  "/api/v1/mcp/audit": ["proofAuthority", "winnerClaimAllowed", "requestHash", "responseHash"],
  "/api/v1/evidence/verify": ["schemaOk", "proofChipAllowed", "winnerClaimAllowed", "finalVerifierComplete"],
  "/api/v1/evidence/judge-check": ["winnerClaimAllowed", "rows.status", "rows.authority"],
  "/api/v1/evidence/claim-readiness": [
    "claimMode",
    "paymentMode",
    "tokenMode",
    "identityMode",
    "targetClaimMode",
    "targetPaymentMode",
    "targetTokenMode",
    "targetIdentityMode",
    "winnerClaimAllowed",
    "finalVerifierComplete",
    "gates.status",
    "blockers",
  ],
  "/api/v1/evidence/replay-bundle": [
    "winnerClaimAllowed",
    "eventRoot",
    "fullReplayRoot",
    "mcpAdapterCalls",
    "cawReceiptOperations",
    "cawLiveInteractions",
    "rawCawReceiptBundles",
    "canonicalCawReceipts",
    "leaseRuns",
    "judgeCheck",
    "replayPages",
  ],
  "/api/v1/evidence/indexer-status": ["provider.ready", "cursors.status", "cursors.lagBlocks", "winnerClaimAllowed"],
  "/api/v1/evidence/runner-heartbeat": ["status", "latestLeaseRunId", "transcriptHash", "leaseRunHash", "winnerClaimAllowed"],
  "/api/v1/evidence/agent-transcript": ["transcriptHash", "toolsCallHash", "boundedToPinnedManifest", "winnerClaimAllowed"],
};

export function createApp(ctx: ServiceCtx): Hono {
  const app = new Hono();
  const rateBuckets = new Map<string, { count: number; resetAt: number }>();

  app.onError((error, c) => {
    const requestId = newRequestId("unhandled");
    const apiError = toApiError(error, requestId);
    ctx.logger.error({ error, requestId }, "unhandled API error");
    return c.json({ ok: false, requestId, error: apiError }, statusFor(apiError.code) as 400);
  });

  app.use("*", async (c, next) => {
    const now = Date.now();
    const client = c.req.header("x-forwarded-for") ?? c.req.header("cf-connecting-ip") ?? "local";
    const key = `${client}:${c.req.method}:${c.req.path}`;
    const limit = rateLimitMaxFor(ctx, c.req.method, c.req.path);
    const bucket = rateBuckets.get(key);
    const nextBucket =
      !bucket || bucket.resetAt <= now ? { count: 1, resetAt: now + ctx.apiSecurity.rateLimitWindowMs } : { ...bucket, count: bucket.count + 1 };
    rateBuckets.set(key, nextBucket);
    c.header("x-ratelimit-limit", String(limit));
    c.header("x-ratelimit-remaining", String(Math.max(0, limit - nextBucket.count)));
    if (nextBucket.count > limit) {
      const requestId = newRequestId("rate_limit");
      return c.json({ ok: false, requestId, error: rateLimitedError(requestId) }, 429);
    }
    await next();
  });

  app.get("/healthz", (c) =>
    c.json({
      ok: true,
      service: "pactfuse-api",
      modes: ctx.config,
    }),
  );

  app.get("/readyz", async (c) => {
    ctx.db.sqlite.prepare("SELECT 1").get();
    return c.json({
      ok: true,
      db: "ready",
      verifier: "fail-closed-scaffold",
      proofProviders: await readProofProviderStatus(ctx),
      apiSecurity: {
        mode: "fail-closed-unless-explicit-dev-bypass",
        operatorTokenConfigured: Boolean(ctx.apiSecurity.operatorToken),
        challengeSubmitterTokenConfigured: Boolean(ctx.apiSecurity.challengeSubmitterToken),
        artifactSignerTokenConfigured: Boolean(ctx.apiSecurity.artifactSignerToken),
        allowInsecureMissingRoleTokens: ctx.apiSecurity.allowInsecureMissingRoleTokens,
        rateLimitWindowMs: ctx.apiSecurity.rateLimitWindowMs,
        defaultRateLimitMax: ctx.apiSecurity.defaultRateLimitMax,
        sessionCreateRateLimitMax: ctx.apiSecurity.sessionCreateRateLimitMax,
        sourceChallengeRateLimitMax: ctx.apiSecurity.sourceChallengeRateLimitMax,
      },
      mcpAudit: {
        mode: "hmac-shared-secret",
        configured: Boolean(ctx.mcpAuditSecret),
      },
      gateIngest: {
        mode: "hmac-shared-secret",
        configured: Boolean(ctx.gateIngestSecret),
      },
      winnerClaimAllowed: false,
    });
  });

  app.get("/api/v1/openapi.json", (c) => c.json(buildOpenApi()));

  app.post("/api/v1/sessions", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await createSession(CreateSessionInputSchema.parse(await readJson(c)), ctx), 201);
  });

  app.get("/api/v1/sessions/:sessionId", async (c) => send(c, await getSession(c.req.param("sessionId"), ctx)));

  app.post("/api/v1/sources/register", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await registerSignedSource(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201);
  });

  app.post("/api/v1/sources/challenge", async (c) => {
    authorizeApiRole(c, ctx, "challenge_submitter");
    return send(c, await challengeSource(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/spends/register-batch", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await registerSourceBoundSpends(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201);
  });

  app.post("/api/v1/caw/operations/build", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await buildCawOperation(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201);
  });

  app.get("/api/v1/caw/live/status", async (c) => send(c, { ok: true, requestId: newRequestId("caw_live_status"), data: await ctx.cawLive.status() }));

  app.post("/api/v1/caw/live/identity/probe", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await probeCawLiveIdentity(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/caw/live/pacts/submit", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await submitCawLivePact(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/caw/live/pacts/sync", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await syncCawLivePact(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/caw/live/transfers/submit", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await submitCawLiveTransfer(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx, c.req.header("x-pactfuse-caw-pact-api-key") ?? null), 202);
  });

  app.post("/api/v1/caw/live/contracts/call", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await submitCawLiveContractCall(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx, c.req.header("x-pactfuse-caw-pact-api-key") ?? null), 202);
  });

  app.post("/api/v1/caw/live/allowances/verify", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await verifyCawAllowance(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/caw/live/audit/sync", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await syncCawLiveAudit(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/caw/receipts/ingest", async (c) => {
    authorizeCawReceiptIngest(c, ctx);
    return send(c, await ingestCawReceiptBundle(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/gate/events/ingest", async (c) => {
    const body = SessionScopedEnvelopeSchema.parse(await readJson(c));
    authorizeGateEventIngest(c, ctx, body);
    return send(c, await ingestGateEvent(body, ctx), 202);
  });

  app.post("/api/v1/token/balance-deltas/verify", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await verifyTokenBalanceDelta(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/indexer/backfill", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await indexChainWindow(ChainIndexerBackfillInputSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/artifacts/preflight", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await runArtifactPreflight(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/quotes", async (c) => {
    authorizeApiRole(c, ctx, "artifact_signer");
    return send(c, await signArtifactQuote(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201);
  });

  app.post("/api/v1/artifacts/access-token", async (c) => {
    authorizeApiRole(c, ctx, "artifact_signer");
    return send(c, await issueArtifactAccessToken(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.get("/api/v1/artifacts/:sessionId/:spendId/:payer/:artifactHash", async (c) => {
    const sessionId = Hex32Schema.parse(c.req.param("sessionId"));
    const spendId = Hex32Schema.parse(c.req.param("spendId"));
    const payer = HexSchema.parse(c.req.param("payer"));
    const artifactHash = Hex32Schema.parse(c.req.param("artifactHash"));
    return send(c, await readArtifactAccess({ sessionId, spendId, payer, artifactHash, bearerToken: bearerTokenFor(c) }, ctx));
  });

  app.post("/api/v1/artifacts/refund", async (c) => {
    authorizeApiRole(c, ctx, "artifact_signer");
    return send(c, await refundUndeliveredArtifact(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/lease/execute", async (c) =>
    send(c, await executeLease(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx, bearerTokenFor(c)), 202),
  );

  app.post("/api/v1/mcp/audit", async (c) =>
    send(c, recordMcpAdapterAudit(authorizeMcpAudit(c, ctx, McpAdapterAuditPayloadSchema.parse(await readJson(c))), ctx), 202),
  );

  app.post("/api/v1/evidence/verify", async (c) => {
    authorizeApiRole(c, ctx, "operator");
    return send(c, await verifyEvidenceForSession(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 200);
  });

  app.get("/api/v1/evidence/:sessionId/verify", async (c) => send(c, await previewVerifyEvidenceForSession(c.req.param("sessionId"), ctx)));

  app.get("/api/v1/evidence/judge-check", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await readJudgeCheck(sessionId, ctx));
  });

  app.get("/api/v1/evidence/claim-readiness", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await readClaimReadiness(sessionId, ctx));
  });

  app.get("/api/v1/evidence/replay-bundle", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await assembleReplayBundle(sessionId, ctx));
  });

  app.get("/api/v1/evidence/replay-page", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    const collection = requiredQuery(c, "collection");
    const page = requiredQuery(c, "page");
    return send(c, await readReplayPage({ sessionId, collection, page }, ctx));
  });

  app.get("/api/v1/evidence/indexer-status", async (c) => send(c, await readChainIndexerStatus(ctx)));

  app.get("/api/v1/evidence/runner-heartbeat", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await readRunnerHeartbeat(sessionId, ctx));
  });

  app.get("/api/v1/evidence/agent-transcript", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await readAgentTranscript(sessionId, ctx));
  });

  app.get("/api/v1/evidence/stream", (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    const afterEventId = c.req.query("afterEventId") ?? null;
    const events = listEventsAfterEventId(ctx, sessionId, afterEventId);
    return streamSSE(c, async (stream) => {
      for (const event of events) {
        await stream.writeSSE({
          id: event.eventId,
          event: event.kind,
          data: JSON.stringify(event),
        });
      }
    });
  });

  return app;
}

async function readJson(c: Context): Promise<unknown> {
  const contentLength = c.req.header("content-length");
  if (contentLength && Number(contentLength) > MAX_JSON_BODY_BYTES) {
    throwBadRequest("request body exceeds the 2 MiB limit", { contentLength });
  }
  const text = await c.req.text();
  if (Buffer.byteLength(text, "utf8") > MAX_JSON_BODY_BYTES) {
    throwBadRequest("request body exceeds the 2 MiB limit");
  }
  if (text.trim() === "") {
    return {};
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throwBadRequest("request body must be valid JSON");
  }
}

function requiredQuery(c: Context, name: string): string {
  const value = c.req.query(name);
  if (!value) {
    throwBadRequest(`missing query parameter: ${name}`);
  }
  return value;
}

function bearerTokenFor(c: Context): string | null {
  const authorization = c.req.header("authorization") ?? "";
  return authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : null;
}

function throwBadRequest(message: string, details?: Record<string, unknown>): never {
  const requestId = newRequestId("bad_request");
  throw Object.assign(new Error(message), { apiError: badRequestError(requestId, message, details) });
}

function rateLimitMaxFor(ctx: ServiceCtx, method: string, path: string): number {
  if (method === "POST" && path === "/api/v1/sessions") {
    return ctx.apiSecurity.sessionCreateRateLimitMax;
  }
  if (method === "POST" && path === "/api/v1/sources/challenge") {
    return ctx.apiSecurity.sourceChallengeRateLimitMax;
  }
  return ctx.apiSecurity.defaultRateLimitMax;
}

function authorizeApiRole(c: Context, ctx: ServiceCtx, role: ApiRole): void {
  const token = tokenForRole(ctx, role);
  if (!token) {
    if (ctx.apiSecurity.allowInsecureMissingRoleTokens) {
      return;
    }
    const requestId = newRequestId(`${role}_auth_config`);
    throw Object.assign(new Error(`${role} token is not configured`), {
      apiError: forbiddenError(requestId, `${role} bearer token is not configured`),
    });
  }
  const requestId = newRequestId(`${role}_auth`);
  const bearer = bearerTokenFor(c);
  if (!bearer || !secureEqualText(bearer, token)) {
    throw Object.assign(new Error(`${role} token is invalid`), {
      apiError: forbiddenError(requestId, `${role} bearer token is invalid`),
    });
  }
}

function tokenForRole(ctx: ServiceCtx, role: ApiRole): string | null {
  if (role === "challenge_submitter") {
    return ctx.apiSecurity.challengeSubmitterToken ?? ctx.apiSecurity.operatorToken;
  }
  if (role === "artifact_signer") {
    return ctx.apiSecurity.artifactSignerToken ?? ctx.apiSecurity.operatorToken;
  }
  return ctx.apiSecurity.operatorToken;
}

function authorizeMcpAudit(c: Context, ctx: ServiceCtx, payload: unknown): unknown {
  const requestId = newRequestId("mcp_audit_auth");
  const secret = ctx.mcpAuditSecret;
  const signature = c.req.header("x-pactfuse-audit-signature") ?? "";
  if (!secret) {
    throw Object.assign(new Error("MCP audit token is not configured"), {
      apiError: forbiddenError(requestId, "MCP audit token is not configured"),
    });
  }
  if (!signature || !secureEqualHex(signature, signMcpAuditPayload(secret, payload))) {
    throw Object.assign(new Error("MCP audit token is invalid"), {
      apiError: forbiddenError(requestId, "MCP audit signature is invalid"),
    });
  }
  return payload;
}

function authorizeGateEventIngest(c: Context, ctx: ServiceCtx, payload: unknown): void {
  const requestId = newRequestId("gate_event_auth");
  const secret = ctx.gateIngestSecret;
  const signature = c.req.header("x-pactfuse-gate-signature") ?? "";
  if (!secret) {
    throw Object.assign(new Error("Gate event ingest token is not configured"), {
      apiError: forbiddenError(requestId, "Gate event ingest token is not configured"),
    });
  }
  if (!signature || !secureEqualHex(signature, signMcpAuditPayload(secret, payload))) {
    throw Object.assign(new Error("Gate event ingest token is invalid"), {
      apiError: forbiddenError(requestId, "Gate event ingest signature is invalid"),
    });
  }
}

function authorizeCawReceiptIngest(c: Context, ctx: ServiceCtx): void {
  const token = ctx.cawIngestToken;
  const requestId = newRequestId("caw_ingest_auth");
  if (!token) {
    throw Object.assign(new Error("CAW receipt ingest token is not configured"), {
      apiError: forbiddenError(requestId, "CAW receipt ingest token is not configured"),
    });
  }
  const bearer = bearerTokenFor(c);
  if (!bearer || !secureEqualText(bearer, token)) {
    throw Object.assign(new Error("CAW receipt ingest token is invalid"), {
      apiError: forbiddenError(requestId, "CAW receipt ingest token is invalid"),
    });
  }
}

function signMcpAuditPayload(secret: string, payload: unknown): `0x${string}` {
  return `0x${createHmac("sha256", secret).update(canonicalizeJson(payload)).digest("hex")}`;
}

function secureEqualText(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function secureEqualHex(left: string, right: string): boolean {
  if (!/^0x[0-9a-fA-F]{64}$/.test(left) || !/^0x[0-9a-fA-F]{64}$/.test(right)) {
    return false;
  }
  const leftBuffer = Buffer.from(left.slice(2), "hex");
  const rightBuffer = Buffer.from(right.slice(2), "hex");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function send<T>(c: Context, result: ServiceResult<T>, okStatus = 200): Response {
  if (result.ok) {
    return c.json(result, okStatus as 200);
  }
  const status = statusFor(result.error.code);
  return c.json(result, status as 400);
}

function statusFor(code: string): number {
  switch (code) {
    case "bad_request":
      return 400;
    case "unauthorized":
      return 401;
    case "forbidden":
      return 403;
    case "not_found":
      return 404;
    case "idempotency_conflict":
      return 409;
    case "proof_pending":
      return 423;
    case "proof_blocked":
    case "verifier_failed_closed":
    case "mode_locked":
      return 422;
    case "rate_limited":
      return 429;
    default:
      return 500;
  }
}

function buildOpenApi(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const { method, path, okStatus } of ROUTES) {
    const proofFields = PROOF_FIELD_ROUTES[path] ?? [];
    const requestBody = requestBodySchemaFor(method, path);
    const parameters = parameterSchemaFor(path);
    paths[path] = {
      ...(paths[path] ?? {}),
      [method.toLowerCase()]: {
        operationId: `${method.toLowerCase()}_${path.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
        ...(parameters.length > 0 ? { parameters } : {}),
        ...(requestBody ? { requestBody } : {}),
        ...(proofFields.length > 0
          ? {
              "x-pactfuse-proof-fields": proofFields,
              "x-pactfuse-proof-authority": "fail-closed",
            }
          : {}),
        responses: {
          [String(okStatus)]: {
            description: "PactFuse fail-closed P0 response",
            content: {
              "application/json": {
                schema: responseSchemaFor(path),
              },
            },
          },
        },
      },
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "PactFuse API",
      version: "0.0.0-p0",
      description: "Generated from the P0 route registry and shared strict schemas. Proof authority remains fail-closed.",
    },
    paths,
    components: {
      schemas: {
        ApiError: {
          type: "object",
          required: ["code", "message", "requestId", "retryable", "downgrade"],
          properties: {
            code: { type: "string" },
            message: { type: "string" },
            requestId: { type: "string" },
            retryable: { type: "boolean" },
            downgrade: { enum: ["pending", "blocked", "failed", "none"] },
          },
        },
        CreateSessionInput: {
          type: "object",
          required: ["idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: {
              type: "object",
              additionalProperties: false,
              properties: {
                label: { type: "string", minLength: 1, maxLength: 120 },
                targetRepo: { type: "string", minLength: 1, maxLength: 400 },
                targetCommit: { type: "string", minLength: 6, maxLength: 128 },
                authorizedQuoteSignerSetHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                finalityDepth: { type: "integer", minimum: 1, maximum: 128, default: 2 },
                modes: { $ref: "#/components/schemas/RuntimeModes" },
                metadata: { type: "object", additionalProperties: true, default: {} },
              },
            },
          },
        },
        RuntimeModes: {
          type: "object",
          required: ["CLAIM_MODE", "PAYMENT_MODE", "TOKEN_MODE", "IDENTITY_MODE", "WINNER_CLAIM_ALLOWED"],
          additionalProperties: false,
          properties: {
            CLAIM_MODE: { const: "simulated" },
            PAYMENT_MODE: { const: "mocked" },
            TOKEN_MODE: { const: "local-mocked" },
            IDENTITY_MODE: { const: "pending" },
            WINNER_CLAIM_ALLOWED: { const: false },
          },
        },
        SessionScopedEnvelope: {
          type: "object",
          required: ["sessionId", "idempotencyKey"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { type: "object", additionalProperties: true },
          },
        },
        SourceRegisterInput: sessionEnvelopeSchema("#/components/schemas/SourceRegisterPayload"),
        SourceRegisterPayload: {
          type: "object",
          required: ["sourceId", "sourceHash", "manifestUrl", "manifestHash"],
          additionalProperties: false,
          properties: {
            sourceId: { type: "string", minLength: 1, maxLength: 120 },
            sourceHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            manifestUrl: { type: "string", minLength: 1, maxLength: 500 },
            manifestHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            issuer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            signature: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            capabilityVector: { type: "object", additionalProperties: true, default: {} },
          },
        },
        SourceChallengeInput: sessionEnvelopeSchema("#/components/schemas/SourceChallengePayload"),
        SourceChallengePayload: {
          type: "object",
          required: ["sourceHash", "reasonHash"],
          additionalProperties: false,
          properties: {
            sourceHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            reasonHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            evidenceRef: { type: "string", minLength: 1, maxLength: 500 },
          },
        },
        SpendRegisterBatchInput: sessionEnvelopeSchema("#/components/schemas/SpendRegisterPayload"),
        SpendRegisterPayload: {
          type: "object",
          required: ["spends"],
          additionalProperties: false,
          properties: {
            spends: {
              type: "array",
              minItems: 1,
              maxItems: 32,
              items: {
                type: "object",
                required: [
                  "spendId",
                  "pactId",
                  "toolId",
                  "payer",
                  "agentWallet",
                  "paymentToken",
                  "artifactHash",
                  "market",
                  "sourceHashes",
                  "maxPriceAtomic",
                  "nonce",
                ],
                additionalProperties: false,
                properties: {
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  pactId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  toolId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  payer: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  agentWallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  paymentToken: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  market: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  sourceHashes: {
                    type: "array",
                    minItems: 1,
                    maxItems: 16,
                    items: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  },
                  maxPriceAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  nonce: { type: "string", minLength: 1, maxLength: 128 },
                },
              },
            },
          },
        },
        CawOperationBuildInput: sessionEnvelopeSchema("#/components/schemas/CawOperationBuildPayload"),
        CawOperationBuildPayload: {
          type: "object",
          required: ["spendId", "operationKind"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            operationKind: { enum: ["deny_probe", "approve", "activate_tool"] },
            target: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            selector: { type: "string", pattern: "^0x[0-9a-fA-F]{8}$" },
            valueAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$", default: "0" },
          },
        },
        CawReceiptIngestInput: sessionEnvelopeSchema("#/components/schemas/CawReceiptIngestPayload"),
        CawReceiptIngestPayload: {
          type: "object",
          required: ["sourceLabel"],
          additionalProperties: false,
          properties: {
            sourceLabel: { type: "string", minLength: 1, maxLength: 120 },
            operationId: { type: "string", minLength: 1, maxLength: 160 },
            receipts: { type: "array", maxItems: 64, items: { type: "object", additionalProperties: true }, default: [] },
            manual: { type: "boolean", default: false },
          },
        },
        CawLiveIdentityProbeInput: sessionEnvelopeSchema("#/components/schemas/CawLiveIdentityProbePayload"),
        CawLiveIdentityProbePayload: {
          type: "object",
          required: ["walletId"],
          additionalProperties: false,
          properties: {
            walletId: { type: "string", minLength: 1, maxLength: 160 },
            expectedWalletAddress: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            identityMode: { enum: ["p0-floor-one-wallet", "p0-win-separate-identities"], default: "p0-floor-one-wallet" },
          },
        },
        CawLiveIdentityProbeResponse: serviceResponseSchema({
          type: "object",
          required: ["walletId", "walletAddress", "identityMode", "pass", "proofAuthority", "winnerClaimAllowed"],
          properties: {
            walletId: { type: "string" },
            walletAddress: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{40}$" }, { type: "null" }] },
            identityMode: { enum: ["p0-floor-one-wallet", "p0-win-separate-identities"] },
            pass: { type: "boolean" },
            proofAuthority: { type: "boolean" },
            winnerClaimAllowed: { type: "boolean" },
          },
        }),
        CawLiveContractCallInput: sessionEnvelopeSchema("#/components/schemas/CawLiveContractCallPayload"),
        CawLiveContractCallPayload: {
          type: "object",
          required: ["spendId", "operationKind", "pactId", "walletId", "chainId", "contractAddress", "calldata"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            operationKind: { enum: ["approve", "activate_tool"] },
            pactId: { type: "string", minLength: 1, maxLength: 160 },
            walletId: { type: "string", minLength: 1, maxLength: 160 },
            chainId: { type: "string", minLength: 1, maxLength: 80 },
            contractAddress: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            calldata: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            valueAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$", default: "0" },
            procurementGateAddress: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
            requestId: { type: "string", minLength: 1, maxLength: 160 },
            sponsor: { type: "boolean" },
            gasProvider: { type: "string", minLength: 1, maxLength: 120 },
            description: { type: "string", minLength: 1, maxLength: 240 },
            fee: { anyOf: [{ type: "object", additionalProperties: true }, { type: "null" }] },
          },
        },
        CawAllowanceVerifyInput: sessionEnvelopeSchema("#/components/schemas/CawAllowanceVerifyPayload"),
        CawAllowanceVerifyPayload: {
          type: "object",
          required: ["spendId"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            approveInteractionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
          },
        },
        CawLiveAuditSyncInput: sessionEnvelopeSchema("#/components/schemas/CawLiveAuditSyncPayload"),
        CawLiveAuditSyncPayload: {
          type: "object",
          additionalProperties: false,
          properties: {
            walletId: { type: "string", minLength: 1, maxLength: 160 },
            principalId: { type: "string", minLength: 1, maxLength: 160 },
            action: { type: "string", minLength: 1, maxLength: 160 },
            result: { enum: ["allowed", "denied", "pending", "error"] },
            startTime: { type: "string", format: "date-time" },
            endTime: { type: "string", format: "date-time" },
            after: { type: "string", minLength: 1, maxLength: 500 },
            before: { type: "string", minLength: 1, maxLength: 500 },
            limit: { type: "integer", minimum: 1, maximum: 200, default: 50 },
          },
        },
        TokenBalanceDeltaVerifyInput: sessionEnvelopeSchema("#/components/schemas/TokenBalanceDeltaVerifyPayload"),
        TokenBalanceDeltaVerifyPayload: {
          type: "object",
          required: ["spendId"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            settlementEventId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
          },
        },
        ArtifactPreflightInput: sessionEnvelopeSchema("#/components/schemas/ArtifactPreflightPayload"),
        ArtifactPreflightPayload: {
          type: "object",
          required: ["spendId", "artifactHashPreview", "artifactCid", "endpointUrl", "priceDisclosureHash", "sourceStateSnapshotHash"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHashPreview: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
            endpointUrl: { type: "string", minLength: 1, maxLength: 500 },
            priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
          },
        },
        QuoteInput: sessionEnvelopeSchema("#/components/schemas/QuotePayload"),
        QuotePayload: {
          type: "object",
          required: ["spendId", "preflightId", "artifactCommitment", "priceAtomic", "quoteNonce", "validUntilBlock"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCommitment: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            priceAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
            quoteNonce: { type: "string", minLength: 1, maxLength: 128 },
            validUntilBlock: { type: "string", pattern: "^[0-9]+$" },
            settlementMode: {
              enum: ["mocked_after_preflight_not_chain_settleable", "chain_settleable_after_preflight"],
              default: "mocked_after_preflight_not_chain_settleable",
            },
          },
        },
        LeaseExecuteInput: {
          type: "object",
          required: ["sessionId", "idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { $ref: "#/components/schemas/LeaseExecutePayload" },
          },
        },
        LeaseExecutePayload: {
          type: "object",
          required: ["spendId", "payer", "artifactHash", "targetRepo", "targetCommit"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            targetRepo: { type: "string", minLength: 1, maxLength: 500 },
            targetCommit: { type: "string", minLength: 6, maxLength: 128 },
          },
        },
        GateEventIngestInput: {
          type: "object",
          required: ["sessionId", "idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { $ref: "#/components/schemas/GateEventIngestPayload" },
          },
        },
        GateEventIngestPayload: {
          type: "object",
          required: ["event", "spendId", "txHash", "logIndex", "chainId", "blockNumber", "currentBlockNumber", "rawLogHash"],
          additionalProperties: false,
          properties: {
            event: { enum: ["SpendTripped", "SpendSettled"] },
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            txHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            logIndex: { type: "integer", minimum: 0, maximum: 1_000_000 },
            chainId: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
            blockNumber: { type: "integer", minimum: 0 },
            currentBlockNumber: { type: "integer", minimum: 0 },
            rawLogHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            reorged: { type: "boolean", default: false },
          },
        },
        ChainIndexerBackfillInput: {
          type: "object",
          required: ["idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { $ref: "#/components/schemas/ChainIndexerBackfillPayload" },
          },
        },
        ChainIndexerBackfillPayload: {
          type: "object",
          required: ["cursorId", "chainId"],
          additionalProperties: false,
          properties: {
            cursorId: { type: "string", minLength: 1, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            chainId: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
            fromBlock: { type: "integer", minimum: 0 },
            toBlock: { type: "integer", minimum: 0 },
            finalityDepth: { type: "integer", minimum: 1, maximum: 128, default: 2 },
            maxWindowBlocks: { type: "integer", minimum: 1, maximum: 10000, default: 2000 },
            address: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            topics: {
              type: "array",
              maxItems: 4,
              items: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
            },
          },
        },
        VerifyEvidenceInput: sessionEnvelopeSchema("#/components/schemas/VerifyEvidencePayload"),
        VerifyEvidencePayload: {
          type: "object",
          additionalProperties: false,
          properties: {
            receipt: { type: "object", additionalProperties: true },
            replayBundle: { type: "object", additionalProperties: true },
            schemaOnly: { type: "boolean", default: false },
          },
        },
        ChainIndexerCursor: {
          type: "object",
          required: [
            "cursorId",
            "chainId",
            "address",
            "topics",
            "lastIndexedBlock",
            "latestHeadBlock",
            "finalizedHeadBlock",
            "finalityDepth",
            "lagBlocks",
            "status",
            "reason",
            "updatedAt",
          ],
          properties: {
            cursorId: { type: "string" },
            chainId: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
            address: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
            topics: {
              type: "array",
              maxItems: 4,
              items: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
            },
            lastIndexedBlock: { anyOf: [{ type: "integer", minimum: 0 }, { type: "null" }] },
            latestHeadBlock: { type: "integer", minimum: 0 },
            finalizedHeadBlock: { type: "integer", minimum: 0 },
            finalityDepth: { type: "integer", minimum: 1, maximum: 128 },
            lagBlocks: { type: "integer", minimum: 0 },
            status: { enum: ["unconfigured", "degraded", "caught_up"] },
            reason: { type: "string" },
            updatedAt: { type: "string", format: "date-time" },
          },
        },
        McpAdapterAuditPayload: {
          type: "object",
          required: ["auditNonce", "toolName", "request", "response", "status"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            auditNonce: { type: "string", minLength: 12, maxLength: 160, pattern: "^[a-zA-Z0-9:_-]+$" },
            toolName: { type: "string", minLength: 1, maxLength: 160 },
            request: { type: "object", additionalProperties: true },
            response: { type: "object", additionalProperties: true },
            status: { enum: ["succeeded", "failed", "blocked"] },
          },
        },
        ServiceError: {
          type: "object",
          required: ["ok", "requestId", "error"],
          properties: {
            ok: { const: false },
            requestId: { type: "string" },
            error: { $ref: "#/components/schemas/ApiError" },
          },
        },
        FailClosedProofState: {
          type: "object",
          required: [
            "proofLevel",
            "claimMode",
            "paymentMode",
            "tokenMode",
            "identityMode",
            "proofChipAllowed",
            "winnerClaimAllowed",
            "finalVerifierComplete",
          ],
          properties: {
            proofLevel: { enum: ["schema_only_no_claim", "fail_closed_no_claim", "final_replay_claim"] },
            claimMode: { enum: ["simulated", "caw-target-real", "caw-stable-params-real"] },
            paymentMode: { enum: ["mocked", "gate-paid-artifact-real", "permit-payment-real"] },
            tokenMode: { enum: ["local-mocked", "mock-test-token", "official-testnet-usdc"] },
            identityMode: { enum: ["pending", "p0-floor-one-wallet", "p0-win-separate-identities"] },
            schemaOk: { type: "boolean" },
            proofAuthority: { type: "boolean" },
            proofChipAllowed: { type: "boolean" },
            winnerClaimAllowed: { type: "boolean" },
            finalVerifierComplete: { type: "boolean" },
          },
        },
        VerifierRunResponse: serviceResponseSchema({
          allOf: [{ $ref: "#/components/schemas/FailClosedProofState" }],
        }),
        ClaimReadinessResponse: serviceResponseSchema({
          type: "object",
          required: [
            "sessionId",
            "claimMode",
            "paymentMode",
            "tokenMode",
            "identityMode",
            "targetClaimMode",
            "targetPaymentMode",
            "targetTokenMode",
            "targetIdentityMode",
            "proofChipAllowed",
            "finalVerifierComplete",
            "winnerClaimAllowed",
            "gates",
            "blockers",
            "requiredExternalInputs",
            "replayBundleHash",
            "verifierRun",
          ],
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            claimMode: { enum: ["simulated", "caw-target-real", "caw-stable-params-real"] },
            paymentMode: { enum: ["mocked", "gate-paid-artifact-real", "permit-payment-real"] },
            tokenMode: { enum: ["local-mocked", "mock-test-token", "official-testnet-usdc"] },
            identityMode: { enum: ["pending", "p0-floor-one-wallet", "p0-win-separate-identities"] },
            targetClaimMode: { anyOf: [{ enum: ["simulated", "caw-target-real", "caw-stable-params-real"] }, { type: "null" }] },
            targetPaymentMode: { anyOf: [{ enum: ["mocked", "gate-paid-artifact-real", "permit-payment-real"] }, { type: "null" }] },
            targetTokenMode: { anyOf: [{ enum: ["local-mocked", "mock-test-token", "official-testnet-usdc"] }, { type: "null" }] },
            targetIdentityMode: { anyOf: [{ enum: ["pending", "p0-floor-one-wallet", "p0-win-separate-identities"] }, { type: "null" }] },
            proofChipAllowed: { type: "boolean" },
            finalVerifierComplete: { type: "boolean" },
            winnerClaimAllowed: { type: "boolean" },
            gates: {
              type: "array",
              items: {
                type: "object",
                required: ["gateId", "label", "status", "blocks", "reason", "evidenceEventId"],
                properties: {
                  gateId: { type: "string" },
                  label: { type: "string" },
                  status: { enum: ["pass", "pending", "blocked"] },
                  blocks: {
                    type: "array",
                    items: { enum: ["claimMode", "paymentMode", "tokenMode", "identityMode", "winnerClaimAllowed"] },
                    minItems: 1,
                  },
                  reason: { type: "string" },
                  evidenceEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                },
              },
            },
            blockers: { type: "array", items: { type: "string" } },
            requiredExternalInputs: { type: "array", items: { type: "string" } },
            replayBundleHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            verifierRun: { $ref: "#/components/schemas/FailClosedProofState" },
          },
        }),
        JudgeCheckData: {
          type: "object",
          required: ["winnerClaimAllowed", "rows"],
          properties: {
            winnerClaimAllowed: { const: false },
            rows: {
              type: "array",
              items: {
                type: "object",
                required: ["status", "authority"],
                properties: {
                  status: { enum: ["pending", "pass", "fail", "blocked", "fixture", "manual"] },
                  authority: { enum: ["proof", "delivery", "operator", "advisory", "fixture"] },
                },
              },
            },
          },
        },
        JudgeCheckResponse: serviceResponseSchema({
          $ref: "#/components/schemas/JudgeCheckData",
        }),
        CawReceiptIngestResponse: serviceResponseSchema({
          type: "object",
          required: [
            "receiptBundleHash",
            "operationId",
            "receiptCount",
            "canonicalReceiptCount",
            "status",
            "proofAuthority",
            "winnerClaimAllowed",
          ],
          properties: {
            receiptBundleHash: { type: "string" },
            rawReceiptBundleHash: { type: "string" },
            operationId: { anyOf: [{ type: "string" }, { type: "null" }] },
            receiptCount: { type: "integer", minimum: 1, maximum: 64 },
            canonicalReceiptCount: { type: "integer", minimum: 0, maximum: 64 },
            status: { enum: ["fixture_manual_receipt", "raw_ingested_pending_proof", "verified_policy_authority_structural"] },
            proofAuthority: { type: "boolean" },
            winnerClaimAllowed: { const: false },
          },
        }),
        GateEventIngestResponse: serviceResponseSchema({
          type: "object",
          required: [
            "gateEventId",
            "spendId",
            "event",
            "finalityStatus",
            "confirmations",
            "finalityDepth",
            "proofAuthority",
            "winnerClaimAllowed",
          ],
          properties: {
            gateEventId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            event: { enum: ["SpendTripped", "SpendSettled"] },
            finalityStatus: { enum: ["observed_finalizing", "finalized", "reorg_invalidated"] },
            confirmations: { type: "integer", minimum: 0 },
            finalityDepth: { type: "integer", minimum: 1, maximum: 128 },
            observedEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            finalizedEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            reorgEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            invalidatedEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            proofAuthority: { type: "boolean" },
            winnerClaimAllowed: { const: false },
          },
        }),
        ChainIndexerBackfillResponse: serviceResponseSchema({
          type: "object",
          required: ["cursor", "fromBlock", "toBlock", "indexedLogCount", "insertedLogCount", "proofAuthority", "winnerClaimAllowed"],
          properties: {
            cursor: { $ref: "#/components/schemas/ChainIndexerCursor" },
            fromBlock: { type: "integer", minimum: 0 },
            toBlock: { type: "integer", minimum: 0 },
            indexedLogCount: { type: "integer", minimum: 0 },
            insertedLogCount: { type: "integer", minimum: 0 },
            proofAuthority: { const: false },
            winnerClaimAllowed: { const: false },
          },
        }),
        ChainIndexerStatusResponse: serviceResponseSchema({
          type: "object",
          required: ["provider", "cursors", "proofAuthority", "winnerClaimAllowed"],
          properties: {
            provider: { type: "object", additionalProperties: true },
            cursors: {
              type: "array",
              items: { $ref: "#/components/schemas/ChainIndexerCursor" },
            },
            proofAuthority: { const: false },
            winnerClaimAllowed: { const: false },
          },
        }),
        ArtifactPreflightResponse: serviceResponseSchema({
          type: "object",
          required: [
            "preflightId",
            "artifactHashPreview",
            "artifactCid",
            "priceDisclosureHash",
            "sourceStateSnapshotHash",
            "status",
            "winnerClaimAllowed",
          ],
          properties: {
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHashPreview: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
            priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            status: { enum: ["pending_live_delivery"] },
            winnerClaimAllowed: { const: false },
          },
        }),
        QuoteResponse: serviceResponseSchema({
          type: "object",
          required: [
            "quoteId",
            "quoteHash",
            "preflightId",
            "artifactCid",
            "priceDisclosureHash",
            "sourceStateSnapshotHash",
            "quoteSignedAfterPreflight",
            "status",
            "chainId",
            "winnerClaimAllowed",
          ],
          properties: {
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
            priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteSignedAfterPreflight: { const: true },
            status: { enum: ["mocked_after_preflight_not_chain_settleable", "chain_settleable_after_preflight"] },
            chainId: { type: ["string", "null"] },
            winnerClaimAllowed: { const: false },
          },
        }),
        ArtifactAccessIssueInput: {
          type: "object",
          required: ["sessionId", "idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { $ref: "#/components/schemas/ArtifactAccessIssuePayload" },
          },
        },
        ArtifactAccessIssuePayload: {
          type: "object",
          required: ["spendId", "payer", "quoteId", "artifactHash", "artifactPayload"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactPayload: { type: "object", additionalProperties: true },
          },
        },
        ArtifactAccessIssueResponse: serviceResponseSchema({
          type: "object",
          required: [
            "tokenId",
            "accessToken",
            "tokenHash",
            "spendId",
            "payer",
            "quoteId",
            "preflightId",
            "artifactHash",
            "artifactCid",
            "artifactPayloadHash",
            "verifierRunId",
            "settlementEventId",
            "bearerBound",
            "accessProofLevel",
            "proofChipAllowed",
            "finalVerifierComplete",
            "status",
            "proofAuthority",
            "winnerClaimAllowed",
          ],
          properties: {
            tokenId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            accessToken: { type: "string", pattern: "^pf_at_[0-9a-fA-F]{64}$" },
            tokenHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
            artifactPayloadHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            verifierRunId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            settlementEventId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            bearerBound: { const: true },
            accessProofLevel: { const: "delivery_access_only" },
            proofChipAllowed: { const: false },
            finalVerifierComplete: { const: false },
            status: { enum: ["active_demo_verifier_gated"] },
            proofAuthority: { const: false },
            winnerClaimAllowed: { const: false },
          },
        }),
        ArtifactAccessReadResponse: serviceResponseSchema({
          type: "object",
          required: [
            "sessionId",
            "spendId",
            "artifactHash",
            "artifactCid",
            "artifactPayloadHash",
            "artifactPayload",
            "status",
            "winnerClaimAllowed",
          ],
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
            artifactPayloadHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactPayload: { type: "object", additionalProperties: true },
            status: { enum: ["available"] },
            winnerClaimAllowed: { const: false },
          },
        }),
        ArtifactRefundInput: {
          type: "object",
          required: ["sessionId", "idempotencyKey", "payload"],
          additionalProperties: false,
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
            payload: { $ref: "#/components/schemas/ArtifactRefundPayload" },
          },
        },
        ArtifactRefundPayload: {
          type: "object",
          required: ["spendId", "quoteId", "reason"],
          additionalProperties: false,
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            reason: { type: "string", minLength: 1, maxLength: 240 },
          },
        },
        ArtifactRefundResponse: serviceResponseSchema({
          type: "object",
          required: ["spendId", "quoteId", "preflightId", "status", "winnerClaimAllowed"],
          properties: {
            spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            status: { enum: ["pending_live_settlement"] },
            winnerClaimAllowed: { const: false },
          },
        }),
        LeaseExecuteResponse: serviceResponseSchema({
          type: "object",
          required: [
            "leaseRunId",
            "payer",
            "artifactHash",
            "bearerBound",
            "transcriptHash",
            "toolsListHash",
            "toolsCallHash",
            "outputHash",
            "leaseRunHash",
            "boundedToPinnedManifest",
            "manifestBindingHash",
            "settlementEventId",
            "status",
            "winnerClaimAllowed",
          ],
          properties: {
            leaseRunId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            bearerBound: { const: true },
            transcriptHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            toolsListHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            toolsCallHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            outputHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            leaseRunHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            boundedToPinnedManifest: { type: "boolean" },
            manifestBindingHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            settlementEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            status: { enum: ["blocked_missing_runner_execution", "blocked_mcp_execution_failed", "succeeded_live_mcp_transcript"] },
            winnerClaimAllowed: { const: false },
          },
        }),
        RunnerHeartbeatResponse: serviceResponseSchema({
          type: "object",
          required: [
            "sessionId",
            "status",
            "latestLeaseRunId",
            "transcriptHash",
            "leaseRunHash",
            "winnerClaimAllowed",
            "updatedAt",
          ],
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            status: { enum: ["pending", "blocked", "idle", "lease_executed"] },
            latestLeaseRunId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            transcriptHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            leaseRunHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            winnerClaimAllowed: { const: false },
            updatedAt: { type: "string", format: "date-time" },
          },
        }),
        McpAuditResponse: serviceResponseSchema({
          type: "object",
          required: ["callId", "requestHash", "responseHash", "proofAuthority", "winnerClaimAllowed"],
          properties: {
            callId: { type: "string" },
            requestHash: { type: "string" },
            responseHash: { type: "string" },
            proofAuthority: { const: false },
            winnerClaimAllowed: { const: false },
          },
        }),
        ReplayBundleResponse: serviceResponseSchema({
          type: "object",
          required: [
            "bundleType",
            "sessionId",
            "summaryMode",
            "asOfEventSeq",
            "asOfMcpAdapterCallCount",
            "winnerClaimAllowed",
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
          ],
          properties: {
            bundleType: { const: "PACTFUSE_EVIDENCE_V1" },
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            summaryMode: { const: true },
            asOfEventSeq: { type: "integer", minimum: 0, maximum: 200 },
            asOfMcpAdapterCallCount: { type: "integer", minimum: 0, maximum: 200 },
            winnerClaimAllowed: { const: false },
            eventRoot: { type: "string" },
            agentTranscriptHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            fullReplayRoot: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            events: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "sessionId",
                  "eventId",
                  "eventSeq",
                  "eventHash",
                  "prevProofEventHash",
                  "authority",
                  "kind",
                  "payloadHash",
                  "payload",
                  "createdAt",
                ],
                properties: {
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  eventId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  eventSeq: { type: "integer", minimum: 1 },
                  eventHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  prevProofEventHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  authority: { enum: ["proof", "delivery", "operator", "advisory"] },
                  kind: { type: "string" },
                  payloadHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  payload: { type: "object", additionalProperties: true },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            sources: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "sourceId",
                  "sessionId",
                  "sourceHash",
                  "manifestUrl",
                  "manifestHash",
                  "issuer",
                  "signature",
                  "capabilityVector",
                  "proofStatus",
                  "createdAt",
                ],
                properties: {
                  sourceId: { type: "string" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sourceHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  manifestUrl: { type: "string" },
                  manifestHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  issuer: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
                  signature: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
                  capabilityVector: { type: "object", additionalProperties: true },
                  proofStatus: { enum: ["pending", "challenged", "active"] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            spends: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "spendId",
                  "sessionId",
                  "pactId",
                  "toolId",
                  "payer",
                  "agentWallet",
                  "paymentToken",
                  "artifactHash",
                  "market",
                  "sourceHashes",
                  "sourceSetHash",
                  "sessionCommitment",
                  "spendPreimage",
                  "maxPriceAtomic",
                  "nonce",
                  "status",
                  "createdAt",
                ],
                properties: {
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  pactId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  toolId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  payer: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  agentWallet: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  paymentToken: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  market: { type: "string", pattern: "^0x[0-9a-fA-F]{40}$" },
                  sourceHashes: { type: "array", items: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" } },
                  sourceSetHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionCommitment: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendPreimage: { type: "object", additionalProperties: true },
                  maxPriceAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  nonce: { type: "string" },
                  status: { type: "string" },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            artifactPreflights: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "preflightId",
                  "sessionId",
                  "spendId",
                  "artifactHashPreview",
                  "artifactCid",
                  "endpointUrl",
                  "priceDisclosureHash",
                  "sourceStateSnapshotHash",
                  "status",
                  "createdAt",
                ],
                properties: {
                  preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactHashPreview: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
                  endpointUrl: { type: "string" },
                  priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  status: { enum: ["pending_live_delivery"] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            quotes: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "quoteId",
                  "sessionId",
                  "spendId",
                  "preflightId",
                  "artifactCommitment",
                  "artifactCid",
                  "priceDisclosureHash",
                  "sourceStateSnapshotHash",
                  "priceAtomic",
                  "quoteNonce",
                  "validUntilBlock",
                  "quoteHash",
                  "status",
                  "createdAt",
                ],
                properties: {
                  quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactCommitment: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
                  priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  priceAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  quoteNonce: { type: "string" },
                  validUntilBlock: { type: "string", pattern: "^[0-9]+$" },
                  quoteHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  status: { enum: ["mocked_after_preflight_not_chain_settleable", "chain_settleable_after_preflight"] },
                  chainId: { type: ["string", "null"] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            artifactAccessTokens: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "tokenId",
                  "sessionId",
                  "spendId",
                  "payer",
                  "quoteId",
                  "preflightId",
                  "artifactHash",
                  "artifactCid",
                  "artifactPayloadHash",
                  "artifactPayload",
                  "tokenHash",
                  "status",
                  "issuedByVerifierRunId",
                  "settlementEventId",
                  "createdAt",
                ],
                properties: {
                  tokenId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
                  quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactCid: { type: "string", pattern: "^sha256:0x[0-9a-fA-F]{64}$" },
                  artifactPayloadHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  artifactPayload: { type: "object", additionalProperties: true },
                  tokenHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  status: { enum: ["active", "consuming", "consumed", "blocked"] },
                  issuedByVerifierRunId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  settlementEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            mcpAdapterCalls: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "callId",
                  "sessionId",
                  "auditNonce",
                  "toolName",
                  "requestHash",
                  "responseHash",
                  "request",
                  "response",
                  "status",
                  "createdAt",
                  "proofAuthority",
                ],
                properties: {
                  callId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  auditNonce: { type: "string", minLength: 12 },
                  toolName: { type: "string" },
                  requestHash: { type: "string" },
                  responseHash: { type: "string" },
                  request: { type: "object", additionalProperties: true },
                  response: { type: "object", additionalProperties: true },
                  status: { enum: ["succeeded", "failed", "blocked"] },
                  createdAt: { type: "string", format: "date-time" },
                  proofAuthority: { const: false },
                },
              },
            },
            cawReceiptOperations: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "operationId",
                  "sessionId",
                  "spendId",
                  "operationKind",
                  "target",
                  "selector",
                  "valueAtomic",
                  "request",
                  "receiptBundleHash",
                  "status",
                  "createdAt",
                ],
                properties: {
                  operationId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  operationKind: { enum: ["deny_probe", "approve", "activate_tool"] },
                  target: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{40}$" }, { type: "null" }] },
                  selector: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{8}$" }, { type: "null" }] },
                  valueAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  request: { type: "object", additionalProperties: true },
                  receiptBundleHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  status: { enum: ["built_mocked", "fixture_manual_receipt", "raw_ingested_pending_proof", "verified_policy_authority_structural"] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            cawLiveInteractions: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "interactionId",
                  "sessionId",
                  "kind",
                  "walletId",
                  "pactId",
                  "cawRequestId",
                  "requestHash",
                  "request",
                  "responseHash",
                  "response",
                  "status",
                  "authKeyHash",
                  "proofAuthority",
                  "winnerClaimAllowed",
                  "createdAt",
                ],
                properties: {
                  interactionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  kind: { enum: ["pact_submit", "pact_sync", "transfer_submit", "contract_call", "audit_sync"] },
                  walletId: { anyOf: [{ type: "string" }, { type: "null" }] },
                  pactId: { anyOf: [{ type: "string" }, { type: "null" }] },
                  cawRequestId: { anyOf: [{ type: "string" }, { type: "null" }] },
                  requestHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  request: { type: "object", additionalProperties: true },
                  responseHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  response: { type: "object", additionalProperties: true },
                  status: { enum: ["live_submitted", "live_active", "live_pending", "live_denied", "live_failed", "live_synced"] },
                  authKeyHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  proofAuthority: { const: true },
                  winnerClaimAllowed: { const: false },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            rawCawReceiptBundles: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "bundleId",
                  "sessionId",
                  "operationId",
                  "sourceLabel",
                  "fetchedAt",
                  "rawBundleHash",
                  "rawBundle",
                  "receiptCount",
                  "createdAt",
                ],
                properties: {
                  bundleId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  operationId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sourceLabel: { type: "string" },
                  fetchedAt: { type: "string", format: "date-time" },
                  rawBundleHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  rawBundle: { type: "object", additionalProperties: true },
                  receiptCount: { type: "integer", minimum: 1, maximum: 64 },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            canonicalCawReceipts: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "rawReceiptHash",
                  "canonicalReceiptHash",
                  "bundleId",
                  "sessionId",
                  "operationId",
                  "operationKind",
                  "sourceLabel",
                  "walletAddress",
                  "target",
                  "selector",
                  "requestId",
                  "effect",
                  "status",
                  "policyDigest",
                  "paramsDigest",
                  "txHash",
                  "txCount",
                  "expiry",
                  "fetchedAt",
                  "createdAt",
                ],
                properties: {
                  rawReceiptHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  canonicalReceiptHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  bundleId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  operationId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  operationKind: { enum: ["deny_probe", "approve", "activate_tool"] },
                  sourceLabel: { type: "string" },
                  walletAddress: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
                  target: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{40}$" }, { type: "null" }] },
                  selector: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{8}$" }, { type: "null" }] },
                  requestId: { type: "string" },
                  effect: { enum: ["allow", "deny"] },
                  status: { type: "string" },
                  policyDigest: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  paramsDigest: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  txHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  txCount: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  expiry: { type: "string", format: "date-time" },
                  fetchedAt: { type: "string", format: "date-time" },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            leaseRuns: {
              type: "array",
              items: {
                type: "object",
                required: [
                  "leaseRunId",
                  "sessionId",
                  "spendId",
                  "payer",
                  "artifactHash",
                  "targetRepo",
                  "targetCommit",
                  "status",
                  "transcriptHash",
                  "toolsListHash",
                  "toolsCallHash",
                  "outputHash",
                  "leaseRunHash",
                  "settlementEventId",
                  "artifactTokenId",
                  "createdAt",
                  "completedAt",
                ],
                properties: {
                  leaseRunId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  spendId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  payer: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
                  artifactHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  targetRepo: { type: "string" },
                  targetCommit: { type: "string" },
                  status: { enum: ["blocked_missing_runner_execution", "blocked_mcp_execution_failed", "succeeded_live_mcp_transcript"] },
                  transcriptHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  toolsListHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  toolsCallHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  outputHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  leaseRunHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  settlementEventId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  artifactTokenId: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  createdAt: { type: "string", format: "date-time" },
                  completedAt: { anyOf: [{ type: "string", format: "date-time" }, { type: "null" }] },
                },
              },
            },
            judgeCheck: { $ref: "#/components/schemas/JudgeCheckData" },
            replayPageIndex: {
              type: "object",
              required: ["pageSize", "pageRoot", "collections"],
              properties: {
                pageSize: { const: 200 },
                pageRoot: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                collections: {
                  type: "object",
                  additionalProperties: {
                    type: "object",
                    required: ["totalRows", "pageCount", "orderBy", "firstPageHash", "pageRoot", "pageHashes"],
                    properties: {
                      totalRows: { type: "integer", minimum: 0 },
                      pageCount: { type: "integer", minimum: 0 },
                      orderBy: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 4 },
                      firstPageHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                      pageRoot: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                      pageHashes: {
                        type: "array",
                        items: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                        maxItems: 5000,
                      },
                    },
                  },
                },
              },
            },
            replayPages: {
              type: "object",
              additionalProperties: {
                type: "array",
                maxItems: 5000,
                items: {
                  type: "object",
                  required: ["bundleType", "sessionId", "collection", "pageIndex", "pageSize", "orderBy", "rows", "pageHash"],
                  properties: {
                    bundleType: { const: "PACTFUSE_REPLAY_PAGE_V1" },
                    sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                    collection: {
                      enum: [
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
                      ],
                    },
                    pageIndex: { type: "integer", minimum: 0 },
                    pageSize: { const: 200 },
                    orderBy: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 4 },
                    rows: { type: "array", maxItems: 200, items: { type: "object", additionalProperties: true } },
                    pageHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  },
                },
              },
            },
          },
        }),
        ReplayPageResponse: serviceResponseSchema({
          type: "object",
          required: ["bundleType", "sessionId", "collection", "pageIndex", "pageSize", "orderBy", "rows", "pageHash"],
          properties: {
            bundleType: { const: "PACTFUSE_REPLAY_PAGE_V1" },
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            collection: {
              enum: [
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
              ],
            },
            pageIndex: { type: "integer", minimum: 0 },
            pageSize: { const: 200 },
            orderBy: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 4 },
            rows: { type: "array", maxItems: 200, items: { type: "object", additionalProperties: true } },
            pageHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
          },
        }),
        AgentTranscriptResponse: serviceResponseSchema({
          type: "object",
          required: [
            "sessionId",
            "status",
            "format",
            "toolsListHash",
            "toolsCallHash",
            "transcriptHash",
            "boundedToPinnedManifest",
            "callCount",
            "calls",
            "winnerClaimAllowed",
          ],
          properties: {
            sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            status: { enum: ["pending", "blocked", "summarized"] },
            format: { const: "mcp-json-rpc" },
            toolsListHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            toolsCallHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            transcriptHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
            boundedToPinnedManifest: { type: "boolean" },
            callCount: { type: "integer", minimum: 0, maximum: 200 },
            calls: {
              type: "array",
              items: {
                type: "object",
                required: ["callId", "auditNonce", "toolName", "requestHash", "responseHash", "status", "createdAt"],
                properties: {
                  callId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  auditNonce: { type: "string", minLength: 12 },
                  toolName: { type: "string" },
                  requestHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  responseHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
                  status: { enum: ["succeeded", "failed", "blocked"] },
                  createdAt: { type: "string", format: "date-time" },
                },
              },
            },
            winnerClaimAllowed: { const: false },
          },
        }),
        ServiceResponse: serviceResponseSchema({ type: "object" }),
      },
    },
    "x-pactfuse-modes": {
      CLAIM_MODE: "simulated",
      PAYMENT_MODE: "mocked",
      TOKEN_MODE: "local-mocked",
      IDENTITY_MODE: "pending",
      WINNER_CLAIM_ALLOWED: false,
    },
  };
}

function requestBodySchemaFor(method: string, path: string): Record<string, unknown> | null {
  if (method !== "POST") {
    return null;
  }
  if (path === "/api/v1/mcp/audit") {
    return jsonRequestBody({ $ref: "#/components/schemas/McpAdapterAuditPayload" });
  }
  if (path === "/api/v1/sessions") {
    return jsonRequestBody({ $ref: "#/components/schemas/CreateSessionInput" });
  }
  if (path === "/api/v1/sources/register") {
    return jsonRequestBody({ $ref: "#/components/schemas/SourceRegisterInput" });
  }
  if (path === "/api/v1/sources/challenge") {
    return jsonRequestBody({ $ref: "#/components/schemas/SourceChallengeInput" });
  }
  if (path === "/api/v1/spends/register-batch") {
    return jsonRequestBody({ $ref: "#/components/schemas/SpendRegisterBatchInput" });
  }
  if (path === "/api/v1/caw/operations/build") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawOperationBuildInput" });
  }
  if (path === "/api/v1/caw/live/identity/probe") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawLiveIdentityProbeInput" });
  }
  if (path === "/api/v1/caw/live/contracts/call") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawLiveContractCallInput" });
  }
  if (path === "/api/v1/caw/live/allowances/verify") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawAllowanceVerifyInput" });
  }
  if (path === "/api/v1/caw/live/audit/sync") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawLiveAuditSyncInput" });
  }
  if (path === "/api/v1/caw/receipts/ingest") {
    return jsonRequestBody({ $ref: "#/components/schemas/CawReceiptIngestInput" });
  }
  if (path === "/api/v1/artifacts/preflight") {
    return jsonRequestBody({ $ref: "#/components/schemas/ArtifactPreflightInput" });
  }
  if (path === "/api/v1/quotes") {
    return jsonRequestBody({ $ref: "#/components/schemas/QuoteInput" });
  }
  if (path === "/api/v1/lease/execute") {
    return jsonRequestBody({ $ref: "#/components/schemas/LeaseExecuteInput" });
  }
  if (path === "/api/v1/gate/events/ingest") {
    return jsonRequestBody({ $ref: "#/components/schemas/GateEventIngestInput" });
  }
  if (path === "/api/v1/token/balance-deltas/verify") {
    return jsonRequestBody({ $ref: "#/components/schemas/TokenBalanceDeltaVerifyInput" });
  }
  if (path === "/api/v1/indexer/backfill") {
    return jsonRequestBody({ $ref: "#/components/schemas/ChainIndexerBackfillInput" });
  }
  if (path === "/api/v1/artifacts/refund") {
    return jsonRequestBody({ $ref: "#/components/schemas/ArtifactRefundInput" });
  }
  if (path === "/api/v1/artifacts/access-token") {
    return jsonRequestBody({ $ref: "#/components/schemas/ArtifactAccessIssueInput" });
  }
  if (path === "/api/v1/evidence/verify") {
    return jsonRequestBody({ $ref: "#/components/schemas/VerifyEvidenceInput" });
  }
  if (path.startsWith("/api/v1/") && !path.includes("{")) {
    return jsonRequestBody({ $ref: "#/components/schemas/SessionScopedEnvelope" });
  }
  return null;
}

function parameterSchemaFor(path: string): Record<string, unknown>[] {
  const parameters = pathParameterSchemas(path);
  if (path === "/api/v1/mcp/audit") {
    parameters.push({
      name: "x-pactfuse-audit-signature",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
      description: "HMAC-SHA256 over the canonical JSON audit payload using PACTFUSE_MCP_AUDIT_TOKEN.",
    });
  }
  if (path === "/api/v1/gate/events/ingest") {
    parameters.push({
      name: "x-pactfuse-gate-signature",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
      description: "HMAC-SHA256 over the canonical JSON gate ingest payload using the internal gate ingest token.",
    });
  }
  if (path === "/api/v1/caw/receipts/ingest") {
    parameters.push({
      name: "authorization",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^Bearer .+" },
      description: "Required for every raw/manual CAW receipt ingest write; configured by PACTFUSE_CAW_INGEST_TOKEN.",
    });
  }
  const apiRole = apiRoleForPath(path);
  if (apiRole) {
    parameters.push({
      name: "authorization",
      in: "header",
      required: false,
      schema: { type: "string", pattern: "^Bearer .+" },
      description: apiRoleHeaderDescription(apiRole),
    });
  }
  if (path === "/api/v1/lease/execute" || path === "/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}") {
    parameters.push({
      name: "authorization",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^Bearer .+" },
      description: "Bearer token bound to the artifact access tuple: sessionId, spendId, payer, artifactHash.",
    });
  }
  if (path === "/api/v1/caw/live/transfers/submit" || path === "/api/v1/caw/live/contracts/call") {
    parameters.push({
      name: "x-pactfuse-caw-pact-api-key",
      in: "header",
      required: true,
      schema: { type: "string", minLength: 16 },
      description: "Transient CAW pact-scoped API key. PactFuse stores only its SHA-256 hash.",
    });
  }
  return parameters;
}

function apiRoleForPath(path: string): ApiRole | null {
  switch (path) {
    case "/api/v1/sessions":
    case "/api/v1/sources/register":
    case "/api/v1/spends/register-batch":
    case "/api/v1/caw/operations/build":
    case "/api/v1/caw/live/pacts/submit":
    case "/api/v1/caw/live/pacts/sync":
    case "/api/v1/caw/live/transfers/submit":
    case "/api/v1/caw/live/contracts/call":
    case "/api/v1/caw/live/allowances/verify":
    case "/api/v1/caw/live/audit/sync":
    case "/api/v1/indexer/backfill":
    case "/api/v1/token/balance-deltas/verify":
    case "/api/v1/artifacts/preflight":
    case "/api/v1/evidence/verify":
      return "operator";
    case "/api/v1/sources/challenge":
      return "challenge_submitter";
    case "/api/v1/quotes":
    case "/api/v1/artifacts/refund":
    case "/api/v1/artifacts/access-token":
      return "artifact_signer";
    default:
      return null;
  }
}

function apiRoleHeaderDescription(role: ApiRole): string {
  if (role === "challenge_submitter") {
    return "Required for protected challenge writes; PACTFUSE_CHALLENGE_SUBMITTER_TOKEN falls back to PACTFUSE_OPERATOR_TOKEN, and missing tokens fail closed unless PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS=true is set for local development.";
  }
  if (role === "artifact_signer") {
    return "Required for protected artifact signer writes; PACTFUSE_ARTIFACT_SIGNER_TOKEN falls back to PACTFUSE_OPERATOR_TOKEN, and missing tokens fail closed unless PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS=true is set for local development.";
  }
  return "Required for protected operator writes; missing PACTFUSE_OPERATOR_TOKEN fails closed unless PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS=true is set for local development.";
}

function pathParameterSchemas(path: string): Record<string, unknown>[] {
  const parameters: Record<string, unknown>[] = [];
  for (const match of path.matchAll(/\{([^}]+)\}/g)) {
    const name = match[1];
    if (!name) {
      continue;
    }
    parameters.push({
      name,
      in: "path",
      required: true,
      schema: parameterValueSchema(name),
    });
  }
  return parameters;
}

function parameterValueSchema(name: string): Record<string, unknown> {
  if (name === "sessionId" || name === "spendId" || name === "artifactHash") {
    return { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" };
  }
  if (name === "payer") {
    return { type: "string", pattern: "^0x[0-9a-fA-F]+$" };
  }
  return { type: "string" };
}

function jsonRequestBody(schema: Record<string, unknown>): Record<string, unknown> {
  return {
    required: true,
    content: {
      "application/json": {
        schema,
      },
    },
  };
}

function sessionEnvelopeSchema(payloadRef: string): Record<string, unknown> {
  return {
    type: "object",
    required: ["sessionId", "idempotencyKey", "payload"],
    additionalProperties: false,
    properties: {
      sessionId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
      idempotencyKey: { type: "string", minLength: 4, maxLength: 160, pattern: "^[a-z][a-z0-9:_-]+$" },
      payload: { $ref: payloadRef },
    },
  };
}

function responseSchemaFor(path: string): Record<string, unknown> {
  switch (path) {
    case "/api/v1/evidence/verify":
    case "/api/v1/evidence/{sessionId}/verify":
      return { $ref: "#/components/schemas/VerifierRunResponse" };
    case "/api/v1/evidence/judge-check":
      return { $ref: "#/components/schemas/JudgeCheckResponse" };
    case "/api/v1/evidence/claim-readiness":
      return { $ref: "#/components/schemas/ClaimReadinessResponse" };
    case "/api/v1/caw/receipts/ingest":
      return { $ref: "#/components/schemas/CawReceiptIngestResponse" };
    case "/api/v1/caw/live/identity/probe":
      return { $ref: "#/components/schemas/CawLiveIdentityProbeResponse" };
    case "/api/v1/gate/events/ingest":
      return { $ref: "#/components/schemas/GateEventIngestResponse" };
    case "/api/v1/indexer/backfill":
      return { $ref: "#/components/schemas/ChainIndexerBackfillResponse" };
    case "/api/v1/artifacts/preflight":
      return { $ref: "#/components/schemas/ArtifactPreflightResponse" };
    case "/api/v1/quotes":
      return { $ref: "#/components/schemas/QuoteResponse" };
    case "/api/v1/artifacts/refund":
      return { $ref: "#/components/schemas/ArtifactRefundResponse" };
    case "/api/v1/artifacts/access-token":
      return { $ref: "#/components/schemas/ArtifactAccessIssueResponse" };
    case "/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}":
      return { $ref: "#/components/schemas/ArtifactAccessReadResponse" };
    case "/api/v1/lease/execute":
      return { $ref: "#/components/schemas/LeaseExecuteResponse" };
    case "/api/v1/mcp/audit":
      return { $ref: "#/components/schemas/McpAuditResponse" };
    case "/api/v1/evidence/replay-bundle":
      return { $ref: "#/components/schemas/ReplayBundleResponse" };
    case "/api/v1/evidence/replay-page":
      return { $ref: "#/components/schemas/ReplayPageResponse" };
    case "/api/v1/evidence/indexer-status":
      return { $ref: "#/components/schemas/ChainIndexerStatusResponse" };
    case "/api/v1/evidence/runner-heartbeat":
      return { $ref: "#/components/schemas/RunnerHeartbeatResponse" };
    case "/api/v1/evidence/agent-transcript":
      return { $ref: "#/components/schemas/AgentTranscriptResponse" };
    default:
      return { $ref: "#/components/schemas/ServiceResponse" };
  }
}

function serviceResponseSchema(data: Record<string, unknown>): Record<string, unknown> {
  return {
    oneOf: [
      {
        type: "object",
        required: ["ok", "requestId", "data"],
        properties: {
          ok: { const: true },
          requestId: { type: "string" },
          data,
        },
      },
      { $ref: "#/components/schemas/ServiceError" },
    ],
  };
}
