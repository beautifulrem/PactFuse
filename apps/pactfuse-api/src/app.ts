import { createHmac, timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import {
  HexSchema,
  Hex32Schema,
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
  listEventsAfterEventId,
  readAgentTranscript,
  readArtifactAccess,
  readJudgeCheck,
  readProofProviderStatus,
  readRunnerHeartbeat,
  recordMcpAdapterAudit,
  previewVerifyEvidenceForSession,
  refundUndeliveredArtifact,
  registerSignedSource,
  registerSourceBoundSpends,
  runArtifactPreflight,
  signArtifactQuote,
  verifyEvidenceForSession,
} from "./services/service.js";
import { badRequestError, forbiddenError, newRequestId, rateLimitedError, toApiError } from "./util.js";

const MAX_JSON_BODY_BYTES = 2 * 1024 * 1024;
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 600;

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
  { method: "POST", path: "/api/v1/caw/receipts/ingest", okStatus: 202 },
  { method: "POST", path: "/api/v1/gate/events/ingest", okStatus: 202 },
  { method: "POST", path: "/api/v1/artifacts/preflight", okStatus: 202 },
  { method: "POST", path: "/api/v1/quotes", okStatus: 201 },
  { method: "GET", path: "/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}", okStatus: 200 },
  { method: "POST", path: "/api/v1/artifacts/refund", okStatus: 202 },
  { method: "POST", path: "/api/v1/lease/execute", okStatus: 202 },
  { method: "POST", path: "/api/v1/mcp/audit", okStatus: 202 },
  { method: "POST", path: "/api/v1/evidence/verify", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/{sessionId}/verify", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/judge-check", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/replay-bundle", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/runner-heartbeat", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/agent-transcript", okStatus: 200 },
  { method: "GET", path: "/api/v1/evidence/stream", okStatus: 200 },
] as const;

const PROOF_FIELD_ROUTES: Record<string, string[]> = {
  "/api/v1/caw/receipts/ingest": ["proofAuthority", "winnerClaimAllowed"],
  "/api/v1/gate/events/ingest": ["finalityStatus", "confirmations", "finalityDepth", "proofAuthority", "winnerClaimAllowed"],
  "/api/v1/artifacts/preflight": ["preflightId", "artifactHashPreview", "priceDisclosureHash", "winnerClaimAllowed"],
  "/api/v1/quotes": ["preflightId", "quoteSignedAfterPreflight", "priceDisclosureHash", "winnerClaimAllowed"],
  "/api/v1/artifacts/refund": ["spendId", "quoteId", "status", "winnerClaimAllowed"],
  "/api/v1/lease/execute": ["leaseRunId", "bearerBound", "artifactHash", "winnerClaimAllowed"],
  "/api/v1/mcp/audit": ["proofAuthority", "winnerClaimAllowed", "requestHash", "responseHash"],
  "/api/v1/evidence/verify": ["schemaOk", "proofChipAllowed", "winnerClaimAllowed", "finalVerifierComplete"],
  "/api/v1/evidence/judge-check": ["winnerClaimAllowed", "rows.status", "rows.authority"],
  "/api/v1/evidence/replay-bundle": [
    "winnerClaimAllowed",
    "eventRoot",
    "mcpAdapterCalls",
    "cawReceiptOperations",
    "rawCawReceiptBundles",
    "canonicalCawReceipts",
    "judgeCheck",
  ],
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
    const bucket = rateBuckets.get(key);
    const nextBucket =
      !bucket || bucket.resetAt <= now ? { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS } : { ...bucket, count: bucket.count + 1 };
    rateBuckets.set(key, nextBucket);
    c.header("x-ratelimit-limit", String(RATE_LIMIT_MAX_REQUESTS));
    c.header("x-ratelimit-remaining", String(Math.max(0, RATE_LIMIT_MAX_REQUESTS - nextBucket.count)));
    if (nextBucket.count > RATE_LIMIT_MAX_REQUESTS) {
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
      mcpAudit: {
        mode: "hmac-shared-secret",
        configured: Boolean(ctx.mcpAuditSecret),
      },
      winnerClaimAllowed: false,
    });
  });

  app.get("/api/v1/openapi.json", (c) => c.json(buildOpenApi()));

  app.post("/api/v1/sessions", async (c) =>
    send(c, await createSession(CreateSessionInputSchema.parse(await readJson(c)), ctx), 201),
  );

  app.get("/api/v1/sessions/:sessionId", async (c) => send(c, await getSession(c.req.param("sessionId"), ctx)));

  app.post("/api/v1/sources/register", async (c) =>
    send(c, await registerSignedSource(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201),
  );

  app.post("/api/v1/sources/challenge", async (c) =>
    send(c, await challengeSource(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/spends/register-batch", async (c) =>
    send(c, await registerSourceBoundSpends(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201),
  );

  app.post("/api/v1/caw/operations/build", async (c) =>
    send(c, await buildCawOperation(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201),
  );

  app.post("/api/v1/caw/receipts/ingest", async (c) => {
    authorizeCawReceiptIngest(c, ctx);
    return send(c, await ingestCawReceiptBundle(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202);
  });

  app.post("/api/v1/gate/events/ingest", async (c) => {
    const body = SessionScopedEnvelopeSchema.parse(await readJson(c));
    authorizeGateEventIngest(c, ctx, body);
    return send(c, await ingestGateEvent(body, ctx), 202);
  });

  app.post("/api/v1/artifacts/preflight", async (c) =>
    send(c, await runArtifactPreflight(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/quotes", async (c) =>
    send(c, await signArtifactQuote(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201),
  );

  app.get("/api/v1/artifacts/:sessionId/:spendId/:payer/:artifactHash", async (c) => {
    const sessionId = Hex32Schema.parse(c.req.param("sessionId"));
    const spendId = Hex32Schema.parse(c.req.param("spendId"));
    const payer = HexSchema.parse(c.req.param("payer"));
    const artifactHash = Hex32Schema.parse(c.req.param("artifactHash"));
    return send(c, await readArtifactAccess({ sessionId, spendId, payer, artifactHash, bearerToken: bearerTokenFor(c) }, ctx));
  });

  app.post("/api/v1/artifacts/refund", async (c) =>
    send(c, await refundUndeliveredArtifact(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/lease/execute", async (c) =>
    send(c, await executeLease(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx, bearerTokenFor(c)), 202),
  );

  app.post("/api/v1/mcp/audit", async (c) =>
    send(c, recordMcpAdapterAudit(authorizeMcpAudit(c, ctx, McpAdapterAuditPayloadSchema.parse(await readJson(c))), ctx), 202),
  );

  app.post("/api/v1/evidence/verify", async (c) =>
    send(c, await verifyEvidenceForSession(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 200),
  );

  app.get("/api/v1/evidence/:sessionId/verify", async (c) => send(c, await previewVerifyEvidenceForSession(c.req.param("sessionId"), ctx)));

  app.get("/api/v1/evidence/judge-check", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await readJudgeCheck(sessionId, ctx));
  });

  app.get("/api/v1/evidence/replay-bundle", async (c) => {
    const sessionId = requiredQuery(c, "sessionId");
    return send(c, await assembleReplayBundle(sessionId, ctx));
  });

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
  const secret = ctx.mcpAuditSecret;
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
  if (!token) {
    return;
  }
  const requestId = newRequestId("caw_ingest_auth");
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
            payload: { type: "object", additionalProperties: true },
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
            proofLevel: { enum: ["schema_only_no_claim", "fail_closed_no_claim"] },
            claimMode: { const: "simulated" },
            paymentMode: { const: "mocked" },
            tokenMode: { const: "local-mocked" },
            identityMode: { const: "pending" },
            schemaOk: { type: "boolean" },
            proofAuthority: { const: false },
            proofChipAllowed: { const: false },
            winnerClaimAllowed: { const: false },
            finalVerifierComplete: { const: false },
          },
        },
        VerifierRunResponse: serviceResponseSchema({
          allOf: [{ $ref: "#/components/schemas/FailClosedProofState" }],
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
            status: { enum: ["fixture_manual_receipt", "raw_ingested_pending_proof"] },
            proofAuthority: { const: false },
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
        ArtifactPreflightResponse: serviceResponseSchema({
          type: "object",
          required: [
            "preflightId",
            "artifactHashPreview",
            "priceDisclosureHash",
            "sourceStateSnapshotHash",
            "status",
            "winnerClaimAllowed",
          ],
          properties: {
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            artifactHashPreview: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
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
            "priceDisclosureHash",
            "sourceStateSnapshotHash",
            "quoteSignedAfterPreflight",
            "status",
            "winnerClaimAllowed",
          ],
          properties: {
            quoteId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            preflightId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            priceDisclosureHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            sourceStateSnapshotHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            quoteSignedAfterPreflight: { const: true },
            status: { enum: ["mocked_after_preflight_not_chain_settleable"] },
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
          required: ["leaseRunId", "payer", "artifactHash", "bearerBound", "status", "winnerClaimAllowed"],
          properties: {
            leaseRunId: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            payer: { type: "string", pattern: "^0x[0-9a-fA-F]+$" },
            artifactHash: { type: "string", pattern: "^0x[0-9a-fA-F]{64}$" },
            bearerBound: { const: true },
            status: { enum: ["blocked_missing_runner_execution"] },
            winnerClaimAllowed: { const: false },
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
            "events",
            "mcpAdapterCalls",
            "cawReceiptOperations",
            "rawCawReceiptBundles",
            "canonicalCawReceipts",
            "judgeCheck",
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
                  target: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
                  selector: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{8}$" }, { type: "null" }] },
                  valueAtomic: { type: "string", pattern: "^(0|[1-9][0-9]*)$" },
                  request: { type: "object", additionalProperties: true },
                  receiptBundleHash: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]{64}$" }, { type: "null" }] },
                  status: { enum: ["built_mocked", "fixture_manual_receipt", "raw_ingested_pending_proof"] },
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
                  target: { anyOf: [{ type: "string", pattern: "^0x[0-9a-fA-F]+$" }, { type: "null" }] },
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
            judgeCheck: { $ref: "#/components/schemas/JudgeCheckData" },
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
            boundedToPinnedManifest: { const: false },
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
  if (path === "/api/v1/lease/execute") {
    return jsonRequestBody({ $ref: "#/components/schemas/LeaseExecuteInput" });
  }
  if (path === "/api/v1/gate/events/ingest") {
    return jsonRequestBody({ $ref: "#/components/schemas/GateEventIngestInput" });
  }
  if (path === "/api/v1/artifacts/refund") {
    return jsonRequestBody({ $ref: "#/components/schemas/ArtifactRefundInput" });
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
      required: false,
      schema: { type: "string", pattern: "^Bearer .+" },
      description: "Required when PACTFUSE_CAW_INGEST_TOKEN is configured; protects raw/manual CAW receipt ingest writes.",
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
  return parameters;
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

function responseSchemaFor(path: string): Record<string, unknown> {
  switch (path) {
    case "/api/v1/evidence/verify":
    case "/api/v1/evidence/{sessionId}/verify":
      return { $ref: "#/components/schemas/VerifierRunResponse" };
    case "/api/v1/evidence/judge-check":
      return { $ref: "#/components/schemas/JudgeCheckResponse" };
    case "/api/v1/caw/receipts/ingest":
      return { $ref: "#/components/schemas/CawReceiptIngestResponse" };
    case "/api/v1/gate/events/ingest":
      return { $ref: "#/components/schemas/GateEventIngestResponse" };
    case "/api/v1/artifacts/preflight":
      return { $ref: "#/components/schemas/ArtifactPreflightResponse" };
    case "/api/v1/quotes":
      return { $ref: "#/components/schemas/QuoteResponse" };
    case "/api/v1/artifacts/refund":
      return { $ref: "#/components/schemas/ArtifactRefundResponse" };
    case "/api/v1/lease/execute":
      return { $ref: "#/components/schemas/LeaseExecuteResponse" };
    case "/api/v1/mcp/audit":
      return { $ref: "#/components/schemas/McpAuditResponse" };
    case "/api/v1/evidence/replay-bundle":
      return { $ref: "#/components/schemas/ReplayBundleResponse" };
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
