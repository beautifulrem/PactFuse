import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import {
  Hex32Schema,
  SessionScopedEnvelopeSchema,
  CreateSessionInputSchema,
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
  ingestCawReceiptBundle,
  listEventsAfterEventId,
  readAgentTranscript,
  readJudgeCheck,
  readRunnerHeartbeat,
  refundUndeliveredArtifact,
  registerSignedSource,
  registerSourceBoundSpends,
  runArtifactPreflight,
  signArtifactQuote,
  verifyEvidenceForSession,
} from "./services/service.js";
import { newRequestId, proofPendingError, toApiError } from "./util.js";

const ROUTES = [
  ["GET", "/healthz"],
  ["GET", "/readyz"],
  ["GET", "/api/v1/openapi.json"],
  ["POST", "/api/v1/sessions"],
  ["GET", "/api/v1/sessions/{sessionId}"],
  ["POST", "/api/v1/sources/register"],
  ["POST", "/api/v1/sources/challenge"],
  ["POST", "/api/v1/spends/register-batch"],
  ["POST", "/api/v1/caw/operations/build"],
  ["POST", "/api/v1/caw/receipts/ingest"],
  ["POST", "/api/v1/artifacts/preflight"],
  ["POST", "/api/v1/quotes"],
  ["GET", "/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}"],
  ["POST", "/api/v1/artifacts/refund"],
  ["POST", "/api/v1/lease/execute"],
  ["POST", "/api/v1/evidence/verify"],
  ["GET", "/api/v1/evidence/judge-check"],
  ["GET", "/api/v1/evidence/replay-bundle"],
  ["GET", "/api/v1/evidence/runner-heartbeat"],
  ["GET", "/api/v1/evidence/agent-transcript"],
  ["GET", "/api/v1/evidence/stream"],
] as const;

export function createApp(ctx: ServiceCtx): Hono {
  const app = new Hono();

  app.onError((error, c) => {
    const requestId = newRequestId("unhandled");
    const apiError = toApiError(error, requestId);
    ctx.logger.error({ error, requestId }, "unhandled API error");
    return c.json({ ok: false, requestId, error: apiError }, statusFor(apiError.code) as 400);
  });

  app.get("/healthz", (c) =>
    c.json({
      ok: true,
      service: "pactfuse-api",
      modes: ctx.config,
    }),
  );

  app.get("/readyz", (c) => {
    ctx.db.sqlite.prepare("SELECT 1").get();
    return c.json({
      ok: true,
      db: "ready",
      verifier: "fail-closed-scaffold",
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

  app.post("/api/v1/caw/receipts/ingest", async (c) =>
    send(c, await ingestCawReceiptBundle(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/artifacts/preflight", async (c) =>
    send(c, await runArtifactPreflight(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/quotes", async (c) =>
    send(c, await signArtifactQuote(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 201),
  );

  app.get("/api/v1/artifacts/:sessionId/:spendId/:payer/:artifactHash", async (c) => {
    const requestId = newRequestId("artifact");
    Hex32Schema.parse(c.req.param("sessionId"));
    Hex32Schema.parse(c.req.param("spendId"));
    Hex32Schema.parse(c.req.param("artifactHash"));
    return send(c, {
      ok: false,
      requestId,
      error: proofPendingError(requestId, "artifact access is pending live settlement and bearer-token proof"),
    });
  });

  app.post("/api/v1/artifacts/refund", async (c) =>
    send(c, await refundUndeliveredArtifact(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/lease/execute", async (c) =>
    send(c, await executeLease(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 202),
  );

  app.post("/api/v1/evidence/verify", async (c) =>
    send(c, await verifyEvidenceForSession(SessionScopedEnvelopeSchema.parse(await readJson(c)), ctx), 200),
  );

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
  try {
    return await c.req.json();
  } catch {
    return {};
  }
}

function requiredQuery(c: Context, name: string): string {
  const value = c.req.query(name);
  if (!value) {
    throw new Error(`missing query parameter: ${name}`);
  }
  return value;
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
    default:
      return 500;
  }
}

function buildOpenApi(): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  for (const [method, path] of ROUTES) {
    paths[path] = {
      ...(paths[path] ?? {}),
      [method.toLowerCase()]: {
        operationId: `${method.toLowerCase()}_${path.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
        responses: {
          "200": { description: "PactFuse fail-closed P0 response" },
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
    "x-pactfuse-modes": {
      CLAIM_MODE: "simulated",
      PAYMENT_MODE: "mocked",
      TOKEN_MODE: "local-mocked",
      IDENTITY_MODE: "pending",
      WINNER_CLAIM_ALLOWED: false,
    },
  };
}
