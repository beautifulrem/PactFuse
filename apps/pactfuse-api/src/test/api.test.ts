import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { encodeEventTopics, keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalizeJson } from "@pactfuse/evidence-schema";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeases } from "../services/jobs.js";
import { INDEX_CHAIN_WINDOW_JOB_KIND, runIndexerWorkerOnce } from "../services/indexer-worker.js";
import {
  createHttpsCawReceiptSource,
  createHttpJsonRpcMcpLeaseClient,
  createStaticTemplateRegistry,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
  createUnconfiguredMcpLeaseClient,
  normalizePactFuseChainLog,
  PACTFUSE_CHAIN_EVENT_ABI,
} from "../services/providers.js";
import { appendEvidenceEvent, recordMcpAdapterCall } from "../services/service.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { ApiSecurityConfig, CawReceiptSource, ChainClient, McpLeaseClient, ServiceCtx } from "../types.js";

const MCP_AUDIT_TOKEN = "test-mcp-audit-token";
const GATE_INGEST_TOKEN = "test-gate-ingest-token";
const CAW_INGEST_TOKEN = "test-caw-ingest-token";

function makeApp(
  dbPath = ":memory:",
  options: {
    caw?: CawReceiptSource;
    chain?: ChainClient;
    mcpLease?: McpLeaseClient;
    mcpAuditSecret?: string | null;
    gateIngestSecret?: string | null;
    cawIngestToken?: string | null;
    apiSecurity?: Partial<ApiSecurityConfig>;
    requiredIndexerCursors?: ServiceCtx["requiredIndexerCursors"];
  } = {},
) {
  const mcpAuditSecret = options.mcpAuditSecret === undefined ? MCP_AUDIT_TOKEN : options.mcpAuditSecret;
  const gateIngestSecret = options.gateIngestSecret === undefined ? GATE_INGEST_TOKEN : options.gateIngestSecret;
  const apiSecurity: ApiSecurityConfig = {
    operatorToken: null,
    challengeSubmitterToken: null,
    artifactSignerToken: null,
    allowInsecureMissingRoleTokens: true,
    rateLimitWindowMs: 60_000,
    defaultRateLimitMax: 600,
    sessionCreateRateLimitMax: 60,
    sourceChallengeRateLimitMax: 20,
    ...options.apiSecurity,
  };
  const ctx: ServiceCtx = {
    db: openPactFuseDb(dbPath),
    verifier: createVerifierAdapter(),
    chain: options.chain ?? createUnconfiguredChainClient(),
    caw: options.caw ?? createUnconfiguredCawReceiptSource(),
    mcpLease: options.mcpLease ?? createUnconfiguredMcpLeaseClient(),
    templates: createStaticTemplateRegistry([
      {
        mode: "gate-paid-artifact-real",
        sourcePath: "/test/gate-paid-artifact-real.json",
        templateHash: hex32("gate-paid-template"),
      },
      {
        mode: "permit-payment-real",
        sourcePath: "/test/permit-payment-real.appendix.json",
        templateHash: hex32("permit-template"),
      },
    ]),
    mcpAuditSecret,
    gateIngestSecret,
    cawIngestToken: options.cawIngestToken === undefined ? CAW_INGEST_TOKEN : options.cawIngestToken,
    requiredIndexerCursors: options.requiredIndexerCursors ?? [],
    apiSecurity,
    clock: { now: () => new Date("2026-06-11T00:00:00.000Z") },
    logger: {
      info: () => undefined,
      warn: () => undefined,
      error: () => undefined,
    },
    config: {
      claimMode: "simulated",
      paymentMode: "mocked",
      tokenMode: "local-mocked",
      identityMode: "pending",
      winnerClaimAllowed: false,
    },
  };
  return { app: createApp(ctx), ctx };
}

describe("pactfuse-api P0", () => {
  it("creates sessions idempotently for the same request hash", async () => {
    const { app } = makeApp();
    const body = { idempotencyKey: "sess-idem-1", payload: { label: "idem" } };

    const first = await post(app, "/api/v1/sessions", body);
    const second = await post(app, "/api/v1/sessions", body);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(first.json.requestId).toBe(second.json.requestId);
    expect(first.json.data.sessionId).toBe(second.json.data.sessionId);
  });

  it("serializes concurrent idempotent session creation to one stored event", async () => {
    const { app } = makeApp();
    const body = { idempotencyKey: "sess-concurrent", payload: { label: "concurrent" } };

    const results = await Promise.all(Array.from({ length: 16 }, () => post(app, "/api/v1/sessions", body)));
    const sessionIds = new Set(results.map((result) => result.json.data.sessionId));
    const requestIds = new Set(results.map((result) => result.json.requestId));
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${results[0].json.data.sessionId}`);
    const replayJson = await replay.json();

    expect(results.every((result) => result.status === 201)).toBe(true);
    expect(sessionIds.size).toBe(1);
    expect(requestIds.size).toBe(1);
    expect(replayJson.data.events).toHaveLength(1);
  });

  it("returns deterministic idempotency conflicts for the same key with a different hash", async () => {
    const { app } = makeApp();

    await post(app, "/api/v1/sessions", { idempotencyKey: "sess-conflict", payload: { label: "a" } });
    const conflict = await post(app, "/api/v1/sessions", {
      idempotencyKey: "sess-conflict",
      payload: { label: "b" },
    });

    expect(conflict.status).toBe(409);
    expect(conflict.json.ok).toBe(false);
    expect(conflict.json.error.code).toBe("idempotency_conflict");
  });

  it("requires configured role tokens before protected mutations read request bodies", async () => {
    const { app } = makeApp(":memory:", {
      apiSecurity: {
        operatorToken: "operator-test-token",
        challengeSubmitterToken: "challenge-test-token",
        artifactSignerToken: "artifact-test-token",
      },
    });

    const missingOperator = await post(app, "/api/v1/sessions", { idempotencyKey: "auth-missing", payload: { label: "x" } });
    const wrongOperator = await post(
      app,
      "/api/v1/sessions",
      { idempotencyKey: "auth-wrong", payload: { label: "x" } },
      { authorization: "Bearer wrong" },
    );
    const allowedOperator = await post(
      app,
      "/api/v1/sessions",
      { idempotencyKey: "auth-allowed", payload: { label: "x" } },
      { authorization: "Bearer operator-test-token" },
    );
    const missingChallenge = await post(app, "/api/v1/sources/challenge", {});
    const allowedChallengeAuth = await post(app, "/api/v1/sources/challenge", {}, { authorization: "Bearer challenge-test-token" });
    const missingArtifactSigner = await post(app, "/api/v1/quotes", {});
    const allowedArtifactAuth = await post(app, "/api/v1/quotes", {}, { authorization: "Bearer artifact-test-token" });
    const missingIndexer = await post(app, "/api/v1/indexer/backfill", {});
    const allowedIndexerAuth = await post(app, "/api/v1/indexer/backfill", {}, { authorization: "Bearer operator-test-token" });
    const invalidJsonWithoutAuth = await rawPost(app, "/api/v1/sources/challenge", "{", {});
    const invalidJsonWithAuth = await rawPost(app, "/api/v1/sources/challenge", "{", { authorization: "Bearer challenge-test-token" });

    expect(missingOperator.status).toBe(403);
    expect(wrongOperator.status).toBe(403);
    expect(allowedOperator.status).toBe(201);
    expect(missingChallenge.status).toBe(403);
    expect(allowedChallengeAuth.status).toBe(400);
    expect(missingArtifactSigner.status).toBe(403);
    expect(allowedArtifactAuth.status).toBe(400);
    expect(missingIndexer.status).toBe(403);
    expect(allowedIndexerAuth.status).toBe(400);
    expect(invalidJsonWithoutAuth.status).toBe(403);
    expect(invalidJsonWithAuth.status).toBe(400);
  });

  it("fails closed when protected mutation role tokens are missing unless test/dev mode explicitly opts in", async () => {
    const secure = makeApp(":memory:", {
      apiSecurity: {
        allowInsecureMissingRoleTokens: false,
      },
    });
    const insecure = makeApp(":memory:", {
      apiSecurity: {
        allowInsecureMissingRoleTokens: true,
      },
    });

    const denied = await post(secure.app, "/api/v1/sessions", { idempotencyKey: "auth-unconfigured-deny", payload: { label: "x" } });
    const challengeDenied = await post(secure.app, "/api/v1/sources/challenge", {});
    const artifactDenied = await post(secure.app, "/api/v1/quotes", {});
    const allowed = await post(insecure.app, "/api/v1/sessions", { idempotencyKey: "auth-unconfigured-allow", payload: { label: "x" } });
    const ready = await secure.app.request("/readyz");

    expect(denied.status).toBe(403);
    expect(denied.json.error.message).toContain("operator bearer token is not configured");
    expect(challengeDenied.status).toBe(403);
    expect(challengeDenied.json.error.message).toContain("challenge_submitter bearer token is not configured");
    expect(artifactDenied.status).toBe(403);
    expect(artifactDenied.json.error.message).toContain("artifact_signer bearer token is not configured");
    expect(allowed.status).toBe(201);
    expect((await ready.json()).apiSecurity.allowInsecureMissingRoleTokens).toBe(false);
  });

  it("falls back to the shared operator token for specialized roles when no role token is configured", async () => {
    const { app } = makeApp(":memory:", {
      apiSecurity: {
        operatorToken: "operator-test-token",
      },
    });

    const missingQuote = await post(app, "/api/v1/quotes", {});
    const allowedQuoteAuth = await post(app, "/api/v1/quotes", {}, { authorization: "Bearer operator-test-token" });

    expect(missingQuote.status).toBe(403);
    expect(allowedQuoteAuth.status).toBe(400);
  });

  it("uses a narrower configurable rate limit for session creation", async () => {
    const { app } = makeApp(":memory:", {
      apiSecurity: {
        sessionCreateRateLimitMax: 2,
        defaultRateLimitMax: 100,
      },
    });

    const first = await post(app, "/api/v1/sessions", { idempotencyKey: "rate-1", payload: { label: "a" } });
    const second = await post(app, "/api/v1/sessions", { idempotencyKey: "rate-2", payload: { label: "b" } });
    const third = await post(app, "/api/v1/sessions", { idempotencyKey: "rate-3", payload: { label: "c" } });

    expect(first.status).toBe(201);
    expect(first.headers.get("x-ratelimit-limit")).toBe("2");
    expect(second.status).toBe(201);
    expect(third.status).toBe(429);
    expect(third.json.error.code).toBe("rate_limited");
  });

  it("uses a narrower configurable rate limit for source challenge attempts", async () => {
    const { app } = makeApp(":memory:", {
      apiSecurity: {
        sourceChallengeRateLimitMax: 1,
        defaultRateLimitMax: 100,
      },
    });

    const first = await post(app, "/api/v1/sources/challenge", {});
    const second = await post(app, "/api/v1/sources/challenge", {});

    expect(first.status).toBe(400);
    expect(first.headers.get("x-ratelimit-limit")).toBe("1");
    expect(second.status).toBe(429);
    expect(second.json.error.code).toBe("rate_limited");
  });

  it("rejects unknown fields at strict public boundaries", async () => {
    const { app } = makeApp();
    const res = await post(app, "/api/v1/sessions", {
      idempotencyKey: "sess-strict",
      payload: { label: "strict" },
      extra: true,
    });

    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe("bad_request");
  });

  it("rejects invalid JSON and oversized JSON bodies as bad requests", async () => {
    const { app } = makeApp();
    const invalid = await app.request("/api/v1/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not-json",
    });
    const oversized = await app.request("/api/v1/sessions", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(3 * 1024 * 1024) },
      body: "{}",
    });
    const invalidJson = await invalid.json();
    const oversizedJson = await oversized.json();

    expect(invalid.status).toBe(400);
    expect(invalidJson.error.code).toBe("bad_request");
    expect(oversized.status).toBe(400);
    expect(oversizedJson.error.code).toBe("bad_request");
  });

  it("keeps the verifier route fail-closed", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-verify");

    const res = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-empty",
      payload: {},
    });

    expect(res.status).toBe(200);
    expect(res.json.data.proofLevel).toBe("fail_closed_no_claim");
    expect(res.json.data.claimMode).toBe("simulated");
    expect(res.json.data.paymentMode).toBe("mocked");
    expect(res.json.data.tokenMode).toBe("local-mocked");
    expect(res.json.data.identityMode).toBe("pending");
    expect(res.json.data.schemaOk).toBe(false);
    expect(res.json.data.proofChipAllowed).toBe(false);
    expect(res.json.data.finalVerifierComplete).toBe(false);
    expect(res.json.data.winnerClaimAllowed).toBe(false);
  });

  it("keeps schema-only verifier success from authorizing proof or winner claims", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-verify-schema-only");

    const res = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-schema-only",
      payload: {
        schemaOnly: true,
        receipt: schemaValidWinnerRequestedReceipt(),
      },
    });

    expect(res.status).toBe(200);
    expect(res.json.data.proofLevel).toBe("schema_only_no_claim");
    expect(res.json.data.schemaOk).toBe(true);
    expect(res.json.data.requestedWinnerClaimAllowed).toBe(true);
    expect(res.json.data.proofChipAllowed).toBe(false);
    expect(res.json.data.winnerClaimAllowed).toBe(false);
    expect(res.json.data.finalVerifierComplete).toBe(false);
  });

  it("fails verifier closed when a required indexer cursor is missing", async () => {
    const { app } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 105, logs: [] }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-required-indexer-missing");
    const status = await app.request("/api/v1/evidence/indexer-status");
    const statusJson = await status.json();
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-required-indexer-missing",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    expect(status.status).toBe(200);
    expect(statusJson.data.cursors[0]).toEqual(expect.objectContaining({ cursorId: "gate:indexer", status: "unconfigured" }));
    expect(verify.status).toBe(200);
    expect(verify.json.data.schemaOk).toBe(false);
    expect(verify.json.data.errors.some((error: string) => error.includes("required chain indexer cursor gate:indexer is missing"))).toBe(true);
    expect(verify.json.data.winnerClaimAllowed).toBe(false);
  });

  it("fails verifier closed when a required indexer cursor filter does not match the initialized cursor", async () => {
    const requiredAddress = "0x9999999999999999999999999999999999999999";
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ chainId: "84532", currentBlockNumber: 201, logs: [] }),
      requiredIndexerCursors: [
        {
          cursorId: "gate:indexer",
          chainId: "84532",
          address: requiredAddress,
          topics: [hex32("required-topic")],
          finalityDepth: 3,
        },
      ],
    });
    const sessionId = await createSession(app, "sess-required-indexer-filter-mismatch");
    insertCaughtUpIndexerCursor(ctx, { chainId: "84532", lastIndexedBlock: 190, finalizedHeadBlock: 190 });

    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-required-indexer-filter-mismatch",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    expect(verify.status).toBe(200);
    expect(verify.json.data.schemaOk).toBe(false);
    expect(verify.json.data.errors.some((error: string) => error.includes("required chain indexer cursor gate:indexer address mismatch"))).toBe(true);
    expect(verify.json.data.errors.some((error: string) => error.includes("required chain indexer cursor gate:indexer topics mismatch"))).toBe(true);
    expect(verify.json.data.errors.some((error: string) => error.includes("required chain indexer cursor gate:indexer finalityDepth mismatch"))).toBe(true);
  });

  it("fails verifier closed when indexed cursor chain or head conflicts with the provider", async () => {
    const mismatched = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ chainId: "1", currentBlockNumber: 201, logs: [] }),
    });
    const mismatchSessionId = await createSession(mismatched.app, "sess-indexer-chain-mismatch-verify");
    insertCaughtUpIndexerCursor(mismatched.ctx, { chainId: "84532", lastIndexedBlock: 200, finalizedHeadBlock: 200 });
    const mismatchVerify = await post(mismatched.app, "/api/v1/evidence/verify", {
      sessionId: mismatchSessionId,
      idempotencyKey: "verify-indexer-chain-mismatch",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    const rollback = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ chainId: "84532", currentBlockNumber: 150, logs: [] }),
    });
    const rollbackSessionId = await createSession(rollback.app, "sess-indexer-head-rollback-verify");
    insertCaughtUpIndexerCursor(rollback.ctx, { chainId: "84532", lastIndexedBlock: 200, finalizedHeadBlock: 200 });
    const rollbackVerify = await post(rollback.app, "/api/v1/evidence/verify", {
      sessionId: rollbackSessionId,
      idempotencyKey: "verify-indexer-head-rollback",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    expect(mismatchVerify.status).toBe(200);
    expect(mismatchVerify.json.data.schemaOk).toBe(false);
    expect(mismatchVerify.json.data.errors.some((error: string) => error.includes("provider is on chain 1"))).toBe(true);
    expect(rollbackVerify.status).toBe(200);
    expect(rollbackVerify.json.data.schemaOk).toBe(false);
    expect(rollbackVerify.json.data.errors.some((error: string) => error.includes("ahead of provider finalized head"))).toBe(true);
  });

  it("decodes raw viem RPC logs into PactFuse semantic event fields before indexer reconciliation", () => {
    const sessionId = hex32("decoded-log-session");
    const spendId = hex32("decoded-log-spend");
    const topics = encodeEventTopics({
      abi: PACTFUSE_CHAIN_EVENT_ABI,
      eventName: "SpendSettled",
      args: { sessionId, spendId },
    });
    const rawLog = {
      address: INDEXER_ADDRESS,
      blockNumber: "0x64",
      transactionHash: hex32("decoded-log-tx"),
      logIndex: "0x0",
      topics,
      data: "0x",
    };
    const normalized = normalizePactFuseChainLog(rawLog);

    expect(normalized.eventName).toBe("SpendSettled");
    expect(normalized.event).toBe("SpendSettled");
    expect(normalized.args).toEqual({ sessionId, spendId });
    expect(normalized.rawRpcLogHash).toBe(hashForTestJson(rawLog));
  });

  it("treats required indexer cursor topics as lower-case canonical filters", async () => {
    const topic = hex32("required-mixed-case-topic");
    const { app } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ chainId: "84532", currentBlockNumber: 105, logs: [] }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", topics: [topic.toLowerCase()], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-topic-case");
    const backfill = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-topic-case",
      payload: {
        cursorId: "gate:indexer",
        chainId: "84532",
        fromBlock: 100,
        toBlock: 100,
        finalityDepth: 2,
        topics: [uppercaseHexBody(topic)],
      },
    });
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-indexer-topic-case",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    expect(backfill.status).toBe(202);
    expect(verify.status).toBe(200);
    expect(verify.json.data.errors.some((error: string) => error.includes("topics mismatch"))).toBe(false);
  });

  it("does not expose MCP audit secrets or derived token hashes in health output", async () => {
    const { app } = makeApp();

    const health = await app.request("/healthz");
    const healthJson = await health.json();
    const serialized = JSON.stringify(healthJson);

    expect(health.status).toBe(200);
    expect(serialized).not.toContain("mcpAuditSecret");
    expect(serialized).not.toContain("mcpAuditTokenHash");
    expect(serialized).not.toContain(MCP_AUDIT_TOKEN);
    expect(serialized).not.toContain("gateIngestSecret");
    expect(serialized).not.toContain(GATE_INGEST_TOKEN);
  });

  it("surfaces disabled MCP audit readiness and rejects audit writes when the secret is missing", async () => {
    const { app } = makeApp(":memory:", { mcpAuditSecret: null });
    const ready = await app.request("/readyz");
    const readyJson = await ready.json();
    const auditPayload = {
      auditNonce: "audit-http-missing-secret",
      toolName: "pactfuse_get_judge_check",
      request: {},
      response: { ok: true },
      status: "succeeded",
    };
    const audit = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });

    expect(ready.status).toBe(200);
    expect(readyJson.mcpAudit).toEqual({ mode: "hmac-shared-secret", configured: false });
    expect(audit.status).toBe(403);
    expect(audit.json.error.code).toBe("forbidden");
  });

  it("keeps gate ingest and MCP audit HMAC secrets separated", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-gate-secret-split");
    const spendId = await registerSpend(app, sessionId);
    const body = gateEventEnvelope(sessionId, spendId, "gate-secret-split");
    logs.push(indexerLog("gate-secret-split", 100, body.payload));

    const wrongSecret = await post(app, "/api/v1/gate/events/ingest", body, {
      "x-pactfuse-gate-signature": signAuditPayload(MCP_AUDIT_TOKEN, body),
    });
    const rightSecret = await postSignedGateEvent(app, body);
    const ready = await app.request("/readyz");
    const readyJson = await ready.json();

    expect(wrongSecret.status).toBe(403);
    expect(wrongSecret.json.error.code).toBe("forbidden");
    expect(rightSecret.status).toBe(202);
    expect(readyJson.gateIngest).toEqual({ mode: "hmac-shared-secret", configured: true });
    expect(ctx.mcpAuditSecret).not.toBe(ctx.gateIngestSecret);
  });

  it("returns six pending Judge Check rows", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-judge");

    const res = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(json.data.rows).toHaveLength(6);
    expect(json.data.rows.every((row: { status: string }) => row.status === "pending")).toBe(true);
    expect(json.data.winnerClaimAllowed).toBe(false);
  });

  it("returns bad_request for missing evidence query parameters", async () => {
    const { app } = makeApp();

    const res = await app.request("/api/v1/evidence/judge-check");
    const json = await res.json();

    expect(res.status).toBe(400);
    expect(json.error.code).toBe("bad_request");
  });

  it("publishes fail-closed proof fields in the OpenAPI contract", async () => {
    const { app } = makeApp();

    const res = await app.request("/api/v1/openapi.json");
    const json = await res.json();
    const serialized = JSON.stringify(json);

    expect(res.status).toBe(200);
    expect(json.paths["/api/v1/evidence/verify"].post["x-pactfuse-proof-fields"]).toEqual([
      "schemaOk",
      "proofChipAllowed",
      "winnerClaimAllowed",
      "finalVerifierComplete",
    ]);
    expect(json.paths["/api/v1/evidence/verify"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/VerifyEvidenceInput",
    );
    expect(json.components.schemas.VerifyEvidenceInput.properties.payload.$ref).toBe(
      "#/components/schemas/VerifyEvidencePayload",
    );
    expect(json.components.schemas.VerifyEvidencePayload.additionalProperties).toBe(false);
    expect(json.components.schemas.VerifyEvidencePayload.properties.schemaOnly.default).toBe(false);
    expect(json.paths["/api/v1/sessions"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
      }),
    ]);
    expect(json.components.schemas.CreateSessionInput.properties.payload.additionalProperties).toBe(false);
    expect(json.components.schemas.CreateSessionInput.properties.payload.properties.modes.$ref).toBe(
      "#/components/schemas/RuntimeModes",
    );
    expect(json.paths["/api/v1/sources/challenge"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
        description: expect.stringContaining("PACTFUSE_CHALLENGE_SUBMITTER_TOKEN"),
      }),
    ]);
    expect(json.paths["/api/v1/sources/register"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/SourceRegisterInput",
    );
    expect(json.paths["/api/v1/sources/challenge"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/SourceChallengeInput",
    );
    expect(json.paths["/api/v1/spends/register-batch"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/SpendRegisterBatchInput",
    );
    expect(json.paths["/api/v1/caw/operations/build"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawOperationBuildInput",
    );
    expect(json.paths["/api/v1/caw/receipts/ingest"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawReceiptIngestInput",
    );
    expect(json.paths["/api/v1/quotes"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
        description: expect.stringContaining("PACTFUSE_ARTIFACT_SIGNER_TOKEN"),
      }),
    ]);
    expect(json.paths["/api/v1/caw/receipts/ingest"].post["x-pactfuse-proof-fields"]).toEqual([
      "proofAuthority",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/caw/receipts/ingest"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: true,
      }),
    ]);
    const cawIngestDataSchema = json.components.schemas.CawReceiptIngestResponse.oneOf[0].properties.data;
    expect(cawIngestDataSchema.required).toEqual([
      "receiptBundleHash",
      "operationId",
      "receiptCount",
      "canonicalReceiptCount",
      "status",
      "proofAuthority",
      "winnerClaimAllowed",
    ]);
    expect(cawIngestDataSchema.properties.status.enum).toEqual([
      "fixture_manual_receipt",
      "raw_ingested_pending_proof",
      "verified_policy_authority_structural",
    ]);
    expect(cawIngestDataSchema.properties.rawReceiptBundleHash.type).toBe("string");
    expect(json.paths["/api/v1/gate/events/ingest"].post["x-pactfuse-proof-fields"]).toEqual([
      "finalityStatus",
      "confirmations",
      "finalityDepth",
      "proofAuthority",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/gate/events/ingest"].post.parameters).toEqual([
      expect.objectContaining({
        name: "x-pactfuse-gate-signature",
        in: "header",
        required: true,
      }),
    ]);
    expect(json.paths["/api/v1/gate/events/ingest"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/GateEventIngestInput",
    );
    expect(json.paths["/api/v1/gate/events/ingest"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/GateEventIngestResponse",
    );
    expect(json.paths["/api/v1/indexer/backfill"].post["x-pactfuse-proof-fields"]).toEqual([
      "cursor.status",
      "cursor.lastIndexedBlock",
      "insertedLogCount",
      "proofAuthority",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/indexer/backfill"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
      }),
    ]);
    expect(json.paths["/api/v1/indexer/backfill"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ChainIndexerBackfillInput",
    );
    expect(json.paths["/api/v1/indexer/backfill"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ChainIndexerBackfillResponse",
    );
    expect(json.paths["/api/v1/evidence/indexer-status"].get["x-pactfuse-proof-fields"]).toEqual([
      "provider.ready",
      "cursors.status",
      "cursors.lagBlocks",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/evidence/indexer-status"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ChainIndexerStatusResponse",
    );
    expect(json.components.schemas.ChainIndexerBackfillPayload.required).toEqual(["cursorId", "chainId"]);
    expect(json.components.schemas.ChainIndexerBackfillResponse.oneOf[0].properties.data.properties.proofAuthority.const).toBe(false);
    expect(json.components.schemas.GateEventIngestPayload.required).toEqual([
      "event",
      "spendId",
      "txHash",
      "logIndex",
      "chainId",
      "blockNumber",
      "currentBlockNumber",
      "rawLogHash",
    ]);
	    expect(json.paths["/api/v1/artifacts/preflight"].post["x-pactfuse-proof-fields"]).toEqual([
	      "preflightId",
	      "artifactHashPreview",
	      "artifactCid",
	      "priceDisclosureHash",
	      "winnerClaimAllowed",
	    ]);
    expect(json.paths["/api/v1/artifacts/preflight"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactPreflightInput",
    );
	    expect(json.paths["/api/v1/quotes"].post["x-pactfuse-proof-fields"]).toEqual([
	      "preflightId",
	      "artifactCid",
	      "quoteSignedAfterPreflight",
	      "priceDisclosureHash",
	      "winnerClaimAllowed",
	    ]);
    expect(json.paths["/api/v1/quotes"].post.requestBody.content["application/json"].schema.$ref).toBe("#/components/schemas/QuoteInput");
	    expect(json.paths["/api/v1/artifacts/access-token"].post["x-pactfuse-proof-fields"]).toEqual([
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
    ]);
    expect(json.paths["/api/v1/artifacts/access-token"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
        description: expect.stringContaining("PACTFUSE_ARTIFACT_SIGNER_TOKEN"),
      }),
    ]);
    expect(json.paths["/api/v1/artifacts/access-token"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactAccessIssueInput",
    );
    expect(json.paths["/api/v1/artifacts/access-token"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactAccessIssueResponse",
    );
    expect(json.components.schemas.ArtifactAccessIssuePayload.required).toEqual(["spendId", "payer", "quoteId", "artifactHash", "artifactPayload"]);
    expect(json.components.schemas.ArtifactAccessIssueResponse.oneOf[0].properties.data.required).toEqual([
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
    ]);
    expect(json.paths["/api/v1/artifacts/refund"].post["x-pactfuse-proof-fields"]).toEqual([
      "spendId",
      "quoteId",
      "status",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/artifacts/refund"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactRefundInput",
    );
    expect(json.paths["/api/v1/artifacts/refund"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactRefundResponse",
    );
    expect(json.components.schemas.ArtifactRefundPayload.required).toEqual(["spendId", "quoteId", "reason"]);
    expect(json.paths["/api/v1/lease/execute"].post["x-pactfuse-proof-fields"]).toEqual([
      "leaseRunId",
      "bearerBound",
      "artifactHash",
      "transcriptHash",
      "leaseRunHash",
      "boundedToPinnedManifest",
      "manifestBindingHash",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/lease/execute"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: true,
      }),
    ]);
    expect(json.paths["/api/v1/lease/execute"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/LeaseExecuteInput",
    );
    expect(json.components.schemas.LeaseExecuteInput.properties.payload.$ref).toBe(
      "#/components/schemas/LeaseExecutePayload",
    );
    expect(json.components.schemas.LeaseExecutePayload.required).toEqual([
      "spendId",
      "payer",
      "artifactHash",
      "targetRepo",
      "targetCommit",
    ]);
    expect(json.paths["/api/v1/lease/execute"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/LeaseExecuteResponse",
    );
    expect(json.paths["/api/v1/artifacts/{sessionId}/{spendId}/{payer}/{artifactHash}"].get.parameters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "authorization",
          in: "header",
          required: true,
        }),
      ]),
    );
    expect(json.paths["/api/v1/quotes"].post.responses["201"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/QuoteResponse",
    );
    expect(json.components.schemas.QuoteResponse.oneOf[0].properties.data.properties.quoteSignedAfterPreflight.const).toBe(
      true,
    );
    expect(json.paths["/api/v1/mcp/audit"].post["x-pactfuse-proof-fields"]).toEqual([
      "proofAuthority",
      "winnerClaimAllowed",
      "requestHash",
      "responseHash",
    ]);
    expect(json.paths["/api/v1/mcp/audit"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/McpAuditResponse",
    );
    expect(json.paths["/api/v1/mcp/audit"].post.parameters).toEqual([
      expect.objectContaining({
        name: "x-pactfuse-audit-signature",
        in: "header",
        required: true,
      }),
    ]);
    expect(json.paths["/api/v1/mcp/audit"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/McpAdapterAuditPayload",
    );
    expect(json.components.schemas.McpAdapterAuditPayload.required).toEqual([
      "auditNonce",
      "toolName",
      "request",
      "response",
      "status",
    ]);
    expect(json.components.schemas.SessionScopedEnvelope.required).toEqual(["sessionId", "idempotencyKey"]);
    expect(
      json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.mcpAdapterCalls.items.required,
    ).toEqual([
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
    ]);
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.required).toEqual([
      "bundleType",
      "sessionId",
      "summaryMode",
      "asOfEventSeq",
      "asOfMcpAdapterCallCount",
      "winnerClaimAllowed",
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
    ]);
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("mcpAdapterCalls");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("rawCawReceiptBundles");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("canonicalCawReceipts");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("leaseRuns");
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.sources.items.required).toEqual([
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
    ]);
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.spends.items.required).toContain(
      "spendPreimage",
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.artifactPreflights.items.required).toContain(
      "sourceStateSnapshotHash",
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.quotes.items.required).toContain(
      "quoteHash",
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.artifactAccessTokens.items.required).toContain(
      "tokenHash",
    );
    expect(json.paths["/api/v1/evidence/runner-heartbeat"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/RunnerHeartbeatResponse",
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.rawCawReceiptBundles.items.required).toEqual([
      "bundleId",
      "sessionId",
      "operationId",
      "sourceLabel",
      "fetchedAt",
      "rawBundleHash",
      "rawBundle",
      "receiptCount",
      "createdAt",
    ]);
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.canonicalCawReceipts.items.required).toEqual([
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
    ]);
    expect(json.paths["/api/v1/evidence/{sessionId}/verify"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/VerifierRunResponse",
    );
    expect(json.paths["/api/v1/evidence/agent-transcript"].get["x-pactfuse-proof-fields"]).toEqual([
      "transcriptHash",
      "toolsCallHash",
      "boundedToPinnedManifest",
      "winnerClaimAllowed",
    ]);
    expect(json.components.schemas.AgentTranscriptResponse.oneOf[0].properties.data.properties.format.const).toBe(
      "mcp-json-rpc",
    );
    expect(json.components.schemas.AgentTranscriptResponse.oneOf[0].properties.data.properties.boundedToPinnedManifest.type).toBe("boolean");
    expect(json.components.schemas.FailClosedProofState.properties.proofChipAllowed.const).toBe(false);
    expect(json.components.schemas.FailClosedProofState.properties.winnerClaimAllowed.const).toBe(false);
    expect(json.components.schemas.FailClosedProofState.properties.finalVerifierComplete.const).toBe(false);
    expect(json.components.schemas.FailClosedProofState.properties.proofLevel.enum).toEqual([
      "schema_only_no_claim",
      "fail_closed_no_claim",
    ]);
    expect(json.components.schemas.FailClosedProofState.properties.claimMode.const).toBe("simulated");
    expect(json.components.schemas.FailClosedProofState.properties.paymentMode.const).toBe("mocked");
    expect(serialized).not.toContain('"verified"');
  });

  it("appends monotonic evidence event sequences", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-events");

    await registerSource(app, sessionId);
    await registerSpend(app, sessionId);

    const res = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const json = await res.json();
    const seqs = json.data.events.map((event: { eventSeq: number }) => event.eventSeq);

    expect(seqs).toEqual([1, 2, 3]);
    expect(json.data.eventRoot).toMatch(/^0x[0-9a-f]{64}$/);
    expect(json.data.agentTranscriptHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(json.data.asOfEventSeq).toBe(3);
    expect(json.data.asOfMcpAdapterCallCount).toBe(0);
  });

  it("verifies signed source identity when issuer and signature are provided", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-source-identity");
    const signed = await signedSourcePayloadForTest("signed-source");

    const res = await post(app, "/api/v1/sources/register", {
      sessionId,
      idempotencyKey: "signed-source-register",
      payload: signed.payload,
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const event = replayJson.data.events.find((candidate: { kind: string }) => candidate.kind === "source.registered");

    expect(res.status).toBe(201);
    expect(res.json.data.status).toBe("pending");
    expect(event.payload).toEqual(
      expect.objectContaining({
        sourceHash: signed.payload.sourceHash,
        sourceIdentityHash: signed.payload.sourceHash,
        identityVerified: true,
      }),
    );
    expect(replayJson.data.sources[0]).toEqual(
      expect.objectContaining({
        sourceHash: signed.payload.sourceHash,
        issuer: signed.payload.issuer,
        signature: signed.payload.signature,
      }),
    );
  });

  it("blocks source identity registrations with partial or invalid signatures", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-source-identity-blocked");
    const signed = await signedSourcePayloadForTest("blocked-source");
    const wrongIssuer = privateKeyToAccount(hex32("wrong-source-issuer")).address;
    const cases = [
      {
        key: "missing-signature",
        payload: { ...signed.payload, signature: undefined },
        expected: "source issuer and signature must be provided together",
      },
      {
        key: "bad-source-hash",
        payload: { ...signed.payload, sourceHash: hex32("bad-source-hash") },
        expected: "sourceHash does not match signed source identity",
      },
      {
        key: "wrong-issuer",
        payload: { ...signed.payload, issuer: wrongIssuer },
        expected: "source signature does not recover issuer",
      },
    ];

    for (const entry of cases) {
      const res = await post(app, "/api/v1/sources/register", {
        sessionId,
        idempotencyKey: `source-${entry.key}`,
        payload: entry.payload,
      });

      expect(res.status).toBe(422);
      expect(res.json.error.code).toBe("proof_blocked");
      expect(res.json.error.message).toContain(entry.expected);
    }
  });

  it("rejects source-bound spends whose spendId is not the W8.1 preimage hash", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-spend-binding-mismatch");
    await registerSource(app, sessionId);

    const res = await post(app, "/api/v1/spends/register-batch", {
      sessionId,
      idempotencyKey: "spend-register-mismatch",
      payload: {
        spends: [
          {
            spendId: hex32("wrong-spend-id"),
            pactId: "pact-c",
            toolId: "code-scan",
            payer: "0x1234",
            agentWallet: "0xabcd",
            sourceHashes: [hex32("source")],
            maxPriceAtomic: "1000",
            nonce: "nonce-1",
          },
        ],
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(res.status).toBe(422);
    expect(res.json.error.code).toBe("proof_blocked");
    expect(res.json.error.details.expectedSpendId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("spend.registered");
  });

  it("requires spend source hashes to be registered before spend binding", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-spend-missing-source");
    const spendId = await computeSpendIdForTest(app, sessionId, [hex32("missing-source")]);

    const res = await post(app, "/api/v1/spends/register-batch", {
      sessionId,
      idempotencyKey: "spend-register-missing-source",
      payload: {
        spends: [
          {
            spendId,
            pactId: "pact-c",
            toolId: "code-scan",
            payer: "0x1234",
            agentWallet: "0xabcd",
            sourceHashes: [hex32("missing-source")],
            maxPriceAtomic: "1000",
            nonce: "nonce-1",
          },
        ],
      },
    });

    expect(res.status).toBe(423);
    expect(res.json.error.code).toBe("proof_pending");
  });

  it("normalizes source hashes before source registration and spend binding", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-source-hash-canonical");
    const lowerSourceHash = hex32("source");
    const upperSourceHash = `0x${lowerSourceHash.slice(2).toUpperCase()}`;
    const source = await post(app, "/api/v1/sources/register", {
      sessionId,
      idempotencyKey: "src-register-uppercase",
      payload: {
        sourceId: "clean-source",
        sourceHash: upperSourceHash,
        manifestUrl: "https://example.com/manifest.json",
        manifestHash: hex32("manifest"),
        capabilityVector: defaultSourceCapabilityForTest(),
      },
    });
    const spendId = await computeSpendIdForTest(app, sessionId, [upperSourceHash]);
    const spend = await post(app, "/api/v1/spends/register-batch", {
      sessionId,
      idempotencyKey: "spend-register-uppercase-source",
      payload: {
        spends: [
          {
            spendId,
            pactId: "pact-c",
            toolId: "code-scan",
            payer: "0x1234",
            agentWallet: "0xabcd",
            sourceHashes: [upperSourceHash],
            maxPriceAtomic: "1000",
            nonce: "nonce-1",
          },
        ],
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(source.status).toBe(201);
    expect(source.json.data.sourceHash).toBe(lowerSourceHash);
    expect(spend.status).toBe(201);
    expect(replayJson.data.sources[0].sourceHash).toBe(lowerSourceHash);
    expect(replayJson.data.spends[0].sourceHashes).toEqual([lowerSourceHash]);
  });

  it("blocks rebinding an existing spend to a different payer or price", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-spend-rebind");
    const spendId = await registerSpend(app, sessionId);

    const rebind = await post(app, "/api/v1/spends/register-batch", {
      sessionId,
      idempotencyKey: "spend-register-rebind",
      payload: {
        spends: [
          {
            spendId,
            pactId: "pact-c",
            toolId: "code-scan",
            payer: "0xbeef",
            agentWallet: "0xabcd",
            sourceHashes: [hex32("source")],
            maxPriceAtomic: "2000",
            nonce: "nonce-1",
          },
        ],
      },
    });

    expect(rebind.status).toBe(422);
    expect(rebind.json.error.code).toBe("proof_blocked");
    expect(rebind.json.error.message).toContain("spendId does not match");
  });

  it("records operator key usage when scheduling a source challenge", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-challenge-key-used");
    await registerSource(app, sessionId);

    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "challenge-key-used",
      payload: {
        sourceHash: hex32("source"),
        reasonHash: hex32("challenge-reason"),
        evidenceRef: "https://example.com/challenge-evidence.json",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const keyEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "operator.key_used");
    const keyRow = ctx.db.sqlite
      .prepare("SELECT role, authority, status, use_count, authorized_methods_json FROM operator_keys")
      .get() as Record<string, unknown>;

    expect(challenge.status).toBe(202);
    expect(keyEvent).toEqual(
      expect.objectContaining({
        authority: "operator",
        payload: expect.objectContaining({
          role: "challenge_submitter",
          method: "SourceStateRegistry.challengeSource",
          operationId: challenge.json.data.challengeId,
          secretMaterialStored: false,
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(JSON.stringify(keyEvent.payload)).not.toContain(MCP_AUDIT_TOKEN);
    expect(keyRow).toEqual(
      expect.objectContaining({
        role: "challenge_submitter",
        authority: "operator",
        status: "active_demo_key",
        use_count: 1,
      }),
    );
    expect(JSON.parse(String(keyRow.authorized_methods_json))).toEqual(["SourceStateRegistry.challengeSource(bytes32,bytes32)"]);
  });

  it("resumes the SSE stream after an event id", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-sse");
    await registerSource(app, sessionId);

    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const firstEventId = replayJson.data.events[0].eventId;

    const stream = await app.request(`/api/v1/evidence/stream?sessionId=${sessionId}&afterEventId=${firstEventId}`);
    const text = await stream.text();

    expect(stream.status).toBe(200);
    expect(text).toContain("event: source.registered");
    expect(text).not.toContain("event: session.created");
  });

  it("rejects SSE resume cursors from another session", async () => {
    const { app } = makeApp();
    const sessionA = await createSession(app, "sess-sse-a");
    const sessionB = await createSession(app, "sess-sse-b");
    const replayA = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionA}`);
    const replayAJson = await replayA.json();

    const stream = await app.request(`/api/v1/evidence/stream?sessionId=${sessionB}&afterEventId=${replayAJson.data.events[0].eventId}`);
    const json = await stream.json();

    expect(stream.status).toBe(400);
    expect(json.error.code).toBe("bad_request");
    expect(json.error.message).toContain("afterEventId does not belong to this session");
  });

  it("does not let manual CAW receipt rows pass proof state", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-caw");

    const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "caw-manual",
      payload: {
        sourceLabel: "manual-row",
        receipts: [{ requestId: "manual", status: "manual" }],
        manual: true,
      },
    });
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();

    expect(ingest.status).toBe(202);
    expect(ingest.json.data.proofAuthority).toBe(false);
    expect(judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "caw_boundary")).toEqual(
      expect.objectContaining({
        status: "manual",
        authority: "fixture",
        evidenceEventId: ingest.json.evidenceEventId,
      }),
    );
    expect(judgeJson.data.rows.some((row: { status: string }) => row.status === "pass")).toBe(false);
    expect(judgeJson.data.winnerClaimAllowed).toBe(false);
  });

  it("requires non-manual CAW receipt ingest to bind an existing operation", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-caw-receipt-binding");
    const spendId = await registerSpend(app, sessionId);

    const missingOperationId = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "caw-receipt-missing-operation-id",
      payload: {
        sourceLabel: "caw-api",
        receipts: [{ requestId: "req-1", spendId }],
        manual: false,
      },
    });
    const unknownOperation = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "caw-receipt-unknown-operation",
      payload: {
        sourceLabel: "caw-api",
        operationId: "missing-operation",
        receipts: [{ requestId: "req-2", spendId }],
        manual: false,
      },
    });

    expect(missingOperationId.status).toBe(400);
    expect(missingOperationId.json.error.code).toBe("bad_request");
    expect(unknownOperation.status).toBe(404);
    expect(unknownOperation.json.error.code).toBe("not_found");
  });

  it("keeps non-manual CAW receipt ingest pending when the raw provider is unavailable", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-caw-raw-unconfigured");
    const spendId = await registerSpend(app, sessionId);
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-unconfigured-caw-op",
      payload: {
        spendId,
        operationKind: "approve",
        target: "0x1234",
        selector: "0x095ea7b3",
      },
    });

    const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-unconfigured-caw-receipt",
      payload: {
        sourceLabel: "caw-api",
        operationId: operation.json.data.operationId,
        manual: false,
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(operation.status).toBe(201);
    expect(ingest.status).toBe(423);
    expect(ingest.json.error.code).toBe("proof_pending");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("caw.receipt.ingested.raw");
  });

  it("protects CAW receipt ingest with a bearer token when configured", async () => {
    const { app } = makeApp(":memory:", { cawIngestToken: "caw-ingest-secret" });
    const sessionId = await createSession(app, "sess-caw-ingest-auth");
    const body = {
      sessionId,
      idempotencyKey: "ingest-auth-check",
      payload: {
        sourceLabel: "operator-entry",
        receipts: [{ requestId: "manual-auth-check" }],
        manual: true,
      },
    };

    const missing = await post(app, "/api/v1/caw/receipts/ingest", body, { "x-test-skip-caw-auth": "1" });
    const wrong = await post(app, "/api/v1/caw/receipts/ingest", body, { authorization: "Bearer wrong" });
    const allowed = await post(app, "/api/v1/caw/receipts/ingest", body, { authorization: "Bearer caw-ingest-secret" });

    expect(missing.status).toBe(403);
    expect(wrong.status).toBe(403);
    expect(allowed.status).toBe(202);
  });

  it("fails closed when CAW receipt ingest token is not configured", async () => {
    const { app } = makeApp(":memory:", { cawIngestToken: null });
    const sessionId = await createSession(app, "sess-caw-ingest-unconfigured");

    const res = await post(
      app,
      "/api/v1/caw/receipts/ingest",
      {
        sessionId,
        idempotencyKey: "ingest-unconfigured",
        payload: {
          sourceLabel: "manual-row",
          receipts: [{ requestId: "manual" }],
          manual: true,
        },
      },
      { "x-test-skip-caw-auth": "1" },
    );

    expect(res.status).toBe(403);
    expect(res.json.error.code).toBe("forbidden");
    expect(res.json.error.message).toContain("not configured");
  });

  it("fetches raw CAW receipts from a configured export source", async () => {
    const requests: Array<{ url: string; authorization: string | undefined }> = [];
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      requests.push({ url: url.toString(), authorization: req.headers.authorization });
      const operationId = url.searchParams.get("operation_id");
      const sessionId = url.searchParams.get("session_id");
      const operationKind = url.searchParams.get("operation_kind") ?? "activate_tool";
      const receipts =
        operationId && sessionId
          ? [
              {
                ...cawReceiptFields("https-source"),
                sessionId,
                operationId,
                operationKind,
                target: "0x1234",
                selector: "0xabcdef12",
              },
            ]
          : [];
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ result: { items: receipts } }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("test server did not expose a TCP address");
      }
      const { app } = makeApp(":memory:", {
        caw: createHttpsCawReceiptSource({
          exportUrl: `http://127.0.0.1:${address.port}/audit`,
          apiKey: "caw-api-key",
          walletId: "wallet-1",
        }),
      });
      const ready = await app.request("/readyz");
      const readyJson = await ready.json();
      const sessionId = await createSession(app, "sess-caw-https-source");
      const spendId = await registerSpend(app, sessionId);
      const operation = await post(app, "/api/v1/caw/operations/build", {
        sessionId,
        idempotencyKey: "build-https-caw-op",
        payload: {
          spendId,
          operationKind: "activate_tool",
          target: "0x1234",
          selector: "0xabcdef12",
        },
      });

      const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
        sessionId,
        idempotencyKey: "ingest-https-caw-receipt",
        payload: {
          sourceLabel: "caw-api",
          operationId: operation.json.data.operationId,
          manual: false,
        },
      });

      expect(ready.status).toBe(200);
      expect(readyJson.proofProviders.find((provider: { name: string }) => provider.name === "caw").ready).toBe(true);
      expect(ingest.status).toBe(202);
      expect(ingest.json.data.canonicalReceiptCount).toBe(1);
      expect(requests.every((request) => request.authorization === "Bearer caw-api-key")).toBe(true);
      expect(requests.some((request) => request.url.includes("wallet_id=wallet-1"))).toBe(true);
      expect(requests.some((request) => request.url.includes(`operation_id=${operation.json.data.operationId}`))).toBe(true);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it("links non-manual CAW receipt ingest to a built operation", async () => {
    const rawReceipt = {
      ...cawReceiptFields("linked"),
      operationKind: "activate_tool",
      target: "0x1234",
      selector: "0xabcdef12",
    };
    const { app, ctx } = makeApp(":memory:", { caw: createFakeCawReceiptSource({ receipts: [rawReceipt] }) });
    const sessionId = await createSession(app, "sess-caw-receipt-linked");
    const spendId = await registerSpend(app, sessionId);

    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-linked-caw-op",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
      },
    });
    const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-linked-caw-receipt",
      payload: {
        sourceLabel: "caw-api",
        operationId: operation.json.data.operationId,
        receipts: [{ ...rawReceipt, operationId: operation.json.data.operationId, sessionId }],
        manual: false,
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const event = replayJson.data.events.find((candidate: { kind: string }) => candidate.kind === "caw.receipt.ingested.raw");
    const cawJudgeRow = replayJson.data.judgeCheck.rows.find((row: { rowId: string }) => row.rowId === "caw_boundary");
    const bundleRow = ctx.db.sqlite
      .prepare("SELECT operation_id, source_label, receipt_count, raw_bundle_hash, raw_bundle_json FROM caw_raw_receipt_bundles")
      .get() as Record<string, unknown>;

    expect(operation.status).toBe(201);
    expect(ingest.status).toBe(202);
    expect(ingest.json.data.operationId).toBe(operation.json.data.operationId);
    expect(ingest.json.data.receiptCount).toBe(1);
    expect(ingest.json.data.canonicalReceiptCount).toBe(1);
    expect(ingest.json.data.status).toBe("verified_policy_authority_structural");
    expect(ingest.json.data.proofAuthority).toBe(true);
    expect(event.payload.operationId).toBe(operation.json.data.operationId);
    expect(event.payload.receiptCount).toBe(1);
    expect(event.payload.manual).toBe(false);
    expect(event.payload.rawReceiptBundleHash).toBe(ingest.json.data.rawReceiptBundleHash);
    expect(event.payload.authorityProofHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(event.payload.authorityProofStatus).toBe("verified_policy_authority_structural");
    expect(event.payload.proofAuthority).toBe(true);
    expect(event.payload.finalVerifierComplete).toBe(false);
    expect(cawJudgeRow).toEqual(
      expect.objectContaining({
        status: "pass",
        authority: "proof",
        evidenceEventId: ingest.json.evidenceEventId,
      }),
    );
    expect(replayJson.data.cawReceiptOperations).toEqual([
      expect.objectContaining({
        operationId: operation.json.data.operationId,
        receiptBundleHash: ingest.json.data.rawReceiptBundleHash,
        status: "verified_policy_authority_structural",
      }),
    ]);
    expect(replayJson.data.rawCawReceiptBundles).toEqual([
      expect.objectContaining({
        operationId: operation.json.data.operationId,
        sourceLabel: "caw-api",
        rawBundleHash: ingest.json.data.rawReceiptBundleHash,
        receiptCount: 1,
      }),
    ]);
    expect(replayJson.data.rawCawReceiptBundles[0].rawBundle.receipts[0].operationId).toBe(operation.json.data.operationId);
    expect(replayJson.data.canonicalCawReceipts).toEqual([
      expect.objectContaining({
        operationId: operation.json.data.operationId,
        sourceLabel: "caw-api",
        effect: "allow",
        policyDigest: rawReceipt.policyDigest,
        paramsDigest: rawReceipt.paramsDigest,
      }),
    ]);
    const verifyTamperedRawCaw = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-raw-caw-bundle-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          rawCawReceiptBundles: [],
        },
      },
    });
    const verifyTamperedCanonicalCaw = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-canonical-caw-receipt-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          canonicalCawReceipts: [],
        },
      },
    });
    expect(verifyTamperedRawCaw.json.data.schemaOk).toBe(false);
    expect(verifyTamperedRawCaw.json.data.errors).toContain("replayBundle.rawCawReceiptBundles does not match the server snapshot");
    expect(verifyTamperedCanonicalCaw.json.data.schemaOk).toBe(false);
    expect(verifyTamperedCanonicalCaw.json.data.errors).toContain("replayBundle.canonicalCawReceipts does not match the server snapshot");
    expect(bundleRow).toEqual(
      expect.objectContaining({
        operation_id: operation.json.data.operationId,
        source_label: "caw-api",
        receipt_count: 1,
        raw_bundle_hash: ingest.json.data.rawReceiptBundleHash,
      }),
    );
    expect(JSON.stringify(JSON.parse(String(bundleRow.raw_bundle_json)))).toContain(operation.json.data.operationId);
  });

  it("does not let later CAW receipt ingests overwrite an operation bundle", async () => {
    const rawReceipt = {
      ...cawReceiptFields("no-overwrite"),
      operationKind: "activate_tool",
      target: "0x1234",
      selector: "0xabcdef12",
    };
    const { app } = makeApp(":memory:", { caw: createFakeCawReceiptSource({ receipts: [rawReceipt] }) });
    const sessionId = await createSession(app, "sess-caw-no-overwrite");
    const spendId = await registerSpend(app, sessionId);
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-no-overwrite-caw-op",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
      },
    });
    const rawIngest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-no-overwrite-raw",
      payload: {
        sourceLabel: "caw-api",
        operationId: operation.json.data.operationId,
        manual: false,
      },
    });
    const manualOverwrite = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-no-overwrite-manual",
      payload: {
        sourceLabel: "operator-entry",
        operationId: operation.json.data.operationId,
        receipts: [{ operationId: operation.json.data.operationId, sessionId, note: "manual overwrite attempt" }],
        manual: true,
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(rawIngest.status).toBe(202);
    expect(manualOverwrite.status).toBe(409);
    expect(manualOverwrite.json.error.code).toBe("idempotency_conflict");
    expect(replayJson.data.cawReceiptOperations[0]).toEqual(
      expect.objectContaining({
        operationId: operation.json.data.operationId,
        receiptBundleHash: rawIngest.json.data.rawReceiptBundleHash,
        status: "verified_policy_authority_structural",
      }),
    );
  });

  it("blocks raw CAW receipt bundles with duplicate canonical receipt rows", async () => {
    const rawReceipt = {
      ...cawReceiptFields("duplicate-canonical"),
      operationKind: "activate_tool",
      target: "0x1234",
      selector: "0xabcdef12",
    };
    const { app } = makeApp(":memory:", { caw: createFakeCawReceiptSource({ receipts: [rawReceipt, rawReceipt] }) });
    const sessionId = await createSession(app, "sess-caw-duplicate-canonical");
    const spendId = await registerSpend(app, sessionId);
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-duplicate-canonical",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
      },
    });

    const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-duplicate-canonical",
      payload: {
        sourceLabel: "caw-api",
        operationId: operation.json.data.operationId,
        manual: false,
      },
    });

    expect(operation.status).toBe(201);
    expect(ingest.status).toBe(422);
    expect(ingest.json.error.code).toBe("proof_blocked");
    expect(ingest.json.error.message).toContain("duplicate canonical receipt rows");
  });

  it("blocks raw CAW receipt bundles that do not contain the requested operation", async () => {
    const { app } = makeApp(":memory:", {
      caw: createFakeCawReceiptSource({
        receipts: [
          {
            ...cawReceiptFields("other-operation"),
            operationId: "other-operation",
            operationKind: "activate_tool",
            target: "0x1234",
            selector: "0xabcdef12",
          },
        ],
      }),
    });
    const sessionId = await createSession(app, "sess-caw-raw-operation-missing");
    const spendId = await registerSpend(app, sessionId);
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-missing-raw-op",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
      },
    });

    const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
      sessionId,
      idempotencyKey: "ingest-missing-raw-op",
      payload: {
        sourceLabel: "caw-api",
        operationId: operation.json.data.operationId,
        manual: false,
      },
    });

    expect(operation.status).toBe(201);
    expect(ingest.status).toBe(422);
    expect(ingest.json.error.code).toBe("proof_blocked");
    expect(ingest.json.error.message).toContain("does not contain the requested operation");
  });

  it.each(["sessionId", "operationKind", "target", "selector"])(
    "blocks raw CAW receipt bundles that omit %s from the operation link",
    async (missingField) => {
      const rawReceipt: Record<string, unknown> = {
        ...cawReceiptFields(`missing-${missingField.toLowerCase()}`),
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
        [missingField]: undefined,
      };
      const { app } = makeApp(":memory:", { caw: createFakeCawReceiptSource({ receipts: [rawReceipt] }) });
      const sessionId = await createSession(app, `sess-caw-raw-missing-${missingField.toLowerCase()}`);
      const spendId = await registerSpend(app, sessionId);
      const operation = await post(app, "/api/v1/caw/operations/build", {
        sessionId,
        idempotencyKey: `build-missing-${missingField.toLowerCase()}-raw-op`,
        payload: {
          spendId,
          operationKind: "activate_tool",
          target: "0x1234",
          selector: "0xabcdef12",
        },
      });

      const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
        sessionId,
        idempotencyKey: `ingest-missing-${missingField.toLowerCase()}-raw-op`,
        payload: {
          sourceLabel: "caw-api",
          operationId: operation.json.data.operationId,
          manual: false,
        },
      });

      expect(operation.status).toBe(201);
      expect(ingest.status).toBe(422);
      expect(ingest.json.error.code).toBe("proof_blocked");
      expect(ingest.json.error.message).toContain("does not contain the requested operation");
    },
  );

  it.each(["walletAddress", "policyDigest", "paramsDigest", "requestId", "txCount", "expiry", "txHash"])(
    "blocks raw CAW receipt bundles that omit canonical %s",
    async (missingField) => {
      const rawReceipt: Record<string, unknown> = {
        ...cawReceiptFields(`missing-canonical-${missingField.toLowerCase()}`),
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
        [missingField]: undefined,
      };
      const { app } = makeApp(":memory:", { caw: createFakeCawReceiptSource({ receipts: [rawReceipt] }) });
      const sessionId = await createSession(app, `sess-caw-canonical-missing-${missingField.toLowerCase()}`);
      const spendId = await registerSpend(app, sessionId);
      const operation = await post(app, "/api/v1/caw/operations/build", {
        sessionId,
        idempotencyKey: `build-canonical-missing-${missingField.toLowerCase()}`,
        payload: {
          spendId,
          operationKind: "activate_tool",
          target: "0x1234",
          selector: "0xabcdef12",
        },
      });

      const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
        sessionId,
        idempotencyKey: `ingest-canonical-missing-${missingField.toLowerCase()}`,
        payload: {
          sourceLabel: "caw-api",
          operationId: operation.json.data.operationId,
          manual: false,
        },
      });

      expect(operation.status).toBe(201);
      expect(ingest.status).toBe(422);
      expect(ingest.json.error.code).toBe("proof_blocked");
      expect(ingest.json.error.message).toContain("canonical CAW");
    },
  );

  it("requires signed gate event ingest before accepting observed logs", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-gate-auth");
    const spendId = await registerSpend(app, sessionId);
    const body = gateEventEnvelope(sessionId, spendId, "gate-auth-observed");

    const unsigned = await post(app, "/api/v1/gate/events/ingest", body);
    const signed = await postSignedGateEvent(app, body);

    expect(unsigned.status).toBe(403);
    expect(unsigned.json.error.code).toBe("forbidden");
    expect(signed.status).toBe(202);
    expect(signed.json.data.finalityStatus).toBe("observed_finalizing");
    expect(signed.json.data.proofAuthority).toBe(false);
  });

  it("keeps sub-finality gate observations out of the proof chain", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-gate-observed", { finalityDepth: 3 });
    const spendId = await registerSpend(app, sessionId);
    const body = gateEventEnvelope(sessionId, spendId, "gate-observed-subd", {
      blockNumber: 100,
      currentBlockNumber: 101,
      txHash: hex32("gate-observed-tx"),
      rawLogHash: hex32("gate-observed-log"),
    });

    const observed = await postSignedGateEvent(app, body);
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const events = replayJson.data.events as Array<{
      kind: string;
      authority: string;
      prevProofEventHash: string | null;
      payload: Record<string, unknown>;
    }>;
    const observedEvent = events.find((event) => event.kind === "gate.spend_settled.observed");

    expect(observed.status).toBe(202);
    expect(observed.json.data.finalityStatus).toBe("observed_finalizing");
    expect(observed.json.data.confirmations).toBe(2);
    expect(observed.json.data.finalityDepth).toBe(3);
    expect(observed.json.data.proofAuthority).toBe(false);
    expect(observed.json.data.winnerClaimAllowed).toBe(false);
    expect(observedEvent).toEqual(
      expect.objectContaining({
        authority: "delivery",
        prevProofEventHash: null,
      }),
    );
    expect(events.map((event) => event.kind)).not.toContain("gate.spend_settled");
  });

  it("keeps finalized gate proof pending when no chain provider can re-fetch the log", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-gate-finality-unconfigured", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const observedBody = gateEventEnvelope(sessionId, spendId, "gate-unconfigured-observed", {
      blockNumber: 100,
      currentBlockNumber: 100,
      txHash: hex32("gate-unconfigured-tx"),
      rawLogHash: hex32("gate-unconfigured-log"),
    });
    const finalizedBody = {
      ...observedBody,
      idempotencyKey: "gate-unconfigured-finalized",
      payload: { ...observedBody.payload, currentBlockNumber: 101 },
    };

    const observed = await postSignedGateEvent(app, observedBody);
    const finalized = await postSignedGateEvent(app, finalizedBody);
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const kinds = replayJson.data.events.map((event: { kind: string }) => event.kind);

    expect(observed.status).toBe(202);
    expect(finalized.status).toBe(423);
    expect(finalized.json.error.code).toBe("proof_pending");
    expect(finalized.json.error.message).toContain("chain proof provider is not ready");
    expect(kinds).toContain("gate.spend_settled.observed");
    expect(kinds).not.toContain("gate.spend_settled");
  });

  it("rejects finalized gate proofs when the re-fetched log lacks decoded event semantics", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const chain = createFakeIndexerChainClient({ currentBlockNumber: 101, logs });
    const { app } = makeApp(":memory:", {
      chain: {
        ...chain,
        getLogs: async () => logs,
      },
    });
    const sessionId = await createSession(app, "sess-gate-finality-undecoded", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const body = gateEventEnvelope(sessionId, spendId, "gate-undecoded-log", {
      blockNumber: 100,
      currentBlockNumber: 101,
      txHash: hex32("gate-undecoded-tx"),
      rawLogHash: hex32("gate-undecoded-log"),
    });
    logs.push(
      indexerLog("gate-undecoded", 100, {
        transactionHash: hex32("gate-undecoded-tx"),
        rawLogHash: hex32("gate-undecoded-log"),
        logIndex: 0,
      }),
    );

    const finalized = await postSignedGateEvent(app, body);

    expect(finalized.status).toBe(423);
    expect(finalized.json.error.code).toBe("proof_pending");
    expect(finalized.json.error.message).toContain("claimed gate event log was not found on chain");
  });

  it("finalizes gate settlement only from indexed public-chain logs and records a matching proof row", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-gate-finalized", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const observedBody = gateEventEnvelope(sessionId, spendId, "gate-finalized-observed", {
      blockNumber: 100,
      currentBlockNumber: 100,
      txHash: hex32("gate-finalized-tx"),
      rawLogHash: hex32("gate-finalized-log"),
    });
    const finalizedBody = {
      ...observedBody,
      idempotencyKey: "gate-finalized-depth",
      payload: { ...observedBody.payload, currentBlockNumber: 101 },
    };
    logs.push(
      indexerLog("gate-finalized", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("gate-finalized-tx"),
        rawLogHash: hex32("gate-finalized-log"),
      }),
    );

    const observed = await postSignedGateEvent(app, observedBody);
    const finalized = await postSignedGateEvent(app, finalizedBody);
    const worker = await runIndexerWorkerOnce(ctx, {
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 1, address: INDEXER_ADDRESS }],
    });
    const staleReplay = await postSignedGateEvent(app, {
      ...observedBody,
      idempotencyKey: "gate-finalized-stale-replay",
      payload: { ...observedBody.payload, currentBlockNumber: 100 },
    });
    const row = ctx.db.sqlite
      .prepare("SELECT * FROM gate_chain_events WHERE session_id = ? AND spend_id = ?")
      .get(sessionId, spendId) as Record<string, unknown>;
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const events = replayJson.data.events as Array<{
      eventId: string;
      kind: string;
      authority: string;
      prevProofEventHash: string | null;
      payload: Record<string, unknown>;
    }>;
    const observedEvent = events.find((event) => event.kind === "gate.spend_settled.observed");
    const proofEvent = events.find((event) => event.kind === "gate.spend_settled");

    expect(observed.status).toBe(202);
    expect(observed.json.data.finalityStatus).toBe("observed_finalizing");
    expect(finalized.status).toBe(202);
    expect(finalized.json.data.finalityStatus).toBe("observed_finalizing");
    expect(finalized.json.data.confirmations).toBe(2);
    expect(finalized.json.data.proofAuthority).toBe(false);
    expect(worker.status).toBe("succeeded");
    expect(staleReplay.status).toBe(202);
    expect(staleReplay.json.data.finalityStatus).toBe("finalized");
    expect(staleReplay.json.data.confirmations).toBe(2);
    expect(row.status).toBe("finalized");
    expect(row.confirmations).toBe(2);
    expect(row.observed_event_id).toBe(observed.json.data.observedEventId);
    expect(row.finalized_event_id).toBe(proofEvent?.eventId);
    expect(proofEvent).toEqual(
      expect.objectContaining({
        eventId: staleReplay.json.data.finalizedEventId,
        authority: "proof",
      }),
    );
    expect(proofEvent?.prevProofEventHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proofEvent?.payload).toEqual(
      expect.objectContaining({
        gateEventId: finalized.json.data.gateEventId,
        observedEventId: observedEvent?.eventId,
        indexedLogId: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        cursorId: "gate:indexer",
        finalityStatus: "finalized",
        contractStateVerified: true,
        contractAddress: INDEXER_ADDRESS,
        contractFunction: "registeredSpend",
        contractSpendState: "Settled",
        proofAuthority: true,
        winnerClaimAllowed: false,
      }),
    );
  });

  it("blocks mutated gate log replay for the same tx/log/event identity", async () => {
    const { app } = makeApp(":memory:", { chain: createFakeGateChainClient() });
    const sessionId = await createSession(app, "sess-gate-mutated", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const observedBody = gateEventEnvelope(sessionId, spendId, "gate-mutated-observed", {
      txHash: hex32("gate-mutated-tx"),
      rawLogHash: hex32("gate-mutated-log-a"),
      blockNumber: 100,
      currentBlockNumber: 100,
    });
    const mutatedBody = {
      ...observedBody,
      idempotencyKey: "gate-mutated-finalize",
      payload: {
        ...observedBody.payload,
        currentBlockNumber: 101,
        rawLogHash: hex32("gate-mutated-log-b"),
      },
    };

    const observed = await postSignedGateEvent(app, observedBody);
    const mutated = await postSignedGateEvent(app, mutatedBody);
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const kinds = replayJson.data.events.map((event: { kind: string }) => event.kind);

    expect(observed.status).toBe(202);
    expect(mutated.status).toBe(422);
    expect(mutated.json.error.code).toBe("proof_blocked");
    expect(kinds).toContain("gate.spend_settled.observed");
    expect(kinds).not.toContain("gate.spend_settled");
  });

  it("blocks gate and indexer payloads when provider chainId differs", async () => {
    const gateApp = makeApp(":memory:", { chain: createFakeGateChainClient(101, "1") }).app;
    const sessionId = await createSession(gateApp, "sess-gate-chain-mismatch", { finalityDepth: 2 });
    const spendId = await registerSpend(gateApp, sessionId);
    const observedBody = gateEventEnvelope(sessionId, spendId, "gate-chain-mismatch-observed", {
      txHash: hex32("gate-chain-mismatch-tx"),
      rawLogHash: hex32("gate-chain-mismatch-log"),
      blockNumber: 100,
      currentBlockNumber: 100,
    });
    const finalizedBody = {
      ...observedBody,
      idempotencyKey: "gate-chain-mismatch-finalized",
      payload: { ...observedBody.payload, currentBlockNumber: 101 },
    };
    const observed = await postSignedGateEvent(gateApp, observedBody);
    const finalized = await postSignedGateEvent(gateApp, finalizedBody);
    const indexerApp = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({
        chainId: "1",
        currentBlockNumber: 101,
        logs: [indexerLog("chain-mismatch", 100)],
      }),
    }).app;
    const backfill = await post(indexerApp, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-chain-mismatch",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100 },
    });

    expect(observed.status).toBe(202);
    expect(finalized.status).toBe(422);
    expect(finalized.json.error.code).toBe("proof_blocked");
    expect(finalized.json.error.message).toContain("chainId mismatch");
    expect(backfill.status).toBe(422);
    expect(backfill.json.error.code).toBe("proof_blocked");
    expect(backfill.json.error.message).toContain("chainId mismatch");
  });

  it("blocks verifier and same-log revival after a finalized gate reorg", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-gate-reorg", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "gate-reorg");
    const reorgBody = gateEventEnvelope(sessionId, spendId, "gate-reorg-invalidated", {
      txHash: hex32("gate-reorg-tx"),
      rawLogHash: hex32("gate-reorg-log"),
      blockNumber: 100,
      currentBlockNumber: 101,
      reorged: true,
    });
    const reviveBody = {
      ...reorgBody,
      idempotencyKey: "gate-reorg-revive",
      payload: { ...reorgBody.payload, reorged: false, currentBlockNumber: 102 },
    };

    const reorg = await postSignedGateEvent(app, reorgBody);
    const revive = await postSignedGateEvent(app, reviveBody);
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-gate-reorg",
      payload: {
        schemaOnly: true,
        receipt: schemaValidWinnerRequestedReceipt(),
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const reorgEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "reorg.invalidated");
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const settlementRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "c_settlement");

    expect(reorg.status).toBe(202);
    expect(reorg.json.data.finalityStatus).toBe("reorg_invalidated");
    expect(reorg.json.data.proofAuthority).toBe(true);
    expect(reorgEvent).toEqual(
      expect.objectContaining({
        authority: "proof",
        payload: expect.objectContaining({
          invalidatedFinalizedEventId: finalized.finalizedEventId,
          finalityStatus: "reorg_invalidated",
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(revive.status).toBe(422);
    expect(revive.json.error.code).toBe("proof_blocked");
    expect(verify.status).toBe(200);
    expect(verify.json.data.schemaOk).toBe(false);
    expect(verify.json.data.winnerClaimAllowed).toBe(false);
    expect(verify.json.data.errors.some((error: string) => error.includes("reorg.invalidated"))).toBe(true);
    expect(settlementRow).toEqual(
      expect.objectContaining({
        status: "blocked",
        authority: "proof",
        evidenceEventId: reorgEvent?.eventId,
      }),
    );
  });

  it("keeps artifact reads bearer-bound and validates path parameters", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    const payer = "0x1234";
    const artifactUrl = `/api/v1/artifacts/${sessionId}/${spendId}/${payer}/${artifactHash}`;
    const uppercaseArtifactHash = `0x${artifactHash.slice(2).toUpperCase()}`;
    const wrongPayer = "0xabcd";

    const pending = await app.request(artifactUrl);
    const pendingJson = await pending.json();
    const invalidPayer = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/not-a-hex/${artifactHash}`);
    const invalidJson = await invalidPayer.json();
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-settlement");
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-token",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const bearerToken = issued.json.data.accessToken as string;
    const issuedReplay = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-token",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const duplicateIssue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-token-duplicate",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const tokenRow = ctx.db.sqlite
      .prepare("SELECT issued_by_verifier_run_id, settlement_event_id FROM artifact_access_tokens WHERE token_id = ?")
      .get(issued.json.data.tokenId) as { issued_by_verifier_run_id: string; settlement_event_id: string } | undefined;
    const verifierRun = ctx.db.sqlite
      .prepare("SELECT schema_ok FROM verifier_runs WHERE session_id = ? AND verifier_run_id = ?")
      .get(sessionId, issued.json.data.verifierRunId) as { schema_ok: number } | undefined;
    const issuedEvent = ctx.db.sqlite
      .prepare("SELECT kind, authority, payload_json FROM evidence_events WHERE event_id = ?")
      .get(issued.json.evidenceEventId) as { kind: string; authority: string; payload_json: string } | undefined;
    const issuedPayload = issuedEvent ? (JSON.parse(issuedEvent.payload_json) as Record<string, unknown>) : {};
    const missingBearer = await app.request(artifactUrl);
    const missingBearerJson = await missingBearer.json();
    const wrongBearer = await app.request(artifactUrl, { headers: { authorization: "Bearer wrong-token" } });
    const wrongBearerJson = await wrongBearer.json();
    const allowed = await app.request(artifactUrl, { headers: { authorization: `Bearer ${bearerToken}` } });
    const allowedJson = await allowed.json();
    const allowedUppercaseHash = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/${payer}/${uppercaseArtifactHash}`, {
      headers: { authorization: `Bearer ${bearerToken}` },
    });
    const allowedUppercaseHashJson = await allowedUppercaseHash.json();
    const payerMismatch = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/${wrongPayer}/${artifactHash}`, {
      headers: { authorization: `Bearer ${bearerToken}` },
    });
    const payerMismatchJson = await payerMismatch.json();

    expect(issued.status).toBe(202);
    expect(issuedReplay.status).toBe(202);
    expect(issuedReplay.json.requestId).toBe(issued.json.requestId);
    expect(duplicateIssue.status).toBe(409);
    expect(duplicateIssue.json.error.code).toBe("idempotency_conflict");
    expect(issued.json.data).toEqual(
      expect.objectContaining({
        spendId,
        payer,
        artifactHash,
        tokenHash: hex32(bearerToken),
        bearerBound: true,
        accessProofLevel: "delivery_access_only",
        proofChipAllowed: false,
        finalVerifierComplete: false,
        proofAuthority: false,
        winnerClaimAllowed: false,
      }),
    );
    expect(tokenRow).toEqual(
      expect.objectContaining({
        issued_by_verifier_run_id: issued.json.data.verifierRunId,
        settlement_event_id: issued.json.data.settlementEventId,
      }),
    );
    expect(verifierRun?.schema_ok).toBe(1);
    expect(issuedEvent).toEqual(expect.objectContaining({ kind: "artifact.access_token.issued", authority: "delivery" }));
    expect(issuedPayload).toEqual(
      expect.objectContaining({
        tokenId: issued.json.data.tokenId,
        tokenHash: issued.json.data.tokenHash,
        verifierRunId: issued.json.data.verifierRunId,
        settlementEventId: issued.json.data.settlementEventId,
        accessProofLevel: "delivery_access_only",
        proofChipAllowed: false,
        finalVerifierComplete: false,
        winnerClaimAllowed: false,
      }),
    );

    expect(pending.status).toBe(423);
    expect(pendingJson.error.code).toBe("proof_pending");
    expect(invalidPayer.status).toBe(400);
    expect(invalidJson.error.code).toBe("bad_request");
    expect(missingBearer.status).toBe(401);
    expect(missingBearerJson.error.code).toBe("unauthorized");
    expect(wrongBearer.status).toBe(403);
    expect(wrongBearerJson.error.code).toBe("forbidden");
    expect(allowed.status).toBe(200);
    expect(allowedJson.data).toEqual(
      expect.objectContaining({
        sessionId,
        spendId,
        artifactHash,
        status: "available",
        winnerClaimAllowed: false,
      }),
    );
    expect(allowedUppercaseHash.status).toBe(200);
    expect(allowedUppercaseHashJson.data.artifactPayloadHash).toBe(artifactHash);
    expect(payerMismatch.status).toBe(422);
    expect(payerMismatchJson.error.code).toBe("proof_blocked");
  });

  it("rejects hand-written artifact token rows without verifier issuance evidence", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact-token-tamper");
    const spendId = await registerSpend(app, sessionId);
    const artifactHash = hex32("artifact-token-tamper");
    const payer = "0x1234";
    const bearerToken = "manual-artifact-access-token";
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-token-tamper");
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_access_tokens
          (token_id, session_id, spend_id, payer, artifact_hash, token_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        hex32("manual-artifact-token-row"),
        sessionId,
        spendId,
        payer,
        artifactHash,
        hex32(bearerToken),
        "2026-06-11T00:00:00.000Z",
      );

    const read = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/${payer}/${artifactHash}`, {
      headers: { authorization: `Bearer ${bearerToken}` },
    });
    const readJson = await read.json();
    const verify = await app.request(`/api/v1/evidence/${sessionId}/verify`);
    const verifyJson = await verify.json();

    expect(read.status).toBe(403);
    expect(readJson.error.code).toBe("forbidden");
    expect(verify.status).toBe(200);
    expect(verifyJson.data.schemaOk).toBe(false);
    expect(verifyJson.data.errors.some((error: string) => error.includes("missing issued_by_verifier_run_id"))).toBe(true);
  });

  it("blocks artifact access issuance when the requested artifact diverges from the quote", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact-quote-mismatch");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-quote-bound");
    const differentPayload = artifactPayloadForTest("artifact-quote-tampered");
    const differentHash = hashForTestJson(differentPayload);
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-quote-mismatch");

    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-quote-mismatch",
      payload: {
        spendId,
        payer: "0x1234",
        quoteId: quoted.quoteId,
        artifactHash: differentHash,
        artifactPayload: differentPayload,
      },
    });

    expect(issue.status).toBe(422);
    expect(issue.json.error.code).toBe("proof_blocked");
    expect(issue.json.error.message).toContain("quote commitment");
  });

  it("blocks artifact access issuance for overpriced or expired quotes", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const overpricedSessionId = await createSession(app, "sess-artifact-overpriced-quote");
    const overpricedSpendId = await registerSpend(app, overpricedSessionId);
    const overpriced = await quoteArtifactForTest(app, overpricedSessionId, overpricedSpendId, "artifact-overpriced", { priceAtomic: "1001" });
    await finalizeSpendSettlement(app, ctx, logs, overpricedSessionId, overpricedSpendId, "artifact-overpriced");

    const overpricedIssue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: overpricedSessionId,
      idempotencyKey: "issue-overpriced-artifact",
      payload: {
        spendId: overpricedSpendId,
        payer: "0x1234",
        quoteId: overpriced.quoteId,
        artifactHash: overpriced.artifactHash,
        artifactPayload: overpriced.artifactPayload,
      },
    });

    const expiredSessionId = await createSession(app, "sess-artifact-expired-quote");
    const expiredSpendId = await registerSpend(app, expiredSessionId);
    const expired = await quoteArtifactForTest(app, expiredSessionId, expiredSpendId, "artifact-expired", { validUntilBlock: "99" });
    await finalizeSpendSettlement(app, ctx, logs, expiredSessionId, expiredSpendId, "artifact-expired");
    const expiredIssue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: expiredSessionId,
      idempotencyKey: "issue-expired-artifact",
      payload: {
        spendId: expiredSpendId,
        payer: "0x1234",
        quoteId: expired.quoteId,
        artifactHash: expired.artifactHash,
        artifactPayload: expired.artifactPayload,
      },
    });

    expect(overpricedIssue.status).toBe(422);
    expect(overpricedIssue.json.error.code).toBe("proof_blocked");
    expect(overpricedIssue.json.error.message).toContain("price exceeds");
    expect(expiredIssue.status).toBe(422);
    expect(expiredIssue.json.error.code).toBe("proof_blocked");
    expect(expiredIssue.json.error.message).toContain("expired");
  });

  it("blocks oversized artifact payloads before issuing bearer access", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact-large-payload");
    const spendId = await registerSpend(app, sessionId);
    const artifactPayload = { artifactType: "source-bound-code-scan-mcp-lease", content: "x".repeat(300 * 1024) };
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-large-payload", { artifactPayload });
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-large-payload");

    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-large-artifact",
      payload: {
        spendId,
        payer: "0x1234",
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload,
      },
    });

    expect(issue.status).toBe(422);
    expect(issue.json.error.code).toBe("proof_blocked");
    expect(issue.json.error.message).toContain("payload exceeds");
  });

  it("blocks artifact token issuance that would exceed the replay summary cap", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact-summary-cap");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-summary-cap");
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-summary-cap");
    const countRow = ctx.db.sqlite.prepare("SELECT COUNT(*) AS count FROM evidence_events WHERE session_id = ?").get(sessionId) as { count: number };
    for (let i = Number(countRow.count); i < 200; i += 1) {
	      appendEvidenceEvent(ctx, {
	        sessionId,
	        authority: "operator",
	        kind: "runner.heartbeat",
	        payload: { i, winnerClaimAllowed: false },
	      });
    }

    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-summary-cap",
      payload: {
        spendId,
        payer: "0x1234",
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload: quoted.artifactPayload,
      },
    });

    expect(issue.status).toBe(422);
    expect(issue.json.error.code).toBe("proof_blocked");
    expect(issue.json.error.message).toContain("replay summary cap");

    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "operator",
      kind: "runner.heartbeat",
      payload: { overflow: true, winnerClaimAllowed: false },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    expect(replay.status).toBe(422);
    expect(replayJson.error.code).toBe("proof_blocked");
    expect(replayJson.error.message).toContain("replay summary cap");
  });

  it("requires registered spends before artifact preflight", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-preflight-spend-required");

    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-missing-spend",
      payload: {
        spendId: hex32("missing-spend"),
        artifactHashPreview: hex32("artifact-preview"),
        artifactCid: artifactCidForTest(hex32("artifact-preview")),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("price-disclosure"),
        sourceStateSnapshotHash: hex32("source-state"),
      },
    });

    expect(preflight.status).toBe(404);
    expect(preflight.json.error.code).toBe("not_found");
  });

  it("requires an artifact preflight before signing mocked quotes", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-required");
    const spendId = await registerSpend(app, sessionId);

    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "quote-without-preflight",
      payload: {
        spendId,
        preflightId: hex32("missing-preflight"),
        artifactCommitment: hex32("artifact-preview"),
        priceAtomic: "1000",
        quoteNonce: "quote-no-preflight",
        validUntilBlock: "123",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(quote.status).toBe(423);
    expect(quote.json.error.code).toBe("proof_pending");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("quote.signed.mocked");
  });

  it("binds mocked quote signing to the matching artifact preflight", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-bound");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = hex32("artifact-preview-bound");
    const priceDisclosureHash = hex32("price-disclosure-bound");
    const sourceStateSnapshotHash = hex32("source-state-bound");

    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-before-quote",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash,
        sourceStateSnapshotHash,
      },
    });
    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "quote-after-preflight",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceAtomic: "1000",
        quoteNonce: "quote-after-preflight",
        validUntilBlock: "123",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const quoteEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "quote.signed.mocked");
    const keyEvent = replayJson.data.events.find(
      (event: { kind: string; payload: Record<string, unknown> }) =>
        event.kind === "operator.key_used" && event.payload.role === "quote_signer",
    );
    const keyRow = ctx.db.sqlite
      .prepare("SELECT role, authority, status, use_count, authorized_methods_hash, authorized_methods_json FROM operator_keys WHERE role = ?")
      .get("quote_signer") as Record<string, unknown>;

    expect(preflight.status).toBe(202);
    expect(preflight.json.data.artifactHashPreview).toBe(artifactHashPreview);
    expect(preflight.json.data.priceDisclosureHash).toBe(priceDisclosureHash);
    expect(preflight.json.data.sourceStateSnapshotHash).toBe(sourceStateSnapshotHash);
    expect(quote.status).toBe(201);
    expect(quote.json.data.preflightId).toBe(preflight.json.data.preflightId);
    expect(quote.json.data.priceDisclosureHash).toBe(priceDisclosureHash);
    expect(quote.json.data.sourceStateSnapshotHash).toBe(sourceStateSnapshotHash);
    expect(quote.json.data.quoteSignedAfterPreflight).toBe(true);
    expect(quote.json.data.status).toBe("mocked_after_preflight_not_chain_settleable");
    expect(keyEvent).toEqual(
      expect.objectContaining({
        authority: "operator",
        payload: expect.objectContaining({
          role: "quote_signer",
          method: "ArtifactQuote.sign",
          operationId: quote.json.data.quoteId,
          secretMaterialStored: false,
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(keyRow).toEqual(
      expect.objectContaining({
        role: "quote_signer",
        authority: "operator",
        status: "active_demo_key",
        use_count: 1,
      }),
    );
    expect(keyEvent.payload.authorizedMethodsHash).toBe(keyRow.authorized_methods_hash);
    expect(JSON.parse(String(keyRow.authorized_methods_json))).toEqual([
      "ArtifactQuote.sign(sessionId,spendId,artifactCommitment,priceAtomic,quoteNonce,validUntilBlock)",
    ]);
    expect(quoteEvent.payload).toEqual(
      expect.objectContaining({
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceDisclosureHash,
        sourceStateSnapshotHash,
        quoteSignedAfterPreflight: true,
      }),
    );
  });

  it("blocks mocked quotes whose artifact commitment diverges from preflight", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-mismatch");
    const spendId = await registerSpend(app, sessionId);
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-mismatch",
      payload: {
        spendId,
        artifactHashPreview: hex32("artifact-preview-original"),
        artifactCid: artifactCidForTest(hex32("artifact-preview-original")),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("price-disclosure-mismatch"),
        sourceStateSnapshotHash: hex32("source-state-mismatch"),
      },
    });

    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "quote-preflight-mismatch",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: hex32("artifact-preview-tampered"),
        priceAtomic: "1000",
        quoteNonce: "quote-preflight-mismatch",
        validUntilBlock: "123",
      },
    });

    expect(quote.status).toBe(422);
    expect(quote.json.error.code).toBe("proof_blocked");
  });

  it("requires a quoted artifact before refunding undelivered delivery", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-refund-unquoted");
    const spendId = await registerSpend(app, sessionId);

    const refund = await post(app, "/api/v1/artifacts/refund", {
      sessionId,
      idempotencyKey: "refund-without-quote",
      payload: {
        spendId,
        quoteId: hex32("missing-refund-quote"),
        reason: "delivery timeout",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(refund.status).toBe(423);
    expect(refund.json.error.code).toBe("proof_pending");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("artifact.refund.pending");
  });

  it("records refund evidence for a quoted undelivered artifact without enabling winner claims", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-refund-quoted");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = hex32("refund-artifact-preview");
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "refund-preflight",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("refund-price-disclosure"),
        sourceStateSnapshotHash: hex32("refund-source-state"),
      },
    });
    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "refund-quote",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceAtomic: "1000",
        quoteNonce: "refund-quote-nonce",
        validUntilBlock: "123",
      },
    });
    const secondPreflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "refund-second-preflight",
      payload: {
        spendId,
        artifactHashPreview: hex32("refund-second-artifact-preview"),
        artifactCid: artifactCidForTest(hex32("refund-second-artifact-preview")),
        endpointUrl: "https://example.com/artifact-2",
        priceDisclosureHash: hex32("refund-second-price-disclosure"),
        sourceStateSnapshotHash: hex32("refund-second-source-state"),
      },
    });
    const secondQuote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "refund-second-quote",
      payload: {
        spendId,
        preflightId: secondPreflight.json.data.preflightId,
        artifactCommitment: secondPreflight.json.data.artifactHashPreview,
        priceAtomic: "2000",
        quoteNonce: "refund-second-quote-nonce",
        validUntilBlock: "124",
      },
    });

    const refund = await post(app, "/api/v1/artifacts/refund", {
      sessionId,
      idempotencyKey: "refund-after-quote",
      payload: {
        spendId,
        quoteId: quote.json.data.quoteId,
        reason: "delivery timeout",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const refundEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "artifact.refund.pending");

    expect(secondQuote.status).toBe(201);
    expect(refund.status).toBe(202);
    expect(refund.json.data).toEqual(
      expect.objectContaining({
        spendId,
        quoteId: quote.json.data.quoteId,
        preflightId: preflight.json.data.preflightId,
        status: "pending_live_settlement",
        winnerClaimAllowed: false,
      }),
    );
    expect(refundEvent.payload).toEqual(
      expect.objectContaining({
        spendId,
        quoteId: quote.json.data.quoteId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        status: "pending_live_settlement",
        winnerClaimAllowed: false,
      }),
    );
  });

  it("keeps artifact access issuance and refund evidence mutually exclusive", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-refund-token-exclusive");
    const spendId = await registerSpend(app, sessionId);
    const artifactPayload = artifactPayloadForTest("refund-token-artifact");
    const artifactHash = hashForTestJson(artifactPayload);
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "exclusive-preflight",
      payload: {
        spendId,
        artifactHashPreview: artifactHash,
        artifactCid: artifactCidForTest(artifactHash),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("exclusive-price-disclosure"),
        sourceStateSnapshotHash: hex32("exclusive-source-state"),
      },
    });
    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "exclusive-quote",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHash,
        priceAtomic: "1000",
        quoteNonce: "exclusive-quote-nonce",
        validUntilBlock: "123",
      },
    });
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "exclusive-token-first");
    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "exclusive-issue-token",
      payload: {
        spendId,
        payer: "0x1234",
        quoteId: quote.json.data.quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const refundAfterToken = await post(app, "/api/v1/artifacts/refund", {
      sessionId,
      idempotencyKey: "exclusive-refund-after-token",
      payload: {
        spendId,
        quoteId: quote.json.data.quoteId,
        reason: "delivery timeout",
      },
    });

    const secondSessionId = await createSession(app, "sess-token-refund-exclusive");
    const secondSpendId = await registerSpend(app, secondSessionId);
    const secondArtifactPayload = artifactPayloadForTest("token-refund-artifact");
    const secondArtifactHash = hashForTestJson(secondArtifactPayload);
    const secondPreflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId: secondSessionId,
      idempotencyKey: "exclusive-second-preflight",
      payload: {
        spendId: secondSpendId,
        artifactHashPreview: secondArtifactHash,
        artifactCid: artifactCidForTest(secondArtifactHash),
        endpointUrl: "https://example.com/artifact-2",
        priceDisclosureHash: hex32("exclusive-second-price-disclosure"),
        sourceStateSnapshotHash: hex32("exclusive-second-source-state"),
      },
    });
    const secondQuote = await post(app, "/api/v1/quotes", {
      sessionId: secondSessionId,
      idempotencyKey: "exclusive-second-quote",
      payload: {
        spendId: secondSpendId,
        preflightId: secondPreflight.json.data.preflightId,
        artifactCommitment: secondArtifactHash,
        priceAtomic: "1000",
        quoteNonce: "exclusive-second-quote-nonce",
        validUntilBlock: "123",
      },
    });
    const refundBeforeToken = await post(app, "/api/v1/artifacts/refund", {
      sessionId: secondSessionId,
      idempotencyKey: "exclusive-refund-before-token",
      payload: {
        spendId: secondSpendId,
        quoteId: secondQuote.json.data.quoteId,
        reason: "delivery timeout",
      },
    });
    await finalizeSpendSettlement(app, ctx, logs, secondSessionId, secondSpendId, "exclusive-refund-first");
    const issueAfterRefund = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: secondSessionId,
      idempotencyKey: "exclusive-issue-after-refund",
      payload: {
        spendId: secondSpendId,
        payer: "0x1234",
        quoteId: secondQuote.json.data.quoteId,
        artifactHash: secondArtifactHash,
        artifactPayload: secondArtifactPayload,
      },
    });

    expect(issue.status).toBe(202);
    expect(refundAfterToken.status).toBe(409);
    expect(refundAfterToken.json.error.code).toBe("idempotency_conflict");
    expect(refundBeforeToken.status).toBe(202);
    expect(issueAfterRefund.status).toBe(422);
    expect(issueAfterRefund.json.error.code).toBe("proof_blocked");
  });

  it("persists sessions across database reopen", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pactfuse-api-"));
    const dbPath = join(dir, "pactfuse.sqlite");
    try {
      const first = makeApp(dbPath);
      const sessionId = await createSession(first.app, "sess-persist");
      first.ctx.db.sqlite.close();

      const second = makeApp(dbPath);
      const res = await second.app.request(`/api/v1/sessions/${sessionId}`);
      const json = await res.json();

      expect(res.status).toBe(200);
      expect(json.data.sessionId).toBe(sessionId);
      expect(json.data.latestEventSeq).toBe(1);
      second.ctx.db.sqlite.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("leases jobs once and preserves dedupe identity", async () => {
    const { ctx } = makeApp();
    const job = enqueueJob(ctx, {
      kind: "index-chain-window",
      dedupeKey: "chain:1:100",
      payload: { fromBlock: "1", toBlock: "100" },
    });
    const duplicate = enqueueJob(ctx, {
      kind: "index-chain-window",
      dedupeKey: "chain:1:100",
      payload: { fromBlock: "1", toBlock: "100" },
    });
    const lease = leaseNextJob(ctx, ["index-chain-window"], "tester");
    const empty = leaseNextJob(ctx, ["index-chain-window"], "tester");
    const done = completeJob(ctx, job.jobId, lease?.leaseToken ?? "", "succeeded");

    expect(duplicate.jobId).toBe(job.jobId);
    expect(lease?.jobId).toBe(job.jobId);
    expect(lease?.leaseToken).toMatch(/^0x[0-9a-f]{64}$/);
    expect(lease?.attempts).toBe(1);
    expect(empty).toBeNull();
    expect(done.status).toBe("succeeded");
  });

  it("rejects stale job lease completion after an expired lease is requeued", async () => {
    const { ctx } = makeApp();
    const job = enqueueJob(ctx, {
      kind: "index-chain-window",
      dedupeKey: "chain:2:200",
      payload: { fromBlock: "2", toBlock: "200" },
    });
    const staleLease = leaseNextJob(ctx, ["index-chain-window"], "old-worker");
    const requeued = requeueExpiredLeases(ctx, "2026-06-11T00:00:01.000Z");
    const currentLease = leaseNextJob(ctx, ["index-chain-window"], "new-worker");

    expect(staleLease?.jobId).toBe(job.jobId);
    expect(requeued).toBe(1);
    expect(currentLease?.jobId).toBe(job.jobId);
    expect(currentLease?.leaseToken).not.toBe(staleLease?.leaseToken);
    expect(() => completeJob(ctx, job.jobId, staleLease?.leaseToken ?? "", "succeeded")).toThrow(/lease token/);
    expect(completeJob(ctx, job.jobId, currentLease?.leaseToken ?? "", "succeeded").status).toBe("succeeded");
  });

  it("runs the indexer worker from configured cursors and advances startup windows without manual HTTP backfill", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 105, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-worker-visible");
    const spendId = await registerSpend(app, sessionId);
    const challengeReasonHash = hex32("worker-source-reason");
    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "worker-source-challenge",
      payload: {
        sourceHash: hex32("source"),
        reasonHash: challengeReasonHash,
        evidenceRef: "https://example.com/worker-source-challenge.json",
      },
    });
    logs.push(
      indexerLog("worker-settled", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("worker-settled-tx"),
        rawLogHash: hex32("worker-settled-log"),
      }),
      indexerLog("worker-source-challenged", 101, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash: hex32("source"),
        reasonHash: challengeReasonHash,
        args: { sessionId, sourceHash: hex32("source"), reasonHash: challengeReasonHash },
        transactionHash: hex32("worker-source-challenged-tx"),
        rawLogHash: hex32("worker-source-challenged-log"),
      }),
      ...[101, 102, 103, 104].map((block) => indexerLog(`worker-${block}`, block)),
    );
    const options = {
      leaseOwner: "test-indexer-worker",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 2, address: INDEXER_ADDRESS }],
    };

    const first = await runIndexerWorkerOnce(ctx, options);
    const second = await runIndexerWorkerOnce(ctx, options);
    const third = await runIndexerWorkerOnce(ctx, options);
    const cursor = ctx.db.sqlite.prepare("SELECT last_indexed_block, lag_blocks, status FROM chain_indexer_cursors WHERE cursor_id = ?").get(
      "gate:indexer",
    ) as Record<string, unknown>;
    const count = ctx.db.sqlite.prepare("SELECT COUNT(*) AS count FROM chain_indexed_logs").get() as Record<string, unknown>;
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const proofEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "gate.spend_settled");
    const sourceProofEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "source.challenge.confirmed");
    const sourceRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "source_challenge");
    const settlementRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "c_settlement");

    expect(challenge.status).toBe(202);
    expect(first.status).toBe("succeeded");
    expect(second.status).toBe("succeeded");
    expect(third.status).toBe("succeeded");
    expect(cursor).toEqual(expect.objectContaining({ last_indexed_block: 104, lag_blocks: 0, status: "caught_up" }));
    expect(Number(count.count)).toBe(6);
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("indexer.worker.succeeded");
    expect(proofEvent).toEqual(
      expect.objectContaining({
        authority: "proof",
        payload: expect.objectContaining({
          spendId,
          cursorId: "gate:indexer",
          indexedLogId: expect.stringMatching(/^0x[0-9a-f]{64}$/),
          contractStateVerified: true,
          contractAddress: INDEXER_ADDRESS,
          contractFunction: "registeredSpend",
          contractSpendState: "Settled",
          proofAuthority: true,
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(sourceProofEvent).toEqual(
      expect.objectContaining({
        authority: "proof",
        payload: expect.objectContaining({
          sourceHash: hex32("source"),
          reasonHash: challengeReasonHash,
          cursorId: "gate:indexer",
          contractStateVerified: true,
          sourceRegistryAddress: INDEXER_ADDRESS,
          contractFunction: "sourceState",
          contractSourceState: "Challenged",
          proofAuthority: true,
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(sourceRow).toEqual(
      expect.objectContaining({
        status: "pass",
        authority: "proof",
        evidenceEventId: sourceProofEvent?.eventId,
      }),
    );
    expect(settlementRow).toEqual(
      expect.objectContaining({
        status: "pass",
        authority: "proof",
        evidenceEventId: proofEvent?.eventId,
      }),
    );
  });

  it("blocks indexed SpendSettled logs when ProcurementGate state is not settled", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const contractSpendStates: Record<string, number> = {};
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs, contractSpendStates }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-contract-spend-mismatch");
    const spendId = await registerSpend(app, sessionId);
    contractSpendStates[spendId.toLowerCase()] = 1;
    logs.push(
      indexerLog("contract-spend-mismatch", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("contract-spend-mismatch-tx"),
        rawLogHash: hex32("contract-spend-mismatch-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-contract-spend-mismatch",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("does not match ProcurementGate spend state");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("gate.spend_settled");
  });

  it("blocks indexed SpendSettled proofs from cursors without a pinned gate address", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs }),
    });
    const sessionId = await createSession(app, "sess-indexer-unpinned-gate-address");
    const spendId = await registerSpend(app, sessionId);
    logs.push(
      indexerLog("unpinned-gate-address", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("unpinned-gate-address-tx"),
        rawLogHash: hex32("unpinned-gate-address-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-unpinned-gate-address",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10 }],
    });

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("proof cursor is missing configured contract address");
  });

  it("blocks indexed SpendSettled logs whose address does not match the pinned gate cursor", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const wrongAddress = "0x2222222222222222222222222222222222222222";
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs, ignoreAddressFilter: true }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-wrong-gate-address");
    const spendId = await registerSpend(app, sessionId);
    logs.push(
      indexerLog("wrong-gate-address", 100, {
        address: wrongAddress,
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("wrong-gate-address-tx"),
        rawLogHash: hex32("wrong-gate-address-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-wrong-gate-address",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("indexed log address does not match proof cursor address");
  });

  it("blocks deterministic contract read failures instead of retrying forever", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({
        currentBlockNumber: 103,
        logs,
        readContractError: new Error("execution reverted: function selector was not recognized"),
      }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-contract-read-blocked");
    const spendId = await registerSpend(app, sessionId);
    logs.push(
      indexerLog("contract-read-blocked", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("contract-read-blocked-tx"),
        rawLogHash: hex32("contract-read-blocked-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-contract-read-blocked",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("failed to read ProcurementGate registeredSpend state");
  });

  it("blocks indexed SourceChallenged logs when SourceStateRegistry state is not challenged", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const sourceStates: Record<string, number> = {};
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs, sourceStates }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-contract-source-mismatch");
    await registerSpend(app, sessionId);
    const sourceHash = hex32("source");
    const reasonHash = hex32("contract-source-mismatch-reason");
    sourceStates[sourceHash.toLowerCase()] = 1;
    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "contract-source-mismatch-challenge",
      payload: {
        sourceHash,
        reasonHash,
        evidenceRef: "https://example.com/contract-source-mismatch.json",
      },
    });
    logs.push(
      indexerLog("contract-source-mismatch", 100, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash,
        reasonHash,
        args: { sessionId, sourceHash, reasonHash },
        transactionHash: hex32("contract-source-mismatch-tx"),
        rawLogHash: hex32("contract-source-mismatch-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-contract-source-mismatch",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(challenge.status).toBe(202);
    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("does not match SourceStateRegistry state");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("source.challenge.confirmed");
  });

  it("blocks indexed SourceChallenged logs for unregistered or unbound sources", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-unbound-source");
    const sourceHash = hex32("unbound-source");
    const reasonHash = hex32("unbound-source-reason");
    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "unbound-source-challenge",
      payload: {
        sourceHash,
        reasonHash,
        evidenceRef: "https://example.com/unbound-source-challenge.json",
      },
    });
    logs.push(
      indexerLog("unbound-source-challenged", 100, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash,
        reasonHash,
        args: { sessionId, sourceHash, reasonHash },
        transactionHash: hex32("unbound-source-challenged-tx"),
        rawLogHash: hex32("unbound-source-challenged-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-unbound-source",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const sourceRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "source_challenge");

    expect(challenge.status).toBe(202);
    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("unregistered source");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("source.challenge.confirmed");
    expect(sourceRow.status).not.toBe("pass");
  });

  it("blocks indexed SourceChallenged logs for registered sources that are not spend-bound", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-registered-unbound-source");
    const sourceHash = hex32("source");
    const reasonHash = hex32("registered-unbound-source-reason");
    await registerSource(app, sessionId);
    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "registered-unbound-source-challenge",
      payload: {
        sourceHash,
        reasonHash,
        evidenceRef: "https://example.com/registered-unbound-source-challenge.json",
      },
    });
    logs.push(
      indexerLog("registered-unbound-source-challenged", 100, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash,
        reasonHash,
        args: { sessionId, sourceHash, reasonHash },
        transactionHash: hex32("registered-unbound-source-challenged-tx"),
        rawLogHash: hex32("registered-unbound-source-challenged-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-registered-unbound-source",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });

    expect(challenge.status).toBe(202);
    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("not bound");
  });

  it("blocks indexed SourceChallenged logs without a pending operator challenge", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-source-no-pending-challenge");
    await registerSpend(app, sessionId);
    const sourceHash = hex32("source");
    const reasonHash = hex32("source-no-pending-reason");
    logs.push(
      indexerLog("source-no-pending-challenged", 100, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash,
        reasonHash,
        args: { sessionId, sourceHash, reasonHash },
        transactionHash: hex32("source-no-pending-challenged-tx"),
        rawLogHash: hex32("source-no-pending-challenged-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-source-no-pending",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("pending source challenge");
  });

  it("normalizes uppercase indexed SourceChallenged hashes before updating source proof status", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-uppercase-source-challenge");
    await registerSpend(app, sessionId);
    const sourceHash = hex32("source");
    const reasonHash = hex32("uppercase-source-reason");
    const uppercaseSourceHash = `0x${sourceHash.slice(2).toUpperCase()}`;
    const uppercaseReasonHash = `0x${reasonHash.slice(2).toUpperCase()}`;
    const challenge = await post(app, "/api/v1/sources/challenge", {
      sessionId,
      idempotencyKey: "uppercase-source-challenge",
      payload: {
        sourceHash,
        reasonHash,
        evidenceRef: "https://example.com/uppercase-source-challenge.json",
      },
    });
    logs.push(
      indexerLog("uppercase-source-challenged", 100, {
        eventName: "SourceChallenged",
        event: "SourceChallenged",
        sessionId,
        sourceHash: uppercaseSourceHash,
        reasonHash: uppercaseReasonHash,
        args: { sessionId, sourceHash: uppercaseSourceHash, reasonHash: uppercaseReasonHash },
        transactionHash: hex32("uppercase-source-challenged-tx"),
        rawLogHash: hex32("uppercase-source-challenged-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-uppercase-source",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });
    const source = ctx.db.sqlite
      .prepare("SELECT proof_status FROM sources WHERE session_id = ? AND source_hash = ?")
      .get(sessionId, sourceHash) as { proof_status: string };
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const proofEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "source.challenge.confirmed");

    expect(challenge.status).toBe(202);
    expect(result.status).toBe("succeeded");
    expect(source.proof_status).toBe("challenged");
    expect(proofEvent.payload.sourceHash).toBe(sourceHash);
    expect(proofEvent.payload.reasonHash).toBe(reasonHash);
  });

  it("keeps indexer worker lease recovery scoped and blocks malformed indexer jobs", async () => {
    const { ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 50, logs: [] }),
    });
    const nonIndexerJob = enqueueJob(ctx, {
      kind: "lease-execute",
      dedupeKey: "lease:test",
      payload: { leaseRunId: "lease-test" },
    });
    const nonIndexerLease = leaseNextJob(ctx, ["lease-execute"], "lease-worker");
    const lowHead = await runIndexerWorkerOnce(ctx, {
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10 }],
      leaseTimeoutMs: -1,
    });
    const nonIndexerAfterWorker = ctx.db.sqlite.prepare("SELECT status FROM jobs WHERE job_id = ?").get(nonIndexerJob.jobId) as Record<string, unknown>;

    enqueueJob(ctx, {
      kind: INDEX_CHAIN_WINDOW_JOB_KIND,
      dedupeKey: "bad:indexer",
      payload: { malformed: true },
    });
    const malformed = await runIndexerWorkerOnce(ctx, { cursors: [] });
    const malformedJob = ctx.db.sqlite.prepare("SELECT status, locked_at FROM jobs WHERE dedupe_key = ?").get("bad:indexer") as Record<string, unknown>;

    expect(nonIndexerLease?.status).toBe("leased");
    expect(lowHead.status).toBe("idle");
    expect(nonIndexerAfterWorker.status).toBe("leased");
    expect(malformed.status).toBe("blocked");
    expect(malformedJob.status).toBe("blocked");
    expect(malformedJob.locked_at).toBeNull();
  });

  it("keeps global indexer retry and blocked states out of unrelated session replay", async () => {
    const retryingApp = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({
        currentBlockNumber: 105,
        logs: [indexerLog("retry-worker", 100)],
        getLogsError: new Error("rpc unavailable"),
      }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", topics: [], finalityDepth: 2 }],
    });
    const retrySessionId = await createSession(retryingApp.app, "sess-indexer-worker-retry-visible");
    const retrying = await runIndexerWorkerOnce(retryingApp.ctx, {
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 1 }],
      retryDelayMs: 1_000,
    });
    const retryReplay = await retryingApp.app.request(`/api/v1/evidence/replay-bundle?sessionId=${retrySessionId}`);
    const retryReplayJson = await retryReplay.json();
    const retryJudge = await retryingApp.app.request(`/api/v1/evidence/judge-check?sessionId=${retrySessionId}`);
    const retryJudgeJson = await retryJudge.json();

    const blockedApp = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 105, logs: [] }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", topics: [], finalityDepth: 2 }],
    });
    const blockedSessionId = await createSession(blockedApp.app, "sess-indexer-worker-blocked-visible");
    enqueueJob(blockedApp.ctx, {
      kind: INDEX_CHAIN_WINDOW_JOB_KIND,
      dedupeKey: "bad:indexer:visible",
      payload: { malformed: true },
    });
    const blocked = await runIndexerWorkerOnce(blockedApp.ctx, { cursors: [] });
    const blockedReplay = await blockedApp.app.request(`/api/v1/evidence/replay-bundle?sessionId=${blockedSessionId}`);
    const blockedReplayJson = await blockedReplay.json();
    const blockedJudge = await blockedApp.app.request(`/api/v1/evidence/judge-check?sessionId=${blockedSessionId}`);
    const blockedJudgeJson = await blockedJudge.json();

    expect(retrying.status).toBe("retrying");
    expect(retryReplayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("indexer.worker.retrying");
    expect(retryJudgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "c_settlement")).toEqual(
      expect.objectContaining({ status: "pending", authority: "proof", evidenceEventId: null }),
    );
    expect(blocked.status).toBe("blocked");
    expect(blockedReplayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("indexer.worker.blocked");
    expect(blockedJudgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "c_settlement")).toEqual(
      expect.objectContaining({ status: "pending", authority: "proof", evidenceEventId: null }),
    );
  });

  it("backfills indexed chain logs in capped windows and replays duplicate windows exactly once", async () => {
    const logs = [100, 101, 102, 103, 104].map((block) => indexerLog(`window-${block}`, block));
    const firstLogTxHash = String(logs[0]?.transactionHash);
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 105, logs }),
    });
    const first = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-window-first",
      payload: {
        cursorId: "gate:indexer",
        chainId: "84532",
        fromBlock: 100,
        toBlock: 104,
        finalityDepth: 2,
        maxWindowBlocks: 2,
        address: INDEXER_ADDRESS,
        topics: [],
      },
    });
    const replay = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-window-replay",
      payload: {
        cursorId: "gate:indexer",
        chainId: "84532",
        fromBlock: 100,
        toBlock: 101,
        finalityDepth: 2,
        maxWindowBlocks: 2,
        address: INDEXER_ADDRESS,
        topics: [],
      },
    });
    const second = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-window-second",
      payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 104, finalityDepth: 2, maxWindowBlocks: 2, address: INDEXER_ADDRESS },
    });
    const third = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-window-third",
      payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 104, finalityDepth: 2, maxWindowBlocks: 2, address: INDEXER_ADDRESS },
    });
    const status = await app.request("/api/v1/evidence/indexer-status");
    const statusJson = await status.json();
    const row = ctx.db.sqlite
      .prepare("SELECT raw_log_json FROM chain_indexed_logs WHERE tx_hash = ?")
      .get(firstLogTxHash) as Record<string, unknown>;
    const count = ctx.db.sqlite.prepare("SELECT COUNT(*) AS count FROM chain_indexed_logs").get() as Record<string, unknown>;

    expect(first.status).toBe(202);
    expect(first.json.data.fromBlock).toBe(100);
    expect(first.json.data.toBlock).toBe(101);
    expect(first.json.data.insertedLogCount).toBe(2);
    expect(first.json.data.cursor.lastIndexedBlock).toBe(101);
    expect(first.json.data.cursor.status).toBe("degraded");
    expect(first.json.data.cursor.lagBlocks).toBe(3);
    expect(first.json.data.proofAuthority).toBe(false);
    expect(first.json.data.winnerClaimAllowed).toBe(false);
    expect(replay.status).toBe(202);
    expect(replay.json.data.insertedLogCount).toBe(0);
    expect(second.status).toBe(202);
    expect(second.json.data.cursor.lastIndexedBlock).toBe(103);
    expect(second.json.data.cursor.status).toBe("degraded");
    expect(third.status).toBe(202);
    expect(third.json.data.cursor.lastIndexedBlock).toBe(104);
    expect(third.json.data.cursor.status).toBe("caught_up");
    expect(third.json.data.cursor.lagBlocks).toBe(0);
    expect(status.status).toBe(200);
    expect(statusJson.data.winnerClaimAllowed).toBe(false);
    expect(statusJson.data.cursors[0]).toEqual(expect.objectContaining({ cursorId: "gate:indexer", status: "caught_up", lagBlocks: 0 }));
    expect(JSON.parse(String(row.raw_log_json))).toEqual(expect.objectContaining({ transactionHash: firstLogTxHash, blockNumber: 100 }));
    expect(Number(count.count)).toBe(5);
  });

  it("persists indexer cursors across database reopen and resumes from the stored block", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pactfuse-indexer-"));
    const dbPath = join(dir, "pactfuse.sqlite");
    const logs = [indexerLog("persist-100", 100), indexerLog("persist-101", 101)];
    try {
      const first = makeApp(dbPath, {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 102, logs }),
      });
      const firstBackfill = await post(first.app, "/api/v1/indexer/backfill", {
        idempotencyKey: "indexer-persist-first",
        payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2 },
      });
      first.ctx.db.sqlite.close();

      const second = makeApp(dbPath, {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 102, logs }),
      });
      const status = await second.app.request("/api/v1/evidence/indexer-status");
      const statusJson = await status.json();
      const resumed = await post(second.app, "/api/v1/indexer/backfill", {
        idempotencyKey: "indexer-persist-resume",
        payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 101, finalityDepth: 2 },
      });
      const count = second.ctx.db.sqlite.prepare("SELECT COUNT(*) AS count FROM chain_indexed_logs").get() as Record<string, unknown>;

      expect(firstBackfill.status).toBe(202);
      expect(firstBackfill.json.data.cursor.lastIndexedBlock).toBe(100);
      expect(status.status).toBe(200);
      expect(statusJson.data.cursors[0].lastIndexedBlock).toBe(100);
      expect(resumed.status).toBe(202);
      expect(resumed.json.data.fromBlock).toBe(101);
      expect(resumed.json.data.cursor.lastIndexedBlock).toBe(101);
      expect(Number(count.count)).toBe(2);
      second.ctx.db.sqlite.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("serializes same-cursor concurrent backfills so the cursor does not regress", async () => {
    const logs = Array.from({ length: 101 }, (_, index) => indexerLog(`concurrent-${index}`, 100 + index));
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 201, logs }),
    });
    const seed = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-concurrent-seed",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2, maxWindowBlocks: 1 },
    });
    const [first, second] = await Promise.all([
      post(app, "/api/v1/indexer/backfill", {
        idempotencyKey: "indexer-concurrent-a",
        payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 200, finalityDepth: 2, maxWindowBlocks: 50 },
      }),
      post(app, "/api/v1/indexer/backfill", {
        idempotencyKey: "indexer-concurrent-b",
        payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 200, finalityDepth: 2, maxWindowBlocks: 50 },
      }),
    ]);
    const final = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-concurrent-final",
      payload: { cursorId: "gate:indexer", chainId: "84532", toBlock: 200, finalityDepth: 2, maxWindowBlocks: 50 },
    });
    const cursor = ctx.db.sqlite.prepare("SELECT last_indexed_block, lag_blocks, status FROM chain_indexer_cursors WHERE cursor_id = ?").get(
      "gate:indexer",
    ) as Record<string, unknown>;
    const count = ctx.db.sqlite.prepare("SELECT COUNT(*) AS count FROM chain_indexed_logs").get() as Record<string, unknown>;

    expect(seed.status).toBe(202);
    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(final.status).toBe(202);
    expect(cursor).toEqual(expect.objectContaining({ last_indexed_block: 200, lag_blocks: 0, status: "caught_up" }));
    expect(Number(count.count)).toBe(101);
  });

  it("rejects indexer gaps, cursor config drift, and mutated raw logs without advancing the cursor", async () => {
    const originalConflictLog = indexerLog("conflict", 100, { rawLogHash: hex32("indexer-conflict-raw-a") });
    const mutableLogs = [originalConflictLog];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs: mutableLogs }),
    });
    const first = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-guard-first",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2, address: INDEXER_ADDRESS },
    });

    mutableLogs[0] = { ...originalConflictLog, rawLogHash: hex32("indexer-conflict-raw-b") };
    const conflict = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-guard-conflict",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2, address: INDEXER_ADDRESS },
    });
    const gap = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-guard-gap",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 102, toBlock: 102, finalityDepth: 2, address: INDEXER_ADDRESS },
    });
    const drift = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-guard-drift",
      payload: {
        cursorId: "gate:indexer",
        chainId: "84532",
        fromBlock: 101,
        toBlock: 101,
        finalityDepth: 2,
        address: "0x2222222222222222222222222222222222222222",
      },
    });
    const cursor = ctx.db.sqlite.prepare("SELECT last_indexed_block, status FROM chain_indexer_cursors WHERE cursor_id = ?").get("gate:indexer") as
      | Record<string, unknown>
      | undefined;

    expect(first.status).toBe(202);
    expect(conflict.status).toBe(422);
    expect(conflict.json.error.message).toContain("rawLogHash conflict");
    expect(gap.status).toBe(422);
    expect(gap.json.error.message).toContain("cannot skip");
    expect(drift.status).toBe(422);
    expect(drift.json.error.message).toContain("configuration cannot change");
    expect(cursor).toEqual(expect.objectContaining({ last_indexed_block: 100, status: "caught_up" }));
  });

	  it("marks indexer provider failures degraded and keeps verifier output fail-closed", async () => {
    const offline = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ ready: false, reason: "rpc offline" }),
    }).app;
    const offlineBackfill = await post(offline, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-provider-offline",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2 },
    });
    const offlineStatus = await offline.request("/api/v1/evidence/indexer-status");
    const offlineStatusJson = await offlineStatus.json();
    const { app } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({
        currentBlockNumber: 105,
        logs: [indexerLog("provider-failure", 100)],
        getLogsError: new Error("rpc unavailable"),
      }),
    });
    const backfill = await post(app, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-provider-failure",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 104, finalityDepth: 2 },
    });
    const status = await app.request("/api/v1/evidence/indexer-status");
    const statusJson = await status.json();
    const sessionId = await createSession(app, "sess-indexer-fail-closed");
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-indexer-degraded",
      payload: { schemaOnly: true, receipt: schemaValidWinnerRequestedReceipt() },
    });

    expect(offlineBackfill.status).toBe(423);
    expect(offlineStatusJson.data.cursors[0]).toEqual(expect.objectContaining({ cursorId: "gate:indexer", status: "degraded" }));
    expect(offlineStatusJson.data.cursors[0].reason).toContain("provider is not ready");
    expect(backfill.status).toBe(423);
    expect(backfill.json.error.code).toBe("proof_pending");
    expect(status.status).toBe(200);
    expect(statusJson.data.cursors[0]).toEqual(expect.objectContaining({ cursorId: "gate:indexer", status: "degraded" }));
    expect(statusJson.data.cursors[0].reason).toContain("chain log backfill failed");
    expect(verify.status).toBe(200);
    expect(verify.json.data.schemaOk).toBe(false);
	    expect(verify.json.data.errors.some((error: string) => error.includes("chain indexer cursor gate:indexer"))).toBe(true);
	    expect(verify.json.data.winnerClaimAllowed).toBe(false);
	  });

	  it("fails verifier replay cleanliness when summary snapshots exceed the cap", async () => {
	    const { app, ctx } = makeApp();
	    const sessionId = await createSession(app, "sess-replay-summary-cap");
	    for (let i = 0; i < 200; i += 1) {
	      appendEvidenceEvent(ctx, {
	        sessionId,
	        authority: "operator",
	        kind: "runner.heartbeat",
	        payload: { i, winnerClaimAllowed: false },
	      });
	    }
	    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
	    const replayJson = await replay.json();
	    const verify = await post(app, "/api/v1/evidence/verify", {
	      sessionId,
	      idempotencyKey: "verify-replay-summary-cap",
	      payload: { schemaOnly: true },
	    });

	    expect(replay.status).toBe(422);
	    expect(replayJson.error.code).toBe("proof_blocked");
	    expect(replayJson.error.message).toContain("replay summary cap");
	    expect(verify.status).toBe(200);
	    expect(verify.json.data.schemaOk).toBe(false);
	    expect(verify.json.data.errors.some((error: string) => error.includes("exceeding replay summary cap"))).toBe(true);
	  });

	  it("records MCP adapter calls with request and response hashes", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-audit");

    const call = recordMcpAdapterCall(
      {
        sessionId,
        toolName: "pactfuse_get_judge_check",
        request: { sessionId },
        response: { winnerClaimAllowed: false },
        status: "succeeded",
      },
      ctx,
    );
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(call.callId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(call.evidenceEventId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).toContain("mcp.adapter.call");
    expect(replayJson.data.mcpAdapterCalls).toEqual([
      expect.objectContaining({
        toolName: "pactfuse_get_judge_check",
        request: { sessionId },
        response: { winnerClaimAllowed: false },
        status: "succeeded",
        proofAuthority: false,
      }),
    ]);
    expect(replayJson.data.agentTranscriptHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("summarizes MCP adapter calls into the agent transcript view without enabling proof claims", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-agent-transcript");
    const pending = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const pendingJson = await pending.json();

    const call = recordMcpAdapterCall(
      {
        sessionId,
        auditNonce: "audit-transcript-summary",
        toolName: "pactfuse_get_judge_check",
        request: { sessionId },
        response: { ok: true, data: { sessionId, winnerClaimAllowed: false } },
        status: "succeeded",
      },
      ctx,
    );
    const transcript = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const transcriptJson = await transcript.json();

    expect(pending.status).toBe(200);
    expect(pendingJson.data.status).toBe("pending");
    expect(pendingJson.data.callCount).toBe(0);
    expect(pendingJson.data.transcriptHash).toBeNull();
    expect(transcript.status).toBe(200);
    expect(transcriptJson.data.status).toBe("summarized");
    expect(transcriptJson.data.format).toBe("mcp-json-rpc");
    expect(transcriptJson.data.toolsListHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(transcriptJson.data.toolsCallHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(transcriptJson.data.transcriptHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(transcriptJson.data.boundedToPinnedManifest).toBe(false);
    expect(transcriptJson.data.winnerClaimAllowed).toBe(false);
    expect(transcriptJson.data.calls).toEqual([
      expect.objectContaining({
        callId: call.callId,
        auditNonce: "audit-transcript-summary",
        toolName: "pactfuse_get_judge_check",
        status: "succeeded",
      }),
    ]);
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    expect(replayJson.data.agentTranscriptHash).toBe(hashForTestJson(transcriptJson.data));
    expect(replayJson.data.asOfMcpAdapterCallCount).toBe(1);
    for (const key of ["sources", "spends", "artifactPreflights", "quotes", "artifactAccessTokens"] as const) {
      expect(replayJson.data[key]).toEqual([]);
    }

    recordMcpAdapterCall(
      {
        sessionId,
        auditNonce: "audit-transcript-after-snapshot",
        toolName: "pactfuse_get_replay_bundle",
        request: { sessionId },
        response: { ok: true, data: { sessionId } },
        status: "succeeded",
      },
      ctx,
    );
    const verifySnapshot = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-agent-transcript-snapshot",
      payload: { replayBundle: replayJson.data },
    });
    const verifyTampered = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-agent-transcript-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          agentTranscriptHash: hex32("tampered-agent-transcript"),
        },
      },
    });
    const verifyTamperedEventRoot = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-event-root-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          eventRoot: hex32("tampered-event-root"),
        },
      },
    });
    const verifyTamperedMcpCalls = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-mcp-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          mcpAdapterCalls: [],
        },
      },
    });
    const verifyTamperedJudgeCheck = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-judge-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          judgeCheck: {
            ...replayJson.data.judgeCheck,
            sessionId: hex32("tampered-judge-check"),
          },
        },
      },
    });
    const replayMissingSources = { ...replayJson.data } as Record<string, unknown>;
    delete replayMissingSources.sources;
    const verifyMissingSources = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-sources-missing",
      payload: { replayBundle: replayMissingSources },
    });

    expect(verifySnapshot.json.data.errors).not.toContain(
      "replayBundle.agentTranscriptHash does not match the server transcript snapshot",
    );
    expect(verifyTampered.json.data.errors).toContain(
      "replayBundle.agentTranscriptHash does not match the server transcript snapshot",
    );
    expect(verifyTamperedEventRoot.json.data.schemaOk).toBe(false);
    expect(verifyTamperedEventRoot.json.data.errors).toContain("replayBundle.eventRoot does not match the server event snapshot");
    expect(verifyTamperedMcpCalls.json.data.schemaOk).toBe(false);
    expect(verifyTamperedMcpCalls.json.data.errors).toContain("replayBundle.mcpAdapterCalls does not match the server snapshot");
    expect(verifyTamperedJudgeCheck.json.data.schemaOk).toBe(false);
    expect(verifyTamperedJudgeCheck.json.data.errors).toContain("replayBundle.judgeCheck does not match the server snapshot");
    expect(verifyMissingSources.json.data.schemaOk).toBe(false);
    expect(verifyMissingSources.json.data.errors).toContain("replayBundle.sources is missing from the verifier replay bundle");
  });

  it("serves a read-only public verifier preview for a replay bundle", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-public-verify-preview");
    const before = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const beforeJson = await before.json();

    const verify = await app.request(`/api/v1/evidence/${sessionId}/verify`);
    const verifyJson = await verify.json();
    const after = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const afterJson = await after.json();

    expect(verify.status).toBe(200);
    expect(verifyJson.data.sessionId).toBe(sessionId);
    expect(verifyJson.data.proofChipAllowed).toBe(false);
    expect(afterJson.data.events).toHaveLength(beforeJson.data.events.length);
    expect(afterJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("verifier.fail_closed");
  });

  it("reports verifier errors when MCP adapter row hashes diverge from evidence events", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-integrity");
    const call = recordMcpAdapterCall(
      {
        sessionId,
        auditNonce: "audit-integrity-check",
        toolName: "pactfuse_get_judge_check",
        request: { sessionId },
        response: { ok: true },
        status: "succeeded",
      },
      ctx,
    );
    ctx.db.sqlite
      .prepare("UPDATE mcp_adapter_calls SET response_hash = ? WHERE call_id = ?")
      .run(hex32("tampered-response"), call.callId);

    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-mcp-integrity",
      payload: {},
    });

    expect(verify.status).toBe(200);
    expect(verify.json.data.errors).toContain(`mcp adapter call mismatch at responseHash for ${call.callId}`);
  });

  it("reports verifier errors when raw MCP adapter JSON diverges from stored hashes", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-raw-integrity");
    const call = recordMcpAdapterCall(
      {
        sessionId,
        auditNonce: "audit-raw-integrity-check",
        toolName: "pactfuse_get_judge_check",
        request: { sessionId },
        response: { ok: true },
        status: "succeeded",
      },
      ctx,
    );
    ctx.db.sqlite
      .prepare("UPDATE mcp_adapter_calls SET request_json = ?, response_json = ? WHERE call_id = ?")
      .run(JSON.stringify({ sessionId, tampered: true }), JSON.stringify({ ok: false }), call.callId);

    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-mcp-raw-integrity",
      payload: {},
    });

    expect(verify.status).toBe(200);
    expect(verify.json.data.errors).toContain(`mcp adapter call request body hash mismatch for ${call.callId}`);
    expect(verify.json.data.errors).toContain(`mcp adapter call response body hash mismatch for ${call.callId}`);
  });

  it("records MCP adapter calls through the HTTP audit endpoint", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-http-audit");

    const auditPayload = {
      sessionId,
      auditNonce: "audit-http-success",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId },
      response: { ok: true, data: { winnerClaimAllowed: false } },
      status: "succeeded",
    };
    const audit = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const event = replayJson.data.events.find((candidate: { kind: string }) => candidate.kind === "mcp.adapter.call");

    expect(audit.status).toBe(202);
    expect(audit.json.data.callId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(audit.json.data.requestHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(audit.json.data.responseHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(audit.json.data.proofAuthority).toBe(false);
    expect(audit.json.data.winnerClaimAllowed).toBe(false);
    expect(event.payload.toolName).toBe("pactfuse_get_replay_bundle");
    expect(event.payload.status).toBe("succeeded");
    expect(replayJson.data.mcpAdapterCalls).toEqual([
      expect.objectContaining({
        toolName: "pactfuse_get_replay_bundle",
        auditNonce: "audit-http-success",
        request: { sessionId },
        response: { ok: true, data: { winnerClaimAllowed: false } },
        status: "succeeded",
        proofAuthority: false,
      }),
    ]);
  });

  it("rejects unauthenticated MCP audit writes before adding replay rows", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-forgery");

    const audit = await post(app, "/api/v1/mcp/audit", {
      sessionId,
      auditNonce: "audit-http-forgery",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId },
      response: { ok: true },
      status: "succeeded",
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(audit.status).toBe(403);
    expect(audit.json.error.code).toBe("forbidden");
    expect(replayJson.data.mcpAdapterCalls).toEqual([]);
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("mcp.adapter.call");
  });

  it("handles MCP audit retries idempotently by audit nonce", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-audit-retry");
    const auditPayload = {
      sessionId,
      auditNonce: "audit-http-retry",
      toolName: "pactfuse_get_judge_check",
      request: { sessionId },
      response: { ok: true, data: { winnerClaimAllowed: false } },
      status: "succeeded",
    };

    const first = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const second = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(second.json.data.callId).toBe(first.json.data.callId);
    expect(replayJson.data.mcpAdapterCalls).toHaveLength(1);
    expect(replayJson.data.events.filter((event: { kind: string }) => event.kind === "mcp.adapter.call")).toHaveLength(1);
  });

  it("rejects MCP audit nonce reuse with a different payload", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-audit-conflict");
    const auditPayload = {
      sessionId,
      auditNonce: "audit-http-conflict",
      toolName: "pactfuse_get_judge_check",
      request: { sessionId },
      response: { ok: true },
      status: "succeeded",
    };
    const conflictingPayload = {
      ...auditPayload,
      response: { ok: false },
    };

    await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const conflict = await post(app, "/api/v1/mcp/audit", conflictingPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, conflictingPayload),
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(conflict.status).toBe(409);
    expect(conflict.json.error.code).toBe("idempotency_conflict");
    expect(replayJson.data.mcpAdapterCalls).toHaveLength(1);
    expect(replayJson.data.mcpAdapterCalls[0].response).toEqual({ ok: true });
  });

  it("rejects signed MCP audits for missing sessions without orphan rows", async () => {
    const { app, ctx } = makeApp();
    const missingSessionId = hex32("missing-mcp-session");
    const auditPayload = {
      sessionId: missingSessionId,
      auditNonce: "audit-http-missing-session",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId: missingSessionId },
      response: { ok: true },
      status: "succeeded",
    };

    const audit = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const row = ctx.db.sqlite
      .prepare("SELECT COUNT(*) AS count FROM mcp_adapter_calls WHERE audit_nonce = ?")
      .get("audit-http-missing-session") as { count: number };

    expect(audit.status).toBe(404);
    expect(audit.json.error.code).toBe("not_found");
    expect(row.count).toBe(0);
  });

  it("rejects MCP audits with mismatched session ids across request and response", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-mcp-audit-mismatch");
    const otherSessionId = hex32("other-mcp-session");
    const auditPayload = {
      sessionId,
      auditNonce: "audit-http-session-mismatch",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId: otherSessionId },
      response: { ok: true, data: { sessionId } },
      status: "succeeded",
    };

    const audit = await post(app, "/api/v1/mcp/audit", auditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, auditPayload),
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(audit.status).toBe(400);
    expect(audit.json.error.code).toBe("bad_request");
    expect(replayJson.data.mcpAdapterCalls).toHaveLength(0);
  });

  it("blocks replay bundles that exceed the response byte cap", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-replay-cap");

    for (let index = 0; index < 3; index += 1) {
      appendEvidenceEvent(ctx, {
        sessionId,
        authority: "operator",
        kind: "runner.heartbeat",
        payload: {
          index,
          blob: "x".repeat(800_000),
        },
      });
    }

    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(replay.status).toBe(422);
    expect(replayJson.error.code).toBe("proof_blocked");
    expect(replayJson.error.details.bundleBytes).toBeGreaterThan(2 * 1024 * 1024);
  });

  it("does not cache transient verifier failures under an idempotency key", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-verifier-retry");
    let calls = 0;
    ctx.verifier = {
      verify: async () => {
        calls += 1;
        if (calls === 1) {
          throw new Error("verifier transient failure");
        }
        return {
          schemaOk: true,
          proofChipAllowed: false,
          winnerClaimAllowed: false,
          requestedWinnerClaimAllowed: false,
          finalVerifierComplete: false,
          warnings: [],
          errors: [],
        };
      },
    };
    const body = {
      sessionId,
      idempotencyKey: "verify-retry",
      payload: { receipt: { receiptId: "retry" } },
    };

    const first = await post(app, "/api/v1/evidence/verify", body);
    const second = await post(app, "/api/v1/evidence/verify", body);

    expect(first.status).toBe(500);
    expect(first.json.error.code).toBe("internal_error");
    expect(second.status).toBe(200);
    expect(second.json.ok).toBe(true);
    expect(second.json.requestId).not.toBe(first.json.requestId);
    expect(calls).toBe(2);
  });

  it("keeps missing live evidence from enabling winner claims", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-missing-live");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const artifactHash = hex32("lease-artifact-pending");

    const lease = await post(app, "/api/v1/lease/execute", {
      sessionId,
      idempotencyKey: "lease-blocked",
      payload: {
        spendId,
        payer,
        artifactHash,
        targetRepo: "https://github.com/example/repo",
        targetCommit: "abcdef123456",
      },
    });
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();

    expect(lease.status).toBe(423);
    expect(lease.json.error.code).toBe("proof_pending");
    expect(judgeJson.data.winnerClaimAllowed).toBe(false);
  });

  it("requires a matching bearer-bound artifact token before lease execution", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-lease-bearer-bound");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const wrongPayer = "0xabcd";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-artifact-active");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-settlement");
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-lease-artifact-token",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const bearerToken = issued.json.data.accessToken as string;

    expect(issued.status).toBe(202);
    expect(issued.json.data).toEqual(
      expect.objectContaining({
        spendId,
        payer,
        artifactHash,
        tokenHash: hex32(bearerToken),
        bearerBound: true,
        winnerClaimAllowed: false,
      }),
    );

    const missingToken = await post(app, "/api/v1/lease/execute", {
      sessionId,
      idempotencyKey: "lease-missing-token",
      payload: {
        spendId,
        payer,
        artifactHash,
        targetRepo: "https://github.com/example/repo",
        targetCommit: "abcdef123456",
      },
    });
    const wrongToken = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-wrong-token",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: "Bearer wrong-token" },
    );
    const payerMismatch = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-wrong-payer",
        payload: {
          spendId,
          payer: wrongPayer,
          artifactHash,
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${bearerToken}` },
    );
    const lease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-active-token",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${bearerToken}` },
    );
    const replayLease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-active-token",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${bearerToken}` },
    );
    const tokenConflict = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-active-token",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: "Bearer wrong-token" },
    );
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const leaseEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "lease.execution.blocked");

    expect(missingToken.status).toBe(401);
    expect(missingToken.json.error.code).toBe("unauthorized");
    expect(wrongToken.status).toBe(403);
    expect(wrongToken.json.error.code).toBe("forbidden");
    expect(payerMismatch.status).toBe(422);
    expect(payerMismatch.json.error.code).toBe("proof_blocked");
    expect(lease.status).toBe(202);
    expect(replayLease.status).toBe(202);
    expect(replayLease.json.requestId).toBe(lease.json.requestId);
    expect(tokenConflict.status).toBe(409);
    expect(tokenConflict.json.error.code).toBe("idempotency_conflict");
    expect(lease.json.data.bearerBound).toBe(true);
    expect(lease.json.data.status).toBe("blocked_missing_runner_execution");
    expect(lease.json.data.winnerClaimAllowed).toBe(false);
    expect(leaseEvent.payload).toEqual(
      expect.objectContaining({
        spendId,
        payer,
        artifactHash,
        bearerBound: true,
        status: "blocked_missing_runner_execution",
        winnerClaimAllowed: false,
      }),
    );
  });

  it("executes a clean lease through MCP JSON-RPC and binds the transcript into replay evidence", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
      mcpLease: createFakeMcpLeaseClient(),
    });
    const sessionId = await createSession(app, "sess-lease-transcript-success");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-artifact-transcript");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-transcript-settlement");
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-transcript-lease-token",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const bearerToken = issued.json.data.accessToken as string;

    const lease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-transcript-success",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${bearerToken}` },
    );
    const repeatedLease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-transcript-repeat",
        payload: {
          spendId,
          payer,
          artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${bearerToken}` },
    );
    const succeededLeaseCount = ctx.db.sqlite
      .prepare("SELECT COUNT(*) AS count FROM lease_runs WHERE session_id = ? AND artifact_token_id = ? AND status = 'succeeded_live_mcp_transcript'")
      .get(sessionId, issued.json.data.tokenId) as { count: number };
    const consumedToken = ctx.db.sqlite
      .prepare("SELECT status FROM artifact_access_tokens WHERE session_id = ? AND token_id = ?")
      .get(sessionId, issued.json.data.tokenId) as { status: string };
    const duplicateAfterLease = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-token-after-lease-consumed",
      payload: {
        spendId,
        payer,
        quoteId,
        artifactHash,
        artifactPayload,
      },
    });
    const transcript = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const transcriptJson = await transcript.json();
    const heartbeat = await app.request(`/api/v1/evidence/runner-heartbeat?sessionId=${sessionId}`);
    const heartbeatJson = await heartbeat.json();
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const verifyReplay = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-lease-transcript-replay",
      payload: { replayBundle: replayJson.data },
    });
    const verifyTamperedLease = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-lease-transcript-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          leaseRuns: [],
        },
      },
    });
    const leaseEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "lease.execution.succeeded");
    const heartbeatEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "runner.heartbeat");

    expect(issued.status).toBe(202);
    expect(lease.status).toBe(202);
    expect(repeatedLease.status).toBe(422);
    expect(repeatedLease.json.error.code).toBe("proof_blocked");
    expect(succeededLeaseCount.count).toBe(1);
    expect(consumedToken.status).toBe("consumed");
    expect(duplicateAfterLease.status).toBe(409);
    expect(lease.json.data).toEqual(
      expect.objectContaining({
        leaseRunId: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        payer,
        artifactHash,
        bearerBound: true,
        transcriptHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        toolsListHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        toolsCallHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        outputHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        leaseRunHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        boundedToPinnedManifest: true,
        manifestBindingHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        settlementEventId: issued.json.data.settlementEventId,
        status: "succeeded_live_mcp_transcript",
        winnerClaimAllowed: false,
      }),
    );
    expect(transcriptJson.data.status).toBe("summarized");
    expect(transcriptJson.data.callCount).toBe(2);
    expect(transcriptJson.data.boundedToPinnedManifest).toBe(true);
    expect(transcriptJson.data.calls.map((call: { toolName: string }) => call.toolName)).toEqual(["tools/list", "tools/call"]);
    expect(heartbeatJson.data).toEqual(
      expect.objectContaining({
        status: "lease_executed",
        latestLeaseRunId: lease.json.data.leaseRunId,
        transcriptHash: lease.json.data.transcriptHash,
        leaseRunHash: lease.json.data.leaseRunHash,
        winnerClaimAllowed: false,
      }),
    );
    expect(replayJson.data.mcpAdapterCalls).toHaveLength(2);
    expect(replayJson.data.sources).toEqual([
      expect.objectContaining({
        sourceId: "clean-source",
        sourceHash: hex32("source"),
        manifestHash: hex32("manifest"),
        capabilityVector: defaultSourceCapabilityForTest(),
        proofStatus: "pending",
      }),
    ]);
    expect(replayJson.data.spends).toEqual([
      expect.objectContaining({
        spendId,
        payer,
        sourceHashes: [hex32("source")],
        maxPriceAtomic: "1000",
        status: "settled_finalized",
      }),
    ]);
    expect(replayJson.data.artifactAccessTokens).toEqual([
      expect.objectContaining({
        tokenId: issued.json.data.tokenId,
        spendId,
        payer,
        artifactHash,
        tokenHash: issued.json.data.tokenHash,
        issuedByVerifierRunId: issued.json.data.verifierRunId,
        settlementEventId: issued.json.data.settlementEventId,
      }),
    ]);
    expect(replayJson.data.leaseRuns).toEqual([
      expect.objectContaining({
        leaseRunId: lease.json.data.leaseRunId,
        status: "succeeded_live_mcp_transcript",
        transcriptHash: lease.json.data.transcriptHash,
        leaseRunHash: lease.json.data.leaseRunHash,
      }),
    ]);
    expect(leaseEvent.payload).toEqual(
      expect.objectContaining({
        leaseRunId: lease.json.data.leaseRunId,
        transcriptHash: lease.json.data.transcriptHash,
        leaseRunHash: lease.json.data.leaseRunHash,
        boundedToPinnedManifest: true,
        manifestBindingHash: lease.json.data.manifestBindingHash,
        status: "succeeded_live_mcp_transcript",
        winnerClaimAllowed: false,
      }),
    );
    expect(heartbeatEvent.payload).toEqual(
      expect.objectContaining({
        step: "lease_executed",
        leaseRunId: lease.json.data.leaseRunId,
        leaseRunHash: lease.json.data.leaseRunHash,
      }),
    );
    expect(judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "lease_execution")).toEqual(
      expect.objectContaining({
        status: "pass",
        authority: "delivery",
        evidenceEventId: lease.json.evidenceEventId,
      }),
    );
    expect(verifyReplay.status).toBe(200);
    expect(verifyReplay.json.data.schemaOk).toBe(true);
    expect(verifyTamperedLease.status).toBe(200);
    expect(verifyTamperedLease.json.data.schemaOk).toBe(false);
    expect(verifyTamperedLease.json.data.errors).toContain("replayBundle.leaseRuns does not match the server snapshot");
  });

  it("executes live HTTP MCP lease only when tools/list exposes the unique read-only PactFuse tool", async () => {
    const mcp = await startMcpJsonRpcServer((request) => {
      if (request.method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: { tools: [leaseToolDefinitionForTest()] },
        };
      }
      return {
        jsonrpc: "2.0",
        id: request.id,
        result: { content: [{ type: "text", text: "clean lease complete" }] },
      };
    });
    try {
      const logs: Array<Record<string, unknown>> = [];
      const { app, ctx } = makeApp(":memory:", {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-http-mcp-success");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-http-mcp-success");
      await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-http-mcp-success");
      const issued = await post(app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-http-mcp-success-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const lease = await post(
        app,
        "/api/v1/lease/execute",
        {
          sessionId,
          idempotencyKey: "lease-http-mcp-success",
          payload: {
            spendId,
            payer,
            artifactHash: quoted.artifactHash,
            targetRepo: "https://github.com/example/independent-target",
            targetCommit: "abcdef123456",
          },
        },
        { authorization: `Bearer ${issued.json.data.accessToken}` },
      );
      const tokenRow = ctx.db.sqlite
        .prepare("SELECT status FROM artifact_access_tokens WHERE session_id = ? AND token_id = ?")
        .get(sessionId, issued.json.data.tokenId) as { status: string };

      expect(issued.status).toBe(202);
      expect(lease.status).toBe(202);
      expect(lease.json.data.status).toBe("succeeded_live_mcp_transcript");
      expect(tokenRow.status).toBe("consumed");
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/call"]);
    } finally {
      await mcp.close();
    }
  });

  it("blocks live MCP lease execution before tools/call when tools/list diverges from the pinned source manifest", async () => {
    const mcp = await startMcpJsonRpcServer((request) => {
      if (request.method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: { tools: [leaseToolDefinitionForTest("pactfuse_code_scan")] },
        };
      }
      return {
        jsonrpc: "2.0",
        id: request.id,
        result: { content: [{ type: "text", text: "should-not-run" }] },
      };
    });
    try {
      const logs: Array<Record<string, unknown>> = [];
      const { app, ctx } = makeApp(":memory:", {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-pinned-manifest-mismatch");
      const spendId = await registerSpend(app, sessionId, defaultSourceCapabilityForTest("pactfuse_other_scan"));
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-pinned-manifest-mismatch");
      await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-pinned-manifest-mismatch");
      const issued = await post(app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-pinned-manifest-mismatch-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const lease = await post(
        app,
        "/api/v1/lease/execute",
        {
          sessionId,
          idempotencyKey: "lease-pinned-manifest-mismatch",
          payload: {
            spendId,
            payer,
            artifactHash: quoted.artifactHash,
            targetRepo: "https://github.com/example/independent-target",
            targetCommit: "abcdef123456",
          },
        },
        { authorization: `Bearer ${issued.json.data.accessToken}` },
      );
      const tokenRow = ctx.db.sqlite
        .prepare("SELECT status FROM artifact_access_tokens WHERE session_id = ? AND token_id = ?")
        .get(sessionId, issued.json.data.tokenId) as { status: string };
      const succeededLeaseCount = ctx.db.sqlite
        .prepare("SELECT COUNT(*) AS count FROM lease_runs WHERE session_id = ? AND status = 'succeeded_live_mcp_transcript'")
        .get(sessionId) as { count: number };

      expect(issued.status).toBe(202);
      expect(lease.status).toBe(202);
      expect(lease.json.data.status).toBe("blocked_mcp_execution_failed");
      expect(tokenRow.status).toBe("active");
      expect(succeededLeaseCount.count).toBe(0);
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list"]);
    } finally {
      await mcp.close();
    }
  });

  it("terminates artifact tokens after tools/call failure so untrusted side effects cannot be replayed", async () => {
    const mcp = await startMcpJsonRpcServer((request) => {
      if (request.method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: { tools: [leaseToolDefinitionForTest()] },
        };
      }
      return {
        jsonrpc: "2.0",
        id: request.id,
        error: { code: -32000, message: "tool failed after execution" },
      };
    });
    try {
      const logs: Array<Record<string, unknown>> = [];
      const { app, ctx } = makeApp(":memory:", {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-call-failure-blocks-token");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-call-failure-blocks-token");
      await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-call-failure-blocks-token");
      const issued = await post(app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-call-failure-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const body = (idempotencyKey: string) => ({
        sessionId,
        idempotencyKey,
        payload: {
          spendId,
          payer,
          artifactHash: quoted.artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
        },
      });

      const first = await post(app, "/api/v1/lease/execute", body("lease-call-failure-a"), {
        authorization: `Bearer ${issued.json.data.accessToken}`,
      });
      const second = await post(app, "/api/v1/lease/execute", body("lease-call-failure-b"), {
        authorization: `Bearer ${issued.json.data.accessToken}`,
      });
      const tokenRow = ctx.db.sqlite
        .prepare("SELECT status FROM artifact_access_tokens WHERE session_id = ? AND token_id = ?")
        .get(sessionId, issued.json.data.tokenId) as { status: string };

      expect(issued.status).toBe(202);
      expect(first.status).toBe(202);
      expect(first.json.data.status).toBe("blocked_mcp_execution_failed");
      expect(second.status).toBe(422);
      expect(second.json.error.code).toBe("proof_blocked");
      expect(tokenRow.status).toBe("blocked");
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/call"]);
    } finally {
      await mcp.close();
    }
  });

  it("reconciles expired consuming lease claims into blocked evidence instead of leaving permanent half-state", async () => {
    const logs: Array<Record<string, unknown>> = [];
    let executeCalls = 0;
    const mcpLease: McpLeaseClient = {
      async status() {
        return { name: "mcp_lease", mode: "fixture", ready: true, reason: "should not execute" };
      },
      async executeCleanLease(input) {
        executeCalls += 1;
        return createFakeMcpLeaseClient().executeCleanLease(input);
      },
    };
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
      mcpLease,
    });
    const sessionId = await createSession(app, "sess-lease-expired-consuming");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-expired-consuming");
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-expired-consuming");
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-expired-consuming-token",
      payload: {
        spendId,
        payer,
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload: quoted.artifactPayload,
      },
    });
    const expiredLeaseRunId = hex32("expired-consuming-lease-run");
    ctx.db.sqlite
      .prepare(
        `UPDATE artifact_access_tokens
         SET status = 'consuming', lease_claim_json = ?, lease_claimed_at = ?
         WHERE session_id = ? AND token_id = ?`,
      )
      .run(
        canonicalizeJson({
          requestId: "req_expired_consuming",
          leaseRunId: expiredLeaseRunId,
          spendId,
          payer,
          artifactHash: quoted.artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
          settlementEventId: issued.json.data.settlementEventId,
        }),
        "2026-06-10T23:50:00.000Z",
        sessionId,
        issued.json.data.tokenId,
      );

    const lease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "lease-expired-consuming",
        payload: {
          spendId,
          payer,
          artifactHash: quoted.artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${issued.json.data.accessToken}` },
    );
    const tokenRow = ctx.db.sqlite
      .prepare("SELECT status FROM artifact_access_tokens WHERE session_id = ? AND token_id = ?")
      .get(sessionId, issued.json.data.tokenId) as { status: string };
    const blockedLease = ctx.db.sqlite
      .prepare("SELECT status FROM lease_runs WHERE session_id = ? AND lease_run_id = ?")
      .get(sessionId, expiredLeaseRunId) as { status: string };

    expect(issued.status).toBe(202);
    expect(lease.status).toBe(422);
    expect(lease.json.error.code).toBe("proof_blocked");
    expect(tokenRow.status).toBe("blocked");
    expect(blockedLease.status).toBe("blocked_mcp_execution_failed");
    expect(executeCalls).toBe(0);
  });

  it("rejects dangerous configured lease MCP tool names before network execution", () => {
    expect(() =>
      createHttpJsonRpcMcpLeaseClient({
        endpointUrl: "http://127.0.0.1:1",
        toolName: "pactfuse_shell_exec",
      }),
    ).toThrow("must not describe write");
  });

  it("blocks live MCP lease execution when tools/list exposes disallowed capabilities", async () => {
    const mcp = await startMcpJsonRpcServer((request) => {
      if (request.method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            tools: [leaseToolDefinitionForTest(), { name: "write_file" }],
          },
        };
      }
      return {
        jsonrpc: "2.0",
        id: request.id,
        result: { content: [{ type: "text", text: "should-not-run" }] },
      };
    });
    try {
      const logs: Array<Record<string, unknown>> = [];
      const { app, ctx } = makeApp(":memory:", {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-dangerous-tools");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-dangerous-tools");
      await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-dangerous-tools");
      const issued = await post(app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-dangerous-tools-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const lease = await post(
        app,
        "/api/v1/lease/execute",
        {
          sessionId,
          idempotencyKey: "lease-dangerous-tools",
          payload: {
            spendId,
            payer,
            artifactHash: quoted.artifactHash,
            targetRepo: "https://github.com/example/independent-target",
            targetCommit: "abcdef123456",
          },
        },
        { authorization: `Bearer ${issued.json.data.accessToken}` },
      );
      const succeededLeaseCount = ctx.db.sqlite
        .prepare("SELECT COUNT(*) AS count FROM lease_runs WHERE session_id = ? AND status = 'succeeded_live_mcp_transcript'")
        .get(sessionId) as { count: number };

      expect(issued.status).toBe(202);
      expect(lease.status).toBe(202);
      expect(lease.json.data.status).toBe("blocked_mcp_execution_failed");
      expect(lease.json.data.winnerClaimAllowed).toBe(false);
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list"]);
      expect(succeededLeaseCount.count).toBe(0);
    } finally {
      await mcp.close();
    }
  });

  it("blocks live MCP lease execution when the required tool omits read-only schema metadata", async () => {
    const mcp = await startMcpJsonRpcServer((request) => {
      if (request.method === "tools/list") {
        return {
          jsonrpc: "2.0",
          id: request.id,
          result: {
            tools: [{ name: "pactfuse_code_scan" }],
          },
        };
      }
      return {
        jsonrpc: "2.0",
        id: request.id,
        result: { content: [{ type: "text", text: "should-not-run" }] },
      };
    });
    try {
      const logs: Array<Record<string, unknown>> = [];
      const { app, ctx } = makeApp(":memory:", {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-missing-tool-metadata");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-missing-tool-metadata");
      await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-missing-tool-metadata");
      const issued = await post(app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-missing-tool-metadata-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const lease = await post(
        app,
        "/api/v1/lease/execute",
        {
          sessionId,
          idempotencyKey: "lease-missing-tool-metadata",
          payload: {
            spendId,
            payer,
            artifactHash: quoted.artifactHash,
            targetRepo: "https://github.com/example/independent-target",
            targetCommit: "abcdef123456",
          },
        },
        { authorization: `Bearer ${issued.json.data.accessToken}` },
      );

      expect(issued.status).toBe(202);
      expect(lease.status).toBe(202);
      expect(lease.json.data.status).toBe("blocked_mcp_execution_failed");
      expect(lease.json.data.winnerClaimAllowed).toBe(false);
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list"]);
    } finally {
      await mcp.close();
    }
  });

  it("serializes concurrent lease executions for the same artifact token before external MCP side effects", async () => {
    const logs: Array<Record<string, unknown>> = [];
    let executeCalls = 0;
    let releaseLease!: () => void;
    let markStarted!: () => void;
    const leaseStarted = new Promise<void>((resolve) => {
      markStarted = resolve;
    });
    const releaseSignal = new Promise<void>((resolve) => {
      releaseLease = resolve;
    });
    const fakeMcp = createFakeMcpLeaseClient();
    const mcpLease: McpLeaseClient = {
      async status() {
        return {
          name: "mcp_lease",
          mode: "fixture",
          ready: true,
          reason: "barrier MCP lease client",
        };
      },
      async executeCleanLease(input) {
        executeCalls += 1;
        markStarted();
        await releaseSignal;
        return fakeMcp.executeCleanLease(input);
      },
    };
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
      mcpLease,
    });
    const sessionId = await createSession(app, "sess-lease-token-race");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-token-race");
    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-token-race");
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-lease-race-token",
      payload: {
        spendId,
        payer,
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload: quoted.artifactPayload,
      },
    });
    const body = (idempotencyKey: string) => ({
      sessionId,
      idempotencyKey,
      payload: {
        spendId,
        payer,
        artifactHash: quoted.artifactHash,
        targetRepo: "https://github.com/example/independent-target",
        targetCommit: "abcdef123456",
      },
    });

    const first = post(app, "/api/v1/lease/execute", body("lease-race-a"), { authorization: `Bearer ${issued.json.data.accessToken}` });
    await leaseStarted;
    const second = post(app, "/api/v1/lease/execute", body("lease-race-b"), { authorization: `Bearer ${issued.json.data.accessToken}` });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(executeCalls).toBe(1);
    releaseLease();
    const [firstResult, secondResult] = await Promise.all([first, second]);
    const succeededLeaseCount = ctx.db.sqlite
      .prepare("SELECT COUNT(*) AS count FROM lease_runs WHERE session_id = ? AND artifact_token_id = ? AND status = 'succeeded_live_mcp_transcript'")
      .get(sessionId, issued.json.data.tokenId) as { count: number };

    expect(issued.status).toBe(202);
    expect(firstResult.status).toBe(202);
    expect(secondResult.status).toBe(422);
    expect(secondResult.json.error.code).toBe("proof_blocked");
    expect(executeCalls).toBe(1);
    expect(succeededLeaseCount.count).toBe(1);
  });

  it("uses the database claim to block cross-instance lease execution before external MCP side effects", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pactfuse-lease-claim-"));
    const dbPath = join(dir, "pactfuse.sqlite");
    try {
      const logs: Array<Record<string, unknown>> = [];
      let executeCalls = 0;
      let releaseLease!: () => void;
      let markStarted!: () => void;
      const leaseStarted = new Promise<void>((resolve) => {
        markStarted = resolve;
      });
      const releaseSignal = new Promise<void>((resolve) => {
        releaseLease = resolve;
      });
      const fakeMcp = createFakeMcpLeaseClient();
      const mcpLease: McpLeaseClient = {
        async status() {
          return { name: "mcp_lease", mode: "fixture", ready: true, reason: "barrier MCP lease client" };
        },
        async executeCleanLease(input) {
          executeCalls += 1;
          markStarted();
          await releaseSignal;
          return fakeMcp.executeCleanLease(input);
        },
      };
      const first = makeApp(dbPath, {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease,
      });
      const sessionId = await createSession(first.app, "sess-cross-instance-lease-claim");
      const spendId = await registerSpend(first.app, sessionId);
      const payer = "0x1234";
      const quoted = await quoteArtifactForTest(first.app, sessionId, spendId, "cross-instance-lease-claim");
      await finalizeSpendSettlement(first.app, first.ctx, logs, sessionId, spendId, "cross-instance-lease-claim");
      const issued = await post(first.app, "/api/v1/artifacts/access-token", {
        sessionId,
        idempotencyKey: "issue-cross-instance-token",
        payload: {
          spendId,
          payer,
          quoteId: quoted.quoteId,
          artifactHash: quoted.artifactHash,
          artifactPayload: quoted.artifactPayload,
        },
      });
      const second = makeApp(dbPath, {
        chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
        mcpLease: createFakeMcpLeaseClient(),
      });
      const body = (idempotencyKey: string) => ({
        sessionId,
        idempotencyKey,
        payload: {
          spendId,
          payer,
          artifactHash: quoted.artifactHash,
          targetRepo: "https://github.com/example/independent-target",
          targetCommit: "abcdef123456",
        },
      });

      const firstLease = post(first.app, "/api/v1/lease/execute", body("lease-cross-instance-a"), {
        authorization: `Bearer ${issued.json.data.accessToken}`,
      });
      await leaseStarted;
      const secondLease = await post(second.app, "/api/v1/lease/execute", body("lease-cross-instance-b"), {
        authorization: `Bearer ${issued.json.data.accessToken}`,
      });
      expect(secondLease.status).toBe(422);
      expect(secondLease.json.error.code).toBe("proof_blocked");
      expect(executeCalls).toBe(1);
      releaseLease();
      const firstResult = await firstLease;
      const succeededLeaseCount = first.ctx.db.sqlite
        .prepare("SELECT COUNT(*) AS count FROM lease_runs WHERE session_id = ? AND artifact_token_id = ? AND status = 'succeeded_live_mcp_transcript'")
        .get(sessionId, issued.json.data.tokenId) as { count: number };

      expect(issued.status).toBe(202);
      expect(firstResult.status).toBe(202);
      expect(succeededLeaseCount.count).toBe(1);
      first.ctx.db.sqlite.close();
      second.ctx.db.sqlite.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("surfaces fail-closed proof providers and binds Pact template hashes", async () => {
    const { app } = makeApp();
    const ready = await app.request("/readyz");
    const readyJson = await ready.json();

    const session = await post(app, "/api/v1/sessions", {
      idempotencyKey: "sess-provider-status",
      payload: { label: "provider-status" },
    });
    const sessionId = session.json.data.sessionId;
    const spendId = await registerSpend(app, sessionId);
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-provider-bound-op",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x1234",
        selector: "0xabcdef12",
      },
    });
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-provider-status",
      payload: { receipt: { receiptId: "provider-status" } },
    });

    expect(readyJson.proofProviders).toEqual([
      expect.objectContaining({ name: "chain", mode: "unconfigured", ready: false }),
      expect.objectContaining({ name: "caw", mode: "unconfigured", ready: false }),
      expect.objectContaining({ name: "mcp_lease", mode: "unconfigured", ready: false }),
    ]);
    expect(session.json.data.pactTemplates).toEqual([
      expect.objectContaining({ mode: "gate-paid-artifact-real", templateHash: hex32("gate-paid-template") }),
      expect.objectContaining({ mode: "permit-payment-real", templateHash: hex32("permit-template") }),
    ]);
    expect(operation.json.data.pactTemplateMode).toBe("gate-paid-artifact-real");
    expect(operation.json.data.pactTemplateHash).toBe(hex32("gate-paid-template"));
    expect(verify.json.data.warnings).toContain("chain proof provider is unconfigured: chain RPC endpoint is not configured");
    expect(verify.json.data.warnings).toContain("caw proof provider is unconfigured: CAW receipt source is not configured");
    expect(verify.json.data.warnings).toContain("mcp_lease proof provider is unconfigured: lease MCP endpoint is not configured");
    expect(verify.json.data.raw.proofProviders).toHaveLength(3);
  });

  it("passes pinned Pact template hashes into the verifier", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-template-verify");

    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-template-mismatch",
      payload: {
        receipt: {
          artifactType: "source-bound-code-scan-mcp-lease",
          pactId: hex32("template-pact"),
          spendId: hex32("template-spend"),
          toolId: "mcp-code-scan-basic",
          pactTemplateHash: hex32("wrong-template"),
          paymentProof: {
            mode: "gate-paid-artifact-real",
            gatePaid: {},
          },
          payment: {
            mode: "gate-paid-artifact-real",
          },
        },
      },
    });

    expect(verify.status).toBe(200);
    expect(verify.json.data.proofChipAllowed).toBe(false);
    expect(verify.json.data.raw.pactTemplates).toEqual([
      expect.objectContaining({ mode: "gate-paid-artifact-real", templateHash: hex32("gate-paid-template") }),
      expect.objectContaining({ mode: "permit-payment-real", templateHash: hex32("permit-template") }),
    ]);
    expect(verify.json.data.raw.proofCompletenessErrors).toContain(
      "pactTemplateHash must match pinned gate-paid-artifact-real template hash",
    );
  });
});

async function createSession(app: ReturnType<typeof createApp>, key: string, payload: Record<string, unknown> = {}): Promise<string> {
  const res = await post(app, "/api/v1/sessions", { idempotencyKey: key, payload: { label: key, ...payload } });
  expect(res.status).toBe(201);
  return res.json.data.sessionId;
}

async function registerSource(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  capabilityVector: Record<string, unknown> = defaultSourceCapabilityForTest(),
) {
  const res = await post(app, "/api/v1/sources/register", {
    sessionId,
    idempotencyKey: "src-register",
    payload: {
      sourceId: "clean-source",
      sourceHash: hex32("source"),
      manifestUrl: "https://example.com/manifest.json",
      manifestHash: hex32("manifest"),
      capabilityVector,
    },
  });
  expect(res.status).toBe(201);
}

async function signedSourcePayloadForTest(seed: string) {
  const account = privateKeyToAccount(hex32(`source-issuer:${seed}`));
  const unsigned = {
    sourceId: seed,
    manifestUrl: `https://example.com/${seed}.json`,
    manifestHash: hex32(`manifest:${seed}`),
      capabilityVector: { ...defaultSourceCapabilityForTest(), seed },
  };
  const sourceHash = hashForTestJson({
    version: "pactfuse-source-identity-v1",
    sourceId: unsigned.sourceId,
    manifestUrl: unsigned.manifestUrl,
    manifestHash: unsigned.manifestHash.toLowerCase(),
    capabilityVector: unsigned.capabilityVector,
  });
  const signature = await account.signMessage({ message: sourceIdentityMessageForTest(sourceHash) });
  return {
    payload: {
      ...unsigned,
      sourceHash,
      issuer: account.address,
      signature,
    },
  };
}

function sourceIdentityMessageForTest(sourceIdentityHash: `0x${string}`): string {
  return `PactFuse source identity v1:${sourceIdentityHash}`;
}

function defaultSourceCapabilityForTest(toolName = "pactfuse_code_scan"): Record<string, unknown> {
  return {
    has_write_file: false,
    mcpTools: [leaseToolDefinitionForTest(toolName)],
  };
}

async function registerSpend(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  capabilityVector: Record<string, unknown> = defaultSourceCapabilityForTest(),
): Promise<string> {
  await registerSource(app, sessionId, capabilityVector);
  const sourceHashes = [hex32("source")];
  const spendId = await computeSpendIdForTest(app, sessionId, sourceHashes, capabilityVector);
  const res = await post(app, "/api/v1/spends/register-batch", {
    sessionId,
    idempotencyKey: "spend-register",
    payload: {
      spends: [
        {
          spendId,
          pactId: "pact-c",
          toolId: "code-scan",
          payer: "0x1234",
          agentWallet: "0xabcd",
          sourceHashes,
          maxPriceAtomic: "1000",
          nonce: "nonce-1",
        },
      ],
    },
  });
  expect(res.status).toBe(201);
  return spendId;
}

function artifactCidForTest(artifactHash: string): string {
  return `sha256:${artifactHash.toLowerCase()}`;
}

function artifactPayloadForTest(seed: string): Record<string, unknown> {
  return { artifactType: "source-bound-code-scan-mcp-lease", seed, content: `scan:${seed}` };
}

async function quoteArtifactForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  spendId: string,
  seed: string,
  options: { artifactPayload?: Record<string, unknown>; priceAtomic?: string; validUntilBlock?: string } = {},
): Promise<{
  artifactPayload: Record<string, unknown>;
  artifactHash: `0x${string}`;
  artifactCid: string;
  preflightId: string;
  quoteId: string;
}> {
  const artifactPayload = options.artifactPayload ?? artifactPayloadForTest(seed);
  const artifactHash = hashForTestJson(artifactPayload);
  const artifactCid = artifactCidForTest(artifactHash);
  const preflight = await post(app, "/api/v1/artifacts/preflight", {
    sessionId,
    idempotencyKey: `${seed}-preflight`,
    payload: {
      spendId,
      artifactHashPreview: artifactHash,
      artifactCid,
      endpointUrl: `https://example.com/${seed}.json`,
      priceDisclosureHash: hex32(`${seed}-price`),
      sourceStateSnapshotHash: hex32(`${seed}-source-state`),
    },
  });
  expect(preflight.status).toBe(202);
  const quote = await post(app, "/api/v1/quotes", {
    sessionId,
    idempotencyKey: `${seed}-quote`,
    payload: {
      spendId,
      preflightId: preflight.json.data.preflightId,
      artifactCommitment: artifactHash,
      priceAtomic: options.priceAtomic ?? "1000",
      quoteNonce: `${seed}-quote-nonce`,
      validUntilBlock: options.validUntilBlock ?? "1000000",
    },
  });
  expect(quote.status).toBe(201);
  return {
    artifactPayload,
    artifactHash,
    artifactCid,
    preflightId: preflight.json.data.preflightId,
    quoteId: quote.json.data.quoteId,
  };
}

const INDEXER_ADDRESS = "0x1111111111111111111111111111111111111111";

function createFakeIndexerChainClient(config: {
  chainId?: string;
  currentBlockNumber?: number;
  logs?: Array<Record<string, unknown>>;
  ready?: boolean;
  reason?: string;
  getLogsError?: Error;
  readContractError?: Error;
  contractSpendStates?: Record<string, number>;
  sourceStates?: Record<string, number>;
  ignoreAddressFilter?: boolean;
}): ChainClient {
  return {
    async status() {
      return {
        name: "chain",
        mode: "fixture",
        ready: config.ready ?? true,
        reason: config.reason ?? "test chain indexer provider",
        chainId: config.chainId ?? "84532",
      };
    },
    async getBlockNumber() {
      return config.currentBlockNumber ?? 101;
    },
    async getTransactionReceipt(txHash: string) {
      const matchingLog = (config.logs ?? []).find((log) => {
        return typeof log.transactionHash === "string" && log.transactionHash.toLowerCase() === txHash.toLowerCase();
      });
      return {
        transactionHash: txHash,
        blockNumber: matchingLog?.blockNumber ?? config.currentBlockNumber ?? 101,
        status: "success",
      };
    },
    async getLogs(query: Record<string, unknown>) {
      if (config.getLogsError) {
        throw config.getLogsError;
      }
      if (query.reorged === true) {
        return [];
      }
      const fromBlock = Number(query.fromBlock ?? query.blockNumber ?? 0);
      const toBlock = Number(query.toBlock ?? query.blockNumber ?? fromBlock);
      const address = !config.ignoreAddressFilter && typeof query.address === "string" ? query.address.toLowerCase() : null;
      const txHash = typeof query.txHash === "string" ? query.txHash.toLowerCase() : null;
      const logIndex = query.logIndex === undefined ? null : Number(query.logIndex);
      const event = typeof query.event === "string" ? query.event : null;
      const spendId = typeof query.spendId === "string" ? query.spendId.toLowerCase() : null;
      return (config.logs ?? []).filter((log) => {
        const blockNumber = Number(log.blockNumber);
        const logAddress = typeof log.address === "string" ? log.address.toLowerCase() : null;
        const logTxHash = typeof log.transactionHash === "string" ? log.transactionHash.toLowerCase() : null;
        const logIndexValue = log.logIndex === undefined ? null : Number(log.logIndex);
        const logEvent = typeof log.eventName === "string" ? log.eventName : typeof log.event === "string" ? log.event : null;
        const args = log.args && typeof log.args === "object" && !Array.isArray(log.args) ? (log.args as Record<string, unknown>) : {};
        const logSpendId = typeof args.spendId === "string" ? args.spendId.toLowerCase() : typeof log.spendId === "string" ? log.spendId.toLowerCase() : null;
        return (
          blockNumber >= fromBlock &&
          blockNumber <= toBlock &&
          (!address || logAddress === address) &&
          (!txHash || logTxHash === txHash) &&
          (logIndex === null || logIndexValue === logIndex) &&
          (!event || logEvent === event) &&
          (!spendId || logSpendId === spendId)
        );
      });
    },
    async readContract(input: {
      address: string;
      abi: readonly unknown[];
      functionName: string;
      args?: readonly unknown[];
      blockNumber?: number;
    }) {
      void input.address;
      void input.abi;
      void input.blockNumber;
      if (config.readContractError) {
        throw config.readContractError;
      }
      const args = input.args ?? [];
      if (input.functionName === "registeredSpend") {
        const spendId = String(args[0] ?? "").toLowerCase();
        const matchingLog = (config.logs ?? []).find((log) => {
          const logArgs = log.args && typeof log.args === "object" && !Array.isArray(log.args) ? (log.args as Record<string, unknown>) : {};
          const logSpendId =
            typeof logArgs.spendId === "string" ? logArgs.spendId.toLowerCase() : typeof log.spendId === "string" ? log.spendId.toLowerCase() : null;
          return logSpendId === spendId;
        });
        const logArgs =
          matchingLog?.args && typeof matchingLog.args === "object" && !Array.isArray(matchingLog.args)
            ? (matchingLog.args as Record<string, unknown>)
            : {};
        const event =
          typeof matchingLog?.eventName === "string"
            ? matchingLog.eventName
            : typeof matchingLog?.event === "string"
              ? matchingLog.event
              : null;
        const sessionId =
          typeof logArgs.sessionId === "string" ? logArgs.sessionId : typeof matchingLog?.sessionId === "string" ? matchingLog.sessionId : hex32("contract-session");
        const state = config.contractSpendStates?.[spendId] ?? (event === "SpendTripped" ? 2 : event === "SpendSettled" ? 3 : 1);
        return [
          sessionId,
          hex32("contract-pact"),
          hex32("contract-tool"),
          hex32(`contract-source-set:${spendId}`),
          INDEXER_ADDRESS,
          INDEXER_ADDRESS,
          "1000",
          hex32("contract-artifact"),
          INDEXER_ADDRESS,
          state,
        ];
      }
      if (input.functionName === "sourceState") {
        const sourceHash = String(args[0] ?? "").toLowerCase();
        return config.sourceStates?.[sourceHash] ?? 2;
      }
      throw new Error(`unsupported fake contract read: ${input.functionName}`);
    },
  };
}

function indexerLog(seed: string, blockNumber: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    transactionHash: hex32(`indexer:${seed}:tx`),
    logIndex: blockNumber - 100,
    chainId: "84532",
    blockNumber,
    address: INDEXER_ADDRESS,
    topics: [hex32(`indexer:${seed}:topic`)],
    data: "0x01",
    rawLogHash: hex32(`indexer:${seed}:raw`),
    ...overrides,
  };
}

function insertCaughtUpIndexerCursor(
  ctx: ServiceCtx,
  input: { chainId: string; lastIndexedBlock: number; finalizedHeadBlock: number; cursorId?: string },
): void {
  ctx.db.sqlite
    .prepare(
      `INSERT INTO chain_indexer_cursors
        (cursor_id, chain_id, address, topics_json, last_indexed_block, latest_head_block, finalized_head_block,
         finality_depth, lag_blocks, status, reason, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 2, 0, 'caught_up', 'test caught up cursor', ?, ?)`,
    )
    .run(
      input.cursorId ?? "gate:indexer",
      input.chainId,
      INDEXER_ADDRESS,
      "[]",
      input.lastIndexedBlock,
      input.finalizedHeadBlock + 1,
      input.finalizedHeadBlock,
      "2026-06-11T00:00:00.000Z",
      "2026-06-11T00:00:00.000Z",
    );
}

function createFakeGateChainClient(currentBlockNumber = 101, chainId = "84532"): ChainClient {
  return {
    async status() {
      return {
        name: "chain",
        mode: "fixture",
        ready: true,
        reason: "test chain provider",
        chainId,
      };
    },
    async getBlockNumber() {
      return currentBlockNumber;
    },
    async getTransactionReceipt(txHash: string) {
      return {
        transactionHash: txHash,
        blockNumber: 100,
        status: "success",
      };
    },
    async getLogs(input: Record<string, unknown>) {
      if (input.reorged === true) {
        return [];
      }
      return [
        {
          transactionHash: input.txHash,
          logIndex: input.logIndex,
          chainId: input.chainId,
          blockNumber: input.blockNumber,
          eventName: input.event,
          args: { spendId: input.spendId },
          rawLogHash: input.rawLogHash,
        },
      ];
    },
    async readContract(input: {
      address: string;
      abi: readonly unknown[];
      functionName: string;
      args?: readonly unknown[];
      blockNumber?: number;
    }) {
      void input.address;
      void input.abi;
      void input.args;
      void input.blockNumber;
      if (input.functionName === "registeredSpend") {
        return [hex32("direct-session"), hex32("direct-pact"), hex32("direct-tool"), hex32("direct-source-set"), INDEXER_ADDRESS, INDEXER_ADDRESS, "1000", hex32("direct-artifact"), INDEXER_ADDRESS, 3];
      }
      if (input.functionName === "sourceState") {
        return 2;
      }
      throw new Error(`unsupported fake contract read: ${input.functionName}`);
    },
  };
}

function createFakeCawReceiptSource(input: { receipts: Array<Record<string, unknown>>; source?: string }): CawReceiptSource {
  return {
    async status() {
      return {
        name: "caw",
        mode: "fixture",
        ready: true,
        reason: "test CAW receipt source",
      };
    },
    async fetchReceiptBundle(request: Record<string, unknown>) {
      return {
        source: input.source ?? "caw-api",
        sourceLabel: request.sourceLabel,
        sessionId: request.sessionId,
        operationId: request.operationId,
        fetchedAt: "2026-06-11T00:00:00.000Z",
        receipts: input.receipts.map((receipt) => ({
          sessionId: request.sessionId,
          operationId: request.operationId,
          ...receipt,
        })),
      };
    },
  };
}

function gateEventEnvelope(
  sessionId: string,
  spendId: string,
  idempotencyKey: string,
  payload: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    sessionId,
    idempotencyKey,
    payload: {
      event: "SpendSettled",
      spendId,
      txHash: hex32(`${idempotencyKey}-tx`),
      logIndex: 0,
      chainId: "84532",
      blockNumber: 100,
      currentBlockNumber: 100,
      rawLogHash: hex32(`${idempotencyKey}-log`),
      ...payload,
    },
  };
}

async function postSignedGateEvent(app: ReturnType<typeof createApp>, body: Record<string, unknown>) {
  return post(app, "/api/v1/gate/events/ingest", body, {
    "x-pactfuse-gate-signature": signAuditPayload(GATE_INGEST_TOKEN, body),
  });
}

async function finalizeSpendSettlement(
  app: ReturnType<typeof createApp>,
  ctx: ServiceCtx,
  logs: Array<Record<string, unknown>>,
  sessionId: string,
  spendId: string,
  key: string,
): Promise<Record<string, unknown>> {
  const observedBody = gateEventEnvelope(sessionId, spendId, `${key}-observed`, {
    txHash: hex32(`${key}-tx`),
    rawLogHash: hex32(`${key}-log`),
    blockNumber: 100,
    currentBlockNumber: 100,
  });
  const observed = await postSignedGateEvent(app, observedBody);
  logs.push(
    indexerLog(key, 100, {
      eventName: "SpendSettled",
      event: "SpendSettled",
      sessionId,
      spendId,
      args: { sessionId, spendId },
      transactionHash: hex32(`${key}-tx`),
      rawLogHash: hex32(`${key}-log`),
    }),
  );
  const worker = await runIndexerWorkerOnce(ctx, {
    cursors: [{ cursorId: `gate:${key}`, chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 1, address: INDEXER_ADDRESS }],
  });
  const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
  const replayJson = await replay.json();
  const proofEvent = replayJson.data.events.find((event: { kind: string; payload: Record<string, unknown> }) => {
    return event.kind === "gate.spend_settled" && event.payload.spendId === spendId;
  });

  expect(observed.status).toBe(202);
  expect(worker.status).toBe("succeeded");
  expect(proofEvent).toEqual(expect.objectContaining({ authority: "proof" }));
  return {
    ...(proofEvent.payload as Record<string, unknown>),
    finalizedEventId: proofEvent.eventId,
    observedEventId: observed.json.data.observedEventId,
  };
}

async function computeSpendIdForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  sourceHashes: string[],
  capabilityVector: Record<string, unknown> = defaultSourceCapabilityForTest(),
): Promise<`0x${string}`> {
  const session = await app.request(`/api/v1/sessions/${sessionId}`);
  const sessionJson = await session.json();
  expect(session.status).toBe(200);
  const normalizedSourceHashes = [...sourceHashes].map((sourceHash) => sourceHash.toLowerCase()).sort();
  const runConfigHash = sessionJson.data.runConfigHash as string;
  const sourceSetHash = keccakJsonForTest(normalizedSourceHashes);
  const sourceCapabilitySnapshotHash = hashForTestJson([
    {
      sourceHash: hex32("source"),
      manifestHash: hex32("manifest"),
      capabilityVector,
    },
  ]);
  const sessionCommitment = keccakJsonForTest({ sessionId: sessionId.toLowerCase(), runConfigHash });
  return keccakJsonForTest({
    runConfigHash,
    sessionCommitment,
    pactId: "pact-c",
    toolId: "code-scan",
    sourceSetHash,
    sourceCapabilitySnapshotHash,
    payer: "0x1234",
    agentWallet: "0xabcd",
    maxPriceAtomic: "1000",
    nonce: "nonce-1",
  });
}

function schemaValidWinnerRequestedReceipt(): Record<string, unknown> {
  return {
    artifactType: "paid-code-scan",
    pactId: "pact-c",
    spendId: hex32("receipt-spend"),
    toolId: "code-scan",
    winnerClaimAllowed: true,
    statusFields: {
      isRealEvidence: true,
      winnerClaimAllowed: true,
    },
    payment: {
      mode: "gate-paid-artifact-real",
    },
    paymentProof: {
      mode: "gate-paid-artifact-real",
      permit: null,
      gatePaid: {
        approveTxHash: hex32("approve-tx"),
        allowanceBefore: "0",
        allowanceAfter: "1000",
        approvedAmount: "1000",
        quotePrice: "1000",
        policyTxCount: "2",
        approveBeforeActivate: true,
      },
    },
    checks: {
      recommendedCawPolicy: {
        txCount: "2",
        allowedCalls: [
          {
            target: "PUBLIC_TESTNET_MOCK_ERC20",
            selector: "approve",
            constraints: {
              spender: "ProcurementGate",
              amountMax: "1000",
            },
          },
          {
            target: "ProcurementGate",
            selector: "activateTool",
            constraints: {
              paymentAuth: "empty",
            },
          },
        ],
      },
    },
  };
}

async function post(
  app: ReturnType<typeof createApp>,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const effectiveHeaders = { ...headers };
  const skipCawAuth = effectiveHeaders["x-test-skip-caw-auth"];
  delete effectiveHeaders["x-test-skip-caw-auth"];
  if (path === "/api/v1/caw/receipts/ingest" && !skipCawAuth && !Object.keys(effectiveHeaders).some((key) => key.toLowerCase() === "authorization")) {
    effectiveHeaders.authorization = `Bearer ${CAW_INGEST_TOKEN}`;
  }
  const res = await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...effectiveHeaders },
    body: JSON.stringify(body),
  });
  return { status: res.status, headers: res.headers, json: await res.json() };
}

async function rawPost(
  app: ReturnType<typeof createApp>,
  path: string,
  body: string,
  headers: Record<string, string> = {},
) {
  const res = await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
  return { status: res.status, headers: res.headers, json: await res.json() };
}

function hex32(seed: string): `0x${string}` {
  return `0x${createHash("sha256").update(seed).digest("hex")}`;
}

function uppercaseHexBody(value: string): `0x${string}` {
  return `0x${value.slice(2).toUpperCase()}`;
}

function cawReceiptFields(seed: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    walletAddress: "0x1111111111111111111111111111111111111111",
    policyDigest: hex32(`policy:${seed}`),
    paramsDigest: hex32(`params:${seed}`),
    requestId: `req-${seed}`,
    effect: "allow",
    status: "succeeded",
    txHash: hex32(`tx:${seed}`),
    txCount: "1",
    expiry: "2026-06-12T00:00:00.000Z",
    ...overrides,
  };
}

function hashForTestJson(value: unknown): `0x${string}` {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function keccakJsonForTest(value: unknown): `0x${string}` {
  return keccak256(toBytes(canonicalizeJson(value)));
}

function createFakeMcpLeaseClient(toolName = "pactfuse_code_scan"): McpLeaseClient {
  return {
    async status() {
      return {
        name: "mcp_lease",
        mode: "fixture",
        ready: true,
        reason: "fake MCP lease client",
      };
    },
    async executeCleanLease(input) {
      const listRequest = {
        jsonrpc: "2.0",
        id: "lease-tools-list",
        method: "tools/list",
        params: {},
      };
      const listResponse = {
        jsonrpc: "2.0",
        id: "lease-tools-list",
        result: {
          tools: [
            leaseToolDefinitionForTest(toolName),
          ],
        },
      };
      const callRequest = {
        jsonrpc: "2.0",
        id: "lease-tools-call",
        method: "tools/call",
        params: {
          name: toolName,
          arguments: {
            sessionId: input.sessionId,
            leaseRunId: input.leaseRunId,
            spendId: input.spendId,
            payer: input.payer,
            artifactHash: input.artifactHash,
            targetRepo: input.targetRepo,
            targetCommit: input.targetCommit,
          },
        },
      };
      const callResponse = {
        jsonrpc: "2.0",
        id: "lease-tools-call",
        result: {
          content: [
            {
              type: "text",
              text: `scan:${input.targetRepo}@${input.targetCommit}`,
            },
          ],
          structuredContent: {
            targetRepo: input.targetRepo,
            targetCommit: input.targetCommit,
            findingCount: 0,
          },
        },
      };
      return {
        toolName,
        toolsList: { method: "tools/list", request: listRequest, response: listResponse },
        toolsCall: { method: "tools/call", request: callRequest, response: callResponse },
        output: callResponse,
      };
    },
  };
}

function leaseToolDefinitionForTest(name = "pactfuse_code_scan"): Record<string, unknown> {
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

async function startMcpJsonRpcServer(respond: (request: Record<string, unknown>) => Record<string, unknown>): Promise<{
  url: string;
  calls: Array<Record<string, unknown>>;
  close: () => Promise<void>;
}> {
  const calls: Array<Record<string, unknown>> = [];
  const server = createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      const request = JSON.parse(body) as Record<string, unknown>;
      calls.push(request);
      const response = respond(request);
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(response));
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test MCP server did not bind to a TCP port");
  }
  return {
    url: `http://127.0.0.1:${address.port}`,
    calls,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      }),
  };
}

function signAuditPayload(secret: string, payload: unknown): `0x${string}` {
  return `0x${createHmac("sha256", secret).update(JSON.stringify(sortForTestCanonicalJson(payload))).digest("hex")}`;
}

function sortForTestCanonicalJson(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sortForTestCanonicalJson(item));
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child !== undefined) {
        result[key] = sortForTestCanonicalJson(child);
      }
    }
    return result;
  }
  return null;
}
