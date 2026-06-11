import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { keccak256, toBytes } from "viem";
import { canonicalizeJson } from "@pactfuse/evidence-schema";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeases } from "../services/jobs.js";
import {
  createHttpsCawReceiptSource,
  createStaticTemplateRegistry,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
} from "../services/providers.js";
import { appendEvidenceEvent, recordMcpAdapterCall } from "../services/service.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { CawReceiptSource, ChainClient, ServiceCtx } from "../types.js";

const MCP_AUDIT_TOKEN = "test-mcp-audit-token";

function makeApp(
  dbPath = ":memory:",
  options: { caw?: CawReceiptSource; chain?: ChainClient; mcpAuditSecret?: string | null; cawIngestToken?: string | null } = {},
) {
  const mcpAuditSecret = options.mcpAuditSecret === undefined ? MCP_AUDIT_TOKEN : options.mcpAuditSecret;
  const ctx: ServiceCtx = {
    db: openPactFuseDb(dbPath),
    verifier: createVerifierAdapter(),
    chain: options.chain ?? createUnconfiguredChainClient(),
    caw: options.caw ?? createUnconfiguredCawReceiptSource(),
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
    cawIngestToken: options.cawIngestToken ?? null,
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

  it("does not expose MCP audit secrets or derived token hashes in health output", async () => {
    const { app } = makeApp();

    const health = await app.request("/healthz");
    const healthJson = await health.json();
    const serialized = JSON.stringify(healthJson);

    expect(health.status).toBe(200);
    expect(serialized).not.toContain("mcpAuditSecret");
    expect(serialized).not.toContain("mcpAuditTokenHash");
    expect(serialized).not.toContain(MCP_AUDIT_TOKEN);
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
    expect(json.paths["/api/v1/caw/receipts/ingest"].post["x-pactfuse-proof-fields"]).toEqual([
      "proofAuthority",
      "winnerClaimAllowed",
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
      "priceDisclosureHash",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/quotes"].post["x-pactfuse-proof-fields"]).toEqual([
      "preflightId",
      "quoteSignedAfterPreflight",
      "priceDisclosureHash",
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
      "mcpAdapterCalls",
      "cawReceiptOperations",
      "rawCawReceiptBundles",
      "canonicalCawReceipts",
      "judgeCheck",
    ]);
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("mcpAdapterCalls");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("rawCawReceiptBundles");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("canonicalCawReceipts");
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
    expect(
      json.components.schemas.AgentTranscriptResponse.oneOf[0].properties.data.properties.boundedToPinnedManifest.const,
    ).toBe(false);
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

    const missing = await post(app, "/api/v1/caw/receipts/ingest", body);
    const wrong = await post(app, "/api/v1/caw/receipts/ingest", body, { authorization: "Bearer wrong" });
    const allowed = await post(app, "/api/v1/caw/receipts/ingest", body, { authorization: "Bearer caw-ingest-secret" });

    expect(missing.status).toBe(403);
    expect(wrong.status).toBe(403);
    expect(allowed.status).toBe(202);
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
    const bundleRow = ctx.db.sqlite
      .prepare("SELECT operation_id, source_label, receipt_count, raw_bundle_hash, raw_bundle_json FROM caw_raw_receipt_bundles")
      .get() as Record<string, unknown>;

    expect(operation.status).toBe(201);
    expect(ingest.status).toBe(202);
    expect(ingest.json.data.operationId).toBe(operation.json.data.operationId);
    expect(ingest.json.data.receiptCount).toBe(1);
    expect(ingest.json.data.canonicalReceiptCount).toBe(1);
    expect(ingest.json.data.status).toBe("raw_ingested_pending_proof");
    expect(ingest.json.data.proofAuthority).toBe(false);
    expect(event.payload.operationId).toBe(operation.json.data.operationId);
    expect(event.payload.receiptCount).toBe(1);
    expect(event.payload.manual).toBe(false);
    expect(event.payload.rawReceiptBundleHash).toBe(ingest.json.data.rawReceiptBundleHash);
    expect(replayJson.data.cawReceiptOperations).toEqual([
      expect.objectContaining({
        operationId: operation.json.data.operationId,
        receiptBundleHash: ingest.json.data.rawReceiptBundleHash,
        status: "raw_ingested_pending_proof",
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
        status: "raw_ingested_pending_proof",
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

  it("finalizes gate settlement only at configured depth and records a matching proof row", async () => {
    const { app, ctx } = makeApp(":memory:", { chain: createFakeGateChainClient() });
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

    const observed = await postSignedGateEvent(app, observedBody);
    const finalized = await postSignedGateEvent(app, finalizedBody);
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
    expect(finalized.json.data.finalityStatus).toBe("finalized");
    expect(finalized.json.data.confirmations).toBe(2);
    expect(finalized.json.data.proofAuthority).toBe(true);
    expect(row.status).toBe("finalized");
    expect(row.observed_event_id).toBe(observed.json.data.observedEventId);
    expect(row.finalized_event_id).toBe(finalized.json.data.finalizedEventId);
    expect(proofEvent).toEqual(
      expect.objectContaining({
        eventId: finalized.json.data.finalizedEventId,
        authority: "proof",
      }),
    );
    expect(proofEvent?.prevProofEventHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proofEvent?.payload).toEqual(
      expect.objectContaining({
        gateEventId: finalized.json.data.gateEventId,
        observedEventId: observedEvent?.eventId,
        finalityStatus: "finalized",
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

  it("blocks verifier and same-log revival after a finalized gate reorg", async () => {
    const { app } = makeApp(":memory:", { chain: createFakeGateChainClient() });
    const sessionId = await createSession(app, "sess-gate-reorg", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const finalized = await finalizeSpendSettlement(app, sessionId, spendId, "gate-reorg");
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
  });

  it("keeps artifact reads bearer-bound and validates path parameters", async () => {
    const { app, ctx } = makeApp(":memory:", { chain: createFakeGateChainClient() });
    const sessionId = await createSession(app, "sess-artifact");
    const spendId = await registerSpend(app, sessionId);
    const artifactHash = hex32("artifact");
    const payer = "0x1234";
    const bearerToken = "artifact-access-token";
    const artifactUrl = `/api/v1/artifacts/${sessionId}/${spendId}/${payer}/${artifactHash}`;
    const wrongPayer = "0xabcd";
    const wrongPayerToken = "wrong-payer-artifact-token";

    const pending = await app.request(artifactUrl);
    const pendingJson = await pending.json();
    const invalidPayer = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/not-a-hex/${artifactHash}`);
    const invalidJson = await invalidPayer.json();
    await finalizeSpendSettlement(app, sessionId, spendId, "artifact-settlement");
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_access_tokens
          (token_id, session_id, spend_id, payer, artifact_hash, token_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        hex32("artifact-token-row"),
        sessionId,
        spendId,
        payer,
        artifactHash,
        hex32(bearerToken),
        "2026-06-11T00:00:00.000Z",
      );
    const missingBearer = await app.request(artifactUrl);
    const missingBearerJson = await missingBearer.json();
    const wrongBearer = await app.request(artifactUrl, { headers: { authorization: "Bearer wrong-token" } });
    const wrongBearerJson = await wrongBearer.json();
    const allowed = await app.request(artifactUrl, { headers: { authorization: `Bearer ${bearerToken}` } });
    const allowedJson = await allowed.json();
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_access_tokens
          (token_id, session_id, spend_id, payer, artifact_hash, token_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        hex32("artifact-wrong-payer-token-row"),
        sessionId,
        spendId,
        wrongPayer,
        artifactHash,
        hex32(wrongPayerToken),
        "2026-06-11T00:00:00.000Z",
      );
    const payerMismatch = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/${wrongPayer}/${artifactHash}`, {
      headers: { authorization: `Bearer ${wrongPayerToken}` },
    });
    const payerMismatchJson = await payerMismatch.json();

    expect(pending.status).toBe(423);
    expect(pendingJson.error.code).toBe("proof_pending");
    expect(invalidPayer.status).toBe(400);
    expect(invalidJson.error.code).toBe("bad_request");
    expect(missingBearer.status).toBe(423);
    expect(missingBearerJson.error.code).toBe("proof_pending");
    expect(wrongBearer.status).toBe(423);
    expect(wrongBearerJson.error.code).toBe("proof_pending");
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
    expect(payerMismatch.status).toBe(422);
    expect(payerMismatchJson.error.code).toBe("proof_blocked");
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
    const { app, ctx } = makeApp(":memory:", { chain: createFakeGateChainClient() });
    const sessionId = await createSession(app, "sess-lease-bearer-bound");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1234";
    const wrongPayer = "0xabcd";
    const artifactHash = hex32("lease-artifact-active");
    const bearerToken = "lease-access-token";
    const wrongPayerToken = "lease-wrong-payer-token";
    await finalizeSpendSettlement(app, sessionId, spendId, "lease-settlement");
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_access_tokens
          (token_id, session_id, spend_id, payer, artifact_hash, token_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(hex32("lease-token-row"), sessionId, spendId, payer, artifactHash, hex32(bearerToken), "2026-06-11T00:00:00.000Z");
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_access_tokens
          (token_id, session_id, spend_id, payer, artifact_hash, token_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
      )
      .run(
        hex32("lease-wrong-payer-token-row"),
        sessionId,
        spendId,
        wrongPayer,
        artifactHash,
        hex32(wrongPayerToken),
        "2026-06-11T00:00:00.000Z",
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
      { authorization: `Bearer ${wrongPayerToken}` },
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

    expect(missingToken.status).toBe(423);
    expect(missingToken.json.error.code).toBe("proof_pending");
    expect(wrongToken.status).toBe(423);
    expect(wrongToken.json.error.code).toBe("proof_pending");
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
    ]);
    expect(session.json.data.pactTemplates).toEqual([
      expect.objectContaining({ mode: "gate-paid-artifact-real", templateHash: hex32("gate-paid-template") }),
      expect.objectContaining({ mode: "permit-payment-real", templateHash: hex32("permit-template") }),
    ]);
    expect(operation.json.data.pactTemplateMode).toBe("gate-paid-artifact-real");
    expect(operation.json.data.pactTemplateHash).toBe(hex32("gate-paid-template"));
    expect(verify.json.data.warnings).toContain("chain proof provider is unconfigured: chain RPC endpoint is not configured");
    expect(verify.json.data.warnings).toContain("caw proof provider is unconfigured: CAW receipt source is not configured");
    expect(verify.json.data.raw.proofProviders).toHaveLength(2);
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

async function registerSource(app: ReturnType<typeof createApp>, sessionId: string) {
  const res = await post(app, "/api/v1/sources/register", {
    sessionId,
    idempotencyKey: "src-register",
    payload: {
      sourceId: "clean-source",
      sourceHash: hex32("source"),
      manifestUrl: "https://example.com/manifest.json",
      manifestHash: hex32("manifest"),
      capabilityVector: { has_write_file: false },
    },
  });
  expect(res.status).toBe(201);
}

async function registerSpend(app: ReturnType<typeof createApp>, sessionId: string): Promise<string> {
  await registerSource(app, sessionId);
  const sourceHashes = [hex32("source")];
  const spendId = await computeSpendIdForTest(app, sessionId, sourceHashes);
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

function createFakeGateChainClient(currentBlockNumber = 101): ChainClient {
  return {
    async status() {
      return {
        name: "chain",
        mode: "fixture",
        ready: true,
        reason: "test chain provider",
        chainId: "84532",
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
    "x-pactfuse-gate-signature": signAuditPayload(MCP_AUDIT_TOKEN, body),
  });
}

async function finalizeSpendSettlement(
  app: ReturnType<typeof createApp>,
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
  const finalizedBody = {
    ...observedBody,
    idempotencyKey: `${key}-finalized`,
    payload: {
      ...(observedBody.payload as Record<string, unknown>),
      currentBlockNumber: 101,
    },
  };
  const observed = await postSignedGateEvent(app, observedBody);
  const finalized = await postSignedGateEvent(app, finalizedBody);

  expect(observed.status).toBe(202);
  expect(finalized.status).toBe(202);
  expect(finalized.json.data.finalityStatus).toBe("finalized");
  return finalized.json.data;
}

async function computeSpendIdForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  sourceHashes: string[],
): Promise<`0x${string}`> {
  const session = await app.request(`/api/v1/sessions/${sessionId}`);
  const sessionJson = await session.json();
  expect(session.status).toBe(200);
  const normalizedSourceHashes = [...sourceHashes].map((sourceHash) => sourceHash.toLowerCase()).sort();
  const runConfigHash = sessionJson.data.runConfigHash as string;
  const sourceSetHash = keccakJsonForTest(normalizedSourceHashes);
  const sessionCommitment = keccakJsonForTest({ sessionId: sessionId.toLowerCase(), runConfigHash });
  return keccakJsonForTest({
    runConfigHash,
    sessionCommitment,
    pactId: "pact-c",
    toolId: "code-scan",
    sourceSetHash,
    agentWallet: "0xabcd",
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
  const res = await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

function hex32(seed: string): `0x${string}` {
  return `0x${createHash("sha256").update(seed).digest("hex")}`;
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
