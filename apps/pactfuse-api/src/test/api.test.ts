import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { canonicalizeJson } from "@pactfuse/evidence-schema";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeases } from "../services/jobs.js";
import {
  createStaticTemplateRegistry,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
} from "../services/providers.js";
import { appendEvidenceEvent, recordMcpAdapterCall } from "../services/service.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { ServiceCtx } from "../types.js";

const MCP_AUDIT_TOKEN = "test-mcp-audit-token";

function makeApp(dbPath = ":memory:", options: { mcpAuditSecret?: string | null } = {}) {
  const mcpAuditSecret = options.mcpAuditSecret === undefined ? MCP_AUDIT_TOKEN : options.mcpAuditSecret;
  const ctx: ServiceCtx = {
    db: openPactFuseDb(dbPath),
    verifier: createVerifierAdapter(),
    chain: createUnconfiguredChainClient(),
    caw: createUnconfiguredCawReceiptSource(),
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
    expect(res.json.data.schemaOk).toBe(false);
    expect(res.json.data.proofChipAllowed).toBe(false);
    expect(res.json.data.finalVerifierComplete).toBe(false);
    expect(res.json.data.winnerClaimAllowed).toBe(false);
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
      "judgeCheck",
    ]);
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("mcpAdapterCalls");
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

  it("keeps artifact reads fail-closed and validates path parameters", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-artifact");
    const spendId = hex32("artifact-spend");
    const artifactHash = hex32("artifact");

    const pending = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/0x1234/${artifactHash}`);
    const pendingJson = await pending.json();
    const invalidPayer = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/not-a-hex/${artifactHash}`);
    const invalidJson = await invalidPayer.json();

    expect(pending.status).toBe(423);
    expect(pendingJson.error.code).toBe("proof_pending");
    expect(invalidPayer.status).toBe(400);
    expect(invalidJson.error.code).toBe("bad_request");
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

    expect(verifySnapshot.json.data.errors).not.toContain(
      "replayBundle.agentTranscriptHash does not match the server transcript snapshot",
    );
    expect(verifyTampered.json.data.errors).toContain(
      "replayBundle.agentTranscriptHash does not match the server transcript snapshot",
    );
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
    const spendId = hex32("spend-live");

    const lease = await post(app, "/api/v1/lease/execute", {
      sessionId,
      idempotencyKey: "lease-blocked",
      payload: {
        spendId,
        targetRepo: "https://github.com/example/repo",
        targetCommit: "abcdef123456",
      },
    });
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();

    expect(lease.status).toBe(202);
    expect(lease.json.data.status).toBe("blocked_missing_finalized_settlement");
    expect(lease.json.data.winnerClaimAllowed).toBe(false);
    expect(judgeJson.data.winnerClaimAllowed).toBe(false);
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
    const operation = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "build-provider-bound-op",
      payload: {
        spendId: hex32("provider-spend"),
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

async function createSession(app: ReturnType<typeof createApp>, key: string): Promise<string> {
  const res = await post(app, "/api/v1/sessions", { idempotencyKey: key, payload: { label: key } });
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

async function registerSpend(app: ReturnType<typeof createApp>, sessionId: string) {
  const res = await post(app, "/api/v1/spends/register-batch", {
    sessionId,
    idempotencyKey: "spend-register",
    payload: {
      spends: [
        {
          spendId: hex32("spend"),
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
  expect(res.status).toBe(201);
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

function hashForTestJson(value: unknown): `0x${string}` {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
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
