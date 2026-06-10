import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeases } from "../services/jobs.js";
import { appendEvidenceEvent, recordMcpAdapterCall } from "../services/service.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { ServiceCtx } from "../types.js";

function makeApp(dbPath = ":memory:") {
  const ctx: ServiceCtx = {
    db: openPactFuseDb(dbPath),
    verifier: createVerifierAdapter(),
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

async function post(app: ReturnType<typeof createApp>, path: string, body: unknown) {
  const res = await app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

function hex32(seed: string): `0x${string}` {
  return `0x${createHash("sha256").update(seed).digest("hex")}`;
}
