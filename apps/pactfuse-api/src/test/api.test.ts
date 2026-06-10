import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { ServiceCtx } from "../types.js";

function makeApp() {
  const ctx: ServiceCtx = {
    db: openPactFuseDb(":memory:"),
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
