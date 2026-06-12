import { createHash, createHmac } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { encodeAbiParameters, encodeEventTopics, encodeFunctionData, keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalizeJson } from "@pactfuse/evidence-schema";
import { createApp } from "../app.js";
import { openPactFuseDb } from "../db/index.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeases } from "../services/jobs.js";
import { INDEX_CHAIN_WINDOW_JOB_KIND, runIndexerWorkerOnce } from "../services/indexer-worker.js";
import {
  createCoboAgenticWalletClient,
  createHttpsCawReceiptSource,
  createHttpJsonRpcMcpLeaseClient,
  createStaticTemplateRegistry,
  createUnconfiguredCawLiveClient,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
  createUnconfiguredMcpLeaseClient,
  normalizePactFuseChainLog,
  PACTFUSE_CHAIN_EVENT_ABI,
} from "../services/providers.js";
import { createRuntimeIndexerWorkerOptions, createServiceCtx } from "../runtime.js";
import { appendEvidenceEvent, recordMcpAdapterCall } from "../services/service.js";
import { createVerifierAdapter } from "../services/verifier.js";
import type { ApiSecurityConfig, CawLiveClient, CawReceiptSource, ChainClient, McpLeaseClient, ServiceCtx } from "../types.js";

const MCP_AUDIT_TOKEN = "test-mcp-audit-token";
const GATE_INGEST_TOKEN = "test-gate-ingest-token";
const CAW_INGEST_TOKEN = "test-caw-ingest-token";
const ZERO_HASH = `0x${"0".repeat(64)}`;
const ERC20_APPROVE_SELECTOR = "0x095ea7b3";
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR = "0xb14620f9";
const ERC20_APPROVE_ABI = [
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;
const PROCUREMENT_GATE_ACTIVATE_TOOL_ABI = [
  {
    type: "function",
    name: "activateTool",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spendId", type: "bytes32" },
      { name: "paymentAuth", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

function makeApp(
  dbPath = ":memory:",
  options: {
    caw?: CawReceiptSource;
    cawLive?: CawLiveClient;
    chain?: ChainClient;
    mcpLease?: McpLeaseClient;
    mcpAuditSecret?: string | null;
    gateIngestSecret?: string | null;
    cawIngestToken?: string | null;
    deploymentRegistry?: ServiceCtx["deploymentRegistry"];
    apiSecurity?: Partial<ApiSecurityConfig>;
    requiredIndexerCursors?: ServiceCtx["requiredIndexerCursors"];
    verifier?: ServiceCtx["verifier"];
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
    verifier: options.verifier ?? createVerifierAdapter(),
    chain: options.chain ?? createUnconfiguredChainClient(),
    caw: options.caw ?? createUnconfiguredCawReceiptSource(),
    cawLive: options.cawLive ?? createUnconfiguredCawLiveClient(),
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
    deploymentRegistry: options.deploymentRegistry,
    server: {
      commit: "test-server-commit",
      buildTime: "2026-06-11T00:00:00.000Z",
    },
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
    const missingClaimReadiness = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${hex32("auth-claim-readiness")}`);
    const wrongClaimReadiness = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${hex32("auth-claim-readiness")}`, {
      headers: { authorization: "Bearer wrong" },
    });
    const missingPublicClaim = await app.request(`/api/v1/evidence/public-claim?sessionId=${hex32("auth-public-claim")}`);
    const wrongPublicClaim = await app.request(`/api/v1/evidence/public-claim?sessionId=${hex32("auth-public-claim")}`, {
      headers: { authorization: "Bearer wrong" },
    });
    const missingProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${hex32("auth-proof-bundle")}`);
    const wrongProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${hex32("auth-proof-bundle")}`, {
      headers: { authorization: "Bearer wrong" },
    });
    const invalidJsonWithoutAuth = await rawPost(app, "/api/v1/sources/challenge", "{", {});
    const invalidJsonWithAuth = await rawPost(app, "/api/v1/sources/challenge", "{", { authorization: "Bearer challenge-test-token" });

    expect(missingOperator.status).toBe(401);
    expect(wrongOperator.status).toBe(403);
    expect(allowedOperator.status).toBe(201);
    expect(missingChallenge.status).toBe(401);
    expect(allowedChallengeAuth.status).toBe(400);
    expect(missingArtifactSigner.status).toBe(401);
    expect(allowedArtifactAuth.status).toBe(400);
    expect(missingIndexer.status).toBe(401);
    expect(allowedIndexerAuth.status).toBe(400);
    expect(missingClaimReadiness.status).toBe(401);
    expect(wrongClaimReadiness.status).toBe(403);
    expect(missingPublicClaim.status).toBe(401);
    expect(wrongPublicClaim.status).toBe(403);
    expect(missingProofBundle.status).toBe(401);
    expect(wrongProofBundle.status).toBe(403);
    expect(invalidJsonWithoutAuth.status).toBe(401);
    expect(invalidJsonWithAuth.status).toBe(400);
  });

  it("trims boolean runtime environment flags before applying production security switches", () => {
    const previousAllowInsecure = process.env.PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS;
    const previousIndexerEnabled = process.env.PACTFUSE_INDEXER_ENABLED;
    const previousChainRpc = process.env.PACTFUSE_CHAIN_RPC_URL;
    const previousChainId = process.env.PACTFUSE_CHAIN_ID;
    try {
      process.env.PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS = " false ";
      const ctx = createServiceCtx({
        dbPath: ":memory:",
        logger: {
          info: () => undefined,
          warn: () => undefined,
          error: () => undefined,
        },
        clock: { now: () => new Date("2026-06-11T00:00:00.000Z") },
      });
      expect(ctx.apiSecurity.allowInsecureMissingRoleTokens).toBe(false);

      process.env.PACTFUSE_CHAIN_RPC_URL = "https://rpc.example";
      process.env.PACTFUSE_CHAIN_ID = "84532";
      process.env.PACTFUSE_INDEXER_ENABLED = " off ";
      expect(createRuntimeIndexerWorkerOptions()).toBeNull();
    } finally {
      restoreEnv("PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS", previousAllowInsecure);
      restoreEnv("PACTFUSE_INDEXER_ENABLED", previousIndexerEnabled);
      restoreEnv("PACTFUSE_CHAIN_RPC_URL", previousChainRpc);
      restoreEnv("PACTFUSE_CHAIN_ID", previousChainId);
    }
  });

  it("live-smoke recomputes public proof bundle hashes against a live endpoint", async () => {
    const result = await runLiveSmokeAgainstStub();
    const stdout = JSON.parse(result.stdout) as Record<string, unknown>;

    expect(result.status, result.stderr).toBe(0);
    expect(stdout.ok).toBe(true);
    expect(stdout.proofBundleHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("live-smoke rejects session and proof hash drift from the live endpoint", async () => {
    const cases: Array<[string, (proofBundle: Record<string, unknown>) => void, string]> = [
      [
        "wrong session",
        (proofBundle) => {
          proofBundle.sessionId = hex32("live-smoke-wrong-session");
        },
        "proof-bundle sessionId does not match",
      ],
      [
        "public claim hash",
        (proofBundle) => {
          proofBundle.publicClaimHash = hex32("live-smoke-bad-public-claim");
        },
        "proof-bundle public claim hash does not match public-claim",
      ],
      [
        "replay bundle hash",
        (proofBundle) => {
          proofBundle.replayBundleHash = hex32("live-smoke-bad-replay");
        },
        "proof-bundle final replay hash does not match public-claim",
      ],
      [
        "provider status hash",
        (proofBundle) => {
          proofBundle.providerStatusHash = hex32("live-smoke-bad-provider");
        },
        "proof-bundle providerStatusHash does not recompute",
      ],
      [
        "public claim event hash",
        (proofBundle) => {
          proofBundle.publicClaimEventHash = hex32("live-smoke-bad-public-claim-event");
        },
        "proof-bundle public claim event hash does not recompute",
      ],
      [
        "proof bundle hash",
        (proofBundle) => {
          proofBundle.proofBundleHash = hex32("live-smoke-bad-bundle");
        },
        "proof-bundle hash does not recompute",
      ],
    ];

    for (const [, mutateProofBundle, expectedError] of cases) {
      const result = await runLiveSmokeAgainstStub(mutateProofBundle);

      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain(expectedError);
    }
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

  it("does not run deep live provider checks from unauthenticated readiness probes in fail-closed mode", async () => {
    const baseCawLive = createFakeCawLiveClient();
    let cawLiveStatusCalls = 0;
    const { app } = makeApp(":memory:", {
      cawLive: {
        ...baseCawLive,
        async status() {
          cawLiveStatusCalls += 1;
          return baseCawLive.status();
        },
      },
      apiSecurity: {
        operatorToken: "operator-test-token",
        allowInsecureMissingRoleTokens: false,
      },
    });

    const unauthReady = await app.request("/readyz");
    const unauthReadyJson = await unauthReady.json();
    const unauthLiveStatus = await app.request("/api/v1/caw/live/status");

    expect(unauthReady.status).toBe(200);
    expect(unauthReadyJson.proofProviders).toEqual([]);
    expect(unauthReadyJson.proofProviderCheck).toEqual(
      expect.objectContaining({
        mode: "operator-deep-check",
        checked: false,
      }),
    );
    expect(unauthLiveStatus.status).toBe(401);
    expect(cawLiveStatusCalls).toBe(0);

    const authReady = await app.request("/readyz", { headers: { authorization: "Bearer operator-test-token" } });
    const authReadyJson = await authReady.json();
    const authLiveStatus = await app.request("/api/v1/caw/live/status", { headers: { authorization: "Bearer operator-test-token" } });

    expect(authReady.status).toBe(200);
    expect(authReadyJson.proofProviderCheck).toEqual(expect.objectContaining({ checked: true }));
    expect(authReadyJson.proofProviders).toEqual(expect.arrayContaining([expect.objectContaining({ name: "caw_live", ready: true })]));
    expect(authLiveStatus.status).toBe(200);
    expect(cawLiveStatusCalls).toBe(2);
  });

  it("keeps proof provider status fail-closed when a provider status check throws", async () => {
    const brokenCaw: CawReceiptSource = {
      async status() {
        throw new Error("CAW export status exploded");
      },
      async fetchReceiptBundle() {
        throw new Error("unused broken CAW export");
      },
    };
    const { app } = makeApp(":memory:", { caw: brokenCaw });

    const ready = await app.request("/readyz");
    const readyJson = await ready.json();
    const sessionId = await createSession(app, "sess-provider-status-throws");
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-provider-status-throws",
      payload: { receipt: { receiptId: "provider-status-throws" } },
    });

    expect(ready.status).toBe(200);
    expect(readyJson.proofProviders).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "caw",
          mode: "live",
          ready: false,
          reason: "CAW export status exploded",
        }),
      ]),
    );
    expect(verify.status).toBe(200);
    expect(verify.json.data.warnings).toContain("caw proof provider is live: CAW export status exploded");
  });

  it("falls back to the shared operator token for specialized roles when no role token is configured", async () => {
    const { app } = makeApp(":memory:", {
      apiSecurity: {
        operatorToken: "operator-test-token",
      },
    });

    const missingQuote = await post(app, "/api/v1/quotes", {});
    const allowedQuoteAuth = await post(app, "/api/v1/quotes", {}, { authorization: "Bearer operator-test-token" });

    expect(missingQuote.status).toBe(401);
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

  it("persists final verifier results instead of hardcoding fail-closed flags", async () => {
    const { app, ctx } = makeApp(":memory:", {
      verifier: {
        verify: async () => ({
          schemaOk: true,
          proofChipAllowed: true,
          winnerClaimAllowed: true,
          requestedWinnerClaimAllowed: true,
          finalVerifierComplete: true,
          warnings: [],
          errors: [],
        }),
      },
    });
    const sessionId = await createSession(app, "sess-verify-final-result");

    const res = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-final-result",
      payload: { receipt: { receiptId: "final-result" } },
    });
    const run = ctx.db.sqlite
      .prepare(
        "SELECT schema_ok, proof_chip_allowed, winner_claim_allowed, final_verifier_complete FROM verifier_runs WHERE session_id = ?",
      )
      .get(sessionId) as
      | { schema_ok: number; proof_chip_allowed: number; winner_claim_allowed: number; final_verifier_complete: number }
      | undefined;
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const verifierEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "verifier.final_replay_claim");

    expect(res.status).toBe(200);
    expect(res.json.data.proofLevel).toBe("final_replay_claim");
    expect(res.json.data.schemaOk).toBe(true);
    expect(res.json.data.proofChipAllowed).toBe(true);
    expect(res.json.data.finalVerifierComplete).toBe(true);
    expect(res.json.data.winnerClaimAllowed).toBe(true);
    expect(run).toEqual({
      schema_ok: 1,
      proof_chip_allowed: 1,
      winner_claim_allowed: 1,
      final_verifier_complete: 1,
    });
    expect(verifierEvent).toEqual(
      expect.objectContaining({
        authority: "operator",
        payload: expect.objectContaining({
          schemaOk: true,
          proofChipAllowed: true,
          winnerClaimAllowed: true,
          finalVerifierComplete: true,
        }),
      }),
    );
  });

  it("keeps public claim authorization closed until readiness and verifier gates all pass", async () => {
    const { app } = makeApp(":memory:", {
      verifier: {
        verify: async () => ({
          schemaOk: true,
          proofChipAllowed: true,
          winnerClaimAllowed: true,
          requestedWinnerClaimAllowed: true,
          finalVerifierComplete: true,
          warnings: [],
          errors: [],
        }),
      },
    });
    const sessionId = await createSession(app, "sess-public-claim-blocked");

    const claim = await app.request(`/api/v1/evidence/public-claim?sessionId=${sessionId}`);
    const claimJson = await claim.json();

    expect(claim.status).toBe(423);
    expect(claimJson.error.code).toBe("proof_pending");
    expect(claimJson.error.message).toContain("public claim remains blocked");
    expect(claimJson.error.details.blockers).toContain("targetClaimMode is not caw-target-real");
    expect(claimJson.error.details.blockers).toContain("claim readiness winnerClaimAllowed is false");
    expect(claimJson.error.details.requiredExternalInputs).toEqual(
      expect.arrayContaining([
        "PACTFUSE_CAW_EXPORT_URL or equivalent raw CAW receipt export source",
        "PACTFUSE_CAW_LIVE_API_URL, PACTFUSE_CAW_LIVE_API_KEY, and a CAW wallet id",
        "PACTFUSE_CHAIN_RPC_URL and PACTFUSE_CHAIN_ID for a live public testnet RPC",
        "PACTFUSE_LEASE_MCP_URL for a live MCP lease runner",
      ]),
    );
  });

  it("authorizes a public claim through the HTTP evidence flow when every live gate passes", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const cawReceipts: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      caw: createFakeCawReceiptSource({ receipts: cawReceipts, mode: "live" }),
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 130, logs, tokenBalances }),
      mcpLease: createFakeMcpLeaseClient("pactfuse_code_scan", "live"),
      deploymentRegistry: testDeploymentRegistry(),
    });
    const sessionId = await createSession(app, "sess-public-claim-authorized");
    const spendId = await registerSpendWithKeyForTest(app, sessionId, "public-claim-c");
    const tripA = await registerSpendWithKeyForTest(app, sessionId, "public-claim-trip-a", {
      artifactHash: hex32("public-claim-trip-a-artifact"),
      nonce: "trip-a",
    });
    const tripB = await registerSpendWithKeyForTest(app, sessionId, "public-claim-trip-b", {
      artifactHash: hex32("public-claim-trip-b-artifact"),
      nonce: "trip-b",
    });
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "public-claim-artifact", {
      artifactPayload: TEST_ARTIFACT_PAYLOAD,
      settlementMode: "chain_settleable_after_preflight",
    });
    const identity = await post(app, "/api/v1/caw/live/identity/probe", {
      sessionId,
      idempotencyKey: "public-claim-caw-identity",
      payload: {
        walletId: "wallet-live-1",
        expectedWalletAddress: TEST_PAYER_ADDRESS,
        identityMode: "p0-floor-one-wallet",
      },
    });
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "public-claim-settle");
    await finalizeSpendTripForTest(app, ctx, logs, sessionId, tripA, "public-claim-trip-a", 101);
    await finalizeSpendTripForTest(app, ctx, logs, sessionId, tripB, "public-claim-trip-b", 102);
    await finalizeSourceChallengeForTest(app, ctx, logs, sessionId, "public-claim-source", 103);
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "public-claim-settle", finalized);
    const denyProbe = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "public-claim-deny-probe",
        payload: {
          spendId,
          operationKind: "deny_probe",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: TEST_MARKET_ADDRESS,
          calldata: cawApproveCalldataForTest(TEST_MARKET_ADDRESS, "1000"),
          requestId: "public-claim-deny-probe",
          description: "PactFuse wrong-target deny proof",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const denyAudit = await post(app, "/api/v1/caw/live/audit/sync", {
      sessionId,
      idempotencyKey: "public-claim-deny-audit",
      payload: { walletId: "wallet-live-1", action: "wrong_target.deny_probe", result: "denied", limit: 20 },
    });
    cawReceipts.push(
      cawReceiptFields("public-claim-deny", {
        operationKind: "deny_probe",
        target: TEST_MARKET_ADDRESS,
        selector: ERC20_APPROVE_SELECTOR,
        requestId: "public-claim-deny-probe",
        effect: "deny",
        status: "denied",
        txHash: null,
        txCount: "0",
      }),
      cawReceiptFields("public-claim-approve", {
        operationKind: "approve",
        target: TEST_PAYMENT_TOKEN_ADDRESS,
        selector: ERC20_APPROVE_SELECTOR,
        requestId: "public-claim-settle-approve",
        txHash: hex32("caw-live-contract:public-claim-settle-approve"),
      }),
      cawReceiptFields("public-claim-activate", {
        operationKind: "activate_tool",
        target: INDEXER_ADDRESS,
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
        requestId: String(finalized.txHash),
        txHash: finalized.txHash,
      }),
    );
    await buildAndIngestCawReceiptForTest(app, sessionId, spendId, "public-claim-deny-receipt", {
      operationKind: "deny_probe",
      target: TEST_MARKET_ADDRESS,
      selector: ERC20_APPROVE_SELECTOR,
    });
    await buildAndIngestCawReceiptForTest(app, sessionId, spendId, "public-claim-approve-receipt", {
      operationKind: "approve",
      target: TEST_PAYMENT_TOKEN_ADDRESS,
      selector: ERC20_APPROVE_SELECTOR,
    });
    await buildAndIngestCawReceiptForTest(app, sessionId, spendId, "public-claim-activate-receipt", {
      operationKind: "activate_tool",
      target: INDEXER_ADDRESS,
      selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
    });
    await catchUpIndexerCursorForTest(ctx, "gate:public-claim-settle", 100);
    await catchUpIndexerCursorForTest(ctx, "gate:public-claim-trip-a", 101);
    await catchUpIndexerCursorForTest(ctx, "gate:public-claim-trip-b", 102);
    await catchUpIndexerCursorForTest(ctx, "source:public-claim-source", 103);
    const issued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "public-claim-artifact-token",
      payload: {
        spendId,
        payer: TEST_PAYER_ADDRESS,
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload: quoted.artifactPayload,
      },
    });
    expect(issued.status, JSON.stringify(issued.json)).toBe(202);
    const lease = await post(
      app,
      "/api/v1/lease/execute",
      {
        sessionId,
        idempotencyKey: "public-claim-lease",
        payload: {
          spendId,
          payer: TEST_PAYER_ADDRESS,
          artifactHash: quoted.artifactHash,
          targetRepo: "https://github.com/example/public-claim-target",
          targetCommit: "abcdef123456",
        },
      },
      { authorization: `Bearer ${issued.json.data.accessToken}` },
    );
    ctx.apiSecurity.operatorToken = "operator-test-token";
    ctx.apiSecurity.allowInsecureMissingRoleTokens = false;
    const readiness = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const readinessJson = await readiness.json();
    const claim = await app.request(`/api/v1/evidence/public-claim?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const claimJson = await claim.json();
    const repeatedClaim = await app.request(`/api/v1/evidence/public-claim?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const repeatedClaimJson = await repeatedClaim.json();
    const missingProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`);
    const wrongProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer wrong" },
    });
    const proofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const proofBundleJson = await proofBundle.json();
    const claimEvents = ctx.db.sqlite
      .prepare(
        `SELECT event_id, event_seq, event_hash, authority, kind, payload_json, created_at
         FROM evidence_events
         WHERE session_id = ? AND kind = 'public.claim.authorized'
         ORDER BY event_seq ASC`,
      )
      .all(sessionId) as Array<{
        event_id: string;
        event_seq: number;
        event_hash: string;
        authority: string;
        kind: string;
        payload_json: string;
        created_at: string;
      }>;
    const claimEventPayload = JSON.parse(claimEvents[0]?.payload_json ?? "{}") as Record<string, unknown>;

    expect(identity.status).toBe(202);
    expect(denyProbe.status, JSON.stringify(denyProbe.json)).toBe(202);
    expect(denyAudit.status).toBe(202);
    expect(lease.status).toBe(202);
    expect(readiness.status).toBe(200);
    expect(readinessJson.data.blockers).toEqual([]);
    expect(readinessJson.data.requiredExternalInputs).toEqual([]);
    expect(readinessJson.data.winnerClaimAllowed).toBe(true);
    expect(readinessJson.data.verifierRun.proofLevel).toBe("final_replay_claim");
    expect(readinessJson.data.verifierRun.finalVerifierComplete).toBe(true);
    expect(readinessJson.data.verifierRun.winnerClaimAllowed).toBe(true);
    expect(readinessJson.data.gates.find((gate: { gateId: string }) => gate.gateId === "token_deployment_registry")).toEqual(
      expect.objectContaining({
        status: "pass",
        reason: expect.stringContaining("mock token deployment registry binds"),
      }),
    );
    expect(claim.status).toBe(200);
    expect(claimJson.data).toEqual(
      expect.objectContaining({
        claimStatus: "authorized_public_claim",
        claimMode: "caw-target-real",
        paymentMode: "gate-paid-artifact-real",
        tokenMode: "mock-test-token",
        identityMode: "p0-floor-one-wallet",
        proofChipAllowed: true,
        finalVerifierComplete: true,
        winnerClaimAllowed: true,
      }),
    );
    expect(claimJson.data.publicClaimHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(repeatedClaim.status).toBe(200);
    expect(repeatedClaimJson.data.publicClaimHash).toBe(claimJson.data.publicClaimHash);
    expect(missingProofBundle.status).toBe(401);
    expect(wrongProofBundle.status).toBe(403);
    expect(claimEvents).toHaveLength(1);
    expect(claimEvents[0]).toEqual(expect.objectContaining({ authority: "proof", kind: "public.claim.authorized" }));
    expect(claimEventPayload).toEqual(
      expect.objectContaining({
        publicClaimHash: claimJson.data.publicClaimHash,
        replayBundleHash: claimJson.data.replayBundleHash,
        proofAuthority: true,
        winnerClaimAllowed: true,
        asOfEventSeq: claimEvents[0].event_seq - 1,
        providerStatusHash: proofBundleJson.data.providerStatusHash,
        deploymentRegistryHash: proofBundleJson.data.deploymentRegistryHash,
        serverHash: proofBundleJson.data.serverHash,
      }),
    );
    expect(claimEventPayload.claim).toEqual(expect.objectContaining({ publicClaimHash: claimJson.data.publicClaimHash }));
    expect(claimEventPayload.providerStatuses).toEqual(proofBundleJson.data.providerStatuses);
    expect(claimEventPayload.deploymentRegistry).toEqual(proofBundleJson.data.deploymentRegistry);
    expect(claimEventPayload.server).toEqual(proofBundleJson.data.server);
    expect(proofBundle.status).toBe(200);
    expect(proofBundleJson.data).toEqual(
      expect.objectContaining({
        bundleType: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
        sessionId,
        publicClaimHash: claimJson.data.publicClaimHash,
        publicClaimEventId: claimEvents[0].event_id,
        publicClaimEventHash: claimEvents[0].event_hash,
        publicClaimEventSeq: claimEvents[0].event_seq,
        claimInputReplayBundleHash: claimJson.data.replayBundleHash,
        replayBundleHash: claimJson.data.replayBundleHash,
        verifierRunHash: hashForTestJson(claimJson.data.verifierRun),
        deploymentRegistryHash: hashForTestJson(testDeploymentRegistry()),
        serverHash: hashForTestJson({
          proofBundleVersion: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
          commit: "test-server-commit",
          buildTime: "2026-06-11T00:00:00.000Z",
          generatedAt: "2026-06-11T00:00:00.000Z",
        }),
        winnerClaimAllowed: true,
      }),
    );
    expect(proofBundleJson.data.publicClaim).toEqual(claimJson.data);
    expect(proofBundleJson.data.replayBundle.winnerClaimAllowed).toBe(true);
    expect(hashForTestJson(proofBundleJson.data.replayBundle)).toBe(claimJson.data.replayBundleHash);
    expect(hashForTestJson(proofBundleJson.data.providerStatuses)).toBe(proofBundleJson.data.providerStatusHash);
    const proofBundleBase = { ...proofBundleJson.data };
    delete (proofBundleBase as { proofBundleHash?: string }).proofBundleHash;
    expect(hashForTestJson(proofBundleBase)).toBe(proofBundleJson.data.proofBundleHash);
    const replayInputEvent = ctx.db.sqlite
      .prepare(
        `SELECT event_id, payload_json
         FROM evidence_events
         WHERE session_id = ? AND event_seq < ?
         ORDER BY event_seq ASC
         LIMIT 1`,
      )
      .get(sessionId, claimEvents[0].event_seq) as { event_id: string; payload_json: string };
    const replayInputEventPayload = JSON.parse(replayInputEvent.payload_json) as Record<string, unknown>;
    ctx.db.sqlite
      .prepare("UPDATE evidence_events SET payload_json = ? WHERE event_id = ?")
      .run(canonicalizeJson({ ...replayInputEventPayload, replayDrift: true }), replayInputEvent.event_id);
    const replayDriftProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const replayDriftProofBundleJson = await replayDriftProofBundle.json();
    expect(replayDriftProofBundle.status).toBe(422);
    expect(replayDriftProofBundleJson.error.code).toBe("proof_blocked");
    expect(replayDriftProofBundleJson.error.message).toContain("replay hash no longer matches");
    ctx.db.sqlite
      .prepare("UPDATE evidence_events SET payload_json = ? WHERE event_id = ?")
      .run(replayInputEvent.payload_json, replayInputEvent.event_id);
    const originalClaimEventPayloadJson = claimEvents[0].payload_json;
    ctx.db.sqlite
      .prepare("UPDATE evidence_events SET payload_json = ? WHERE event_id = ?")
      .run(canonicalizeJson({ ...claimEventPayload, providerStatusHash: ZERO_HASH }), claimEvents[0].event_id);
    const tamperedProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const tamperedProofBundleJson = await tamperedProofBundle.json();
    expect(tamperedProofBundle.status).toBe(423);
    expect(tamperedProofBundleJson.error.code).toBe("proof_pending");
    ctx.db.sqlite
      .prepare("UPDATE evidence_events SET payload_json = ? WHERE event_id = ?")
      .run(originalClaimEventPayloadJson, claimEvents[0].event_id);
    const originalChain = ctx.chain;
    const originalCaw = ctx.caw;
    const originalCawLive = ctx.cawLive;
    const originalMcpLease = ctx.mcpLease;
    const originalDeploymentRegistry = ctx.deploymentRegistry;
    ctx.clock.now = () => new Date("2026-06-12T00:00:00.000Z");
    ctx.chain = createUnconfiguredChainClient();
    ctx.caw = createUnconfiguredCawReceiptSource();
    ctx.cawLive = createUnconfiguredCawLiveClient();
    ctx.mcpLease = createUnconfiguredMcpLeaseClient();
    ctx.deploymentRegistry = undefined;
    const stableProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const stableProofBundleJson = await stableProofBundle.json();

    expect(stableProofBundle.status).toBe(200);
    expect(stableProofBundleJson.data.server.generatedAt).toBe(claimEvents[0].created_at);
    expect(stableProofBundleJson.data.providerStatuses).toEqual(proofBundleJson.data.providerStatuses);
    expect(stableProofBundleJson.data.providerStatusHash).toBe(proofBundleJson.data.providerStatusHash);
    expect(stableProofBundleJson.data.deploymentRegistry).toEqual(proofBundleJson.data.deploymentRegistry);
    expect(stableProofBundleJson.data.deploymentRegistryHash).toBe(proofBundleJson.data.deploymentRegistryHash);
    expect(stableProofBundleJson.data.serverHash).toBe(proofBundleJson.data.serverHash);
    expect(stableProofBundleJson.data.proofBundleHash).toBe(proofBundleJson.data.proofBundleHash);
    ctx.chain = originalChain;
    ctx.caw = originalCaw;
    ctx.cawLive = originalCawLive;
    ctx.mcpLease = originalMcpLease;
    ctx.deploymentRegistry = originalDeploymentRegistry;

    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "advisory",
      kind: "public.claim.authorized",
      payload: {
        claim: claimJson.data,
        publicClaimHash: claimJson.data.publicClaimHash,
        replayBundleHash: claimJson.data.replayBundleHash,
        verifierRunHash: hashForTestJson(claimJson.data.verifierRun),
        asOfEventSeq: claimEvents[0].event_seq,
        proofAuthority: true,
        winnerClaimAllowed: true,
      },
    });
    const advisoryProofBundle = await app.request(`/api/v1/evidence/proof-bundle?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const advisoryProofBundleJson = await advisoryProofBundle.json();

    expect(advisoryProofBundle.status).toBe(423);
    expect(advisoryProofBundleJson.error.code).toBe("proof_pending");

    const refreshedClaim = await app.request(`/api/v1/evidence/public-claim?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const refreshedClaimJson = await refreshedClaim.json();
    const refreshedClaimEvents = ctx.db.sqlite
      .prepare(
        `SELECT event_seq, authority, kind
         FROM evidence_events
         WHERE session_id = ? AND kind = 'public.claim.authorized'
         ORDER BY event_seq ASC`,
      )
      .all(sessionId) as Array<{ event_seq: number; authority: string; kind: string }>;

    expect(refreshedClaim.status, JSON.stringify(refreshedClaimJson)).toBe(200);
    expect(refreshedClaimJson.data.publicClaimHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(refreshedClaimEvents).toHaveLength(3);
    expect(refreshedClaimEvents[1]).toEqual(expect.objectContaining({ authority: "advisory" }));
    expect(refreshedClaimEvents[2]).toEqual(expect.objectContaining({ authority: "proof" }));
  });

  it("fails verifier closed when a required indexer cursor is missing", async () => {
    const { app } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
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

  it("reports evidence-derived claim readiness gates without unlocking public modes by default", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-claim-readiness");

    const res = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(json.data).toEqual(
      expect.objectContaining({
        sessionId,
        claimMode: "simulated",
        paymentMode: "mocked",
        tokenMode: "local-mocked",
        identityMode: "pending",
        targetClaimMode: null,
        targetPaymentMode: null,
        targetTokenMode: null,
        targetIdentityMode: null,
        proofChipAllowed: false,
        finalVerifierComplete: false,
        winnerClaimAllowed: false,
      }),
    );
    expect(json.data.gates.find((gate: { gateId: string }) => gate.gateId === "final_verifier_complete")).toEqual(
      expect.objectContaining({
        status: "blocked",
        reason: "current verifier still reports finalVerifierComplete=false",
      }),
    );
    expect(json.data.blockers).toContain("final_verifier_complete: current verifier still reports finalVerifierComplete=false");
    expect(json.data.blockers).toContain("caw_raw_receipts: missing raw and canonical CAW receipts for deny_probe, approve, and activate_tool");
    expect(json.data.blockers).toContain("artifact_quote_live: artifact quote is still mocked_after_preflight_not_chain_settleable");
    expect(json.data.requiredExternalInputs).toContain("chain-settleable artifact quote issued after preflight");
    expect(json.data.requiredExternalInputs).toContain("PACTFUSE_LEASE_MCP_URL for a live MCP lease runner");
    expect(json.data.requiredExternalInputs).toContain("raw CAW API/export receipts canonicalized for deny_probe, approve, and activate_tool");
    expect(json.data.requiredExternalInputs).toContain(
      "live deployment registry for the payment token address, deployment tx, explorer URL, decimals, and code hash",
    );
    expect(json.data.requiredExternalInputs).toContain("full chain/signature/hash verifier that can set finalVerifierComplete=true");
    expect(json.data.verifierRun.winnerClaimAllowed).toBe(false);
    expect(json.data.replayBundleHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("does not pass the mock token deployment registry gate with placeholder deployment hashes", async () => {
    const registry = testDeploymentRegistry();
    const { app, ctx } = makeApp(":memory:", {
      deploymentRegistry: {
        ...registry,
        entries: registry.entries.map((entry) => ({
          ...entry,
          deploymentTxHash: ZERO_HASH,
          codeHash: ZERO_HASH,
        })),
      },
    });
    const sessionId = await createSession(app, "sess-registry-placeholder-hash");
    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "proof",
      kind: "token.balance_delta.verified",
      payload: {
        spendId: hex32("registry-placeholder-spend"),
        settlementEventId: hex32("registry-placeholder-settlement"),
        txHash: hex32("registry-placeholder-tx"),
        chainProviderMode: "live",
        chainId: "84532",
        paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
        agentWallet: TEST_PAYER_ADDRESS,
        market: TEST_MARKET_ADDRESS,
        amountAtomic: "1000",
        agentDeltaAtomic: "-1000",
        marketDeltaAtomic: "1000",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });

    const res = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const json = await res.json();
    const registryGate = json.data.gates.find((gate: { gateId: string }) => gate.gateId === "token_deployment_registry");

    expect(res.status).toBe(200);
    expect(registryGate).toEqual(
      expect.objectContaining({
        status: "pending",
        evidenceEventId: null,
        reason: "missing live deployment registry entry for the mock payment token",
      }),
    );
    expect(json.data.requiredExternalInputs).toContain(
      "live deployment registry for the payment token address, deployment tx, explorer URL, decimals, and code hash",
    );
  });

  it("does not pass the mock token deployment registry gate without a failed official USDC probe", async () => {
    const registry = testDeploymentRegistry();
    const { app, ctx } = makeApp(":memory:", {
      deploymentRegistry: {
        ...registry,
        officialUsdcProbe: {
          status: "not_attempted",
          reason: "official USDC probe was not recorded",
        },
      },
    });
    const sessionId = await createSession(app, "sess-registry-mock-requires-official-probe");
    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "proof",
      kind: "token.balance_delta.verified",
      payload: {
        spendId: hex32("registry-mock-probe-spend"),
        settlementEventId: hex32("registry-mock-probe-settlement"),
        txHash: hex32("registry-mock-probe-tx"),
        chainProviderMode: "live",
        chainId: "84532",
        paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
        agentWallet: TEST_PAYER_ADDRESS,
        market: TEST_MARKET_ADDRESS,
        amountAtomic: "1000",
        agentDeltaAtomic: "-1000",
        marketDeltaAtomic: "1000",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });

    const res = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const json = await res.json();
    const registryGate = json.data.gates.find((gate: { gateId: string }) => gate.gateId === "token_deployment_registry");

    expect(res.status).toBe(200);
    expect(json.data.targetTokenMode).toBe("mock-test-token");
    expect(registryGate).toEqual(
      expect.objectContaining({
        status: "pending",
        evidenceEventId: null,
        reason: "mock token fallback requires a failed official-USDC probe reason",
      }),
    );
    expect(json.data.requiredExternalInputs).toContain(
      "live deployment registry for the payment token address, deployment tx, explorer URL, decimals, and code hash",
    );
  });

  it("does not pass the official USDC registry gate without a passed probe and live registry entry", async () => {
    const { app, ctx } = makeApp(":memory:", {
      deploymentRegistry: {
        mode: "live",
        chainId: "84532",
        officialUsdcProbe: {
          status: "failed",
          reason: "probe not captured",
        },
        entries: [],
      },
    });
    const sessionId = await createSession(app, "sess-official-usdc-probe-required");
    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "proof",
      kind: "token.balance_delta.verified",
      payload: {
        spendId: hex32("official-usdc-spend"),
        settlementEventId: hex32("official-usdc-settlement"),
        txHash: hex32("official-usdc-tx"),
        chainProviderMode: "live",
        chainId: "84532",
        paymentToken: BASE_SEPOLIA_USDC,
        agentWallet: TEST_PAYER_ADDRESS,
        market: TEST_MARKET_ADDRESS,
        amountAtomic: "1000",
        agentDeltaAtomic: "-1000",
        marketDeltaAtomic: "1000",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });

    const res = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const json = await res.json();
    const registryGate = json.data.gates.find((gate: { gateId: string }) => gate.gateId === "token_deployment_registry");

    expect(res.status).toBe(200);
    expect(json.data.targetTokenMode).toBe("official-testnet-usdc");
    expect(registryGate).toEqual(
      expect.objectContaining({
        status: "pending",
        evidenceEventId: null,
        reason: "official USDC token mode requires Base Sepolia chainId 84532, passed USDC probe evidence, and a live registry entry",
      }),
    );
    expect(json.data.requiredExternalInputs).toContain(
      "live deployment registry for the payment token address, deployment tx, explorer URL, decimals, and code hash",
    );
  });

  it("blocks live proof preflight when production auth or live providers are not configured", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-live-preflight-blocked");

    const res = await app.request(`/api/v1/evidence/live-preflight?sessionId=${sessionId}`);
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(json.data).toEqual(
      expect.objectContaining({
        sessionId,
        status: "blocked",
        readyForPublicClaim: false,
        winnerClaimAllowed: false,
      }),
    );
    expect(json.data.security).toEqual(expect.objectContaining({ allowInsecureMissingRoleTokens: true }));
    expect(json.data.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ checkId: "provider_chain", status: "pending" }),
        expect.objectContaining({ checkId: "provider_caw_live", status: "pending" }),
        expect.objectContaining({ checkId: "security_role_tokens", status: "blocked" }),
        expect.objectContaining({ checkId: "claim_caw_raw_receipts", status: "pending" }),
      ]),
    );
    expect(json.data.blockingReasons).toContain("security_role_tokens: insecure missing-role-token bypass is enabled");
    expect(json.data.requiredExternalInputs).toContain("PACTFUSE_CHAIN_RPC_URL and PACTFUSE_CHAIN_ID for a live public testnet RPC");
    expect(json.data.requiredExternalInputs).toContain(
      "PACTFUSE_OPERATOR_TOKEN plus challenge/artifact role tokens or an intentional operator-token fallback",
    );
    expect(json.data.claimReadiness.blockers).toContain(
      "caw_raw_receipts: missing raw and canonical CAW receipts for deny_probe, approve, and activate_tool",
    );
  });

  it("keeps live proof preflight blocked by session evidence after providers and production auth are ready", async () => {
    const { app } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ mode: "live", chainId: "84532", currentBlockNumber: 120, logs: [] }),
      caw: createFakeCawReceiptSource({ mode: "live", receipts: [] }),
      cawLive: createFakeCawLiveClient(),
      mcpLease: createFakeMcpLeaseClient("pactfuse_code_scan", "live"),
      apiSecurity: {
        operatorToken: "operator-test-token",
        allowInsecureMissingRoleTokens: false,
      },
    });
    const session = await post(
      app,
      "/api/v1/sessions",
      { idempotencyKey: "sess-live-preflight-evidence-blocked", payload: { label: "live-preflight-evidence-blocked" } },
      { authorization: "Bearer operator-test-token" },
    );
    expect(session.status).toBe(201);
    const sessionId = session.json.data.sessionId;

    const unauth = await app.request(`/api/v1/evidence/live-preflight?sessionId=${sessionId}`);
    const res = await app.request(`/api/v1/evidence/live-preflight?sessionId=${sessionId}`, {
      headers: { authorization: "Bearer operator-test-token" },
    });
    const json = await res.json();

    expect(unauth.status).toBe(401);
    expect(res.status).toBe(200);
    expect(json.data.status).toBe("blocked");
    expect(json.data.security).toEqual(
      expect.objectContaining({
        operatorTokenConfigured: true,
        roleTokenFallbackToOperator: true,
        allowInsecureMissingRoleTokens: false,
        cawIngestTokenConfigured: true,
        mcpAuditSecretConfigured: true,
        gateIngestSecretConfigured: true,
      }),
    );
    expect(json.data.checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ checkId: "provider_chain", status: "pass" }),
        expect.objectContaining({ checkId: "provider_caw", status: "pass" }),
        expect.objectContaining({ checkId: "provider_caw_live", status: "pass" }),
        expect.objectContaining({ checkId: "provider_mcp_lease", status: "pass" }),
        expect.objectContaining({ checkId: "security_role_tokens", status: "pass" }),
        expect.objectContaining({ checkId: "claim_caw_identity_probe", status: "pending" }),
        expect.objectContaining({ checkId: "claim_final_verifier_complete", status: "blocked" }),
      ]),
    );
    expect(json.data.blockingReasons).toContain(
      "claim_final_verifier_complete: current verifier still reports finalVerifierComplete=false",
    );
    expect(json.data.requiredExternalInputs).toContain("live CAW identity probe evidence with mode=real and same-wallet semantics");
    expect(json.data.claimReadiness.requiredExternalInputs).not.toContain("PACTFUSE_LEASE_MCP_URL for a live MCP lease runner");
  });

  it("records a live CAW identity probe that can satisfy the readiness identity gate", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient() });
    const sessionId = await createSession(app, "sess-caw-identity-probe");

    const probe = await post(app, "/api/v1/caw/live/identity/probe", {
      sessionId,
      idempotencyKey: "caw-identity-probe",
      payload: {
        walletId: "wallet-live-1",
        expectedWalletAddress: TEST_PAYER_ADDRESS,
        identityMode: "p0-floor-one-wallet",
      },
    });
    const readiness = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const readinessJson = await readiness.json();
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const identityEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "caw.identity.probed");

    expect(probe.status).toBe(202);
    expect(probe.json.data).toEqual(
      expect.objectContaining({
        walletId: "wallet-live-1",
        walletAddress: TEST_PAYER_ADDRESS.toLowerCase(),
        identityMode: "p0-floor-one-wallet",
        pass: true,
        proofAuthority: true,
        winnerClaimAllowed: false,
      }),
    );
    expect(readiness.status).toBe(200);
    expect(readinessJson.data.targetIdentityMode).toBe("p0-floor-one-wallet");
    expect(readinessJson.data.gates.find((gate: { gateId: string }) => gate.gateId === "caw_identity_probe")).toEqual(
      expect.objectContaining({ status: "pass", evidenceEventId: probe.json.evidenceEventId }),
    );
    expect(readinessJson.data.winnerClaimAllowed).toBe(false);
    expect(identityEvent.payload).toEqual(expect.objectContaining({ proofAuthority: true, winnerClaimAllowed: false }));
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
    expect(json.paths["/api/v1/evidence/claim-readiness"].get["x-pactfuse-proof-fields"]).toContain("targetClaimMode");
    expect(json.paths["/api/v1/evidence/claim-readiness"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ClaimReadinessResponse",
    );
    expect(json.paths["/api/v1/evidence/live-preflight"].get["x-pactfuse-proof-fields"]).toEqual([
      "status",
      "readyForPublicClaim",
      "providerStatuses.ready",
      "security.allowInsecureMissingRoleTokens",
      "indexer.status",
      "blockingReasons",
      "requiredExternalInputs",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/evidence/live-preflight"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/LiveProofPreflightResponse",
    );
    expect(json.components.schemas.LiveProofPreflightResponse.oneOf[0].properties.data.properties.status.enum).toEqual(["ready", "blocked"]);
    expect(json.paths["/api/v1/evidence/public-claim"].get["x-pactfuse-proof-fields"]).toEqual([
      "claimStatus",
      "claimMode",
      "paymentMode",
      "tokenMode",
      "identityMode",
      "replayBundleHash",
      "publicClaimHash",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/evidence/proof-bundle"].get["x-pactfuse-proof-fields"]).toEqual([
      "bundleType",
      "proofBundleHash",
      "publicClaimHash",
      "publicClaimEventId",
      "publicClaimEventHash",
      "publicClaimEventSeq",
      "claimInputReplayBundleHash",
      "replayBundleHash",
      "verifierRunHash",
      "providerStatusHash",
      "deploymentRegistryHash",
      "serverHash",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/evidence/proof-bundle"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ProofBundleResponse",
    );
    const proofBundleProviderStatus =
      json.components.schemas.ProofBundleResponse.oneOf[0].properties.data.properties.providerStatuses.items;
    expect(proofBundleProviderStatus.required).toEqual(["name", "mode", "ready", "reason", "endpoint"]);
    expect(proofBundleProviderStatus.properties.endpoint.anyOf).toEqual([{ type: "string" }, { type: "null" }]);
    expect(json.paths["/api/v1/evidence/public-claim"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/PublicClaimResponse",
    );
    expect(json.paths["/api/v1/caw/live/identity/probe"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawLiveIdentityProbeInput",
    );
    expect(json.paths["/api/v1/caw/live/identity/probe"].post.responses["202"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawLiveIdentityProbeResponse",
    );
    expect(json.components.schemas.ClaimReadinessResponse.oneOf[0].properties.data.properties.claimMode.enum).toEqual([
      "simulated",
      "caw-target-real",
      "caw-stable-params-real",
    ]);
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
    expect(json.components.schemas.SpendRegisterPayload.properties.spends.items.required).toEqual([
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
    ]);
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
    expect(json.paths["/api/v1/token/balance-deltas/verify"].post["x-pactfuse-proof-fields"]).toEqual([
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
    ]);
    expect(json.paths["/api/v1/token/balance-deltas/verify"].post.parameters).toEqual([
      expect.objectContaining({
        name: "authorization",
        in: "header",
        required: false,
      }),
    ]);
    expect(json.paths["/api/v1/token/balance-deltas/verify"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/TokenBalanceDeltaVerifyInput",
    );
    expect(json.components.schemas.TokenBalanceDeltaVerifyPayload.required).toEqual(["spendId"]);
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
      "status",
	      "winnerClaimAllowed",
	    ]);
    expect(json.paths["/api/v1/artifacts/preflight"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactPreflightInput",
    );
    expect(json.paths["/api/v1/artifacts/preflight/verify"].post["x-pactfuse-proof-fields"]).toEqual([
      "preflightId",
      "deliveryProofHash",
      "manifestFetchHash",
      "endpointResponseHash",
      "leaseDryRunHash",
      "status",
      "winnerClaimAllowed",
    ]);
    expect(json.paths["/api/v1/artifacts/preflight/verify"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ArtifactPreflightVerifyInput",
    );
	    expect(json.paths["/api/v1/quotes"].post["x-pactfuse-proof-fields"]).toEqual([
	      "preflightId",
	      "artifactCid",
	      "quoteSignedAfterPreflight",
	      "priceDisclosureHash",
      "status",
      "chainId",
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
      "consumedArtifactPayloadHash",
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
    expect(json.components.schemas.QuotePayload.properties.settlementMode.enum).toEqual([
      "mocked_after_preflight_not_chain_settleable",
      "chain_settleable_after_preflight",
    ]);
    expect(json.components.schemas.QuoteResponse.oneOf[0].properties.data.properties.status.enum).toContain(
      "chain_settleable_after_preflight",
    );
    expect(json.components.schemas.QuoteResponse.oneOf[0].properties.data.properties.chainId.type).toEqual(["string", "null"]);
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
    expect(
      json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.cawLiveInteractions.items.required,
    ).toEqual([
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
    ]);
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.cawLiveInteractions.items.properties.kind.enum).toContain(
      "contract_call",
    );
    expect(json.paths["/api/v1/caw/live/contracts/call"].post["x-pactfuse-proof-fields"]).toEqual([
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
    ]);
    expect(json.paths["/api/v1/caw/live/contracts/call"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawLiveContractCallInput",
    );
    expect(json.paths["/api/v1/caw/live/allowances/verify"].post["x-pactfuse-proof-fields"]).toEqual([
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
    ]);
    expect(json.paths["/api/v1/caw/live/allowances/verify"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawAllowanceVerifyInput",
    );
    expect(json.paths["/api/v1/caw/live/audit/sync"].post.requestBody.content["application/json"].schema.$ref).toBe(
      "#/components/schemas/CawLiveAuditSyncInput",
    );
    expect(json.components.schemas.CawLiveAuditSyncPayload.properties.result.enum).toEqual(["allowed", "denied", "pending", "error"]);
    expect(json.components.schemas.CawLiveContractCallPayload.properties.operationKind.enum).toEqual(["deny_probe", "approve", "activate_tool"]);
    expect(json.paths["/api/v1/caw/live/contracts/call"].post.parameters).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "x-pactfuse-caw-pact-api-key", in: "header", required: true }),
      ]),
    );
    expect(json.components.schemas.CawLiveContractCallPayload.required).toEqual([
      "spendId",
      "operationKind",
      "pactId",
      "walletId",
      "chainId",
      "contractAddress",
      "calldata",
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
    ]);
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("mcpAdapterCalls");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("rawCawReceiptBundles");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("canonicalCawReceipts");
    expect(json.paths["/api/v1/evidence/replay-bundle"].get["x-pactfuse-proof-fields"]).toContain("leaseRuns");
    expect(json.paths["/api/v1/evidence/replay-page"].get.responses["200"].content["application/json"].schema.$ref).toBe(
      "#/components/schemas/ReplayPageResponse",
    );
    expect(json.components.schemas.ReplayPageResponse.oneOf[0].properties.data.required).toEqual([
      "bundleType",
      "sessionId",
      "collection",
      "pageIndex",
      "pageSize",
      "orderBy",
      "rows",
      "pageHash",
    ]);
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
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.spends.items.required).toEqual(
      expect.arrayContaining(["paymentToken", "artifactHash", "market"]),
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.artifactPreflights.items.required).toContain(
      "sourceStateSnapshotHash",
    );
    expect(json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.artifactPreflights.items.required).toEqual(
      expect.arrayContaining([
        "deliveryProofHash",
        "manifestFetchHash",
        "endpointResponseHash",
        "leaseDryRunHash",
        "verifiedAt",
        "verifiedEventId",
      ]),
    );
    expect(
      json.components.schemas.ReplayBundleResponse.oneOf[0].properties.data.properties.artifactPreflights.items.properties.status.enum,
    ).toEqual(["pending_live_delivery", "passed_live_delivery"]);
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
    expect(json.components.schemas.FailClosedProofState.properties.proofChipAllowed.type).toBe("boolean");
    expect(json.components.schemas.FailClosedProofState.properties.winnerClaimAllowed.type).toBe("boolean");
    expect(json.components.schemas.FailClosedProofState.properties.finalVerifierComplete.type).toBe("boolean");
    expect(json.components.schemas.FailClosedProofState.properties.proofLevel.enum).toEqual([
      "schema_only_no_claim",
      "fail_closed_no_claim",
      "final_replay_claim",
    ]);
    expect(json.components.schemas.FailClosedProofState.properties.claimMode.enum).toContain("simulated");
    expect(json.components.schemas.FailClosedProofState.properties.paymentMode.enum).toContain("mocked");
    expect(json.components.schemas.PublicClaimResponse.oneOf[0].properties.data.properties.claimStatus.const).toBe(
      "authorized_public_claim",
    );
    expect(json.components.schemas.PublicClaimResponse.oneOf[0].properties.data.properties.winnerClaimAllowed.const).toBe(true);
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
          spendRegistrationForTest(hex32("wrong-spend-id")),
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
          spendRegistrationForTest(spendId, { sourceHashes: [hex32("missing-source")] }),
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
          spendRegistrationForTest(spendId, { sourceHashes: [upperSourceHash] }),
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
          spendRegistrationForTest(spendId, {
            payer: "0x3000000000000000000000000000000000000003",
            agentWallet: "0x3000000000000000000000000000000000000003",
            maxPriceAtomic: "2000",
          }),
        ],
      },
    });

    expect(rebind.status).toBe(422);
    expect(rebind.json.error.code).toBe("proof_blocked");
    expect(rebind.json.error.message).toContain("spendId does not match");
  });

  it.each([
    ["zero agentWallet", { payer: "0x0000000000000000000000000000000000000000", agentWallet: "0x0000000000000000000000000000000000000000" }],
    ["zero paymentToken", { paymentToken: "0x0000000000000000000000000000000000000000" }],
    ["zero market", { market: "0x0000000000000000000000000000000000000000" }],
    ["zero artifactHash", { artifactHash: ZERO_HASH }],
    ["zero price", { maxPriceAtomic: "0" }],
  ])("rejects ProcurementGate spends with %s before chain registration", async (_label, overrides) => {
    const { app } = makeApp();
    const labelKey = _label.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
    const sessionId = await createSession(app, `sess-spend-${labelKey}`);
    await registerSource(app, sessionId);
    const spendId = await computeSpendIdForTest(app, sessionId, [hex32("source")]);

    const res = await post(app, "/api/v1/spends/register-batch", {
      sessionId,
      idempotencyKey: `spend-register-${labelKey}`,
      payload: {
        spends: [spendRegistrationForTest(spendId, overrides)],
      },
    });

    expect(res.status).toBe(422);
    expect(res.json.error.code).toBe("proof_blocked");
    expect(res.json.error.message).toContain("chain-registerable");
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

  it("pins CAW operation builds to current ProcurementGate selectors and registered spend targets", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-caw-operation-pins");
    const spendId = await registerSpend(app, sessionId);

    const missingGateTarget = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "caw-op-missing-gate-target",
      payload: {
        spendId,
        operationKind: "activate_tool",
      },
    });
    const legacySelector = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "caw-op-legacy-selector",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: "0x2222222222222222222222222222222222222222",
        selector: "0xca255603",
      },
    });
    const directMarket = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "caw-op-direct-market",
      payload: {
        spendId,
        operationKind: "activate_tool",
        target: TEST_MARKET_ADDRESS,
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
      },
    });
    const wrongApproveTarget = await post(app, "/api/v1/caw/operations/build", {
      sessionId,
      idempotencyKey: "caw-op-wrong-approve-target",
      payload: {
        spendId,
        operationKind: "approve",
        target: TEST_PAYER_ADDRESS,
        selector: ERC20_APPROVE_SELECTOR,
      },
    });

    expect(missingGateTarget.status).toBe(422);
    expect(missingGateTarget.json.error.message).toContain("requires a ProcurementGate target address");
    expect(legacySelector.status).toBe(422);
    expect(legacySelector.json.error.message).toContain("activateTool(bytes32,bytes)");
    expect(directMarket.status).toBe(422);
    expect(directMarket.json.error.message).toContain("cannot be the PaidArtifactMarket");
    expect(wrongApproveTarget.status).toBe(422);
    expect(wrongApproveTarget.json.error.message).toContain("target must match registered ProcurementGate paymentToken");
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
        target: TEST_PAYMENT_TOKEN_ADDRESS,
        selector: ERC20_APPROVE_SELECTOR,
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
                target: "0x1000000000000000000000000000000000000001",
                selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
          target: "0x1000000000000000000000000000000000000001",
          selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
      target: "0x1000000000000000000000000000000000000001",
      selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
      target: "0x1000000000000000000000000000000000000001",
      selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
      target: "0x1000000000000000000000000000000000000001",
      selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
            target: "0x1000000000000000000000000000000000000001",
            selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
          target: "0x1000000000000000000000000000000000000001",
          selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
          target: "0x1000000000000000000000000000000000000001",
          selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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

  it("blocks signed finalized gate proofs whose chain log address differs from the required gate cursor", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-gate-signed-wrong-address", { finalityDepth: 2 });
    const spendId = await registerSpend(app, sessionId);
    const body = gateEventEnvelope(sessionId, spendId, "gate-signed-wrong-address", {
      blockNumber: 100,
      currentBlockNumber: 101,
      txHash: hex32("gate-signed-wrong-address-tx"),
      rawLogHash: hex32("gate-signed-wrong-address-log"),
    });
    logs.push(
      indexerLog("gate-signed-wrong-address", 100, {
        address: "0x2222222222222222222222222222222222222222",
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("gate-signed-wrong-address-tx"),
        rawLogHash: hex32("gate-signed-wrong-address-log"),
      }),
    );

    const finalized = await postSignedGateEvent(app, body);

    expect(finalized.status).toBe(422);
    expect(finalized.json.error.code).toBe("proof_blocked");
    expect(finalized.json.error.message).toContain("claimed gate event log address does not match a required gate cursor address");
  });

  it("finalizes gate settlement only from indexed public-chain logs and records a matching proof row", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
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
      cawLive: createFakeCawLiveClient(),
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
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
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
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-artifact");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    const payer = "0x1000000000000000000000000000000000000001";
    const artifactUrl = `/api/v1/artifacts/${sessionId}/${spendId}/${payer}/${artifactHash}`;
    const uppercaseArtifactHash = `0x${artifactHash.slice(2).toUpperCase()}`;
    const wrongPayer = "0x2000000000000000000000000000000000000002";

    const pending = await app.request(artifactUrl);
    const pendingJson = await pending.json();
    const invalidPayer = await app.request(`/api/v1/artifacts/${sessionId}/${spendId}/not-a-hex/${artifactHash}`);
    const invalidJson = await invalidPayer.json();
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-settlement");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "artifact-settlement", finalized);
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

  it("rechecks artifact token quote and settlement bindings when the bearer token is used", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
    });
    const payer = "0x1000000000000000000000000000000000000001";
    const settlementSessionId = await createSession(app, "sess-artifact-token-settlement-drift");
    const settlementSpendId = await registerSpend(app, settlementSessionId);
    const settlementQuote = await quoteArtifactForTest(app, settlementSessionId, settlementSpendId, "artifact-settlement-drift");
    const settlementFinalized = await finalizeSpendSettlement(
      app,
      ctx,
      logs,
      settlementSessionId,
      settlementSpendId,
      "artifact-settlement-drift",
    );
    await verifyTokenBalanceDeltaForTest(
      app,
      logs,
      tokenBalances,
      settlementSessionId,
      settlementSpendId,
      "artifact-settlement-drift",
      settlementFinalized,
    );
    const settlementIssued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: settlementSessionId,
      idempotencyKey: "issue-settlement-drift-token",
      payload: {
        spendId: settlementSpendId,
        payer,
        quoteId: settlementQuote.quoteId,
        artifactHash: settlementQuote.artifactHash,
        artifactPayload: settlementQuote.artifactPayload,
      },
    });
    ctx.db.sqlite
      .prepare("UPDATE artifact_access_tokens SET settlement_event_id = ? WHERE session_id = ? AND token_id = ?")
      .run(hex32("wrong-artifact-settlement-event"), settlementSessionId, settlementIssued.json.data.tokenId);
    const settlementRead = await app.request(
      `/api/v1/artifacts/${settlementSessionId}/${settlementSpendId}/${payer}/${settlementQuote.artifactHash}`,
      { headers: { authorization: `Bearer ${settlementIssued.json.data.accessToken}` } },
    );
    const settlementReadJson = await settlementRead.json();

    const quoteSessionId = await createSession(app, "sess-artifact-token-quote-drift");
    const quoteSpendId = await registerSpend(app, quoteSessionId);
    const quote = await quoteArtifactForTest(app, quoteSessionId, quoteSpendId, "artifact-quote-drift");
    const quoteFinalized = await finalizeSpendSettlement(app, ctx, logs, quoteSessionId, quoteSpendId, "artifact-quote-drift");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, quoteSessionId, quoteSpendId, "artifact-quote-drift", quoteFinalized);
    const quoteIssued = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: quoteSessionId,
      idempotencyKey: "issue-quote-drift-token",
      payload: {
        spendId: quoteSpendId,
        payer,
        quoteId: quote.quoteId,
        artifactHash: quote.artifactHash,
        artifactPayload: quote.artifactPayload,
      },
    });
    ctx.db.sqlite
      .prepare("UPDATE quotes SET chain_id = ? WHERE session_id = ? AND quote_id = ?")
      .run("1", quoteSessionId, quote.quoteId);
    const quoteRead = await app.request(`/api/v1/artifacts/${quoteSessionId}/${quoteSpendId}/${payer}/${quote.artifactHash}`, {
      headers: { authorization: `Bearer ${quoteIssued.json.data.accessToken}` },
    });
    const quoteReadJson = await quoteRead.json();

    expect(settlementIssued.status).toBe(202);
    expect(settlementRead.status).toBe(422);
    expect(settlementReadJson.error.code).toBe("proof_blocked");
    expect(settlementReadJson.error.message).toContain("settlement proof no longer matches");
    expect(quoteIssued.status).toBe(202);
    expect(quoteRead.status).toBe(422);
    expect(quoteReadJson.error.code).toBe("proof_blocked");
  });

  it("rejects hand-written artifact token rows without verifier issuance evidence", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs }) });
    const sessionId = await createSession(app, "sess-artifact-token-tamper");
    const spendId = await registerSpend(app, sessionId);
    const artifactHash = hex32("artifact-token-tamper");
    const payer = "0x1000000000000000000000000000000000000001";
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
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-artifact-quote-mismatch");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-quote-bound");
    const differentPayload = artifactPayloadForTest("artifact-quote-tampered");
    const differentHash = hashForTestJson(differentPayload);
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-quote-mismatch");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "artifact-quote-mismatch", finalized);

    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-artifact-quote-mismatch",
      payload: {
        spendId,
        payer: "0x1000000000000000000000000000000000000001",
        quoteId: quoted.quoteId,
        artifactHash: differentHash,
        artifactPayload: differentPayload,
      },
    });

    expect(issue.status).toBe(422);
    expect(issue.json.error.code).toBe("proof_blocked");
    expect(issue.json.error.message).toContain("registered ProcurementGate artifactHash");
  });

  it("blocks artifact access issuance for overpriced or expired quotes", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const overpricedSessionId = await createSession(app, "sess-artifact-overpriced-quote");
    const overpricedSpendId = await registerSpend(app, overpricedSessionId);
    const overpricedPreflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId: overpricedSessionId,
      idempotencyKey: "overpriced-preflight",
      payload: {
        spendId: overpricedSpendId,
        artifactHashPreview: TEST_ARTIFACT_HASH,
        artifactCid: artifactCidForTest(TEST_ARTIFACT_HASH),
        endpointUrl: "https://example.com/overpriced.json",
        priceDisclosureHash: hex32("overpriced-price-disclosure"),
        sourceStateSnapshotHash: hex32("overpriced-source-state"),
      },
    });
    expect(overpricedPreflight.status).toBe(202);
    await verifyArtifactPreflightForTest(
      app,
      overpricedSessionId,
      overpricedPreflight.json.data.preflightId,
      TEST_ARTIFACT_HASH,
      artifactCidForTest(TEST_ARTIFACT_HASH),
      "overpriced",
    );
    const overpricedQuote = await post(app, "/api/v1/quotes", {
      sessionId: overpricedSessionId,
      idempotencyKey: "overpriced-quote",
      payload: {
        spendId: overpricedSpendId,
        preflightId: overpricedPreflight.json.data.preflightId,
        artifactCommitment: TEST_ARTIFACT_HASH,
        priceAtomic: "1001",
        quoteNonce: "overpriced-quote-nonce",
        validUntilBlock: "1000000",
      },
    });

    const expiredSessionId = await createSession(app, "sess-artifact-expired-quote");
    const expiredSpendId = await registerSpend(app, expiredSessionId);
    const expired = await quoteArtifactForTest(app, expiredSessionId, expiredSpendId, "artifact-expired", { validUntilBlock: "99" });
    const expiredFinalized = await finalizeSpendSettlement(app, ctx, logs, expiredSessionId, expiredSpendId, "artifact-expired");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, expiredSessionId, expiredSpendId, "artifact-expired", expiredFinalized);
    const expiredIssue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: expiredSessionId,
      idempotencyKey: "issue-expired-artifact",
      payload: {
        spendId: expiredSpendId,
        payer: "0x1000000000000000000000000000000000000001",
        quoteId: expired.quoteId,
        artifactHash: expired.artifactHash,
        artifactPayload: expired.artifactPayload,
      },
    });

    expect(overpricedQuote.status).toBe(422);
    expect(overpricedQuote.json.error.code).toBe("proof_blocked");
    expect(overpricedQuote.json.error.message).toContain("priceAtomic does not match registered ProcurementGate price");
    expect(expiredIssue.status).toBe(422);
    expect(expiredIssue.json.error.code).toBe("proof_blocked");
    expect(expiredIssue.json.error.message).toContain("expired");
  });

  it("blocks oversized artifact payloads before issuing bearer access", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-artifact-large-payload");
    const artifactPayload = { artifactType: "source-bound-code-scan-mcp-lease", content: "x".repeat(300 * 1024) };
    const artifactHash = hashForTestJson(artifactPayload);
    const spendId = await registerSpend(app, sessionId, defaultSourceCapabilityForTest(), { artifactHash });
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-large-payload", { artifactPayload });
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-large-payload", { artifactHash });
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "artifact-large-payload", finalized);

    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "issue-large-artifact",
      payload: {
        spendId,
        payer: "0x1000000000000000000000000000000000000001",
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload,
      },
    });

    expect(issue.status).toBe(422);
    expect(issue.json.error.code).toBe("proof_blocked");
    expect(issue.json.error.message).toContain("payload exceeds");
  });

  it("keeps artifact token issuance live when replay rows exceed the summary page", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-artifact-summary-cap");
    const spendId = await registerSpend(app, sessionId);
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "artifact-summary-cap");
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "artifact-summary-cap");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "artifact-summary-cap", finalized);
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
        payer: "0x1000000000000000000000000000000000000001",
        quoteId: quoted.quoteId,
        artifactHash: quoted.artifactHash,
        artifactPayload: quoted.artifactPayload,
      },
    });

    expect(issue.status).toBe(202);
    expect(issue.json.data.winnerClaimAllowed).toBe(false);

    appendEvidenceEvent(ctx, {
      sessionId,
      authority: "operator",
      kind: "runner.heartbeat",
      payload: { overflow: true, winnerClaimAllowed: false },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    expect(replay.status).toBe(200);
    expect(replayJson.data.events).toHaveLength(200);
    expect(replayJson.data.replayPageIndex.collections.events.totalRows).toBeGreaterThan(200);
    expect(replayJson.data.replayPageIndex.collections.events.pageHashes.length).toBeGreaterThan(1);
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

  it("blocks quote signing until artifact preflight passes delivery verification", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-verify-required");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-pending-before-quote",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("pending-before-quote-price"),
        sourceStateSnapshotHash: hex32("pending-before-quote-source"),
      },
    });

    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "quote-before-preflight-verify",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceAtomic: "1000",
        quoteNonce: "quote-before-preflight-verify",
        validUntilBlock: "123",
      },
    });

    expect(preflight.status).toBe(202);
    expect(quote.status).toBe(422);
    expect(quote.json.error.code).toBe("proof_blocked");
    expect(quote.json.error.message).toContain("artifact preflight is not quote-eligible");
  });

  it("verifies artifact preflight delivery proof before quote signing", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-preflight-verify-proof");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
    const artifactCid = artifactCidForTest(artifactHashPreview);
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-verify-proof",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid,
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("preflight-verify-price"),
        sourceStateSnapshotHash: hex32("preflight-verify-source"),
      },
    });
    const mismatch = await post(app, "/api/v1/artifacts/preflight/verify", {
      sessionId,
      idempotencyKey: "preflight-verify-mismatch",
      payload: {
        preflightId: preflight.json.data.preflightId,
        artifactPayloadHash: hex32("wrong-artifact-payload"),
        artifactCid,
        manifestFetchHash: hex32("preflight-verify-manifest"),
        endpointResponseHash: hex32("preflight-verify-endpoint"),
        leaseDryRunHash: hex32("preflight-verify-lease"),
      },
    });
    const verify = await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCid,
      "preflight-verify-proof",
    );
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const verifiedEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "artifact.preflight.verified");
    const preflightView = replayJson.data.artifactPreflights.find(
      (row: { preflightId: string }) => row.preflightId === preflight.json.data.preflightId,
    );

    expect(mismatch.status).toBe(422);
    expect(mismatch.json.error.code).toBe("proof_blocked");
    expect(verify.json.data.deliveryProofHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(preflightView).toEqual(
      expect.objectContaining({
        preflightId: preflight.json.data.preflightId,
        status: "passed_live_delivery",
        deliveryProofHash: verify.json.data.deliveryProofHash,
        manifestFetchHash: hex32("preflight-verify-proof-manifest-fetch"),
        endpointResponseHash: hex32("preflight-verify-proof-endpoint-response"),
        leaseDryRunHash: hex32("preflight-verify-proof-lease-dry-run"),
        verifiedEventId: verify.json.evidenceEventId,
      }),
    );
    expect(verifiedEvent).toEqual(
      expect.objectContaining({
        authority: "delivery",
        payload: expect.objectContaining({
          preflightId: preflight.json.data.preflightId,
          deliveryProofHash: verify.json.data.deliveryProofHash,
          status: "passed_live_delivery",
          winnerClaimAllowed: false,
        }),
      }),
    );
  });

  it("binds mocked quote signing to the matching artifact preflight", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-bound");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
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
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCidForTest(artifactHashPreview),
      "preflight-before-quote",
    );
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
    expect(quote.json.data.chainId).toBeNull();
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
        status: "mocked_after_preflight_not_chain_settleable",
        chainId: null,
        priceDisclosureHash,
        sourceStateSnapshotHash,
        quoteSignedAfterPreflight: true,
      }),
    );
  });

  it("requires a live chain provider before signing chain-settleable quotes", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-live-quote-provider-required");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "live-quote-provider-preflight",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("live-quote-provider-price"),
        sourceStateSnapshotHash: hex32("live-quote-provider-source"),
      },
    });
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCidForTest(artifactHashPreview),
      "live-quote-provider",
    );

    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "live-quote-provider-missing",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceAtomic: "1000",
        quoteNonce: "live-quote-provider-missing",
        validUntilBlock: "123",
        settlementMode: "chain_settleable_after_preflight",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(quote.status).toBe(423);
    expect(quote.json.error.message).toContain("chain-settleable quote requires a live chain proof provider");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("quote.signed.chain_settleable");
  });

  it("signs chain-settleable quotes with live chain and payment bindings", async () => {
    const { app, ctx } = makeApp(":memory:", {
      chain: createFakeIndexerChainClient({ mode: "live", chainId: "84532", currentBlockNumber: 100, logs: [] }),
    });
    const sessionId = await createSession(app, "sess-live-quote-bound");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "live-quote-bound-preflight",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("live-quote-bound-price"),
        sourceStateSnapshotHash: hex32("live-quote-bound-source"),
      },
    });
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCidForTest(artifactHashPreview),
      "live-quote-bound",
    );
    const quote = await post(app, "/api/v1/quotes", {
      sessionId,
      idempotencyKey: "live-quote-bound",
      payload: {
        spendId,
        preflightId: preflight.json.data.preflightId,
        artifactCommitment: artifactHashPreview,
        priceAtomic: "1000",
        quoteNonce: "live-quote-bound",
        validUntilBlock: "123",
        settlementMode: "chain_settleable_after_preflight",
      },
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const quoteEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "quote.signed.chain_settleable");
    const quoteRow = ctx.db.sqlite.prepare("SELECT status, chain_id FROM quotes WHERE quote_id = ?").get(quote.json.data.quoteId) as Record<
      string,
      unknown
    >;

    expect(quote.status).toBe(201);
    expect(quote.json.data.status).toBe("chain_settleable_after_preflight");
    expect(quote.json.data.chainId).toBe("84532");
    expect(quoteRow).toEqual(expect.objectContaining({ status: "chain_settleable_after_preflight", chain_id: "84532" }));
    expect(quoteEvent).toEqual(
      expect.objectContaining({
        authority: "delivery",
        payload: expect.objectContaining({
          quoteId: quote.json.data.quoteId,
          quoteHash: quote.json.data.quoteHash,
          spendId,
          preflightId: preflight.json.data.preflightId,
          artifactCommitment: artifactHashPreview,
          priceAtomic: "1000",
          validUntilBlock: "123",
          paymentToken: TEST_PAYMENT_TOKEN_ADDRESS.toLowerCase(),
          agentWallet: TEST_PAYER_ADDRESS.toLowerCase(),
          market: TEST_MARKET_ADDRESS.toLowerCase(),
          chainId: "84532",
          status: "chain_settleable_after_preflight",
          proofAuthority: false,
          winnerClaimAllowed: false,
        }),
      }),
    );
  });

  it("blocks mocked quotes whose artifact commitment diverges from preflight", async () => {
    const { app } = makeApp();
    const sessionId = await createSession(app, "sess-quote-preflight-mismatch");
    const spendId = await registerSpend(app, sessionId);
    const artifactHashPreview = TEST_ARTIFACT_HASH;
    const preflight = await post(app, "/api/v1/artifacts/preflight", {
      sessionId,
      idempotencyKey: "preflight-mismatch",
      payload: {
        spendId,
        artifactHashPreview,
        artifactCid: artifactCidForTest(artifactHashPreview),
        endpointUrl: "https://example.com/artifact",
        priceDisclosureHash: hex32("price-disclosure-mismatch"),
        sourceStateSnapshotHash: hex32("source-state-mismatch"),
      },
    });
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCidForTest(artifactHashPreview),
      "preflight-mismatch",
    );

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
    const artifactHashPreview = TEST_ARTIFACT_HASH;
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
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHashPreview,
      artifactCidForTest(artifactHashPreview),
      "refund",
    );
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

    expect(secondPreflight.status).toBe(422);
    expect(secondPreflight.json.error.code).toBe("proof_blocked");
    expect(secondPreflight.json.error.message).toContain("registered ProcurementGate artifactHash");
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
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-refund-token-exclusive");
    const artifactPayload = artifactPayloadForTest("refund-token-artifact");
    const artifactHash = hashForTestJson(artifactPayload);
    const spendId = await registerSpend(app, sessionId, defaultSourceCapabilityForTest(), { artifactHash });
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
    await verifyArtifactPreflightForTest(
      app,
      sessionId,
      preflight.json.data.preflightId,
      artifactHash,
      artifactCidForTest(artifactHash),
      "exclusive",
    );
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
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "exclusive-token-first", { artifactHash });
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "exclusive-token-first", finalized);
    const issue = await post(app, "/api/v1/artifacts/access-token", {
      sessionId,
      idempotencyKey: "exclusive-issue-token",
      payload: {
        spendId,
        payer: "0x1000000000000000000000000000000000000001",
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
    const secondArtifactPayload = artifactPayloadForTest("token-refund-artifact");
    const secondArtifactHash = hashForTestJson(secondArtifactPayload);
    const secondSpendId = await registerSpend(app, secondSessionId, defaultSourceCapabilityForTest(), { artifactHash: secondArtifactHash });
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
    await verifyArtifactPreflightForTest(
      app,
      secondSessionId,
      secondPreflight.json.data.preflightId,
      secondArtifactHash,
      artifactCidForTest(secondArtifactHash),
      "exclusive-second",
    );
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
    const secondFinalized = await finalizeSpendSettlement(app, ctx, logs, secondSessionId, secondSpendId, "exclusive-refund-first", {
      artifactHash: secondArtifactHash,
    });
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, secondSessionId, secondSpendId, "exclusive-refund-first", secondFinalized);
    const issueAfterRefund = await post(app, "/api/v1/artifacts/access-token", {
      sessionId: secondSessionId,
      idempotencyKey: "exclusive-issue-after-refund",
      payload: {
        spendId: secondSpendId,
        payer: "0x1000000000000000000000000000000000000001",
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
      cawLive: createFakeCawLiveClient(),
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
        status: "pending",
        authority: "proof",
        evidenceEventId: proofEvent?.eventId,
      }),
    );
  });

  it("verifies ERC20 balance deltas only when the finalized SpendSettled tx contains the matching Transfer log", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
    });
    const sessionId = await createSession(app, "sess-token-balance-delta");
    const spendId = await registerSpend(app, sessionId);
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "token-balance-delta");

    const verified = await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "token-balance-delta", finalized);
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const tokenEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "token.balance_delta.verified");
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const settlementRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "c_settlement");
    const verify = await app.request(`/api/v1/evidence/${sessionId}/verify`);
    const verifyJson = await verify.json();

    expect(verified).toEqual(
      expect.objectContaining({
        spendId,
        settlementEventId: finalized.finalizedEventId,
        txHash: finalized.txHash,
        paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
        agentWallet: TEST_PAYER_ADDRESS,
        market: TEST_MARKET_ADDRESS,
        amountAtomic: "1000",
        agentDeltaAtomic: "-1000",
        marketDeltaAtomic: "1000",
        payerAgentWalletSame: true,
        proofAuthority: true,
        winnerClaimAllowed: false,
      }),
    );
    expect(tokenEvent).toEqual(expect.objectContaining({ authority: "proof", payload: expect.objectContaining({ transferLogIndex: 20 }) }));
    expect(settlementRow).toEqual(
      expect.objectContaining({
        status: "pass",
        authority: "proof",
        evidenceEventId: tokenEvent?.eventId,
      }),
    );
	  expect(verify.status).toBe(200);
	  expect(verifyJson.data.schemaOk).toBe(true);
	});

  it("refuses CAW allowance and token settlement proof when the chain provider is fixture-mode", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ mode: "fixture", currentBlockNumber: 101, logs, tokenBalances }),
    });
    const sessionId = await createSession(app, "sess-token-delta-fixture-chain");
    const spendId = await registerSpend(app, sessionId);
	    await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "token-delta-fixture-chain");
    const allowance = await verifyCawAllowanceForTest(
      app,
      logs,
      tokenBalances,
      sessionId,
      spendId,
      "token-delta-fixture-chain",
      {},
      423,
    );
	    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
	    const replayJson = await replay.json();

    expect((allowance.error as { code?: string }).code).toBe("proof_pending");
    expect((allowance.error as { message?: string }).message).toContain("live chain proof provider");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("caw.allowance.verified");
	    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("token.balance_delta.verified");
	  });

	it("blocks ERC20 balance delta verification when the settlement tx has no matching Transfer log", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs, tokenBalances }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-token-delta-missing-transfer");
    const spendId = await registerSpend(app, sessionId);
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "token-delta-missing-transfer");
    await prepareCawProofsForTokenDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "token-delta-missing-transfer", finalized, {
      blockNumber: Number(finalized.blockNumber) - 1,
    });
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_PAYER_ADDRESS, 99)] = "5000";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_PAYER_ADDRESS, 100)] = "4000";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_MARKET_ADDRESS, 99)] = "10";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_MARKET_ADDRESS, 100)] = "1010";

    const verified = await post(app, "/api/v1/token/balance-deltas/verify", {
      sessionId,
      idempotencyKey: "token-delta-missing-transfer",
      payload: { spendId, settlementEventId: finalized.finalizedEventId },
    });

    expect(verified.status).toBe(422);
    expect(verified.json.error.code).toBe("proof_blocked");
    expect(verified.json.error.message).toContain("matching ERC20 Transfer log");
  });

  it("blocks ERC20 balance delta verification when the Transfer value does not match the registered price", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 103, logs, tokenBalances }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-token-delta-wrong-transfer");
    const spendId = await registerSpend(app, sessionId);
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "token-delta-wrong-transfer");
    await prepareCawProofsForTokenDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "token-delta-wrong-transfer", finalized, {
      blockNumber: Number(finalized.blockNumber) - 1,
    });
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_PAYER_ADDRESS, 99)] = "5000";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_PAYER_ADDRESS, 100)] = "4000";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_MARKET_ADDRESS, 99)] = "10";
    tokenBalances[balanceKeyForTest(TEST_PAYMENT_TOKEN_ADDRESS, TEST_MARKET_ADDRESS, 100)] = "1010";
    logs.push(
      erc20TransferLogForTest("token-delta-wrong-transfer", {
        txHash: String(finalized.txHash),
        blockNumber: Number(finalized.blockNumber),
        value: "999",
      }),
    );

    const verified = await post(app, "/api/v1/token/balance-deltas/verify", {
      sessionId,
      idempotencyKey: "token-delta-wrong-transfer",
      payload: { spendId, settlementEventId: finalized.finalizedEventId },
    });

    expect(verified.status).toBe(422);
    expect(verified.json.error.code).toBe("proof_blocked");
    expect(verified.json.error.message).toContain("matching ERC20 Transfer log");
  });

  it("blocks indexed SpendSettled logs when ProcurementGate state is not settled", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const contractSpendStates: Record<string, number> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
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

  it("blocks indexed SpendSettled logs when ProcurementGate registeredSpend tuple diverges", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({
        currentBlockNumber: 103,
        logs,
        contractRegisteredSpendOverrides: { paymentToken: "0x9999999999999999999999999999999999999999" },
      }),
      requiredIndexerCursors: [{ cursorId: "gate:indexer", chainId: "84532", address: INDEXER_ADDRESS, topics: [], finalityDepth: 2 }],
    });
    const sessionId = await createSession(app, "sess-indexer-contract-tuple-mismatch");
    const spendId = await registerSpend(app, sessionId);
    logs.push(
      indexerLog("contract-tuple-mismatch", 100, {
        eventName: "SpendSettled",
        event: "SpendSettled",
        sessionId,
        spendId,
        args: { sessionId, spendId },
        transactionHash: hex32("contract-tuple-mismatch-tx"),
        rawLogHash: hex32("contract-tuple-mismatch-log"),
      }),
    );

    const result = await runIndexerWorkerOnce(ctx, {
      leaseOwner: "test-indexer-contract-tuple-mismatch",
      cursors: [{ cursorId: "gate:indexer", chainId: "84532", startBlock: 100, finalityDepth: 2, maxWindowBlocks: 10, address: INDEXER_ADDRESS }],
    });
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(result.status).toBe("blocked");
    expect(result.reason).toContain("registeredSpend state does not match backend spend binding");
    expect(replayJson.data.events.map((event: { kind: string }) => event.kind)).not.toContain("gate.spend_settled");
  });

  it("blocks indexed SpendSettled proofs from cursors without a pinned gate address", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 102, logs }),
      });
      const firstBackfill = await post(first.app, "/api/v1/indexer/backfill", {
        idempotencyKey: "indexer-persist-first",
        payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2 },
      });
      first.ctx.db.sqlite.close();

      const second = makeApp(dbPath, {
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ ready: false, reason: "rpc offline" }),
    }).app;
    const offlineBackfill = await post(offline, "/api/v1/indexer/backfill", {
      idempotencyKey: "indexer-provider-offline",
      payload: { cursorId: "gate:indexer", chainId: "84532", fromBlock: 100, toBlock: 100, finalityDepth: 2 },
    });
    const offlineStatus = await offline.request("/api/v1/evidence/indexer-status");
    const offlineStatusJson = await offlineStatus.json();
    const { app } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
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

  it("indexes replay pages when summary snapshots exceed the first page", async () => {
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
    const eventPage0 = await app.request(`/api/v1/evidence/replay-page?sessionId=${sessionId}&collection=events&page=0`);
    const eventPage0Json = await eventPage0.json();
    const eventPage1 = await app.request(`/api/v1/evidence/replay-page?sessionId=${sessionId}&collection=events&page=1`);
    const eventPage1Json = await eventPage1.json();
    const emptyPage = await app.request(`/api/v1/evidence/replay-page?sessionId=${sessionId}&collection=rawCawReceiptBundles&page=0`);
    const emptyPageJson = await emptyPage.json();
    const outOfRange = await app.request(`/api/v1/evidence/replay-page?sessionId=${sessionId}&collection=events&page=99`);
    const outOfRangeJson = await outOfRange.json();
    const verify = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-summary-cap",
      payload: { replayBundle: replayJson.data },
    });

    expect(replay.status).toBe(200);
    expect(replayJson.data.events).toHaveLength(200);
    expect(replayJson.data.fullReplayRoot).toBe(replayJson.data.replayPageIndex.pageRoot);
    expect(replayJson.data.replayPageIndex.collections.events.totalRows).toBeGreaterThan(200);
    expect(replayJson.data.replayPageIndex.collections.events.pageHashes.length).toBeGreaterThan(1);
    expect(replayJson.data.replayPages.events).toHaveLength(replayJson.data.replayPageIndex.collections.events.pageCount);
    expect(eventPage0.status).toBe(200);
    expect(eventPage0Json.data.bundleType).toBe("PACTFUSE_REPLAY_PAGE_V1");
    expect(eventPage0Json.data.collection).toBe("events");
    expect(eventPage0Json.data.rows).toHaveLength(200);
    expect(eventPage0Json.data.pageHash).toBe(replayJson.data.replayPageIndex.collections.events.pageHashes[0]);
    expect(replayJson.data.replayPages.events[0]).toEqual(eventPage0Json.data);
    expect(eventPage1.status).toBe(200);
    expect(eventPage1Json.data.pageIndex).toBe(1);
    expect(eventPage1Json.data.rows.length).toBeGreaterThan(0);
    expect(eventPage1Json.data.pageHash).toBe(replayJson.data.replayPageIndex.collections.events.pageHashes[1]);
    expect(replayJson.data.replayPages.events[1]).toEqual(eventPage1Json.data);
    expect(replayJson.data.replayPageIndex.collections.rawCawReceiptBundles.pageCount).toBe(0);
    expect(replayJson.data.replayPages.rawCawReceiptBundles).toEqual([]);
    expect(emptyPage.status).toBe(400);
    expect(emptyPageJson.error.code).toBe("bad_request");
    expect(outOfRange.status).toBe(400);
    expect(outOfRangeJson.error.code).toBe("bad_request");
    expect(verify.status).toBe(200);
    expect(verify.json.data.schemaOk).toBe(false);
    expect(verify.json.data.errors).toContain(
      `replayBundle.events has ${replayJson.data.replayPageIndex.collections.events.totalRows} rows, above final verifier cap 200`,
    );
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
    const tamperedReplayPages = JSON.parse(JSON.stringify(replayJson.data.replayPages));
    tamperedReplayPages.events[0].rows[0].kind = "tampered.event";
    const verifyTamperedReplayPages = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-replay-pages-tampered",
      payload: {
        replayBundle: {
          ...replayJson.data,
          replayPages: tamperedReplayPages,
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
    expect(verifyTamperedReplayPages.json.data.schemaOk).toBe(false);
    expect(verifyTamperedReplayPages.json.data.errors).toContain("replayBundle.replayPages does not match the server snapshot");
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
    const payer = "0x1000000000000000000000000000000000000001";
    const artifactHash = TEST_ARTIFACT_HASH;

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
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", { cawLive: createFakeCawLiveClient(), chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }) });
    const sessionId = await createSession(app, "sess-lease-bearer-bound");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1000000000000000000000000000000000000001";
    const wrongPayer = "0x2000000000000000000000000000000000000002";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-artifact-active");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-settlement");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-settlement", finalized);
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
        consumedArtifactPayloadHash: issued.json.data.artifactPayloadHash,
        bearerBound: true,
        status: "blocked_missing_runner_execution",
        winnerClaimAllowed: false,
      }),
    );
  });

  it("executes a clean lease through MCP JSON-RPC and binds the transcript into replay evidence", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
    const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
      mcpLease: createFakeMcpLeaseClient(),
    });
    const sessionId = await createSession(app, "sess-lease-transcript-success");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1000000000000000000000000000000000000001";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-artifact-transcript");
    const { artifactHash, artifactPayload, quoteId } = quoted;
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-transcript-settlement");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-transcript-settlement", finalized);
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
    expect(replayJson.data.mcpAdapterCalls[1].request.params.arguments).toEqual(
      expect.objectContaining({
        artifactPayloadHash: issued.json.data.artifactPayloadHash,
        artifactPayload: quoted.artifactPayload,
      }),
    );
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
        consumedArtifactPayloadHash: issued.json.data.artifactPayloadHash,
      }),
    ]);
    expect(leaseEvent.payload).toEqual(
      expect.objectContaining({
        leaseRunId: lease.json.data.leaseRunId,
        consumedArtifactPayloadHash: issued.json.data.artifactPayloadHash,
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

    const extraAuditPayload = {
      sessionId,
      auditNonce: "audit-extra-after-lease",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId },
      response: { ok: true, data: { sessionId, winnerClaimAllowed: false } },
      status: "succeeded",
    };
    const extraAudit = await post(app, "/api/v1/mcp/audit", extraAuditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, extraAuditPayload),
    });
    const pollutedTranscript = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const pollutedTranscriptJson = await pollutedTranscript.json();
    const pollutedReplay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const pollutedReplayJson = await pollutedReplay.json();
    const verifyPollutedReplay = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-lease-transcript-polluted",
      payload: { replayBundle: pollutedReplayJson.data },
    });

    expect(extraAudit.status).toBe(202);
    expect(pollutedTranscriptJson.data.callCount).toBe(3);
    expect(pollutedTranscriptJson.data.boundedToPinnedManifest).toBe(false);
    expect(verifyPollutedReplay.status).toBe(200);
    expect(verifyPollutedReplay.json.data.schemaOk).toBe(false);
    expect(verifyPollutedReplay.json.data.errors).toContain(
      "agentTranscript with succeeded leases must contain only pinned manifest MCP transcript frames",
    );
  });

  it("does not mark lease transcripts bounded when an extra MCP frame lands after the first summary page", async () => {
    const { app, ctx } = makeApp();
    const sessionId = await createSession(app, "sess-lease-boundary-extra-mcp-page");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1000000000000000000000000000000000000001";
    const artifactHash = hex32("lease-boundary-artifact");
    const pinnedTool = leaseToolDefinitionForTest();
    const leaseInsert = ctx.db.sqlite.prepare(
      `INSERT INTO lease_runs
        (lease_run_id, session_id, spend_id, payer, artifact_hash, consumed_artifact_payload_hash, target_repo, target_commit, status, transcript_hash,
         tools_list_hash, tools_call_hash, output_hash, lease_run_hash, settlement_event_id, artifact_token_id, completed_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'succeeded_live_mcp_transcript', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const consumedArtifactPayloadHash = artifactHash;
    const consumedArtifactPayload = TEST_ARTIFACT_PAYLOAD;

    for (let index = 0; index < 100; index += 1) {
      const leaseRunId = hex32(`lease-boundary-run-${index}`);
      const auditPrefix = leaseRunId.slice(2, 22);
      const targetRepo = "https://github.com/example/boundary-target";
      const targetCommit = `commit-${index}`;
      const listRequest = { jsonrpc: "2.0", id: `lease-tools-list-${index}`, method: "tools/list", params: {} };
      const listResponse = { jsonrpc: "2.0", id: `lease-tools-list-${index}`, result: { tools: [pinnedTool] } };
      const callRequest = {
        jsonrpc: "2.0",
        id: `lease-tools-call-${index}`,
        method: "tools/call",
        params: {
          name: "pactfuse_code_scan",
          arguments: {
            sessionId,
            leaseRunId,
            spendId,
            payer,
            artifactHash,
            artifactPayloadHash: consumedArtifactPayloadHash,
            artifactPayload: consumedArtifactPayload,
            targetRepo,
            targetCommit,
          },
        },
      };
      const callResponse = {
        jsonrpc: "2.0",
        id: `lease-tools-call-${index}`,
        result: { content: [{ type: "text", text: `scan:${index}` }], structuredContent: { findingCount: 0 } },
      };
      const listCall = recordMcpAdapterCall(
        {
          sessionId,
          auditNonce: `lease_${auditPrefix}_tools_list`,
          toolName: "tools/list",
          request: listRequest,
          response: listResponse,
          status: "succeeded",
        },
        ctx,
      );
      const toolCall = recordMcpAdapterCall(
        {
          sessionId,
          auditNonce: `lease_${auditPrefix}_tools_call`,
          toolName: "tools/call",
          request: callRequest,
          response: callResponse,
          status: "succeeded",
        },
        ctx,
      );
      const toolsListHash = hashForTestJson({ requestHash: listCall.requestHash, responseHash: listCall.responseHash });
      const toolsCallHash = hashForTestJson({ requestHash: toolCall.requestHash, responseHash: toolCall.responseHash });
      const transcriptHash = hashForTestJson({
        format: "mcp-json-rpc",
        sessionId,
        leaseRunId,
        frameCallIds: [listCall.callId, toolCall.callId],
        frames: [
          { method: "tools/list", requestHash: listCall.requestHash, responseHash: listCall.responseHash },
          { method: "tools/call", requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
        ],
      });
      const outputHash = hashForTestJson(callResponse);
      const settlementEventId = hex32(`lease-boundary-settlement-${index}`);
      const artifactTokenId = hex32(`lease-boundary-token-${index}`);
      const leaseRunHash = hashForTestJson({
        sessionId,
        leaseRunId,
        spendId,
        payer,
        artifactHash,
        consumedArtifactPayloadHash,
        targetRepo,
        targetCommit,
        settlementEventId,
        artifactTokenId,
        transcriptHash,
        outputHash,
      });
      const createdAt = new Date(Date.UTC(2026, 5, 11, 0, 0, index)).toISOString();
      leaseInsert.run(
        leaseRunId,
        sessionId,
        spendId,
        payer,
        artifactHash,
        consumedArtifactPayloadHash,
        targetRepo,
        targetCommit,
        transcriptHash,
        toolsListHash,
        toolsCallHash,
        outputHash,
        leaseRunHash,
        settlementEventId,
        artifactTokenId,
        createdAt,
        createdAt,
      );
    }

    const cleanTranscript = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const cleanTranscriptJson = await cleanTranscript.json();
    const extraAuditPayload = {
      sessionId,
      auditNonce: "audit-extra-page-boundary",
      toolName: "pactfuse_get_replay_bundle",
      request: { sessionId },
      response: { ok: true, data: { sessionId, winnerClaimAllowed: false } },
      status: "succeeded",
    };
    const extraAudit = await post(app, "/api/v1/mcp/audit", extraAuditPayload, {
      "x-pactfuse-audit-signature": signAuditPayload(MCP_AUDIT_TOKEN, extraAuditPayload),
    });
    const pollutedTranscript = await app.request(`/api/v1/evidence/agent-transcript?sessionId=${sessionId}`);
    const pollutedTranscriptJson = await pollutedTranscript.json();
    const pollutedReplay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const pollutedReplayJson = await pollutedReplay.json();
    const verifyPollutedReplay = await post(app, "/api/v1/evidence/verify", {
      sessionId,
      idempotencyKey: "verify-lease-transcript-page-boundary-polluted",
      payload: { replayBundle: pollutedReplayJson.data },
    });

    expect(cleanTranscript.status).toBe(200);
    expect(cleanTranscriptJson.data.callCount).toBe(200);
    expect(cleanTranscriptJson.data.boundedToPinnedManifest).toBe(true);
    expect(extraAudit.status).toBe(202);
    expect(pollutedTranscriptJson.data.callCount).toBe(200);
    expect(pollutedTranscriptJson.data.boundedToPinnedManifest).toBe(false);
    expect(pollutedReplayJson.data.replayPageIndex.collections.mcpAdapterCalls.totalRows).toBe(201);
    expect(verifyPollutedReplay.status).toBe(200);
    expect(verifyPollutedReplay.json.data.schemaOk).toBe(false);
    expect(verifyPollutedReplay.json.data.errors).toContain(
      "agentTranscript with succeeded leases must contain only pinned manifest MCP transcript frames",
    );
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
      const tokenBalances: Record<string, string> = {};
      const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-http-mcp-success");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-http-mcp-success");
      const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-http-mcp-success");
      await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-http-mcp-success", finalized);
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
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/list", "tools/call"]);
    } finally {
      await mcp.close();
    }
  });

  it("requires live MCP provider readiness to list the unique read-only PactFuse tool", async () => {
    const goodMcp = await startMcpJsonRpcServer((request) => ({
      jsonrpc: "2.0",
      id: request.id,
      result: { tools: [leaseToolDefinitionForTest()] },
    }));
    const badMcp = await startMcpJsonRpcServer((request) => ({
      jsonrpc: "2.0",
      id: request.id,
      result: { tools: [leaseToolDefinitionForTest("pactfuse_other_scan")] },
    }));
    try {
      const goodStatus = await createHttpJsonRpcMcpLeaseClient({ endpointUrl: goodMcp.url, timeoutMs: 1_000 }).status();
      const badStatus = await createHttpJsonRpcMcpLeaseClient({ endpointUrl: badMcp.url, timeoutMs: 1_000 }).status();

      expect(goodStatus).toEqual(
        expect.objectContaining({
          name: "mcp_lease",
          mode: "live",
          ready: true,
        }),
      );
      expect(badStatus).toEqual(
        expect.objectContaining({
          name: "mcp_lease",
          mode: "live",
          ready: false,
        }),
      );
      expect(badStatus.reason).toContain("required unique tool pactfuse_code_scan");
      expect(goodMcp.calls.map((call) => call.method)).toEqual(["tools/list"]);
      expect(badMcp.calls.map((call) => call.method)).toEqual(["tools/list"]);
    } finally {
      await goodMcp.close();
      await badMcp.close();
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
      const tokenBalances: Record<string, string> = {};
      const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-pinned-manifest-mismatch");
      const spendId = await registerSpend(app, sessionId, defaultSourceCapabilityForTest("pactfuse_other_scan"));
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-pinned-manifest-mismatch");
      const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-pinned-manifest-mismatch");
      await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-pinned-manifest-mismatch", finalized);
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
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/list"]);
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
      const tokenBalances: Record<string, string> = {};
      const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-call-failure-blocks-token");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-call-failure-blocks-token");
      const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-call-failure-blocks-token");
      await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-call-failure-blocks-token", finalized);
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
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/list", "tools/call"]);
    } finally {
      await mcp.close();
    }
  });

  it("reconciles expired consuming lease claims into blocked evidence instead of leaving permanent half-state", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
      mcpLease,
    });
    const sessionId = await createSession(app, "sess-lease-expired-consuming");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1000000000000000000000000000000000000001";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-expired-consuming");
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-expired-consuming");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-expired-consuming", finalized);
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
      const tokenBalances: Record<string, string> = {};
      const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-dangerous-tools");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-dangerous-tools");
      const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-dangerous-tools");
      await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-dangerous-tools", finalized);
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
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/list"]);
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
      const tokenBalances: Record<string, string> = {};
      const { app, ctx } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease: createHttpJsonRpcMcpLeaseClient({ endpointUrl: mcp.url, timeoutMs: 1_000 }),
      });
      const sessionId = await createSession(app, "sess-lease-missing-tool-metadata");
      const spendId = await registerSpend(app, sessionId);
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-missing-tool-metadata");
      const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-missing-tool-metadata");
      await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-missing-tool-metadata", finalized);
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
      expect(mcp.calls.map((call) => call.method)).toEqual(["tools/list", "tools/list"]);
    } finally {
      await mcp.close();
    }
  });

  it("serializes concurrent lease executions for the same artifact token before external MCP side effects", async () => {
    const logs: Array<Record<string, unknown>> = [];
    const tokenBalances: Record<string, string> = {};
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
      mcpLease,
    });
    const sessionId = await createSession(app, "sess-lease-token-race");
    const spendId = await registerSpend(app, sessionId);
    const payer = "0x1000000000000000000000000000000000000001";
    const quoted = await quoteArtifactForTest(app, sessionId, spendId, "lease-token-race");
    const finalized = await finalizeSpendSettlement(app, ctx, logs, sessionId, spendId, "lease-token-race");
    await verifyTokenBalanceDeltaForTest(app, logs, tokenBalances, sessionId, spendId, "lease-token-race", finalized);
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
      const tokenBalances: Record<string, string> = {};
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
        mcpLease,
      });
      const sessionId = await createSession(first.app, "sess-cross-instance-lease-claim");
      const spendId = await registerSpend(first.app, sessionId);
      const payer = "0x1000000000000000000000000000000000000001";
      const quoted = await quoteArtifactForTest(first.app, sessionId, spendId, "cross-instance-lease-claim");
      const finalized = await finalizeSpendSettlement(first.app, first.ctx, logs, sessionId, spendId, "cross-instance-lease-claim");
      await verifyTokenBalanceDeltaForTest(first.app, logs, tokenBalances, sessionId, spendId, "cross-instance-lease-claim", finalized);
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
      cawLive: createFakeCawLiveClient(),
      chain: createFakeIndexerChainClient({ currentBlockNumber: 101, logs, tokenBalances }),
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
        target: "0x1000000000000000000000000000000000000001",
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
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
      expect.objectContaining({ name: "caw_live", mode: "unconfigured", ready: false }),
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
    expect(verify.json.data.warnings).toContain("caw_live proof provider is unconfigured: CAW live API is not configured");
    expect(verify.json.data.warnings).toContain("mcp_lease proof provider is unconfigured: lease MCP endpoint is not configured");
    expect(verify.json.data.raw.proofProviders).toHaveLength(4);
  });

  it("uses the official Cobo SDK surface for live wallet, pact, transaction, denial, and audit calls", async () => {
    const requests: Array<{ method: string; path: string; apiKey: string | undefined; body: unknown }> = [];
    const server = createServer(async (req, res) => {
      const body = await readNodeRequestJson(req);
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      requests.push({
        method: req.method ?? "GET",
        path: `${url.pathname}${url.search}`,
        apiKey: Array.isArray(req.headers["x-api-key"]) ? req.headers["x-api-key"][0] : req.headers["x-api-key"],
        body,
      });
      const sendJson = (status: number, payload: Record<string, unknown>) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      if (req.method === "GET" && url.pathname === "/api/v1/wallets/wallet-sdk-1") {
        sendJson(200, { result: { id: "wallet-sdk-1", status: "active", wallet_address: TEST_PAYER_ADDRESS } });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/pacts/submit") {
        sendJson(200, { result: { pact_id: "pact-sdk-1", wallet_id: "wallet-sdk-1", status: "PENDING_APPROVAL" } });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/pacts/pact-sdk-1") {
        sendJson(200, { result: { id: "pact-sdk-1", wallet_id: "wallet-sdk-1", status: "active", api_key: "pact-sdk-key" } });
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/v1/wallets/wallet-sdk-1/contract-call") {
        const record = body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
        if (record.request_id === "sdk-deny") {
          sendJson(403, { error: { code: "policy_denied", reason: "target denied by pact" }, suggestion: "Use the allowed target" });
          return;
        }
        sendJson(200, { result: { id: "tx-sdk-1", request_id: record.request_id, status: "submitted", transaction_hash: hex32("sdk-contract") } });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/audit-logs") {
        sendJson(200, { result: { items: [{ id: "audit-sdk-1", result: "allowed", transaction_hash: hex32("sdk-contract") }] } });
        return;
      }
      sendJson(404, { error: { code: "not_found", reason: `${req.method ?? "GET"} ${url.pathname}` } });
    });
    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (!address || typeof address !== "object") {
        throw new Error("test server did not expose a TCP address");
      }
      const client = createCoboAgenticWalletClient({
        baseUrl: `http://127.0.0.1:${address.port}`,
        apiKey: "owner-sdk-key",
        walletId: "wallet-sdk-1",
      });

      const status = await client.status();
      const submit = await client.submitPact({ walletId: "wallet-sdk-1", intent: "sdk pact", spec: { policies: [] } });
      const pact = await client.getPact("pact-sdk-1");
      const allowed = await client.contractCall({
        walletId: "wallet-sdk-1",
        pactApiKey: "pact-sdk-key",
        chainId: "SETH",
        contractAddress: TEST_MARKET_ADDRESS,
        calldata: "0x12345678",
        requestId: "sdk-allow",
      });
      const denied = await client.contractCall({
        walletId: "wallet-sdk-1",
        pactApiKey: "pact-sdk-key",
        chainId: "SETH",
        contractAddress: TEST_MARKET_ADDRESS,
        calldata: "0x12345678",
        requestId: "sdk-deny",
      });
      const audit = await client.listAuditLogs({ walletId: "wallet-sdk-1", result: "allowed", limit: 20 });

      expect(status).toEqual(expect.objectContaining({ mode: "live", ready: true }));
      expect(submit.result).toEqual(expect.objectContaining({ pact_id: "pact-sdk-1" }));
      expect(pact.result).toEqual(expect.objectContaining({ api_key: "pact-sdk-key" }));
      expect(allowed.result).toEqual(expect.objectContaining({ request_id: "sdk-allow", transaction_hash: hex32("sdk-contract") }));
      expect(denied).toEqual(expect.objectContaining({ status: "denied", code: "policy_denied", request_id: "sdk-deny", transaction_hash: null }));
      expect(audit.result).toEqual(expect.objectContaining({ items: [expect.objectContaining({ id: "audit-sdk-1" })] }));
      expect(requests).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ method: "GET", path: "/api/v1/wallets/wallet-sdk-1?include_spend_summary=false", apiKey: "owner-sdk-key" }),
          expect.objectContaining({ method: "POST", path: "/api/v1/pacts/submit", apiKey: "owner-sdk-key" }),
          expect.objectContaining({ method: "GET", path: "/api/v1/pacts/pact-sdk-1", apiKey: "owner-sdk-key" }),
          expect.objectContaining({ method: "POST", path: "/api/v1/wallets/wallet-sdk-1/contract-call", apiKey: "pact-sdk-key" }),
          expect.objectContaining({ method: "GET", path: "/api/v1/audit-logs?wallet_id=wallet-sdk-1&result=allowed&limit=20", apiKey: "owner-sdk-key" }),
        ]),
      );
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    }
  });

  it("records live CAW pact, transfer, and audit interactions without storing pact API keys", async () => {
    const pactKeyHash = "0xe731d15044e2dac2b1cee3ea70e39cccc583c28ad1f42510b6a6dbc0b70b4adb";
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient() });
    const sessionId = await createSession(app, "sess-caw-live");
    const spendId = await registerSpend(app, sessionId);

    const status = await app.request("/api/v1/caw/live/status");
    const statusJson = await status.json();
    expect(status.status).toBe(200);
    expect(statusJson.data).toEqual(expect.objectContaining({ name: "caw_live", mode: "live", ready: true }));

    const submit = await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "caw-live-pact-submit",
      payload: {
        walletId: "wallet-live-1",
        intent: "Pay for a PactFuse source-fresh code-scan lease",
        spec: {
          policies: [
            {
              name: "pactfuse-transfer-cap",
              type: "transfer",
              rules: { effect: "allow", when: { token_in: [{ chain_id: "SETH", token_id: "SETH" }] }, deny_if: { amount_gt: "0.002" } },
            },
          ],
          completion_conditions: [{ type: "time_elapsed", threshold: "86400" }],
        },
      },
    });
    expect(submit.status).toBe(202);
    expect(submit.json.data).toEqual(expect.objectContaining({ pactId: "pact-live-1", status: "live_pending", proofAuthority: true }));

    const sync = await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "caw-live-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    expect(sync.status).toBe(202);
    expect(sync.json.data).toEqual(expect.objectContaining({ pactId: "pact-live-1", status: "live_active", pactScopedApiKeyHash: pactKeyHash }));

    const transfer = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-live-transfer-submit",
        payload: {
          spendId,
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          destinationAddress: TEST_MARKET_ADDRESS,
          amount: "1000",
          paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
          tokenId: TEST_PAYMENT_TOKEN_ADDRESS,
          sourceAddress: TEST_PAYER_ADDRESS,
          requestId: "pf-live-transfer-1",
          description: "PactFuse live transfer proof",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    expect(transfer.status).toBe(202);
    expect(transfer.json.data).toEqual(
      expect.objectContaining({
        spendId,
        cawRequestId: "pf-live-transfer-1",
        paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
        tokenId: TEST_PAYMENT_TOKEN_ADDRESS,
        amount: "1000",
        destinationAddress: TEST_MARKET_ADDRESS,
        status: "live_pending",
      }),
    );
    expect(transfer.json.data.pactScopedApiKeyHash).toBe(pactKeyHash);

    const approve = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-live-approve-call",
        payload: {
          spendId,
          operationKind: "approve",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: TEST_PAYMENT_TOKEN_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawApproveCalldataForTest(INDEXER_ADDRESS, "1000"),
          requestId: "pf-live-approve-1",
          description: "PactFuse live approve proof",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    expect(approve.status).toBe(202);
    expect(approve.json.data).toEqual(
      expect.objectContaining({
        spendId,
        operationKind: "approve",
        cawRequestId: "pf-live-approve-1",
        contractAddress: TEST_PAYMENT_TOKEN_ADDRESS,
        selector: ERC20_APPROVE_SELECTOR,
        status: "live_pending",
      }),
    );

    const activate = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-live-activate-call",
        payload: {
          spendId,
          operationKind: "activate_tool",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: INDEXER_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawActivateToolCalldataForTest(spendId),
          requestId: "pf-live-activate-1",
          description: "PactFuse live activate proof",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    expect(activate.status).toBe(202);
    expect(activate.json.data).toEqual(
      expect.objectContaining({
        spendId,
        operationKind: "activate_tool",
        cawRequestId: "pf-live-activate-1",
        contractAddress: INDEXER_ADDRESS,
        selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
        status: "live_pending",
      }),
    );

    const audit = await post(app, "/api/v1/caw/live/audit/sync", {
      sessionId,
      idempotencyKey: "caw-live-audit-sync",
      payload: { walletId: "wallet-live-1", action: "transfer.initiate", result: "allowed", limit: 20 },
    });
    expect(audit.status).toBe(202);
    expect(audit.json.data).toEqual(expect.objectContaining({ status: "live_synced", proofAuthority: true }));
    expect(Number(audit.json.data.usageCount)).toBeGreaterThanOrEqual(2);

    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    expect(replayJson.data.cawLiveInteractions).toHaveLength(6);
    expect(JSON.stringify(replayJson.data.cawLiveInteractions)).not.toContain("pact-scoped-secret");
    expect(replayJson.data.cawLiveInteractions.find((row: { kind: string }) => row.kind === "transfer_submit")).toEqual(
      expect.objectContaining({
        request: expect.objectContaining({
          spend_id: spendId,
          payment_token: TEST_PAYMENT_TOKEN_ADDRESS,
          dst_addr: TEST_MARKET_ADDRESS,
          amount: "1000",
        }),
      }),
    );
    expect(replayJson.data.cawLiveInteractions.filter((row: { kind: string }) => row.kind === "contract_call")).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          request: expect.objectContaining({
            operation_kind: "approve",
            spend_id: spendId,
            contract_addr: TEST_PAYMENT_TOKEN_ADDRESS,
            procurement_gate_addr: INDEXER_ADDRESS,
            selector: ERC20_APPROVE_SELECTOR,
            amount: "1000",
          }),
        }),
        expect.objectContaining({
          request: expect.objectContaining({
            operation_kind: "activate_tool",
            spend_id: spendId,
            contract_addr: INDEXER_ADDRESS,
            procurement_gate_addr: INDEXER_ADDRESS,
            selector: PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR,
            payment_auth: "0x",
          }),
        }),
      ]),
    );
    expect(replayJson.data.events.filter((event: { kind: string }) => event.kind === "caw.live.audit.usage.verified")).toHaveLength(2);
    expect(replayJson.data.replayPageIndex.collections.cawLiveInteractions.totalRows).toBe(6);
  });

  it("blocks CAW live transfers that are not bound to an active Pact and registered spend", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient() });
    const sessionId = await createSession(app, "sess-caw-live-transfer-binding");
    const spendId = await registerSpend(app, sessionId);
    const basePayload = {
      spendId,
      pactId: "pact-live-1",
      walletId: "wallet-live-1",
      destinationAddress: TEST_MARKET_ADDRESS,
      amount: "1000",
      paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
      tokenId: TEST_PAYMENT_TOKEN_ADDRESS,
      requestId: "pf-live-transfer-binding",
    };

    const beforePact = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-before-active-pact",
        payload: basePayload,
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "binding-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "bind transfer", spec: { policies: [] } },
    });
    await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "binding-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const badPactKey = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-bad-pact-key",
        payload: basePayload,
      },
      { "x-pactfuse-caw-pact-api-key": "wrong-pact-scoped-secret" },
    );
    const badToken = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-bad-token",
        payload: { ...basePayload, paymentToken: "0x9999999999999999999999999999999999999999" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badTokenId = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-bad-token-id",
        payload: { ...basePayload, tokenId: "0x9999999999999999999999999999999999999999" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badAmount = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-bad-amount",
        payload: { ...basePayload, amount: "999" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badMarket = await post(
      app,
      "/api/v1/caw/live/transfers/submit",
      {
        sessionId,
        idempotencyKey: "caw-transfer-bad-market",
        payload: { ...basePayload, destinationAddress: "0x9999999999999999999999999999999999999999" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );

    expect(beforePact.status).toBe(422);
    expect(beforePact.json.error.code).toBe("proof_blocked");
    expect(beforePact.json.error.message).toContain("active synced Pact");
    expect(badPactKey.status).toBe(422);
    expect(badPactKey.json.error.message).toContain("pact API key does not match");
    expect(badToken.status).toBe(422);
    expect(badToken.json.error.message).toContain("paymentToken does not match");
    expect(badTokenId.status).toBe(422);
    expect(badTokenId.json.error.message).toContain("tokenId must match");
    expect(badAmount.status).toBe(422);
    expect(badAmount.json.error.message).toContain("priceAtomic does not match");
    expect(badMarket.status).toBe(422);
    expect(badMarket.json.error.message).toContain("destinationAddress does not match");
  });

  it("blocks CAW live contract calls that are not bound to the registered ProcurementGate spend", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient() });
    const sessionId = await createSession(app, "sess-caw-live-contract-binding");
    const spendId = await registerSpend(app, sessionId);
    const approvePayload = {
      spendId,
      operationKind: "approve",
      pactId: "pact-live-1",
      walletId: "wallet-live-1",
      chainId: "84532",
      contractAddress: TEST_PAYMENT_TOKEN_ADDRESS,
      procurementGateAddress: INDEXER_ADDRESS,
      calldata: cawApproveCalldataForTest(INDEXER_ADDRESS, "1000"),
      requestId: "pf-live-approve-binding",
    };
    const activatePayload = {
      spendId,
      operationKind: "activate_tool",
      pactId: "pact-live-1",
      walletId: "wallet-live-1",
      chainId: "84532",
      contractAddress: INDEXER_ADDRESS,
      procurementGateAddress: INDEXER_ADDRESS,
      calldata: cawActivateToolCalldataForTest(spendId),
      requestId: "pf-live-activate-binding",
    };

    const beforePact = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-before-active-pact",
        payload: approvePayload,
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "contract-binding-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "bind contract calls", spec: { policies: [] } },
    });
    await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "contract-binding-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const missingPactKey = await post(app, "/api/v1/caw/live/contracts/call", {
      sessionId,
      idempotencyKey: "caw-contract-missing-pact-key",
      payload: approvePayload,
    });
    const badPactKey = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-pact-key",
        payload: approvePayload,
      },
      { "x-pactfuse-caw-pact-api-key": "wrong-pact-scoped-secret" },
    );
    const badApproveTarget = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-approve-target",
        payload: { ...approvePayload, contractAddress: "0x9999999999999999999999999999999999999999" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badApproveSpender = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-approve-spender",
        payload: { ...approvePayload, calldata: cawApproveCalldataForTest(TEST_MARKET_ADDRESS, "1000") },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badApproveAmount = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-approve-amount",
        payload: { ...approvePayload, calldata: cawApproveCalldataForTest(INDEXER_ADDRESS, "999") },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badActivateMarket = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-activate-market",
        payload: { ...activatePayload, contractAddress: TEST_MARKET_ADDRESS, procurementGateAddress: TEST_MARKET_ADDRESS },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badActivateSpend = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-activate-spend",
        payload: { ...activatePayload, calldata: cawActivateToolCalldataForTest(hex32("wrong-contract-spend")) },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const badActivateValue = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "caw-contract-bad-activate-value",
        payload: { ...activatePayload, valueAtomic: "1" },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );

    expect(beforePact.status).toBe(422);
    expect(beforePact.json.error.message).toContain("active synced Pact");
    expect(missingPactKey.status).toBe(401);
    expect(missingPactKey.json.error.message).toContain("missing x-pactfuse-caw-pact-api-key");
    expect(badPactKey.status).toBe(422);
    expect(badPactKey.json.error.message).toContain("pact API key does not match");
    expect(badApproveTarget.status).toBe(422);
    expect(badApproveTarget.json.error.message).toContain("approve contract target must match");
    expect(badApproveSpender.status).toBe(422);
    expect(badApproveSpender.json.error.message).toContain("approve calldata must approve");
    expect(badApproveAmount.status).toBe(422);
    expect(badApproveAmount.json.error.message).toContain("approve calldata must approve");
    expect(badActivateMarket.status).toBe(422);
    expect(badActivateMarket.json.error.message).toContain("target cannot be the PaidArtifactMarket");
    expect(badActivateSpend.status).toBe(422);
    expect(badActivateSpend.json.error.message).toContain("activate_tool calldata must call");
    expect(badActivateValue.status).toBe(422);
    expect(badActivateValue.json.error.message).toContain("must not send native value");
  });

  it("blocks proof-bearing CAW contract calls when active Pact policy authority is missing", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient({ includePolicyBinding: false }) });
    const sessionId = await createSession(app, "sess-caw-live-missing-policy-binding");
    const spendId = await registerSpend(app, sessionId);
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "missing-policy-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "missing policy", spec: { policies: [] } },
    });
    const sync = await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "missing-policy-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const approve = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "missing-policy-approve",
        payload: {
          spendId,
          operationKind: "approve",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: TEST_PAYMENT_TOKEN_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawApproveCalldataForTest(INDEXER_ADDRESS, "1000"),
          requestId: "missing-policy-approve",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const judge = await app.request(`/api/v1/evidence/judge-check?sessionId=${sessionId}`);
    const judgeJson = await judge.json();
    const cawRow = judgeJson.data.rows.find((row: { rowId: string }) => row.rowId === "caw_boundary");

    expect(sync.status).toBe(202);
    expect(sync.json.data.policyDigest).toBeNull();
    expect(cawRow.status).toBe("blocked");
    expect(approve.status).toBe(422);
    expect(approve.json.error.message).toContain("policy authority binding");
  });

  it("blocks CAW contract calls when no single Pact policy rule allows the chain target selector tuple", async () => {
    const { app } = makeApp(":memory:", {
      cawLive: createFakeCawLiveClient({
        policy: {
          rules: [
            {
              chain_ids: ["84532"],
              target_addresses: [TEST_PAYMENT_TOKEN_ADDRESS],
              selectors: [ERC20_APPROVE_SELECTOR],
            },
            {
              chain_ids: ["1"],
              target_addresses: [INDEXER_ADDRESS],
              selectors: [PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR],
            },
          ],
          request_limit: "2",
          expiry: "2026-06-12T00:00:00.000Z",
        },
      }),
    });
    const sessionId = await createSession(app, "sess-caw-live-policy-tuple");
    const spendId = await registerSpend(app, sessionId);
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "tuple-policy-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "tuple policy", spec: { policies: [] } },
    });
    const sync = await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "tuple-policy-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const activate = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "tuple-policy-activate",
        payload: {
          spendId,
          operationKind: "activate_tool",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: INDEXER_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawActivateToolCalldataForTest(spendId),
          requestId: "tuple-policy-activate",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();

    expect(sync.status).toBe(202);
    expect(sync.json.data.policyRules).toHaveLength(2);
    expect(activate.status).toBe(422);
    expect(activate.json.error.message).toContain("chain/target/selector tuple");
    expect(
      replayJson.data.events.some(
        (event: { kind: string; payload: { requestId?: string } }) =>
          event.kind === "caw.live.contract_call.submitted" && event.payload.requestId === "tuple-policy-activate",
      ),
    ).toBe(false);
  });

  it("records a live CAW deny_probe for a wrong-target policy denial", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient() });
    const sessionId = await createSession(app, "sess-caw-live-deny-probe");
    const spendId = await registerSpend(app, sessionId);
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "deny-probe-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "deny probe", spec: { policies: [] } },
    });
    await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "deny-probe-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const denyProbe = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "deny-probe-call",
        payload: {
          spendId,
          operationKind: "deny_probe",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: TEST_MARKET_ADDRESS,
          calldata: `${PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR}${"00".repeat(32)}`,
          requestId: "deny-probe-wrong-target",
          description: "wrong-target deny probe",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const audit = await post(app, "/api/v1/caw/live/audit/sync", {
      sessionId,
      idempotencyKey: "deny-probe-audit",
      payload: { walletId: "wallet-live-1", action: "wrong_target.deny_probe", result: "denied", limit: 20 },
    });
    const readiness = await app.request(`/api/v1/evidence/claim-readiness?sessionId=${sessionId}`);
    const readinessJson = await readiness.json();
    const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
    const replayJson = await replay.json();
    const usageEvent = replayJson.data.events.find(
      (event: { kind: string; payload: Record<string, unknown> }) =>
        event.kind === "caw.live.audit.usage.verified" && event.payload.operationKind === "deny_probe",
    );

    expect(denyProbe.status).toBe(202);
    expect(denyProbe.json.data).toEqual(expect.objectContaining({ operationKind: "deny_probe", status: "live_denied", txHash: null }));
    expect(audit.status).toBe(202);
    expect(usageEvent).toEqual(
      expect.objectContaining({
        authority: "proof",
        payload: expect.objectContaining({
          result: "denied",
          action: "wrong_target.deny_probe",
          txHash: null,
          proofAuthority: true,
          winnerClaimAllowed: false,
        }),
      }),
    );
    expect(readiness.status).toBe(200);
    expect(readinessJson.data.gates.find((gate: { gateId: string }) => gate.gateId === "caw_wrong_target_deny")).toEqual(
      expect.objectContaining({ status: "pass", evidenceEventId: usageEvent.eventId }),
    );
  });

  it("blocks CAW contract calls after Pact policy request limit is exhausted", async () => {
    const { app } = makeApp(":memory:", { cawLive: createFakeCawLiveClient({ policyRequestLimit: "1" }) });
    const sessionId = await createSession(app, "sess-caw-live-policy-limit");
    const spendId = await registerSpend(app, sessionId);
    await post(app, "/api/v1/caw/live/pacts/submit", {
      sessionId,
      idempotencyKey: "policy-limit-pact-submit",
      payload: { walletId: "wallet-live-1", intent: "policy limit", spec: { policies: [] } },
    });
    await post(app, "/api/v1/caw/live/pacts/sync", {
      sessionId,
      idempotencyKey: "policy-limit-pact-sync",
      payload: { pactId: "pact-live-1" },
    });
    const approve = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "policy-limit-approve",
        payload: {
          spendId,
          operationKind: "approve",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: TEST_PAYMENT_TOKEN_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawApproveCalldataForTest(INDEXER_ADDRESS, "1000"),
          requestId: "policy-limit-approve",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );
    const activate = await post(
      app,
      "/api/v1/caw/live/contracts/call",
      {
        sessionId,
        idempotencyKey: "policy-limit-activate",
        payload: {
          spendId,
          operationKind: "activate_tool",
          pactId: "pact-live-1",
          walletId: "wallet-live-1",
          chainId: "84532",
          contractAddress: INDEXER_ADDRESS,
          procurementGateAddress: INDEXER_ADDRESS,
          calldata: cawActivateToolCalldataForTest(spendId),
          requestId: "policy-limit-activate",
        },
      },
      { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
    );

    expect(approve.status).toBe(202);
    expect(activate.status).toBe(422);
    expect(activate.json.error.message).toContain("request limit is exhausted");
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
  spendOverrides: Partial<{
    paymentToken: string;
    artifactHash: string;
    market: string;
    maxPriceAtomic: string;
    nonce: string;
  }> = {},
): Promise<string> {
  await registerSource(app, sessionId, capabilityVector);
  const sourceHashes = [hex32("source")];
  const spendId = await computeSpendIdForTest(app, sessionId, sourceHashes, capabilityVector, spendOverrides);
  const res = await post(app, "/api/v1/spends/register-batch", {
    sessionId,
    idempotencyKey: "spend-register",
    payload: {
      spends: [
        spendRegistrationForTest(spendId, { sourceHashes, ...spendOverrides }),
      ],
    },
  });
  expect(res.status).toBe(201);
  return spendId;
}

async function registerSpendWithKeyForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  key: string,
  spendOverrides: Partial<{
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    maxPriceAtomic: string;
    nonce: string;
  }> = {},
  capabilityVector: Record<string, unknown> = defaultSourceCapabilityForTest(),
): Promise<string> {
  await registerSource(app, sessionId, capabilityVector);
  const sourceHashes = [hex32("source")];
  const spendId = await computeSpendIdForTest(app, sessionId, sourceHashes, capabilityVector, spendOverrides);
  const res = await post(app, "/api/v1/spends/register-batch", {
    sessionId,
    idempotencyKey: `${key}-spend-register`,
    payload: {
      spends: [
        spendRegistrationForTest(spendId, { sourceHashes, ...spendOverrides }),
      ],
    },
  });
  expect(res.status).toBe(201);
  return spendId;
}

function artifactCidForTest(artifactHash: string): string {
  return `sha256:${artifactHash.toLowerCase()}`;
}

async function verifyArtifactPreflightForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  preflightId: string,
  artifactHash: string,
  artifactCid: string,
  seed: string,
) {
  const verify = await post(app, "/api/v1/artifacts/preflight/verify", {
    sessionId,
    idempotencyKey: `${seed}-preflight-verify`,
    payload: {
      preflightId,
      artifactPayloadHash: artifactHash,
      artifactCid,
      manifestFetchHash: hex32(`${seed}-manifest-fetch`),
      endpointResponseHash: hex32(`${seed}-endpoint-response`),
      leaseDryRunHash: hex32(`${seed}-lease-dry-run`),
    },
  });
  expect(verify.status).toBe(202);
  expect(verify.json.data.status).toBe("passed_live_delivery");
  return verify;
}

function artifactPayloadForTest(seed: string): Record<string, unknown> {
  return seed === "artifact" ? { ...TEST_ARTIFACT_PAYLOAD } : { artifactType: "source-bound-code-scan-mcp-lease", seed, content: `scan:${seed}` };
}

async function quoteArtifactForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  spendId: string,
  seed: string,
  options: { artifactPayload?: Record<string, unknown>; priceAtomic?: string; validUntilBlock?: string; settlementMode?: "chain_settleable_after_preflight" } = {},
): Promise<{
  artifactPayload: Record<string, unknown>;
  artifactHash: `0x${string}`;
  artifactCid: string;
  preflightId: string;
  quoteId: string;
}> {
  const artifactPayload = options.artifactPayload ?? artifactPayloadForTest("artifact");
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
  await verifyArtifactPreflightForTest(app, sessionId, preflight.json.data.preflightId, artifactHash, artifactCid, seed);
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
        ...(options.settlementMode ? { settlementMode: options.settlementMode } : {}),
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
const TEST_PAYER_ADDRESS = "0x1000000000000000000000000000000000000001";
const TEST_PAYMENT_TOKEN_ADDRESS = "0x4000000000000000000000000000000000000004";
const TEST_MARKET_ADDRESS = "0x5000000000000000000000000000000000000005";
const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const TEST_PACT_ID = hex32("pact-c");
const TEST_TOOL_ID = hex32("code-scan");
const TEST_ARTIFACT_PAYLOAD = Object.freeze({ artifactType: "source-bound-code-scan-mcp-lease", seed: "artifact", content: "scan:artifact" });
const TEST_ARTIFACT_HASH = hashForTestJson(TEST_ARTIFACT_PAYLOAD);

function testDeploymentRegistry(): NonNullable<ServiceCtx["deploymentRegistry"]> {
  return {
    mode: "live",
    chainId: "84532",
    officialUsdcProbe: {
      status: "failed",
      reason: "test fixture uses a public mock token path",
    },
    entries: [
      {
        contractName: "PaymentToken",
        chainId: "84532",
        address: TEST_PAYMENT_TOKEN_ADDRESS,
        deploymentTxHash: hex32("test-payment-token-deploy"),
        explorerUrl: "https://sepolia.basescan.org/tx/0x0000000000000000000000000000000000000000000000000000000000000000",
        codeHash: hex32("test-payment-token-code"),
        tokenMode: "mock-test-token",
        symbol: "MOCK",
        decimals: 18,
      },
    ],
  };
}

function cawApproveCalldataForTest(spender: string, amountAtomic: string): `0x${string}` {
  return encodeFunctionData({
    abi: ERC20_APPROVE_ABI,
    functionName: "approve",
    args: [spender as `0x${string}`, BigInt(amountAtomic)],
  });
}

function cawActivateToolCalldataForTest(spendId: string): `0x${string}` {
  return encodeFunctionData({
    abi: PROCUREMENT_GATE_ACTIVATE_TOOL_ABI,
    functionName: "activateTool",
    args: [spendId as `0x${string}`, "0x"],
  });
}

function spendRegistrationForTest(
  spendId: string,
  overrides: Partial<{
    pactId: string;
    toolId: string;
    payer: string;
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    sourceHashes: string[];
    maxPriceAtomic: string;
    nonce: string;
  }> = {},
): Record<string, unknown> {
  return {
    spendId,
    pactId: TEST_PACT_ID,
    toolId: TEST_TOOL_ID,
    payer: TEST_PAYER_ADDRESS,
    agentWallet: TEST_PAYER_ADDRESS,
    paymentToken: TEST_PAYMENT_TOKEN_ADDRESS,
    artifactHash: TEST_ARTIFACT_HASH,
    market: TEST_MARKET_ADDRESS,
    sourceHashes: [hex32("source")],
    maxPriceAtomic: "1000",
    nonce: "nonce-1",
    ...overrides,
  };
}

function createFakeIndexerChainClient(config: {
  chainId?: string;
  currentBlockNumber?: number;
  logs?: Array<Record<string, unknown>>;
  mode?: "fixture" | "live";
  ready?: boolean;
  reason?: string;
  getLogsError?: Error;
  readContractError?: Error;
  contractSpendStates?: Record<string, number>;
  contractRegisteredSpendOverrides?: Partial<{
    pactId: string;
    toolId: string;
    sourceSetHash: string;
    agentWallet: string;
    paymentToken: string;
    price: string;
    artifactHash: string;
    market: string;
  }>;
  sourceStates?: Record<string, number>;
  tokenBalances?: Record<string, string>;
  ignoreAddressFilter?: boolean;
}): ChainClient {
  return {
    async status() {
      return {
        name: "chain",
        mode: config.mode ?? "live",
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
      const topics = Array.isArray(query.topics) ? query.topics.map((topic) => (typeof topic === "string" ? topic.toLowerCase() : null)) : [];
      return (config.logs ?? []).filter((log) => {
        const blockNumber = Number(log.blockNumber);
        const logAddress = typeof log.address === "string" ? log.address.toLowerCase() : null;
        const logTxHash = typeof log.transactionHash === "string" ? log.transactionHash.toLowerCase() : null;
        const logIndexValue = log.logIndex === undefined ? null : Number(log.logIndex);
        const logEvent = typeof log.eventName === "string" ? log.eventName : typeof log.event === "string" ? log.event : null;
        const logTopics = Array.isArray(log.topics) ? log.topics.map((topic) => (typeof topic === "string" ? topic.toLowerCase() : null)) : [];
        const args = log.args && typeof log.args === "object" && !Array.isArray(log.args) ? (log.args as Record<string, unknown>) : {};
        const logSpendId = typeof args.spendId === "string" ? args.spendId.toLowerCase() : typeof log.spendId === "string" ? log.spendId.toLowerCase() : null;
        return (
          blockNumber >= fromBlock &&
          blockNumber <= toBlock &&
          (!address || logAddress === address) &&
          (!txHash || logTxHash === txHash) &&
          (logIndex === null || logIndexValue === logIndex) &&
          (!event || logEvent === event) &&
          (!spendId || logSpendId === spendId) &&
          topics.every((topic, index) => topic === null || logTopics[index] === topic)
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
        const logContractPactId = typeof logArgs.pactId === "string" ? logArgs.pactId : undefined;
        const logContractToolId = typeof logArgs.toolId === "string" ? logArgs.toolId : undefined;
        const logContractSourceSetHash = typeof logArgs.sourceSetHash === "string" ? logArgs.sourceSetHash : undefined;
        const logContractAgentWallet = typeof logArgs.agentWallet === "string" ? logArgs.agentWallet : undefined;
        const logContractPaymentToken = typeof logArgs.paymentToken === "string" ? logArgs.paymentToken : undefined;
        const logContractPrice = typeof logArgs.price === "string" ? logArgs.price : undefined;
        const logContractArtifactHash = typeof logArgs.artifactHash === "string" ? logArgs.artifactHash : undefined;
        const logContractMarket = typeof logArgs.market === "string" ? logArgs.market : undefined;
        return [
          sessionId,
          config.contractRegisteredSpendOverrides?.pactId ?? logContractPactId ?? TEST_PACT_ID,
          config.contractRegisteredSpendOverrides?.toolId ?? logContractToolId ?? TEST_TOOL_ID,
          config.contractRegisteredSpendOverrides?.sourceSetHash ?? logContractSourceSetHash ?? procurementGateSourceSetHashForTest([hex32("source")]),
          config.contractRegisteredSpendOverrides?.agentWallet ?? logContractAgentWallet ?? TEST_PAYER_ADDRESS,
          config.contractRegisteredSpendOverrides?.paymentToken ?? logContractPaymentToken ?? TEST_PAYMENT_TOKEN_ADDRESS,
          config.contractRegisteredSpendOverrides?.price ?? logContractPrice ?? "1000",
          config.contractRegisteredSpendOverrides?.artifactHash ?? logContractArtifactHash ?? TEST_ARTIFACT_HASH,
          config.contractRegisteredSpendOverrides?.market ?? logContractMarket ?? TEST_MARKET_ADDRESS,
          state,
        ];
      }
      if (input.functionName === "sourceState") {
        const sourceHash = String(args[0] ?? "").toLowerCase();
        return config.sourceStates?.[sourceHash] ?? 2;
      }
      if (input.functionName === "balanceOf") {
        const token = input.address.toLowerCase();
        const account = String(args[0] ?? "").toLowerCase();
        const blockNumber = input.blockNumber ?? 0;
        const balance = config.tokenBalances?.[`${token}:${account}:${blockNumber}`];
        if (balance === undefined) {
          throw new Error(`missing fake balanceOf for ${token}:${account}:${blockNumber}`);
        }
        return balance;
      }
      if (input.functionName === "allowance") {
        const token = input.address.toLowerCase();
        const owner = String(args[0] ?? "").toLowerCase();
        const spender = String(args[1] ?? "").toLowerCase();
        const blockNumber = input.blockNumber ?? 0;
        const allowance = config.tokenBalances?.[allowanceKeyForTest(token, owner, spender, blockNumber)];
        if (allowance === undefined) {
          throw new Error(`missing fake allowance for ${token}:${owner}:${spender}:${blockNumber}`);
        }
        return allowance;
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

function erc20TransferLogForTest(
  seed: string,
  input: {
    txHash: string;
    blockNumber: number;
    logIndex?: number;
    token?: string;
    from?: string;
    to?: string;
    value?: string;
  },
): Record<string, unknown> {
  const value = input.value ?? "1000";
  return {
    transactionHash: input.txHash,
    logIndex: input.logIndex ?? 20,
    chainId: "84532",
    blockNumber: input.blockNumber,
    address: input.token ?? TEST_PAYMENT_TOKEN_ADDRESS,
    topics: [
      ERC20_TRANSFER_TOPIC,
      evmAddressTopicForTest(input.from ?? TEST_PAYER_ADDRESS),
      evmAddressTopicForTest(input.to ?? TEST_MARKET_ADDRESS),
    ],
    data: uint256DataForTest(value),
    rawLogHash: hex32(`erc20-transfer:${seed}:raw`),
  };
}

function erc20ApprovalLogForTest(
  seed: string,
  input: {
    txHash: string;
    blockNumber: number;
    logIndex?: number;
    token?: string;
    owner?: string;
    spender?: string;
    value?: string;
  },
): Record<string, unknown> {
  const value = input.value ?? "1000";
  return {
    transactionHash: input.txHash,
    logIndex: input.logIndex ?? 10,
    chainId: "84532",
    blockNumber: input.blockNumber,
    address: input.token ?? TEST_PAYMENT_TOKEN_ADDRESS,
    topics: [
      ERC20_APPROVAL_TOPIC,
      evmAddressTopicForTest(input.owner ?? TEST_PAYER_ADDRESS),
      evmAddressTopicForTest(input.spender ?? INDEXER_ADDRESS),
    ],
    data: uint256DataForTest(value),
    rawLogHash: hex32(`erc20-approval:${seed}:raw`),
  };
}

function evmAddressTopicForTest(address: string): `0x${string}` {
  return `0x${address.toLowerCase().replace(/^0x/, "").padStart(64, "0")}`;
}

function uint256DataForTest(value: string): `0x${string}` {
  return `0x${BigInt(value).toString(16).padStart(64, "0")}`;
}

function balanceKeyForTest(token: string, account: string, blockNumber: number): string {
  return `${token.toLowerCase()}:${account.toLowerCase()}:${blockNumber}`;
}

function allowanceKeyForTest(token: string, owner: string, spender: string, blockNumber: number): string {
  return `allowance:${token.toLowerCase()}:${owner.toLowerCase()}:${spender.toLowerCase()}:${blockNumber}`;
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

function createFakeCawReceiptSource(input: { receipts: Array<Record<string, unknown>>; source?: string; mode?: "fixture" | "live" }): CawReceiptSource {
  return {
    async status() {
      return {
        name: "caw",
        mode: input.mode ?? "fixture",
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
  contractOverrides: Partial<{
    pactId: string;
    toolId: string;
    sourceSetHash: string;
    agentWallet: string;
    paymentToken: string;
    price: string;
    artifactHash: string;
    market: string;
  }> = {},
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
      args: { sessionId, spendId, ...contractOverrides },
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
  expect(worker.status, JSON.stringify(worker)).toBe("succeeded");
  expect(proofEvent).toEqual(expect.objectContaining({ authority: "proof" }));
  return {
    ...(proofEvent.payload as Record<string, unknown>),
    finalizedEventId: proofEvent.eventId,
    observedEventId: observed.json.data.observedEventId,
  };
}

async function finalizeSpendTripForTest(
  app: ReturnType<typeof createApp>,
  ctx: ServiceCtx,
  logs: Array<Record<string, unknown>>,
  sessionId: string,
  spendId: string,
  key: string,
  blockNumber: number,
): Promise<Record<string, unknown>> {
  const observedBody = gateEventEnvelope(sessionId, spendId, `${key}-observed`, {
    event: "SpendTripped",
    txHash: hex32(`${key}-tx`),
    rawLogHash: hex32(`${key}-log`),
    blockNumber,
    currentBlockNumber: blockNumber,
  });
  const observed = await postSignedGateEvent(app, observedBody);
  const contractArgs = contractRegisteredSpendArgsForTest(ctx, sessionId, spendId);
  logs.push(
    indexerLog(key, blockNumber, {
      eventName: "SpendTripped",
      event: "SpendTripped",
      sessionId,
      spendId,
      args: { sessionId, spendId, ...contractArgs },
      transactionHash: hex32(`${key}-tx`),
      rawLogHash: hex32(`${key}-log`),
    }),
  );
  const worker = await runIndexerWorkerOnce(ctx, {
    cursors: [{ cursorId: `gate:${key}`, chainId: "84532", startBlock: blockNumber, finalityDepth: 2, maxWindowBlocks: 1, address: INDEXER_ADDRESS }],
  });
  const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
  const replayJson = await replay.json();
  const proofEvent = replayJson.data.events.find((event: { kind: string; payload: Record<string, unknown> }) => {
    return event.kind === "gate.spend_tripped" && event.payload.spendId === spendId;
  });

  expect(observed.status).toBe(202);
  expect(worker.status, JSON.stringify(worker)).toBe("succeeded");
  expect(proofEvent).toEqual(expect.objectContaining({ authority: "proof" }));
  return {
    ...(proofEvent.payload as Record<string, unknown>),
    finalizedEventId: proofEvent.eventId,
    observedEventId: observed.json.data.observedEventId,
  };
}

async function catchUpIndexerCursorForTest(ctx: ServiceCtx, cursorId: string, startBlock: number): Promise<void> {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const worker = await runIndexerWorkerOnce(ctx, {
      cursors: [{ cursorId, chainId: "84532", startBlock, finalityDepth: 2, maxWindowBlocks: 64, address: INDEXER_ADDRESS }],
    });
    if (worker.status === "idle") {
      return;
    }
    expect(worker.status, JSON.stringify(worker)).toBe("succeeded");
  }
}

function contractRegisteredSpendArgsForTest(ctx: ServiceCtx, sessionId: string, spendId: string): Record<string, unknown> {
  const row = ctx.db.sqlite
    .prepare(
      `SELECT pact_id, tool_id, source_set_hash, agent_wallet, payment_token, max_price_atomic, artifact_hash, market
       FROM spends
       WHERE session_id = ? AND spend_id = ?`,
    )
    .get(sessionId, spendId) as Record<string, unknown> | undefined;
  expect(row).toBeTruthy();
  return {
    pactId: row?.pact_id,
    toolId: row?.tool_id,
    sourceSetHash: row?.source_set_hash,
    agentWallet: row?.agent_wallet,
    paymentToken: row?.payment_token,
    price: row?.max_price_atomic,
    artifactHash: row?.artifact_hash,
    market: row?.market,
  };
}

async function finalizeSourceChallengeForTest(
  app: ReturnType<typeof createApp>,
  ctx: ServiceCtx,
  logs: Array<Record<string, unknown>>,
  sessionId: string,
  key: string,
  blockNumber: number,
): Promise<Record<string, unknown>> {
  const reasonHash = hex32(`${key}-reason`);
  const challenge = await post(app, "/api/v1/sources/challenge", {
    sessionId,
    idempotencyKey: `${key}-challenge`,
    payload: {
      sourceHash: hex32("source"),
      reasonHash,
      evidenceRef: `https://example.com/${key}.json`,
    },
  });
  logs.push(
    indexerLog(key, blockNumber, {
      eventName: "SourceChallenged",
      event: "SourceChallenged",
      sessionId,
      sourceHash: hex32("source"),
      reasonHash,
      args: { sessionId, sourceHash: hex32("source"), reasonHash },
      transactionHash: hex32(`${key}-tx`),
      rawLogHash: hex32(`${key}-log`),
    }),
  );
  const worker = await runIndexerWorkerOnce(ctx, {
    cursors: [{ cursorId: `source:${key}`, chainId: "84532", startBlock: blockNumber, finalityDepth: 2, maxWindowBlocks: 1, address: INDEXER_ADDRESS }],
  });
  const replay = await app.request(`/api/v1/evidence/replay-bundle?sessionId=${sessionId}`);
  const replayJson = await replay.json();
  const proofEvent = replayJson.data.events.find((event: { kind: string }) => event.kind === "source.challenge.confirmed");

  expect(challenge.status).toBe(202);
  expect(worker.status).toBe("succeeded");
  expect(proofEvent).toEqual(expect.objectContaining({ authority: "proof" }));
  return proofEvent.payload as Record<string, unknown>;
}

async function verifyTokenBalanceDeltaForTest(
  app: ReturnType<typeof createApp>,
  logs: Array<Record<string, unknown>>,
  tokenBalances: Record<string, string>,
  sessionId: string,
  spendId: string,
  key: string,
  finalized: Record<string, unknown>,
  overrides: Partial<{
    paymentToken: string;
    agentWallet: string;
    market: string;
    amountAtomic: string;
    agentWalletBefore: string;
    marketBefore: string;
  }> = {},
): Promise<Record<string, unknown>> {
  const paymentToken = overrides.paymentToken ?? TEST_PAYMENT_TOKEN_ADDRESS;
  const agentWallet = overrides.agentWallet ?? TEST_PAYER_ADDRESS;
  const market = overrides.market ?? TEST_MARKET_ADDRESS;
  const amountAtomic = overrides.amountAtomic ?? "1000";
  const blockNumber = Number(finalized.blockNumber);
  const preBlockNumber = blockNumber - 1;
  await prepareCawProofsForTokenDeltaForTest(app, logs, tokenBalances, sessionId, spendId, key, finalized, {
    paymentToken,
    agentWallet,
    amountAtomic,
    blockNumber: Math.max(1, preBlockNumber),
  });
  const agentWalletBefore = BigInt(overrides.agentWalletBefore ?? "5000");
  const marketBefore = BigInt(overrides.marketBefore ?? "10");
  tokenBalances[balanceKeyForTest(paymentToken, agentWallet, preBlockNumber)] = agentWalletBefore.toString();
  tokenBalances[balanceKeyForTest(paymentToken, agentWallet, blockNumber)] = (agentWalletBefore - BigInt(amountAtomic)).toString();
  tokenBalances[balanceKeyForTest(paymentToken, market, preBlockNumber)] = marketBefore.toString();
  tokenBalances[balanceKeyForTest(paymentToken, market, blockNumber)] = (marketBefore + BigInt(amountAtomic)).toString();
  logs.push(
    erc20TransferLogForTest(key, {
      txHash: String(finalized.txHash),
      blockNumber,
      token: paymentToken,
      from: agentWallet,
      to: market,
      value: amountAtomic,
    }),
  );
  const verified = await post(app, "/api/v1/token/balance-deltas/verify", {
    sessionId,
    idempotencyKey: `${key}-token-delta`,
    payload: { spendId, settlementEventId: finalized.finalizedEventId },
  });
  expect(verified.status).toBe(202);
  return verified.json.data as Record<string, unknown>;
}

async function prepareCawProofsForTokenDeltaForTest(
  app: ReturnType<typeof createApp>,
  logs: Array<Record<string, unknown>>,
  tokenBalances: Record<string, string>,
  sessionId: string,
  spendId: string,
  key: string,
  finalized: Record<string, unknown>,
  overrides: Partial<{
    paymentToken: string;
    agentWallet: string;
    procurementGateAddress: string;
    amountAtomic: string;
    blockNumber: number;
  }> = {},
): Promise<{ allowance: Record<string, unknown>; activation: Record<string, unknown> }> {
  const allowance = await verifyCawAllowanceForTest(app, logs, tokenBalances, sessionId, spendId, key, overrides);
  const activation = await verifyCawActivationForTest(app, sessionId, spendId, key, finalized, {
    procurementGateAddress: overrides.procurementGateAddress,
  });
  return { allowance, activation };
}

async function verifyCawAllowanceForTest(
  app: ReturnType<typeof createApp>,
  logs: Array<Record<string, unknown>>,
  tokenBalances: Record<string, string>,
  sessionId: string,
  spendId: string,
  key: string,
	  overrides: Partial<{
	    paymentToken: string;
	    agentWallet: string;
	    procurementGateAddress: string;
	    amountAtomic: string;
	    blockNumber: number;
	  }> = {},
	  expectedStatus = 202,
	): Promise<Record<string, unknown>> {
  const paymentToken = overrides.paymentToken ?? TEST_PAYMENT_TOKEN_ADDRESS;
  const agentWallet = overrides.agentWallet ?? TEST_PAYER_ADDRESS;
  const procurementGateAddress = overrides.procurementGateAddress ?? INDEXER_ADDRESS;
  const amountAtomic = overrides.amountAtomic ?? "1000";
  const blockNumber = overrides.blockNumber ?? 99;
  const preBlockNumber = blockNumber - 1;
  const walletId = "wallet-live-1";
  const pactId = "pact-live-1";
  const pactKey = "pact-scoped-secret";
  const pactSubmit = await post(app, "/api/v1/caw/live/pacts/submit", {
    sessionId,
    idempotencyKey: `${key}-caw-pact-submit`,
    payload: {
      walletId,
      intent: `PactFuse test allowance ${key}`,
      spec: { policies: [{ type: "contract_call", effect: "allow" }] },
    },
  });
  expect(pactSubmit.status).toBe(202);
  const pactSync = await post(app, "/api/v1/caw/live/pacts/sync", {
    sessionId,
    idempotencyKey: `${key}-caw-pact-sync`,
    payload: { pactId },
  });
  expect(pactSync.status).toBe(202);
  const approve = await post(
    app,
    "/api/v1/caw/live/contracts/call",
    {
      sessionId,
      idempotencyKey: `${key}-caw-approve`,
      payload: {
        spendId,
        operationKind: "approve",
        pactId,
        walletId,
        chainId: "84532",
        contractAddress: paymentToken,
        procurementGateAddress,
        calldata: cawApproveCalldataForTest(procurementGateAddress, amountAtomic),
        requestId: `${key}-approve`,
        description: `PactFuse test approve ${key}`,
      },
    },
    { "x-pactfuse-caw-pact-api-key": pactKey },
  );
  expect(approve.status).toBe(202);
  const approveAudit = await post(app, "/api/v1/caw/live/audit/sync", {
    sessionId,
    idempotencyKey: `${key}-caw-audit-after-approve`,
    payload: { walletId, result: "allowed", limit: 20 },
  });
  expect(approveAudit.status).toBe(202);
  expect(Number(approveAudit.json.data.usageCount)).toBeGreaterThan(0);
  const approveTxHash = String(approve.json.data.txHash);
  logs.push(
    erc20ApprovalLogForTest(key, {
      txHash: approveTxHash,
      blockNumber,
      token: paymentToken,
      owner: agentWallet,
      spender: procurementGateAddress,
      value: amountAtomic,
    }),
  );
  tokenBalances[allowanceKeyForTest(paymentToken, agentWallet, procurementGateAddress, preBlockNumber)] = "0";
  tokenBalances[allowanceKeyForTest(paymentToken, agentWallet, procurementGateAddress, blockNumber)] = amountAtomic;
  const allowance = await post(app, "/api/v1/caw/live/allowances/verify", {
    sessionId,
    idempotencyKey: `${key}-caw-allowance`,
    payload: { spendId, approveInteractionId: approve.json.data.interactionId },
  });
  expect(allowance.status, JSON.stringify(allowance.json)).toBe(expectedStatus);
  return (expectedStatus === 202 ? allowance.json.data : allowance.json) as Record<string, unknown>;
}

async function verifyCawActivationForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  spendId: string,
  key: string,
  finalized: Record<string, unknown>,
  overrides: Partial<{ procurementGateAddress: string }> = {},
): Promise<Record<string, unknown>> {
  const walletId = "wallet-live-1";
  const pactId = "pact-live-1";
  const procurementGateAddress = overrides.procurementGateAddress ?? INDEXER_ADDRESS;
  const activate = await post(
    app,
    "/api/v1/caw/live/contracts/call",
    {
      sessionId,
      idempotencyKey: `${key}-caw-activate`,
      payload: {
        spendId,
        operationKind: "activate_tool",
        pactId,
        walletId,
        chainId: "84532",
        contractAddress: procurementGateAddress,
        procurementGateAddress,
        calldata: cawActivateToolCalldataForTest(spendId),
        requestId: String(finalized.txHash),
        description: `PactFuse test activate ${key}`,
      },
    },
    { "x-pactfuse-caw-pact-api-key": "pact-scoped-secret" },
  );
  expect(activate.status).toBe(202);
  const activateAudit = await post(app, "/api/v1/caw/live/audit/sync", {
    sessionId,
    idempotencyKey: `${key}-caw-audit-after-activate`,
    payload: { walletId, result: "allowed", limit: 20 },
  });
  expect(activateAudit.status).toBe(202);
  expect(Number(activateAudit.json.data.usageCount)).toBeGreaterThan(0);
  return activate.json.data as Record<string, unknown>;
}

async function computeSpendIdForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  sourceHashes: string[],
  capabilityVector: Record<string, unknown> = defaultSourceCapabilityForTest(),
  spendOverrides: Partial<{
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    maxPriceAtomic: string;
  }> = {},
): Promise<`0x${string}`> {
  const session = await app.request(`/api/v1/sessions/${sessionId}`);
  const sessionJson = await session.json();
  expect(session.status).toBe(200);
  const normalizedSourceHashes = [...sourceHashes].map((sourceHash) => sourceHash.toLowerCase()).sort();
  const runConfigHash = sessionJson.data.runConfigHash as string;
  const sourceSetHash = procurementGateSourceSetHashForTest(normalizedSourceHashes);
  const sourceCapabilitySnapshotHash = hashForTestJson([
    {
      sourceHash: hex32("source"),
      manifestHash: hex32("manifest"),
      capabilityVector,
    },
  ]);
  const sessionCommitment = keccakJsonForTest({ sessionId: sessionId.toLowerCase(), runConfigHash });
  void runConfigHash;
  void sessionCommitment;
  void sourceCapabilitySnapshotHash;
  return procurementGateSpendIdForTest({
    sessionId: sessionId.toLowerCase(),
    pactId: TEST_PACT_ID,
    toolId: TEST_TOOL_ID,
    sourceSetHash,
    agentWallet: spendOverrides.agentWallet ?? TEST_PAYER_ADDRESS,
    paymentToken: spendOverrides.paymentToken ?? TEST_PAYMENT_TOKEN_ADDRESS,
    priceAtomic: spendOverrides.maxPriceAtomic ?? "1000",
    artifactHash: spendOverrides.artifactHash ?? TEST_ARTIFACT_HASH,
    market: spendOverrides.market ?? TEST_MARKET_ADDRESS,
  });
}

function procurementGateSourceSetHashForTest(sourceHashes: string[]): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32[]" }],
      [sourceHashes.map((sourceHash) => sourceHash.toLowerCase() as `0x${string}`)],
    ),
  );
}

function procurementGateSpendIdForTest(input: {
  sessionId: string;
  pactId: string;
  toolId: string;
  sourceSetHash: string;
  agentWallet: string;
  paymentToken: string;
  priceAtomic: string;
  artifactHash: string;
  market: string;
}): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "address" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "address" },
      ],
      [
        input.sessionId as `0x${string}`,
        input.pactId as `0x${string}`,
        input.toolId as `0x${string}`,
        input.sourceSetHash as `0x${string}`,
        input.agentWallet as `0x${string}`,
        input.paymentToken as `0x${string}`,
        BigInt(input.priceAtomic),
        input.artifactHash as `0x${string}`,
        input.market as `0x${string}`,
      ],
    ),
  );
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
              paymentAuth: "0x",
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

async function readNodeRequestJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text.trim().length === 0) {
    return null;
  }
  return JSON.parse(text) as unknown;
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

async function buildAndIngestCawReceiptForTest(
  app: ReturnType<typeof createApp>,
  sessionId: string,
  spendId: string,
  key: string,
  payload: {
    operationKind: "deny_probe" | "approve" | "activate_tool";
    target: string;
    selector: string;
  },
): Promise<Record<string, unknown>> {
  const operation = await post(app, "/api/v1/caw/operations/build", {
    sessionId,
    idempotencyKey: `${key}-build`,
    payload: {
      spendId,
      operationKind: payload.operationKind,
      target: payload.target,
      selector: payload.selector,
    },
  });
  expect(operation.status).toBe(201);
  const ingest = await post(app, "/api/v1/caw/receipts/ingest", {
    sessionId,
    idempotencyKey: `${key}-ingest`,
    payload: {
      sourceLabel: "caw-api",
      operationId: operation.json.data.operationId,
      manual: false,
    },
  });
  expect(ingest.status).toBe(202);
  expect(ingest.json.data.canonicalReceiptCount).toBe(1);
  return ingest.json.data as Record<string, unknown>;
}

function createFakeCawLiveClient(
  options: Partial<{
    includePolicyBinding: boolean;
    auditPolicyDigest: `0x${string}`;
    policyRequestLimit: string;
    policy: Record<string, unknown>;
  }> = {},
): CawLiveClient {
  const contractCalls: Array<{ input: Parameters<CawLiveClient["contractCall"]>[0]; txHash: `0x${string}` | null }> = [];
  const includePolicyBinding = options.includePolicyBinding ?? true;
  const pactPolicyDigest = hex32("pact-live-policy");
  const auditPolicyDigest = options.auditPolicyDigest ?? pactPolicyDigest;
  const policyRequestLimit = options.policyRequestLimit ?? "2";
  return {
    async status() {
      return {
        name: "caw_live",
        mode: "live",
        ready: true,
        reason: "fake CAW live API",
        endpoint: "https://api.agenticwallet.cobo.test",
      };
    },
    async getWallet(walletId) {
      return { success: true, result: { id: walletId, status: "active", wallet_address: TEST_PAYER_ADDRESS } };
    },
    async submitPact(input) {
      return {
        success: true,
        result: {
          pact_id: "pact-live-1",
          wallet_id: input.walletId,
          status: "PENDING_APPROVAL",
        },
      };
    },
    async getPact(pactId) {
      const policyFields = includePolicyBinding
        ? {
            policy_digest: pactPolicyDigest,
            policy: options.policy ?? {
              chain_ids: ["84532"],
              target_addresses: [TEST_PAYMENT_TOKEN_ADDRESS, INDEXER_ADDRESS],
              selectors: [ERC20_APPROVE_SELECTOR, PROCUREMENT_GATE_ACTIVATE_TOOL_SELECTOR],
              request_limit: policyRequestLimit,
              expiry: "2026-06-12T00:00:00.000Z",
            },
          }
        : {};
      return {
        success: true,
        result: {
          pact_id: pactId,
          wallet_id: "wallet-live-1",
          status: "ACTIVE",
          ...policyFields,
          api_key: "pact-scoped-secret",
        },
      };
    },
    async transferToken(input) {
      return {
        success: true,
        result: {
          id: "tx-live-1",
          wallet_id: input.walletId,
          request_id: input.requestId,
          status: "submitted",
          transaction_hash: null,
        },
      };
    },
    async contractCall(input) {
      const txHash = /^0x[0-9a-fA-F]{64}$/.test(input.requestId ?? "")
        ? (input.requestId as `0x${string}`)
        : hex32(`caw-live-contract:${input.requestId ?? "default"}`);
      const denied = input.operationKind === "deny_probe";
      contractCalls.push({ input, txHash: denied ? null : txHash });
      return {
        success: true,
        result: {
          id: "contract-live-1",
          wallet_id: input.walletId,
          request_id: input.requestId,
          status: denied ? "denied" : "submitted",
          reason: denied ? "policy_denied" : undefined,
          transaction_hash: denied ? null : txHash,
        },
      };
    },
    async listAuditLogs(input) {
      const items = contractCalls
        .filter((call) => !input.walletId || call.input.walletId === input.walletId)
        .map((call) => ({
          id: `audit-${call.input.requestId ?? call.txHash}`,
          wallet_id: call.input.walletId,
          pact_id: call.input.pactId,
          action: input.action ?? `contract_call.${call.input.operationKind}`,
          result: input.result ?? (call.input.operationKind === "deny_probe" ? "denied" : "allowed"),
          request_id: call.input.requestId,
          ...(call.txHash ? { transaction_hash: call.txHash } : {}),
          policy_digest: auditPolicyDigest,
        }));
      return {
        success: true,
        result: {
          items,
        },
      };
    },
  };
}

function hashForTestJson(value: unknown): `0x${string}` {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}

function keccakJsonForTest(value: unknown): `0x${string}` {
  return keccak256(toBytes(canonicalizeJson(value)));
}

function createFakeMcpLeaseClient(toolName = "pactfuse_code_scan", mode: "fixture" | "live" = "fixture"): McpLeaseClient {
  return {
    async status() {
      return {
        name: "mcp_lease",
        mode,
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
            artifactPayloadHash: input.artifactPayloadHash,
            artifactPayload: input.artifactPayload,
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
    ["sessionId", "leaseRunId", "spendId", "payer", "artifactHash", "artifactPayloadHash", "artifactPayload", "targetRepo", "targetCommit"].map((field) => [
      field,
      field === "artifactPayload" ? { type: "object" } : { type: "string" },
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

async function runLiveSmokeAgainstStub(mutateProofBundle?: (proofBundle: Record<string, unknown>) => void): Promise<{
  status: number | null;
  stdout: string;
  stderr: string;
}> {
  const fixture = liveSmokeFixture();
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const proofBundle = deepClone(fixture.proofBundle);
    if (mutateProofBundle) {
      mutateProofBundle(proofBundle);
    }
    const responses: Record<string, unknown> = {
      "/readyz": fixture.ready,
      "/api/v1/evidence/live-preflight": fixture.preflight,
      "/api/v1/evidence/public-claim": { ok: true, requestId: "stub_public_claim", data: fixture.claim },
      "/api/v1/evidence/proof-bundle": { ok: true, requestId: "stub_proof_bundle", data: proofBundle },
    };
    const body = responses[url.pathname];
    if (!body) {
      res.statusCode = 404;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: false, error: { code: "not_found" } }));
      return;
    }
    res.statusCode = 200;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(body));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("live-smoke stub server did not bind to a TCP port");
  }
  try {
    const result = await runNodeScript([join(process.cwd(), "../../scripts/live-smoke.mjs")], {
      cwd: join(process.cwd(), "../.."),
      env: {
        ...process.env,
        PACTFUSE_API_BASE_URL: `http://127.0.0.1:${address.port}`,
        PACTFUSE_OPERATOR_TOKEN: "operator-test-token",
        PACTFUSE_LIVE_SMOKE_SESSION_ID: fixture.sessionId,
        PACTFUSE_LIVE_SMOKE_REQUIRED_PROVIDERS: "chain,caw_live,caw,mcp_lease",
      },
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  }
}

function runNodeScript(args: string[], options: { cwd: string; env: NodeJS.ProcessEnv }): Promise<{
  status: number | null;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`node ${args.join(" ")} timed out`));
    }, 10_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (status) => {
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
  });
}

function liveSmokeFixture(): {
  sessionId: string;
  ready: Record<string, unknown>;
  preflight: Record<string, unknown>;
  claim: Record<string, unknown>;
  proofBundle: Record<string, unknown>;
} {
  const sessionId = hex32("live-smoke-stub-session");
  const providerStatuses = [
    { name: "chain", mode: "live", ready: true, reason: "stub chain", chainId: "84532", endpoint: null },
    { name: "caw_live", mode: "live", ready: true, reason: "stub caw live", endpoint: "https://api.agenticwallet.cobo.test/" },
    { name: "caw", mode: "live", ready: true, reason: "stub caw receipts", endpoint: null },
    { name: "mcp_lease", mode: "live", ready: true, reason: "stub mcp lease", endpoint: null },
  ];
  const priorProofPayload = { proofAuthority: true, winnerClaimAllowed: false, stub: "final verifier passed" };
  const priorProofPayloadHash = hashForTestJson(priorProofPayload);
  const priorProofEventHash = hashForTestJson({
    sessionId,
    eventSeq: 49,
    authority: "proof",
    kind: "verifier.final_replay_claim",
    payloadHash: priorProofPayloadHash,
    prevProofEventHash: ZERO_HASH,
  });
  const events = [
    {
      sessionId,
      eventId: priorProofEventHash,
      eventSeq: 49,
      eventHash: priorProofEventHash,
      prevProofEventHash: ZERO_HASH,
      authority: "proof",
      kind: "verifier.final_replay_claim",
      payloadHash: priorProofPayloadHash,
      payload: priorProofPayload,
      createdAt: "2026-06-11T00:00:00.000Z",
    },
  ];
  const replayBundle = {
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId,
    summaryMode: true,
    asOfEventSeq: 49,
    winnerClaimAllowed: true,
    eventRoot: hashForTestJson(events.map((event) => event.eventHash)),
    events,
    replayPageIndex: { pageSize: 200, pageRoot: hashForTestJson([]), collections: {} },
    replayPages: {},
  };
  const replayBundleHash = hashForTestJson(replayBundle);
  const verifierRun = {
    sessionId,
    proofLevel: "final_replay_claim",
    claimMode: "caw-target-real",
    paymentMode: "gate-paid-artifact-real",
    tokenMode: "mock-test-token",
    identityMode: "p0-floor-one-wallet",
    schemaOk: true,
    proofChipAllowed: true,
    winnerClaimAllowed: true,
    requestedWinnerClaimAllowed: true,
    finalVerifierComplete: true,
    errors: [],
    warnings: [],
    raw: {},
  };
  const publicClaimHash = hashForTestJson({
    sessionId,
    claimMode: "caw-target-real",
    paymentMode: "gate-paid-artifact-real",
    tokenMode: "mock-test-token",
    identityMode: "p0-floor-one-wallet",
    replayBundleHash,
    verifierRun: {
      proofLevel: verifierRun.proofLevel,
      proofChipAllowed: verifierRun.proofChipAllowed,
      finalVerifierComplete: verifierRun.finalVerifierComplete,
      winnerClaimAllowed: verifierRun.winnerClaimAllowed,
    },
  });
  const claim = {
    sessionId,
    claimStatus: "authorized_public_claim",
    claimMode: "caw-target-real",
    paymentMode: "gate-paid-artifact-real",
    tokenMode: "mock-test-token",
    identityMode: "p0-floor-one-wallet",
    replayBundleHash,
    publicClaimHash,
    verifierRun,
    proofChipAllowed: true,
    finalVerifierComplete: true,
    winnerClaimAllowed: true,
  };
  const server = {
    proofBundleVersion: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
    commit: "stub-commit",
    buildTime: "2026-06-11T00:00:00.000Z",
    generatedAt: "2026-06-11T00:00:00.000Z",
  };
  const proofBundleBase = {
    bundleType: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
    sessionId,
    publicClaimHash,
    publicClaimEventSeq: 50,
    claimInputReplayBundleHash: replayBundleHash,
    replayBundleHash,
    verifierRunHash: hashForTestJson(verifierRun),
    providerStatusHash: hashForTestJson(providerStatuses),
    deploymentRegistryHash: null,
    serverHash: hashForTestJson(server),
    publicClaim: claim,
    replayBundle,
    providerStatuses,
    deploymentRegistry: null,
    server,
    winnerClaimAllowed: true,
  };
  const publicClaimPayloadHash = hashForTestJson({
    claim,
    publicClaimHash,
    replayBundleHash,
    verifierRunHash: proofBundleBase.verifierRunHash,
    asOfEventSeq: 49,
    providerStatuses,
    providerStatusHash: proofBundleBase.providerStatusHash,
    deploymentRegistry: null,
    deploymentRegistryHash: null,
    server,
    serverHash: proofBundleBase.serverHash,
    proofAuthority: true,
    winnerClaimAllowed: true,
  });
  const publicClaimEventHash = hashForTestJson({
    sessionId,
    eventSeq: 50,
    authority: "proof",
    kind: "public.claim.authorized",
    payloadHash: publicClaimPayloadHash,
    prevProofEventHash: priorProofEventHash,
  });
  const proofBundleWithEvent = {
    ...proofBundleBase,
    publicClaimEventId: publicClaimEventHash,
    publicClaimEventHash,
  };
  return {
    sessionId,
    ready: {
      ok: true,
      proofProviderCheck: { checked: true },
      apiSecurity: { operatorTokenConfigured: true, allowInsecureMissingRoleTokens: false },
      mcpAudit: { configured: true },
      gateIngest: { configured: true },
      proofProviders: providerStatuses,
    },
    preflight: {
      ok: true,
      requestId: "stub_preflight",
      data: {
        sessionId,
        status: "ready",
        readyForPublicClaim: true,
        winnerClaimAllowed: true,
        blockingReasons: [],
        requiredExternalInputs: [],
        checks: [{ checkId: "stub", status: "pass" }],
        security: { cawIngestTokenConfigured: true },
      },
    },
    claim,
    proofBundle: {
      ...proofBundleWithEvent,
      proofBundleHash: hashForTestJson(proofBundleWithEvent),
    },
  };
}

function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
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
