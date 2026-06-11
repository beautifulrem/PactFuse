import { describe, expect, it } from "vitest";
import { createPactFuseTools } from "./index.js";

const SESSION_ID = "0x1111111111111111111111111111111111111111111111111111111111111111";

describe("pactfuse MCP tools", () => {
  it("audits successful tool calls and binds start_session to the returned session", async () => {
    const calls: Array<{ url: string; init: RequestInit; body: unknown }> = [];
    const fetch = fakeFetch(calls, [
      {
        ok: true,
        status: 201,
        body: { ok: true, requestId: "req_1", data: { sessionId: SESSION_ID, winnerClaimAllowed: false } },
      },
      {
        ok: true,
        status: 202,
        body: {
          ok: true,
          requestId: "audit_1",
          data: {
            callId: "0x2222222222222222222222222222222222222222222222222222222222222222",
            requestHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
            responseHash: "0x4444444444444444444444444444444444444444444444444444444444444444",
            proofAuthority: false,
            winnerClaimAllowed: false,
          },
        },
      },
    ]);
    const tool = createPactFuseTools({ baseUrl: "http://pactfuse.test", auditToken: "audit-token", fetch }).find(
      (candidate) => candidate.name === "pactfuse_start_session",
    );

    expect(tool).toBeDefined();
    const result = (await tool!.invoke({ idempotencyKey: "mcp-start", payload: { label: "mcp" } })) as Record<string, any>;
    expect(calls).toHaveLength(2);
    const businessCall = calls[0]!;
    const auditCall = calls[1]!;
    const auditBody = auditCall.body as Record<string, any>;

    expect(businessCall.url).toBe("http://pactfuse.test/api/v1/sessions");
    expect(auditCall.url).toBe("http://pactfuse.test/api/v1/mcp/audit");
    expect(auditBody.sessionId).toBe(SESSION_ID);
    expect(auditBody.auditNonce).toMatch(/^mcp_/);
    expect(auditBody.toolName).toBe("pactfuse_start_session");
    expect(auditBody.status).toBe("succeeded");
    expect((auditCall.init.headers as Record<string, string>)["x-pactfuse-audit-signature"]).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result._pactfuseAudit.ok).toBe(true);
    expect(result._pactfuseAudit.data.proofAuthority).toBe(false);
    expect(result._pactfuseAudit.data.winnerClaimAllowed).toBe(false);
  });

  it("audits proof-pending API responses as blocked", async () => {
    const calls: Array<{ url: string; init: RequestInit; body: unknown }> = [];
    const fetch = fakeFetch(calls, [
      {
        ok: false,
        status: 423,
        body: {
          ok: false,
          requestId: "req_blocked",
          error: { code: "proof_pending", message: "pending", retryable: true, downgrade: "pending" },
        },
      },
      {
        ok: true,
        status: 202,
        body: {
          ok: true,
          requestId: "audit_blocked",
          data: {
            callId: "0x5555555555555555555555555555555555555555555555555555555555555555",
            requestHash: "0x6666666666666666666666666666666666666666666666666666666666666666",
            responseHash: "0x7777777777777777777777777777777777777777777777777777777777777777",
            proofAuthority: false,
            winnerClaimAllowed: false,
          },
        },
      },
    ]);
    const tool = createPactFuseTools({
      baseUrl: "http://pactfuse.test",
      auditToken: "audit-token",
      artifactBearerToken: "lease-access-token",
      fetch,
    }).find((candidate) => candidate.name === "pactfuse_execute_clean_lease");

    expect(tool).toBeDefined();
    expect(
      tool!.inputSchema.safeParse({
        sessionId: SESSION_ID,
        idempotencyKey: "mcp-lease-missing-fields",
        payload: {
          spendId: "0x8888888888888888888888888888888888888888888888888888888888888888",
          targetRepo: "https://github.com/example/repo",
          targetCommit: "abcdef123456",
        },
      }).success,
    ).toBe(false);
    const result = (await tool!.invoke({
      sessionId: SESSION_ID,
      idempotencyKey: "mcp-lease",
      payload: {
        spendId: "0x8888888888888888888888888888888888888888888888888888888888888888",
        payer: "0x1234",
        artifactHash: "0x9999999999999999999999999999999999999999999999999999999999999999",
        targetRepo: "https://github.com/example/repo",
        targetCommit: "abcdef123456",
      },
    })) as Record<string, any>;
    expect(calls).toHaveLength(2);
    const businessCall = calls[0]!;
    const auditCall = calls[1]!;
    const auditBody = auditCall.body as Record<string, any>;

    expect(businessCall.url).toBe("http://pactfuse.test/api/v1/lease/execute");
    expect((businessCall.init.headers as Record<string, string>).authorization).toBe("Bearer lease-access-token");
    expect(auditCall.url).toBe("http://pactfuse.test/api/v1/mcp/audit");
    expect(auditBody.sessionId).toBe(SESSION_ID);
    expect(auditBody.auditNonce).toMatch(/^mcp_/);
    expect(auditBody.status).toBe("blocked");
    expect(auditBody.response.error.code).toBe("proof_pending");
    expect(result.ok).toBe(false);
    expect(result._pactfuseAudit.ok).toBe(true);
  });

  it("blocks tool invocation before the business request when the audit token is missing", async () => {
    const calls: Array<{ url: string; init: RequestInit; body: unknown }> = [];
    const fetch = fakeFetch(calls, []);
    const tool = createPactFuseTools({ baseUrl: "http://pactfuse.test", fetch }).find(
      (candidate) => candidate.name === "pactfuse_get_judge_check",
    );

    expect(tool).toBeDefined();
    await expect(tool!.invoke({ sessionId: SESSION_ID })).rejects.toThrow(/audit token is required/);
    expect(calls).toEqual([]);
  });

  it("does not return a successful business response when audit is rejected", async () => {
    const calls: Array<{ url: string; init: RequestInit; body: unknown }> = [];
    const fetch = fakeFetch(calls, [
      {
        ok: true,
        status: 200,
        body: { ok: true, requestId: "req_1", data: { winnerClaimAllowed: false } },
      },
      {
        ok: false,
        status: 403,
        body: { ok: false, requestId: "audit_forbidden", error: { code: "forbidden" } },
      },
    ]);
    const tool = createPactFuseTools({ baseUrl: "http://pactfuse.test", auditToken: "audit-token", fetch }).find(
      (candidate) => candidate.name === "pactfuse_get_judge_check",
    );

    expect(tool).toBeDefined();
    await expect(tool!.invoke({ sessionId: SESSION_ID })).rejects.toThrow(/audit endpoint rejected/);
    expect(calls).toHaveLength(2);
  });

  it("audits replay bundle responses as bounded summaries instead of recursive raw bundles", async () => {
    const calls: Array<{ url: string; init: RequestInit; body: unknown }> = [];
    const replayResponse = {
      ok: true,
      requestId: "replay_1",
      data: {
        bundleType: "PACTFUSE_EVIDENCE_V1",
        sessionId: SESSION_ID,
        summaryMode: true,
        winnerClaimAllowed: false,
        eventRoot: "0x9999999999999999999999999999999999999999999999999999999999999999",
        events: [{ kind: "session.created" }],
        mcpAdapterCalls: [{ response: { data: { bundleType: "PACTFUSE_EVIDENCE_V1" } } }],
        judgeCheck: { rows: [{ rowId: "lease_execution" }] },
      },
    };
    const fetch = fakeFetch(calls, [
      {
        ok: true,
        status: 200,
        body: replayResponse,
      },
      {
        ok: true,
        status: 202,
        body: {
          ok: true,
          requestId: "audit_replay",
          data: {
            callId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            requestHash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            responseHash: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            proofAuthority: false,
            winnerClaimAllowed: false,
          },
        },
      },
    ]);
    const tool = createPactFuseTools({ baseUrl: "http://pactfuse.test", auditToken: "audit-token", fetch }).find(
      (candidate) => candidate.name === "pactfuse_get_replay_bundle",
    );

    expect(tool).toBeDefined();
    const result = (await tool!.invoke({ sessionId: SESSION_ID })) as Record<string, any>;
    const auditBody = calls[1]!.body as Record<string, any>;

    expect(result.data.mcpAdapterCalls).toHaveLength(1);
    expect(auditBody.response.data.bundleType).toBe("PACTFUSE_EVIDENCE_V1");
    expect(auditBody.response.data.eventCount).toBe(1);
    expect(auditBody.response.data.mcpAdapterCallCount).toBe(1);
    expect(auditBody.response.data.originalResponseHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(auditBody.response.data.redactedReason).toBe("replay_bundle_response_summary");
    expect(auditBody.response.data.events).toBeUndefined();
    expect(auditBody.response.data.mcpAdapterCalls).toBeUndefined();
  });
});

function fakeFetch(
  calls: Array<{ url: string; init: RequestInit; body: unknown }>,
  responses: Array<{ ok: boolean; status: number; body: unknown }>,
): typeof fetch {
  return (async (url: string | URL | Request, init: RequestInit = {}) => {
    const body = typeof init.body === "string" ? JSON.parse(init.body) : null;
    calls.push({ url: String(url), init, body });
    const response = responses.shift();
    if (!response) {
      throw new Error("unexpected fetch call");
    }
    return new Response(JSON.stringify(response.body), {
      status: response.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}
