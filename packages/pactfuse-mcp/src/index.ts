import { createHash, createHmac, randomUUID } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CreateSessionInputSchema,
  Hex32Schema,
  LeaseExecuteEnvelopeSchema,
  type JsonValue,
  SessionScopedEnvelopeSchema,
  canonicalizeJson,
} from "@pactfuse/evidence-schema";

export type PactFuseMcpClient = {
  baseUrl: string;
  auditToken?: string;
  artifactBearerToken?: string;
  fetch?: typeof fetch;
};

export type PactFuseTool = {
  name: string;
  description: string;
  inputSchema: z.ZodTypeAny;
  invoke: (input: unknown) => Promise<unknown>;
};

const SessionOnlySchema = z.object({ sessionId: Hex32Schema }).strict();

export function createPactFuseTools(client: PactFuseMcpClient): PactFuseTool[] {
  const tools: PactFuseTool[] = [
    {
      name: "pactfuse_start_session",
      description: "Start a fail-closed PactFuse P0 session.",
      inputSchema: CreateSessionInputSchema,
      invoke: (input) => post(client, "/api/v1/sessions", CreateSessionInputSchema.parse(input)),
    },
    {
      name: "pactfuse_register_sources",
      description: "Register signed source metadata; proof remains pending until public-chain evidence exists.",
      inputSchema: SessionScopedEnvelopeSchema,
      invoke: (input) => post(client, "/api/v1/sources/register", SessionScopedEnvelopeSchema.parse(input)),
    },
    {
      name: "pactfuse_register_spends",
      description: "Register source-bound spends in the P0 backend store.",
      inputSchema: SessionScopedEnvelopeSchema,
      invoke: (input) => post(client, "/api/v1/spends/register-batch", SessionScopedEnvelopeSchema.parse(input)),
    },
    {
      name: "pactfuse_build_caw_operation",
      description: "Build a mocked CAW operation envelope for the current fail-closed mode.",
      inputSchema: SessionScopedEnvelopeSchema,
      invoke: (input) => post(client, "/api/v1/caw/operations/build", SessionScopedEnvelopeSchema.parse(input)),
    },
    {
      name: "pactfuse_execute_clean_lease",
      description: "Attempt clean lease execution; P0 blocks unless finalized settlement proof exists.",
      inputSchema: LeaseExecuteEnvelopeSchema,
      invoke: (input) =>
        post(client, "/api/v1/lease/execute", LeaseExecuteEnvelopeSchema.parse(input), artifactAuthorizationHeader(client)),
    },
    {
      name: "pactfuse_get_judge_check",
      description: "Read the six-row fail-closed Judge Check view.",
      inputSchema: SessionOnlySchema,
      invoke: async (input) => {
        const parsed = SessionOnlySchema.parse(input);
        return get(client, `/api/v1/evidence/judge-check?sessionId=${encodeURIComponent(parsed.sessionId)}`);
      },
    },
    {
      name: "pactfuse_get_replay_bundle",
      description: "Read the summary PACTFUSE_EVIDENCE_V1 replay bundle.",
      inputSchema: SessionOnlySchema,
      invoke: async (input) => {
        const parsed = SessionOnlySchema.parse(input);
        return get(client, `/api/v1/evidence/replay-bundle?sessionId=${encodeURIComponent(parsed.sessionId)}`);
      },
    },
  ];
  return tools.map((tool) => ({
    ...tool,
    invoke: (input) => invokeWithAudit(client, tool, input),
  }));
}

export function createPactFuseMcpServer(client: PactFuseMcpClient): McpServer {
  const server = new McpServer({ name: "pactfuse-mcp", version: "0.0.0-p0" });
  for (const tool of createPactFuseTools(client)) {
    server.registerTool(
      tool.name,
      {
        title: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        _meta: {
          pactfuse: "p0-thin-adapter",
          proofAuthority: false,
        },
      },
      async (args) => ({
        content: [
          {
            type: "text",
            text: JSON.stringify(await tool.invoke(args), null, 2),
          },
        ],
      }),
    );
  }
  return server;
}

async function post(client: PactFuseMcpClient, path: string, body: unknown, headers: Record<string, string> = {}): Promise<unknown> {
  const res = await request(client, path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return res.json();
}

function artifactAuthorizationHeader(client: PactFuseMcpClient): Record<string, string> {
  return client.artifactBearerToken ? { authorization: `Bearer ${client.artifactBearerToken}` } : {};
}

async function invokeWithAudit(client: PactFuseMcpClient, tool: PactFuseTool, input: unknown): Promise<unknown> {
  if (!client.auditToken) {
    throw new Error("PactFuse MCP audit token is required before invoking audited tools");
  }
  let response: unknown;
  let status: "succeeded" | "failed" | "blocked" = "succeeded";
  try {
    response = await tool.invoke(input);
    status = responseStatus(response);
  } catch (error) {
    status = "failed";
    response = {
      error: error instanceof Error ? error.message : "unknown MCP tool invocation error",
    };
    await auditToolCall(client, tool.name, input, response, status);
    throw error;
  }
  const audit = await auditToolCall(client, tool.name, input, response, status);
  return attachAudit(response, audit);
}

async function auditToolCall(
  client: PactFuseMcpClient,
  toolName: string,
  requestBody: unknown,
  responseBody: unknown,
  status: "succeeded" | "failed" | "blocked",
): Promise<Record<string, JsonValue>> {
  const payload = {
    sessionId: extractSessionId(requestBody) ?? extractSessionId(responseBody),
    auditNonce: `mcp_${randomUUID()}`,
    toolName,
    request: toJsonObject(requestBody),
    response: toJsonObject(responseForAudit(toolName, responseBody)),
    status,
  };
  const audit = await postWithHeaders(client, "/api/v1/mcp/audit", payload, {
    "x-pactfuse-audit-signature": signAuditPayload(client.auditToken ?? "", payload),
  });
  const auditObject = toJsonObject(audit);
  if (auditObject.ok === false) {
    throw new Error("PactFuse MCP audit endpoint rejected the tool call");
  }
  return {
    ok: true,
    ...auditObject,
  };
}

function responseForAudit(toolName: string, responseBody: unknown): unknown {
  if (toolName !== "pactfuse_get_replay_bundle") {
    return responseBody;
  }
  const response = toJsonObject(responseBody);
  const data = response.data && typeof response.data === "object" && !Array.isArray(response.data) ? response.data : null;
  if (!data || data.bundleType !== "PACTFUSE_EVIDENCE_V1") {
    return responseBody;
  }
  return {
    ok: response.ok,
    requestId: response.requestId,
    data: {
      bundleType: "PACTFUSE_EVIDENCE_V1",
      sessionId: data.sessionId,
      summaryMode: data.summaryMode,
      winnerClaimAllowed: data.winnerClaimAllowed,
      eventRoot: data.eventRoot,
      eventCount: Array.isArray(data.events) ? data.events.length : null,
      mcpAdapterCallCount: Array.isArray(data.mcpAdapterCalls) ? data.mcpAdapterCalls.length : null,
      judgeCheckRowCount:
        data.judgeCheck && typeof data.judgeCheck === "object" && !Array.isArray(data.judgeCheck)
          ? Array.isArray(data.judgeCheck.rows)
            ? data.judgeCheck.rows.length
            : null
          : null,
      originalResponseHash: hashJsonValue(responseBody),
      originalResponseBytes: Buffer.byteLength(canonicalizeJson(toJsonValue(responseBody)), "utf8"),
      redactedReason: "replay_bundle_response_summary",
    },
  };
}

function attachAudit(response: unknown, audit: Record<string, JsonValue>): unknown {
  if (response && typeof response === "object" && !Array.isArray(response)) {
    return {
      ...(response as Record<string, unknown>),
      _pactfuseAudit: audit,
    };
  }
  return {
    value: toJsonValue(response),
    _pactfuseAudit: audit,
  };
}

function responseStatus(response: unknown): "succeeded" | "failed" | "blocked" {
  if (!response || typeof response !== "object" || Array.isArray(response)) {
    return "succeeded";
  }
  const object = response as Record<string, unknown>;
  if (object.ok === false) {
    const code = String((object.error as { code?: unknown } | undefined)?.code ?? "");
    return code === "proof_pending" || code === "proof_blocked" || code === "mode_locked" ? "blocked" : "failed";
  }
  return "succeeded";
}

function extractSessionId(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const object = value as Record<string, unknown>;
  if (typeof object.sessionId === "string" && Hex32Schema.safeParse(object.sessionId).success) {
    return object.sessionId;
  }
  const data = object.data;
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const sessionId = (data as Record<string, unknown>).sessionId;
    if (typeof sessionId === "string" && Hex32Schema.safeParse(sessionId).success) {
      return sessionId;
    }
  }
  return undefined;
}

function toJsonObject(value: unknown): Record<string, JsonValue> {
  const json = toJsonValue(value);
  return json && typeof json === "object" && !Array.isArray(json) ? json : { value: json };
}

function toJsonValue(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => toJsonValue(item));
  }
  if (value && typeof value === "object") {
    const object: Record<string, JsonValue> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (child !== undefined) {
        object[key] = toJsonValue(child);
      }
    }
    return object;
  }
  return null;
}

function signAuditPayload(secret: string, payload: unknown): `0x${string}` {
  return `0x${createHmac("sha256", secret).update(canonicalizeJson(payload)).digest("hex")}`;
}

function hashJsonValue(value: unknown): `0x${string}` {
  return `0x${createHash("sha256").update(canonicalizeJson(toJsonValue(value))).digest("hex")}`;
}

async function get(client: PactFuseMcpClient, path: string): Promise<unknown> {
  const res = await request(client, path, { method: "GET" });
  return res.json();
}

async function postWithHeaders(
  client: PactFuseMcpClient,
  path: string,
  body: unknown,
  headers: Record<string, string>,
): Promise<unknown> {
  const res = await request(client, path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function request(client: PactFuseMcpClient, path: string, init: RequestInit): Promise<Response> {
  const fetchImpl = client.fetch ?? fetch;
  const baseUrl = client.baseUrl.replace(/\/$/, "");
  const res = await fetchImpl(`${baseUrl}${path}`, init);
  if (!res.ok) {
    return res;
  }
  return res;
}
