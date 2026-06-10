import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  CreateSessionInputSchema,
  Hex32Schema,
  SessionScopedEnvelopeSchema,
} from "@pactfuse/evidence-schema";

export type PactFuseMcpClient = {
  baseUrl: string;
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
  return [
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
      inputSchema: SessionScopedEnvelopeSchema,
      invoke: (input) => post(client, "/api/v1/lease/execute", SessionScopedEnvelopeSchema.parse(input)),
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

async function post(client: PactFuseMcpClient, path: string, body: unknown): Promise<unknown> {
  const res = await request(client, path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function get(client: PactFuseMcpClient, path: string): Promise<unknown> {
  const res = await request(client, path, { method: "GET" });
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
