import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicClient, decodeEventLog, http } from "viem";
import type {
  CawReceiptSource,
  ChainClient,
  McpLeaseClient,
  McpLeaseExecutionInput,
  McpLeaseExecutionResult,
  PactTemplateBinding,
  PactTemplateRegistry,
  ProofProviderStatus,
} from "../types.js";
import { hashJson } from "../util.js";

const DEFAULT_TEMPLATES: Array<{ mode: PactTemplateBinding["mode"]; path: string }> = [
  { mode: "gate-paid-artifact-real", path: "../../../../pact-template/gate-paid-artifact-real.json" },
  { mode: "permit-payment-real", path: "../../../../pact-template/permit-payment-real.appendix.json" },
];
export const PACTFUSE_CHAIN_EVENT_ABI = [
  {
    type: "event",
    name: "SpendTripped",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "spendId", type: "bytes32", indexed: true },
    ],
  },
  {
    type: "event",
    name: "SpendSettled",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "spendId", type: "bytes32", indexed: true },
    ],
  },
  {
    type: "event",
    name: "SourceChallenged",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "sourceHash", type: "bytes32", indexed: true },
      { name: "reasonHash", type: "bytes32", indexed: true },
    ],
  },
] as const;
const MAX_MCP_RESPONSE_BYTES = 512 * 1024;
const REQUIRED_LEASE_TOOL_ARGUMENTS = ["sessionId", "leaseRunId", "spendId", "payer", "artifactHash", "targetRepo", "targetCommit"] as const;
const DANGEROUS_TOOL_NAME_PATTERN =
  /(write|edit|delete|remove|shell|exec|terminal|command|commit|push|deploy|transfer|send|apply|patch|modify|create|move|copy|rename|upload|download|file|fs|process|subprocess)/;

export function createUnconfiguredChainClient(): ChainClient {
  return {
    async status() {
      return unconfiguredStatus("chain", "chain RPC endpoint is not configured");
    },
    async getBlockNumber() {
      throw new Error("chain provider is unconfigured; cannot read current block number");
    },
    async getTransactionReceipt() {
      throw new Error("chain provider is unconfigured; cannot verify transaction receipt");
    },
    async getLogs() {
      throw new Error("chain provider is unconfigured; cannot verify event logs");
    },
    async readContract() {
      throw new Error("chain provider is unconfigured; cannot verify contract state");
    },
  };
}

export function createViemChainClient(input: { rpcUrl: string; chainId?: string | number }): ChainClient {
  const client = createPublicClient({ transport: http(input.rpcUrl) });
  const configuredChainId = input.chainId === undefined || input.chainId === "" ? undefined : String(input.chainId);
  return {
    async status() {
      try {
        const [, chainId] = await Promise.all([client.getBlockNumber(), client.getChainId()]);
        const actualChainId = String(chainId);
        if (configuredChainId !== undefined && actualChainId !== configuredChainId) {
          return {
            name: "chain",
            mode: "live",
            ready: false,
            reason: `configured chainId ${configuredChainId} does not match RPC chainId ${actualChainId}`,
            endpoint: input.rpcUrl,
            chainId: actualChainId,
          };
        }
        return {
          name: "chain",
          mode: "live",
          ready: true,
          reason: "chain RPC endpoint is configured",
          endpoint: input.rpcUrl,
          chainId: actualChainId,
        };
      } catch (error) {
        const failedStatus: ProofProviderStatus = {
          name: "chain",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "chain RPC endpoint failed readiness check",
          endpoint: input.rpcUrl,
        };
        if (configuredChainId !== undefined) {
          failedStatus.chainId = configuredChainId;
        }
        return failedStatus;
      }
    },
    async getBlockNumber() {
      return Number(await client.getBlockNumber());
    },
    async getTransactionReceipt(txHash: string) {
      const receipt = await client.getTransactionReceipt({ hash: txHash as `0x${string}` });
      return normalizeChainValue(receipt) as Record<string, unknown>;
    },
    async getLogs(query: Record<string, unknown>) {
      if (configuredChainId !== undefined && typeof query.chainId === "string" && query.chainId !== configuredChainId) {
        throw new Error(`requested chainId ${query.chainId} does not match configured chainId ${configuredChainId}`);
      }
      const fromBlock = toBigIntBlock(query.fromBlock ?? query.blockNumber);
      const toBlock = toBigIntBlock(query.toBlock ?? query.blockNumber ?? query.fromBlock);
      const filter: Record<string, unknown> = {
        fromBlock: toRpcBlock(fromBlock),
        toBlock: toRpcBlock(toBlock),
      };
      const address = optionalHex(query.address);
      if (address) {
        filter.address = address;
      }
      const topics = Array.isArray(query.topics)
        ? query.topics.map((topic) => (typeof topic === "string" && topic.length > 0 ? (topic as `0x${string}`) : null))
        : undefined;
      if (topics) {
        filter.topics = topics;
      }
      const requestLogs = client.request as (args: { method: "eth_getLogs"; params: [Record<string, unknown>] }) => Promise<unknown[]>;
      const logs = await requestLogs({
        method: "eth_getLogs",
        params: [filter],
      });
      return logs.map((log: unknown) => normalizePactFuseChainLog(normalizeChainValue(log) as Record<string, unknown>));
    },
    async readContract(query: {
      address: string;
      abi: readonly unknown[];
      functionName: string;
      args?: readonly unknown[];
      blockNumber?: number;
    }) {
      const readContract = client.readContract as (input: {
        address: `0x${string}`;
        abi: readonly unknown[];
        functionName: string;
        args?: readonly unknown[];
        blockNumber?: bigint;
      }) => Promise<unknown>;
      const request: {
        address: `0x${string}`;
        abi: readonly unknown[];
        functionName: string;
        args?: readonly unknown[];
        blockNumber?: bigint;
      } = {
        address: query.address as `0x${string}`,
        abi: query.abi,
        functionName: query.functionName,
      };
      if (query.args !== undefined) {
        request.args = query.args;
      }
      if (query.blockNumber !== undefined) {
        request.blockNumber = toBigIntBlock(query.blockNumber);
      }
      const result = await readContract(request);
      return normalizeChainValue(result);
    },
  };
}

export function normalizePactFuseChainLog(log: Record<string, unknown>): Record<string, unknown> {
  const rawRpcLogHash = hashChainJson(log);
  const topics = Array.isArray(log.topics) ? log.topics.filter((topic): topic is `0x${string}` => typeof topic === "string") : [];
  const data = typeof log.data === "string" && log.data.startsWith("0x") ? (log.data as `0x${string}`) : "0x";
  if (topics.length === 0) {
    return { ...log, rawRpcLogHash };
  }
  try {
    const eventTopics = topics as [signature: `0x${string}`, ...args: `0x${string}`[]];
    const decoded = decodeEventLog({
      abi: PACTFUSE_CHAIN_EVENT_ABI,
      data,
      topics: eventTopics,
    });
    return {
      ...log,
      rawRpcLogHash,
      eventName: decoded.eventName,
      event: decoded.eventName,
      name: decoded.eventName,
      args: normalizeChainValue(decoded.args),
    };
  } catch {
    return { ...log, rawRpcLogHash };
  }
}

function hashChainJson(value: unknown): `0x${string}` {
  return hashJson(normalizeChainValue(value));
}

export function createUnconfiguredCawReceiptSource(): CawReceiptSource {
  return {
    async status() {
      return unconfiguredStatus("caw", "CAW receipt source is not configured");
    },
    async fetchReceiptBundle() {
      throw new Error("CAW receipt source is unconfigured; cannot fetch raw receipt bundle");
    },
  };
}

export function createHttpsCawReceiptSource(input: {
  exportUrl: string;
  apiKey?: string;
  walletId?: string;
  limit?: number;
}): CawReceiptSource {
  const limit = input.limit ?? 50;
  return {
    async status() {
      try {
        const url = cawExportUrl(input.exportUrl, input.walletId, { limit: 1 });
        const response = await fetch(url, {
          method: "GET",
          headers: cawHeaders(input.apiKey),
        });
        if (!response.ok) {
          return {
            name: "caw",
            mode: "live",
            ready: false,
            reason: `CAW export endpoint returned HTTP ${response.status}`,
            endpoint: input.exportUrl,
          } satisfies ProofProviderStatus;
        }
        return {
          name: "caw",
          mode: "live",
          ready: true,
          reason: "CAW raw audit/export endpoint is configured",
          endpoint: input.exportUrl,
        };
      } catch (error) {
        return {
          name: "caw",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "CAW export endpoint failed readiness check",
          endpoint: input.exportUrl,
        };
      }
    },
    async fetchReceiptBundle(request: Record<string, unknown>) {
      const url = cawExportUrl(input.exportUrl, input.walletId, {
        limit,
        session_id: optionalString(request.sessionId),
        operation_id: optionalString(request.operationId),
        source_label: optionalString(request.sourceLabel),
        operation_kind: optionalString(request.operationKind),
      });
      const response = await fetch(url, {
        method: "GET",
        headers: cawHeaders(input.apiKey),
      });
      const body = await parseCawResponse(response);
      const receipts = extractCawReceiptItems(body);
      return {
        source: "caw-api",
        sourceLabel: optionalString(request.sourceLabel) ?? "caw-api",
        sessionId: request.sessionId,
        operationId: request.operationId,
        operationKind: request.operationKind,
        walletId: input.walletId ?? null,
        fetchedAt: new Date().toISOString(),
        exportUrl: input.exportUrl,
        receipts,
        raw: body,
      };
    },
  };
}

export function createUnconfiguredMcpLeaseClient(): McpLeaseClient {
  return {
    async status() {
      return unconfiguredStatus("mcp_lease", "lease MCP endpoint is not configured");
    },
    async executeCleanLease() {
      throw new Error("lease MCP endpoint is unconfigured; cannot execute tools/list or tools/call");
    },
  };
}

export function createHttpJsonRpcMcpLeaseClient(input: {
  endpointUrl: string;
  toolName?: string;
  timeoutMs?: number;
}): McpLeaseClient {
  const toolName = normalizeLeaseToolName(input.toolName ?? "pactfuse_code_scan");
  const timeoutMs = input.timeoutMs ?? 10_000;
  return {
    async status() {
      try {
        new URL(input.endpointUrl);
        return {
          name: "mcp_lease",
          mode: "live",
          ready: true,
          reason: "lease MCP JSON-RPC endpoint is configured",
          endpoint: input.endpointUrl,
        };
      } catch (error) {
        return {
          name: "mcp_lease",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "lease MCP endpoint URL is invalid",
          endpoint: input.endpointUrl,
        };
      }
    },
    async executeCleanLease(leaseInput) {
      const toolsListRequest = jsonRpcRequest("tools/list", {});
      const toolsListResponse = await withMcpStage("tools/list", async () => {
        const response = await postJsonRpc(input.endpointUrl, toolsListRequest, timeoutMs);
        const tools = assertToolListed(response, toolName);
        assertPinnedManifestTools(tools, leaseInput.pinnedManifestTools);
        return response;
      });
      const toolsCallRequest = jsonRpcRequest("tools/call", {
        name: toolName,
        arguments: {
          sessionId: leaseInput.sessionId,
          leaseRunId: leaseInput.leaseRunId,
          spendId: leaseInput.spendId,
          payer: leaseInput.payer,
          artifactHash: leaseInput.artifactHash,
          targetRepo: leaseInput.targetRepo,
          targetCommit: leaseInput.targetCommit,
        },
      });
      const toolsCallResponse = await withMcpStage("tools/call", async () => {
        const response = await postJsonRpc(input.endpointUrl, toolsCallRequest, timeoutMs);
        assertJsonRpcSuccess(response, "tools/call");
        return response;
      });
      return {
        toolName,
        toolsList: {
          method: "tools/list",
          request: toolsListRequest,
          response: toolsListResponse,
        },
        toolsCall: {
          method: "tools/call",
          request: toolsCallRequest,
          response: toolsCallResponse,
        },
        output: toolsCallResponse,
      } satisfies McpLeaseExecutionResult;
    },
  };
}

async function withMcpStage<T>(stage: "tools/list" | "tools/call", fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof Error) {
      (error as Error & { leaseStage?: string }).leaseStage = stage;
    }
    throw error;
  }
}

export function createLocalTemplateRegistry(): PactTemplateRegistry {
  const bindings = DEFAULT_TEMPLATES.map((template) => {
    const url = new URL(template.path, import.meta.url);
    const parsed = JSON.parse(readFileSync(url, "utf8")) as unknown;
    return {
      mode: template.mode,
      sourcePath: fileURLToPath(url),
      templateHash: hashJson(parsed),
    };
  });
  return createStaticTemplateRegistry(bindings);
}

function jsonRpcRequest(method: "tools/list" | "tools/call", params: Record<string, unknown>): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: `${method}:${Date.now()}:${Math.random().toString(16).slice(2)}`,
    method,
    params,
  };
}

async function postJsonRpc(endpointUrl: string, request: Record<string, unknown>, timeoutMs: number): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpointUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_MCP_RESPONSE_BYTES) {
      throw new Error("lease MCP endpoint response exceeded 512 KiB");
    }
    let parsed: unknown = {};
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        throw new Error("lease MCP endpoint returned non-JSON response");
      }
    }
    if (!response.ok) {
      throw new Error(`lease MCP endpoint returned HTTP ${response.status}`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("lease MCP endpoint must return a JSON-RPC object");
    }
    return parsed as Record<string, unknown>;
  } finally {
    clearTimeout(timeout);
  }
}

function assertJsonRpcSuccess(response: Record<string, unknown>, method: string): void {
  if (response.jsonrpc !== "2.0") {
    throw new Error(`${method} response is missing jsonrpc=2.0`);
  }
  if ("error" in response) {
    throw new Error(`${method} returned JSON-RPC error`);
  }
  if (!("result" in response)) {
    throw new Error(`${method} response is missing result`);
  }
}

function assertToolListed(response: Record<string, unknown>, toolName: string): Array<Record<string, unknown>> {
  assertJsonRpcSuccess(response, "tools/list");
  const result = response.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("tools/list result must be an object");
  }
  const tools = (result as Record<string, unknown>).tools;
  if (!Array.isArray(tools)) {
    throw new Error("tools/list result must include a tools array");
  }
  if (tools.length !== 1) {
    throw new Error("tools/list must expose exactly one PactFuse lease tool");
  }
  const [tool] = tools;
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    throw new Error("tools/list tool entry must be an object");
  }
  const toolRecord = tool as Record<string, unknown>;
  if (toolRecord.name !== toolName) {
    throw new Error(`tools/list did not expose the required unique tool ${toolName}`);
  }
  assertLeaseToolDefinition(toolRecord);
  return [toolRecord];
}

function assertPinnedManifestTools(actualTools: Array<Record<string, unknown>>, pinnedTools: Array<Record<string, unknown>>): void {
  if (pinnedTools.length !== 1) {
    throw new Error("pinned source manifest must expose exactly one PactFuse lease tool");
  }
  if (hashJson(actualTools) !== hashJson(pinnedTools)) {
    throw new Error("tools/list is not bounded to the pinned source manifest");
  }
}

function normalizeLeaseToolName(toolName: string): string {
  if (!/^pactfuse_[a-z0-9_:-]{1,80}$/.test(toolName)) {
    throw new Error("lease MCP tool name must be a controlled pactfuse_* capability");
  }
  if (DANGEROUS_TOOL_NAME_PATTERN.test(toolName.toLowerCase())) {
    throw new Error("lease MCP tool name must not describe write, execution, transfer, or file capabilities");
  }
  return toolName;
}

function assertLeaseToolDefinition(tool: Record<string, unknown>): void {
  const annotations = tool.annotations;
  if (!annotations || typeof annotations !== "object" || Array.isArray(annotations) || (annotations as Record<string, unknown>).readOnlyHint !== true) {
    throw new Error("lease MCP tool must advertise annotations.readOnlyHint=true");
  }
  const inputSchema = tool.inputSchema;
  if (!inputSchema || typeof inputSchema !== "object" || Array.isArray(inputSchema)) {
    throw new Error("lease MCP tool must expose an inputSchema object");
  }
  const schema = inputSchema as Record<string, unknown>;
  if (schema.type !== "object") {
    throw new Error("lease MCP tool inputSchema.type must be object");
  }
  if (schema.additionalProperties !== false) {
    throw new Error("lease MCP tool inputSchema must set additionalProperties=false");
  }
  const properties = schema.properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    throw new Error("lease MCP tool inputSchema must declare properties");
  }
  const required = schema.required;
  if (!Array.isArray(required)) {
    throw new Error("lease MCP tool inputSchema must declare required fields");
  }
  const propertyNames = new Set(Object.keys(properties as Record<string, unknown>));
  const requiredNames = new Set(required.filter((field): field is string => typeof field === "string"));
  const missing = REQUIRED_LEASE_TOOL_ARGUMENTS.filter((field) => !propertyNames.has(field) || !requiredNames.has(field));
  if (missing.length > 0) {
    throw new Error(`lease MCP tool inputSchema is missing required PactFuse fields: ${missing.join(",")}`);
  }
}

export function createStaticTemplateRegistry(bindings: PactTemplateBinding[]): PactTemplateRegistry {
  const sorted = [...bindings].sort((a, b) => a.mode.localeCompare(b.mode));
  return {
    list: () => sorted.map((binding) => ({ ...binding })),
    require: (mode) => {
      const binding = sorted.find((candidate) => candidate.mode === mode);
      if (!binding) {
        throw new Error(`Pact template binding is missing for mode: ${mode}`);
      }
      return { ...binding };
    },
  };
}

function cawExportUrl(base: string, walletId: string | undefined, params: Record<string, string | number | undefined>): URL {
  const url = new URL(base);
  if (walletId) {
    url.searchParams.set("wallet_id", walletId);
  }
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function cawHeaders(apiKey: string | undefined): Headers {
  const headers = new Headers({ accept: "application/json" });
  if (apiKey) {
    headers.set("authorization", `Bearer ${apiKey}`);
  }
  return headers;
}

async function parseCawResponse(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  let body: unknown = {};
  if (text.length > 0) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      throw new Error("CAW export endpoint returned non-JSON response");
    }
  }
  if (!response.ok) {
    throw new Error(`CAW export endpoint returned HTTP ${response.status}`);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("CAW export endpoint must return a JSON object");
  }
  return body as Record<string, unknown>;
}

function extractCawReceiptItems(body: Record<string, unknown>): unknown[] {
  const result = body.result && typeof body.result === "object" && !Array.isArray(body.result) ? (body.result as Record<string, unknown>) : null;
  const candidates = [
    body.receipts,
    body.items,
    body.auditLogs,
    body.logs,
    result?.receipts,
    result?.items,
    result?.auditLogs,
    result?.logs,
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate;
    }
  }
  return [];
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function optionalHex(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
}

function toRpcBlock(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function toBigIntBlock(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return BigInt(value);
  }
  throw new Error("chain log query requires a decimal blockNumber");
}

function normalizeChainValue(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeChainValue(item));
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      result[key] = normalizeChainValue(child);
    }
    return result;
  }
  return value;
}

function unconfiguredStatus(name: ProofProviderStatus["name"], reason: string): ProofProviderStatus {
  return {
    name,
    mode: "unconfigured",
    ready: false,
    reason,
  };
}
