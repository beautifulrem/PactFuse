import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicClient, http } from "viem";
import type {
  CawReceiptSource,
  ChainClient,
  PactTemplateBinding,
  PactTemplateRegistry,
  ProofProviderStatus,
} from "../types.js";
import { hashJson } from "../util.js";

const DEFAULT_TEMPLATES: Array<{ mode: PactTemplateBinding["mode"]; path: string }> = [
  { mode: "gate-paid-artifact-real", path: "../../../../pact-template/gate-paid-artifact-real.json" },
  { mode: "permit-payment-real", path: "../../../../pact-template/permit-payment-real.appendix.json" },
];

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
  };
}

export function createViemChainClient(input: { rpcUrl: string; chainId?: string | number }): ChainClient {
  const client = createPublicClient({ transport: http(input.rpcUrl) });
  const configuredChainId = input.chainId === undefined || input.chainId === "" ? undefined : String(input.chainId);
  return {
    async status() {
      try {
        const [, chainId] = await Promise.all([client.getBlockNumber(), client.getChainId()]);
        return {
          name: "chain",
          mode: "live",
          ready: true,
          reason: "chain RPC endpoint is configured",
          endpoint: input.rpcUrl,
          chainId: String(chainId),
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
      const blockNumber = toBigIntBlock(query.blockNumber);
      const logs = await client.getLogs({
        fromBlock: blockNumber,
        toBlock: blockNumber,
      });
      return logs.map((log) => normalizeChainValue(log) as Record<string, unknown>);
    },
  };
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
