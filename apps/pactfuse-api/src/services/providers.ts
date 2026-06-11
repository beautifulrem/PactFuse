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
