import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
    async getTransactionReceipt() {
      throw new Error("chain provider is unconfigured; cannot verify transaction receipt");
    },
    async getLogs() {
      throw new Error("chain provider is unconfigured; cannot verify event logs");
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

function unconfiguredStatus(name: ProofProviderStatus["name"], reason: string): ProofProviderStatus {
  return {
    name,
    mode: "unconfigured",
    ready: false,
    reason,
  };
}
