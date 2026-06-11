import { readFileSync } from "node:fs";
import pino from "pino";
import { DeploymentRegistrySchema, type DeploymentRegistry } from "@pactfuse/evidence-schema";
import { openPactFuseDb } from "./db/index.js";
import {
  createCoboAgenticWalletClient,
  createLocalTemplateRegistry,
  createHttpJsonRpcMcpLeaseClient,
  createHttpsCawReceiptSource,
  createUnconfiguredCawLiveClient,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
  createUnconfiguredMcpLeaseClient,
  createViemChainClient,
} from "./services/providers.js";
import { createVerifierAdapter } from "./services/verifier.js";
import type { Clock, Logger, ServiceCtx } from "./types.js";
import type { ChainIndexerWorkerCursorConfig, IndexerWorkerOptions } from "./services/indexer-worker.js";

function createRuntimeCawSource() {
  if (!process.env.PACTFUSE_CAW_EXPORT_URL) {
    return createUnconfiguredCawReceiptSource();
  }
  const input: Parameters<typeof createHttpsCawReceiptSource>[0] = {
    exportUrl: process.env.PACTFUSE_CAW_EXPORT_URL,
  };
  const apiKey = process.env.PACTFUSE_CAW_API_KEY ?? process.env.AGENT_WALLET_API_KEY;
  const walletId = process.env.PACTFUSE_CAW_WALLET_ID ?? process.env.AGENT_WALLET_WALLET_ID;
  if (apiKey) {
    input.apiKey = apiKey;
  }
  if (walletId) {
    input.walletId = walletId;
  }
  if (process.env.PACTFUSE_CAW_EXPORT_LIMIT) {
    input.limit = Number(process.env.PACTFUSE_CAW_EXPORT_LIMIT);
  }
  return createHttpsCawReceiptSource(input);
}

function createRuntimeMcpLeaseClient() {
  if (!process.env.PACTFUSE_LEASE_MCP_URL) {
    return createUnconfiguredMcpLeaseClient();
  }
  return createHttpJsonRpcMcpLeaseClient({
    endpointUrl: process.env.PACTFUSE_LEASE_MCP_URL,
    toolName: process.env.PACTFUSE_LEASE_MCP_TOOL_NAME ?? "pactfuse_code_scan",
    timeoutMs: numberEnv("PACTFUSE_LEASE_MCP_TIMEOUT_MS", 10_000),
  });
}

function createRuntimeCawLiveClient() {
  const baseUrl = process.env.AGENT_WALLET_API_URL ?? process.env.PACTFUSE_CAW_LIVE_API_URL;
  const apiKey = process.env.AGENT_WALLET_API_KEY ?? process.env.PACTFUSE_CAW_LIVE_API_KEY;
  if (!baseUrl || !apiKey) {
    return createUnconfiguredCawLiveClient();
  }
  const clientInput: Parameters<typeof createCoboAgenticWalletClient>[0] = {
    baseUrl,
    apiKey,
    timeoutMs: numberEnv("PACTFUSE_CAW_LIVE_TIMEOUT_MS", 10_000),
  };
  const walletId = process.env.AGENT_WALLET_WALLET_ID ?? process.env.PACTFUSE_CAW_LIVE_WALLET_ID;
  if (walletId) {
    clientInput.walletId = walletId;
  }
  return createCoboAgenticWalletClient(clientInput);
}

function createRuntimeDeploymentRegistry(): DeploymentRegistry | undefined {
  const rawJson = process.env.PACTFUSE_DEPLOYMENT_REGISTRY_JSON;
  const registryPath = process.env.PACTFUSE_DEPLOYMENT_REGISTRY_PATH;
  if (!rawJson && !registryPath) {
    return undefined;
  }
  const raw = rawJson ?? readFileSync(String(registryPath), "utf8");
  return DeploymentRegistrySchema.parse(JSON.parse(raw));
}

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

function optionalNumberEnv(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) {
    return undefined;
  }
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : undefined;
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  return !["0", "false", "no", "off"].includes(raw.toLowerCase());
}

function hexEnv(name: string): `0x${string}` | undefined {
  const raw = process.env[name];
  return raw && /^0x[0-9a-fA-F]+$/.test(raw) ? (raw as `0x${string}`) : undefined;
}

function topicsEnv(name: string): Array<`0x${string}` | null> {
  const raw = process.env[name];
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => (part.toLowerCase() === "null" ? null : (part as `0x${string}`)))
    .filter((part): part is `0x${string}` | null => part === null || /^0x[0-9a-fA-F]+$/.test(part));
}

export function createRuntimeIndexerWorkerOptions():
  | (IndexerWorkerOptions & { pollIntervalMs: number })
  | null {
  const chainId = process.env.PACTFUSE_CHAIN_ID;
  const rpcConfigured = Boolean(process.env.PACTFUSE_CHAIN_RPC_URL);
  const enabled = booleanEnv("PACTFUSE_INDEXER_ENABLED", rpcConfigured && Boolean(chainId));
  if (!enabled || !chainId) {
    return null;
  }
  const startBlock = optionalNumberEnv("PACTFUSE_INDEXER_START_BLOCK");
  const address = hexEnv("PACTFUSE_INDEXER_ADDRESS");
  const cursor: ChainIndexerWorkerCursorConfig = {
    cursorId: process.env.PACTFUSE_INDEXER_CURSOR_ID ?? "gate:indexer",
    chainId,
    finalityDepth: numberEnv("PACTFUSE_INDEXER_FINALITY_DEPTH", numberEnv("PACTFUSE_FINALITY_DEPTH", 2)),
    maxWindowBlocks: numberEnv("PACTFUSE_INDEXER_MAX_WINDOW_BLOCKS", 2_000),
    topics: topicsEnv("PACTFUSE_INDEXER_TOPICS"),
  };
  if (startBlock !== undefined) {
    cursor.startBlock = startBlock;
  }
  if (address) {
    cursor.address = address;
  }
  return {
    cursors: [cursor],
    leaseOwner: process.env.PACTFUSE_INDEXER_WORKER_ID ?? "indexer-worker",
    retryDelayMs: numberEnv("PACTFUSE_INDEXER_RETRY_MS", 5_000),
    leaseTimeoutMs: numberEnv("PACTFUSE_INDEXER_LEASE_TIMEOUT_MS", 60_000),
    pollIntervalMs: numberEnv("PACTFUSE_INDEXER_POLL_MS", 5_000),
  };
}

export function createServiceCtx(options: {
  dbPath: string;
  logger?: Logger;
  clock?: Clock;
  requiredIndexerCursors?: ChainIndexerWorkerCursorConfig[];
}): ServiceCtx {
  const runtimeIndexerOptions = createRuntimeIndexerWorkerOptions();
  return {
    db: openPactFuseDb(options.dbPath),
    verifier: createVerifierAdapter(),
    chain: process.env.PACTFUSE_CHAIN_RPC_URL
      ? createViemChainClient({
          rpcUrl: process.env.PACTFUSE_CHAIN_RPC_URL,
          ...(process.env.PACTFUSE_CHAIN_ID ? { chainId: process.env.PACTFUSE_CHAIN_ID } : {}),
        })
      : createUnconfiguredChainClient(),
    caw: createRuntimeCawSource(),
    cawLive: createRuntimeCawLiveClient(),
    mcpLease: createRuntimeMcpLeaseClient(),
    templates: createLocalTemplateRegistry(),
    mcpAuditSecret: process.env.PACTFUSE_MCP_AUDIT_TOKEN ?? null,
    gateIngestSecret: process.env.PACTFUSE_GATE_INGEST_TOKEN ?? null,
    cawIngestToken: process.env.PACTFUSE_CAW_INGEST_TOKEN ?? null,
    deploymentRegistry: createRuntimeDeploymentRegistry(),
    requiredIndexerCursors: options.requiredIndexerCursors ?? runtimeIndexerOptions?.cursors ?? [],
    apiSecurity: {
      operatorToken: process.env.PACTFUSE_OPERATOR_TOKEN ?? null,
      challengeSubmitterToken: process.env.PACTFUSE_CHALLENGE_SUBMITTER_TOKEN ?? null,
      artifactSignerToken: process.env.PACTFUSE_ARTIFACT_SIGNER_TOKEN ?? null,
      allowInsecureMissingRoleTokens: booleanEnv("PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS", false),
      rateLimitWindowMs: numberEnv("PACTFUSE_RATE_LIMIT_WINDOW_MS", 60_000),
      defaultRateLimitMax: numberEnv("PACTFUSE_RATE_LIMIT_MAX_REQUESTS", 600),
      sessionCreateRateLimitMax: numberEnv("PACTFUSE_SESSION_RATE_LIMIT_MAX_REQUESTS", 60),
      sourceChallengeRateLimitMax: numberEnv("PACTFUSE_CHALLENGE_RATE_LIMIT_MAX_REQUESTS", 20),
    },
    clock: options.clock ?? { now: () => new Date() },
    logger: options.logger ?? pino({ name: "pactfuse-api" }),
    config: {
      claimMode: "simulated",
      paymentMode: "mocked",
      tokenMode: "local-mocked",
      identityMode: "pending",
      winnerClaimAllowed: false,
    },
  };
}
