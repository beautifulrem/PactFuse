import pino from "pino";
import { openPactFuseDb } from "./db/index.js";
import {
  createLocalTemplateRegistry,
  createHttpsCawReceiptSource,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
  createViemChainClient,
} from "./services/providers.js";
import { createVerifierAdapter } from "./services/verifier.js";
import type { Clock, Logger, ServiceCtx } from "./types.js";

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

function numberEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

export function createServiceCtx(options: {
  dbPath: string;
  logger?: Logger;
  clock?: Clock;
}): ServiceCtx {
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
    templates: createLocalTemplateRegistry(),
    mcpAuditSecret: process.env.PACTFUSE_MCP_AUDIT_TOKEN ?? null,
    cawIngestToken: process.env.PACTFUSE_CAW_INGEST_TOKEN ?? null,
    apiSecurity: {
      operatorToken: process.env.PACTFUSE_OPERATOR_TOKEN ?? null,
      challengeSubmitterToken: process.env.PACTFUSE_CHALLENGE_SUBMITTER_TOKEN ?? null,
      artifactSignerToken: process.env.PACTFUSE_ARTIFACT_SIGNER_TOKEN ?? null,
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
