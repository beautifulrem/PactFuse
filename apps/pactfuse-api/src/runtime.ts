import pino from "pino";
import { openPactFuseDb } from "./db/index.js";
import {
  createLocalTemplateRegistry,
  createUnconfiguredCawReceiptSource,
  createUnconfiguredChainClient,
  createViemChainClient,
} from "./services/providers.js";
import { createVerifierAdapter } from "./services/verifier.js";
import type { Clock, Logger, ServiceCtx } from "./types.js";

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
    caw: createUnconfiguredCawReceiptSource(),
    templates: createLocalTemplateRegistry(),
    mcpAuditSecret: process.env.PACTFUSE_MCP_AUDIT_TOKEN ?? null,
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
