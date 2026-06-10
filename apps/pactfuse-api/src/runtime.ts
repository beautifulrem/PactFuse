import pino from "pino";
import { openPactFuseDb } from "./db/index.js";
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
