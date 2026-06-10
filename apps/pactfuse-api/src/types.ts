import type { DatabaseSync } from "node:sqlite";
import type { ApiError } from "@pactfuse/evidence-schema";
import type * as schema from "./db/schema.js";

export type Logger = {
  info: (obj: unknown, msg?: string) => void;
  warn: (obj: unknown, msg?: string) => void;
  error: (obj: unknown, msg?: string) => void;
};

export type Clock = {
  now: () => Date;
};

export type PactFuseDb = {
  sqlite: DatabaseSync;
  drizzleSchema: typeof schema;
};

export type LockedRuntimeConfig = {
  claimMode: "simulated";
  paymentMode: "mocked";
  tokenMode: "local-mocked";
  identityMode: "pending";
  winnerClaimAllowed: false;
};

export type EvidenceVerifier = {
  verify: (receipt: unknown, options?: Record<string, unknown>) => Promise<Record<string, unknown>>;
};

export type ProofProviderStatus = {
  name: "chain" | "caw";
  mode: "unconfigured" | "fixture" | "live";
  ready: boolean;
  reason: string;
  chainId?: string;
  endpoint?: string;
};

export type ChainClient = {
  status: () => Promise<ProofProviderStatus>;
  getTransactionReceipt: (txHash: string) => Promise<Record<string, unknown>>;
  getLogs: (input: Record<string, unknown>) => Promise<Record<string, unknown>[]>;
};

export type CawReceiptSource = {
  status: () => Promise<ProofProviderStatus>;
  fetchReceiptBundle: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
};

export type PactTemplateBinding = {
  mode: "gate-paid-artifact-real" | "permit-payment-real";
  sourcePath: string;
  templateHash: `0x${string}`;
};

export type PactTemplateRegistry = {
  list: () => PactTemplateBinding[];
  require: (mode: PactTemplateBinding["mode"]) => PactTemplateBinding;
};

export type ServiceCtx = {
  db: PactFuseDb;
  verifier: EvidenceVerifier;
  chain: ChainClient;
  caw: CawReceiptSource;
  templates: PactTemplateRegistry;
  clock: Clock;
  logger: Logger;
  config: LockedRuntimeConfig;
};

export type ServiceResult<T> =
  | { ok: true; requestId: string; data: T; evidenceEventId?: string }
  | { ok: false; requestId: string; error: ApiError };
