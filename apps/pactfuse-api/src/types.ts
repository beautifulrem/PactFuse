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
  name: "chain" | "caw" | "mcp_lease";
  mode: "unconfigured" | "fixture" | "live";
  ready: boolean;
  reason: string;
  chainId?: string;
  endpoint?: string;
};

export type RequiredIndexerCursor = {
  cursorId: string;
  chainId: string;
  address?: string | null;
  topics?: Array<string | null>;
  finalityDepth?: number;
};

export type ChainClient = {
  status: () => Promise<ProofProviderStatus>;
  getBlockNumber: () => Promise<number>;
  getTransactionReceipt: (txHash: string) => Promise<Record<string, unknown>>;
  getLogs: (input: Record<string, unknown>) => Promise<Record<string, unknown>[]>;
  readContract: (input: {
    address: string;
    abi: readonly unknown[];
    functionName: string;
    args?: readonly unknown[];
    blockNumber?: number;
  }) => Promise<unknown>;
};

export type CawReceiptSource = {
  status: () => Promise<ProofProviderStatus>;
  fetchReceiptBundle: (input: Record<string, unknown>) => Promise<Record<string, unknown>>;
};

export type McpLeaseExecutionInput = {
  sessionId: string;
  leaseRunId: string;
  spendId: string;
  payer: string;
  artifactHash: string;
  targetRepo: string;
  targetCommit: string;
};

export type McpJsonRpcFrame = {
  method: "tools/list" | "tools/call";
  request: Record<string, unknown>;
  response: Record<string, unknown>;
};

export type McpLeaseExecutionResult = {
  toolName: string;
  toolsList: McpJsonRpcFrame;
  toolsCall: McpJsonRpcFrame;
  output: Record<string, unknown>;
};

export type McpLeaseClient = {
  status: () => Promise<ProofProviderStatus>;
  executeCleanLease: (input: McpLeaseExecutionInput) => Promise<McpLeaseExecutionResult>;
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

export type ApiSecurityConfig = {
  operatorToken: string | null;
  challengeSubmitterToken: string | null;
  artifactSignerToken: string | null;
  allowInsecureMissingRoleTokens: boolean;
  rateLimitWindowMs: number;
  defaultRateLimitMax: number;
  sessionCreateRateLimitMax: number;
  sourceChallengeRateLimitMax: number;
};

export type ServiceCtx = {
  db: PactFuseDb;
  verifier: EvidenceVerifier;
  chain: ChainClient;
  caw: CawReceiptSource;
  mcpLease: McpLeaseClient;
  templates: PactTemplateRegistry;
  mcpAuditSecret: string | null;
  gateIngestSecret: string | null;
  cawIngestToken: string | null;
  apiSecurity: ApiSecurityConfig;
  requiredIndexerCursors: RequiredIndexerCursor[];
  clock: Clock;
  logger: Logger;
  config: LockedRuntimeConfig;
};

export type ServiceResult<T> =
  | { ok: true; requestId: string; data: T; evidenceEventId?: string }
  | { ok: false; requestId: string; error: ApiError };
