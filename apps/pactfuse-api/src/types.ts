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
  name: "chain" | "caw" | "caw_live" | "mcp_lease";
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

export type CawLivePactSubmitInput = {
  walletId: string;
  intent: string;
  originalIntent?: string;
  name?: string;
  recipeSlugs?: string[];
  spec: Record<string, unknown>;
};

export type CawLiveTransferInput = {
  walletId: string;
  destinationAddress: string;
  amount: string;
  tokenId?: string;
  chainId?: string;
  requestId?: string;
  sourceAddress?: string;
  sponsor?: boolean;
  gasProvider?: string;
  description?: string;
  fee?: Record<string, unknown> | null;
  pactApiKey: string;
};

export type CawLiveContractCallInput = {
  walletId: string;
  chainId: string;
  contractAddress: string;
  calldata: string;
  valueAtomic?: string;
  requestId?: string;
  sponsor?: boolean;
  gasProvider?: string;
  description?: string;
  fee?: Record<string, unknown> | null;
  pactApiKey: string;
};

export type CawLiveAuditInput = {
  walletId?: string;
  principalId?: string;
  action?: string;
  result?: "allowed" | "denied" | "pending" | "error";
  startTime?: string;
  endTime?: string;
  after?: string;
  before?: string;
  limit?: number;
};

export type CawLiveClient = {
  status: () => Promise<ProofProviderStatus>;
  getWallet: (walletId: string) => Promise<Record<string, unknown>>;
  submitPact: (input: CawLivePactSubmitInput) => Promise<Record<string, unknown>>;
  getPact: (pactId: string) => Promise<Record<string, unknown>>;
  transferToken: (input: CawLiveTransferInput) => Promise<Record<string, unknown>>;
  contractCall: (input: CawLiveContractCallInput) => Promise<Record<string, unknown>>;
  listAuditLogs: (input: CawLiveAuditInput) => Promise<Record<string, unknown>>;
};

export type McpLeaseExecutionInput = {
  sessionId: string;
  leaseRunId: string;
  spendId: string;
  payer: string;
  artifactHash: string;
  targetRepo: string;
  targetCommit: string;
  pinnedManifestTools: Array<Record<string, unknown>>;
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
  cawLive: CawLiveClient;
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
