import {
  ChainIndexerBackfillInputSchema,
  ChainIndexerBackfillResultSchema,
  type ChainIndexerBackfillInput,
  type JsonValue,
} from "@pactfuse/evidence-schema";
import type { ServiceCtx, ServiceResult } from "../types.js";
import { hashJson, newRequestId, toApiError } from "../util.js";
import { completeJob, enqueueJob, leaseNextJob, requeueExpiredLeasesForKinds, retryJob, type JobLease, type JobStatus } from "./jobs.js";
import { indexChainWindow, reconcileIndexedEvents } from "./service.js";

export const INDEX_CHAIN_WINDOW_JOB_KIND = "index-chain-window";

export type ChainIndexerWorkerCursorConfig = {
  cursorId: string;
  chainId: string;
  startBlock?: number;
  finalityDepth?: number;
  maxWindowBlocks?: number;
  address?: `0x${string}`;
  topics?: Array<`0x${string}` | null>;
};

export type IndexerWorkerOptions = {
  cursors: ChainIndexerWorkerCursorConfig[];
  leaseOwner?: string;
  retryDelayMs?: number;
  leaseTimeoutMs?: number;
};

export type IndexerWorkerLoopHandle = {
  started: boolean;
  stop: () => void;
};

export type IndexerWorkerRunResult =
  | { status: "idle"; seededJobs: number; requeuedLeases: number }
  | { status: "succeeded"; job: JobLease; seededJobs: number; requeuedLeases: number; queuedNextJobs: number }
  | { status: "retrying"; job: JobLease; seededJobs: number; requeuedLeases: number; reason: string }
  | { status: "blocked" | "failed"; job: JobLease; seededJobs: number; requeuedLeases: number; reason: string };

type Row = Record<string, unknown>;

export async function runIndexerWorkerOnce(ctx: ServiceCtx, options: IndexerWorkerOptions): Promise<IndexerWorkerRunResult> {
  const requeuedLeases = requeueExpiredIndexerLeases(ctx, options.leaseTimeoutMs);
  const seededJobs = (await seedChainIndexerBackfillJobs(ctx, options.cursors)).length;
  const lease = leaseNextJob(ctx, [INDEX_CHAIN_WINDOW_JOB_KIND], options.leaseOwner ?? newRequestId("indexer_worker"));
  if (!lease) {
    return { status: "idle", seededJobs, requeuedLeases };
  }
  const leaseToken = requireLeaseToken(lease);
  let input: ChainIndexerBackfillInput;
  try {
    input = parseIndexerJobPayload(lease);
  } catch (error) {
    return {
      status: "blocked",
      job: completeJob(ctx, lease.jobId, leaseToken, "blocked"),
      seededJobs,
      requeuedLeases,
      reason: error instanceof Error ? error.message : "invalid indexer job payload",
    };
  }
  let result: ServiceResult<unknown>;
  try {
    result = await indexChainWindow(input, ctx);
  } catch (error) {
    const requestId = newRequestId("indexer_worker_error");
    result = { ok: false, requestId, error: toApiError(error, requestId) };
  }
  if (!result.ok) {
    const reason = result.error.message;
    if (result.error.retryable) {
      return {
        status: "retrying",
        job: retryJob(ctx, lease.jobId, leaseToken, nextAttemptIso(ctx, options.retryDelayMs)),
        seededJobs,
        requeuedLeases,
        reason,
      };
    }
    const terminalStatus: Extract<JobStatus, "failed" | "blocked"> = result.error.code === "proof_blocked" ? "blocked" : "failed";
    return {
      status: terminalStatus,
      job: completeJob(ctx, lease.jobId, leaseToken, terminalStatus),
      seededJobs,
      requeuedLeases,
      reason,
    };
  }

  const parsedResult = ChainIndexerBackfillResultSchema.parse(result.data);
  let reconciledEventCount = 0;
  try {
    reconciledEventCount = reconcileIndexedEvents(ctx, {
      cursorId: parsedResult.cursor.cursorId,
      requestId: result.requestId,
    }).reconciledEventCount;
  } catch (error) {
    const requestId = newRequestId("indexer_reconcile_error");
    const apiError = toApiError(error, requestId);
    if (apiError.retryable) {
      return {
        status: "retrying",
        job: retryJob(ctx, lease.jobId, leaseToken, nextAttemptIso(ctx, options.retryDelayMs)),
        seededJobs,
        requeuedLeases,
        reason: apiError.message,
      };
    }
    const terminalStatus: Extract<JobStatus, "failed" | "blocked"> = apiError.code === "proof_blocked" ? "blocked" : "failed";
    return {
      status: terminalStatus,
      job: completeJob(ctx, lease.jobId, leaseToken, terminalStatus),
      seededJobs,
      requeuedLeases,
      reason: apiError.message,
    };
  }
  const completed = completeJob(ctx, lease.jobId, leaseToken, "succeeded");
  let queuedNextJobs = 0;
  if (parsedResult.cursor.lastIndexedBlock !== null && parsedResult.cursor.lagBlocks > 0) {
    const nextPayload: ChainIndexerBackfillInput["payload"] & { fromBlock: number; toBlock?: number } = {
      cursorId: parsedResult.cursor.cursorId,
      chainId: parsedResult.cursor.chainId,
      fromBlock: parsedResult.cursor.lastIndexedBlock + 1,
      toBlock: Math.min(
        parsedResult.cursor.finalizedHeadBlock,
        parsedResult.cursor.lastIndexedBlock + Number(input.payload.maxWindowBlocks ?? 2_000),
      ),
      finalityDepth: parsedResult.cursor.finalityDepth,
      maxWindowBlocks: input.payload.maxWindowBlocks ?? 2_000,
      topics: parsedResult.cursor.topics,
    };
    if (parsedResult.cursor.address !== null) {
      nextPayload.address = parsedResult.cursor.address;
    }
    queuedNextJobs = enqueueKnownIndexerWindow(ctx, nextPayload).length;
  }
  if (reconciledEventCount > 0) {
    ctx.logger.info(
      { cursorId: parsedResult.cursor.cursorId, reconciledEventCount },
      "reconciled indexed chain logs",
    );
  }
  return { status: "succeeded", job: completed, seededJobs, requeuedLeases, queuedNextJobs };
}

export async function seedChainIndexerBackfillJobs(ctx: ServiceCtx, cursors: ChainIndexerWorkerCursorConfig[]): Promise<JobLease[]> {
  const jobs: JobLease[] = [];
  for (const cursor of cursors) {
    jobs.push(...(await seedChainIndexerCursor(ctx, cursor)));
  }
  return jobs;
}

export function startIndexerWorkerLoop(
  ctx: ServiceCtx,
  options: IndexerWorkerOptions & { pollIntervalMs?: number },
): IndexerWorkerLoopHandle {
  if (options.cursors.length === 0) {
    return { started: false, stop: () => undefined };
  }
  let stopped = false;
  let running = false;
  const run = async () => {
    if (stopped || running) {
      return;
    }
    running = true;
    try {
      const result = await runIndexerWorkerOnce(ctx, options);
      ctx.logger.info({ result }, "pactfuse indexer worker tick");
    } catch (error) {
      ctx.logger.error({ error }, "pactfuse indexer worker tick failed");
    } finally {
      running = false;
    }
  };
  const timer = setInterval(run, options.pollIntervalMs ?? 5_000);
  void run();
  return {
    started: true,
    stop: () => {
      stopped = true;
      clearInterval(timer);
    },
  };
}

async function seedChainIndexerCursor(ctx: ServiceCtx, config: ChainIndexerWorkerCursorConfig): Promise<JobLease[]> {
  const payloadBase = normalizedCursorPayload(config);
  const cursor = readCursor(ctx, config.cursorId);
  const lastIndexedBlock = integerOrNull(cursor?.last_indexed_block);
  const fromBlock = lastIndexedBlock === null ? (config.startBlock ?? 0) : lastIndexedBlock + 1;
  let finalizedHeadBlock: number | null = null;
  try {
    const provider = await ctx.chain.status();
    if (provider.ready) {
      const head = await ctx.chain.getBlockNumber();
      if (Number.isInteger(head) && head >= 0) {
        finalizedHeadBlock = Math.max(0, head - payloadBase.finalityDepth + 1);
      }
    }
  } catch {
    finalizedHeadBlock = null;
  }
  const toBlock =
    finalizedHeadBlock === null ? undefined : Math.min(finalizedHeadBlock, fromBlock + payloadBase.maxWindowBlocks - 1);
  if (toBlock !== undefined && toBlock < fromBlock) {
    return [];
  }
  const payload: ChainIndexerBackfillInput["payload"] & { fromBlock: number; toBlock?: number } = {
    cursorId: payloadBase.cursorId,
    chainId: payloadBase.chainId,
    fromBlock,
    finalityDepth: payloadBase.finalityDepth,
    maxWindowBlocks: payloadBase.maxWindowBlocks,
    topics: payloadBase.topics,
  };
  if (payloadBase.address !== undefined) {
    payload.address = payloadBase.address;
  }
  if (toBlock !== undefined) {
    payload.toBlock = toBlock;
  }
  return enqueueKnownIndexerWindow(ctx, payload);
}

function enqueueKnownIndexerWindow(
  ctx: ServiceCtx,
  payload: ChainIndexerBackfillInput["payload"] & { fromBlock: number; toBlock?: number },
): JobLease[] {
  const parsed = ChainIndexerBackfillInputSchema.parse({
    idempotencyKey: indexerJobIdempotencyKey(payload),
    payload: compactIndexerPayload(payload),
  });
  return [
    enqueueJob(ctx, {
      kind: INDEX_CHAIN_WINDOW_JOB_KIND,
      dedupeKey: indexerJobDedupeKey(parsed.payload),
      payload: parsed as unknown as Record<string, JsonValue>,
    }),
  ];
}

function compactIndexerPayload(payload: ChainIndexerBackfillInput["payload"]): ChainIndexerBackfillInput["payload"] {
  return ChainIndexerBackfillInputSchema.parse({
    idempotencyKey: "indexer-compact-payload",
    payload: {
      cursorId: payload.cursorId,
      chainId: payload.chainId,
      finalityDepth: payload.finalityDepth,
      maxWindowBlocks: payload.maxWindowBlocks,
      ...(payload.fromBlock !== undefined ? { fromBlock: payload.fromBlock } : {}),
      ...(payload.toBlock !== undefined ? { toBlock: payload.toBlock } : {}),
      ...(payload.address !== undefined ? { address: payload.address } : {}),
      topics: payload.topics,
    },
  }).payload;
}

function normalizedCursorPayload(config: ChainIndexerWorkerCursorConfig): ChainIndexerBackfillInput["payload"] {
  return ChainIndexerBackfillInputSchema.parse({
    idempotencyKey: "indexer-normalize-cursor",
    payload: {
      cursorId: config.cursorId,
      chainId: config.chainId,
      finalityDepth: config.finalityDepth ?? 2,
      maxWindowBlocks: config.maxWindowBlocks ?? 2_000,
      ...(config.address ? { address: config.address } : {}),
      topics: config.topics ?? [],
    },
  }).payload;
}

function parseIndexerJobPayload(lease: JobLease): ChainIndexerBackfillInput {
  return ChainIndexerBackfillInputSchema.parse(lease.payload);
}

function indexerJobDedupeKey(payload: ChainIndexerBackfillInput["payload"]): string {
  return `${payload.cursorId}:${payload.fromBlock ?? "auto"}:${payload.toBlock ?? "auto"}:${hashJson(filterIdentity(payload)).slice(2, 18)}`;
}

function indexerJobIdempotencyKey(payload: ChainIndexerBackfillInput["payload"]): string {
  return `indexer-${hashJson({ kind: INDEX_CHAIN_WINDOW_JOB_KIND, payload }).slice(2, 34)}`;
}

function filterIdentity(payload: ChainIndexerBackfillInput["payload"]): JsonValue {
  return {
    chainId: payload.chainId,
    finalityDepth: payload.finalityDepth,
    maxWindowBlocks: payload.maxWindowBlocks,
    address: payload.address ?? null,
    topics: payload.topics,
  };
}

function readCursor(ctx: ServiceCtx, cursorId: string): Row | undefined {
  return ctx.db.sqlite.prepare("SELECT * FROM chain_indexer_cursors WHERE cursor_id = ?").get(cursorId) as Row | undefined;
}

function integerOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

function requireLeaseToken(lease: JobLease): string {
  if (!lease.leaseToken) {
    throw new Error("leased indexer job is missing a lease token");
  }
  return lease.leaseToken;
}

function nextAttemptIso(ctx: ServiceCtx, retryDelayMs = 5_000): string {
  return new Date(ctx.clock.now().getTime() + retryDelayMs).toISOString();
}

function requeueExpiredIndexerLeases(ctx: ServiceCtx, leaseTimeoutMs = 60_000): number {
  return requeueExpiredLeasesForKinds(ctx, [INDEX_CHAIN_WINDOW_JOB_KIND], new Date(ctx.clock.now().getTime() - leaseTimeoutMs).toISOString());
}
