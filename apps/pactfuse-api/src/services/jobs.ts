import type { JsonValue } from "@pactfuse/evidence-schema";
import type { ServiceCtx } from "../types.js";
import { hashJson, newRequestId } from "../util.js";
import { canonicalizeJson } from "@pactfuse/evidence-schema";

type Row = Record<string, unknown>;

export type JobStatus = "queued" | "leased" | "succeeded" | "failed" | "blocked";

export type EnqueueJobInput = {
  sessionId?: string | null;
  kind: string;
  dedupeKey: string;
  payload: Record<string, JsonValue>;
  nextAttemptAt?: string | null;
};

export type JobLease = {
  jobId: string;
  sessionId: string | null;
  kind: string;
  status: JobStatus;
  dedupeKey: string;
  attempts: number;
  payload: Record<string, JsonValue>;
  lockedAt: string | null;
  leaseToken: string | null;
};

export function enqueueJob(ctx: ServiceCtx, input: EnqueueJobInput): JobLease {
  const createdAt = ctx.clock.now().toISOString();
  const jobId = hashJson({ kind: input.kind, dedupeKey: input.dedupeKey });
  ctx.db.sqlite
    .prepare(
      `INSERT OR IGNORE INTO jobs
        (job_id, session_id, kind, status, dedupe_key, attempts, next_attempt_at, locked_at, payload_json, created_at)
       VALUES (?, ?, ?, 'queued', ?, 0, ?, NULL, ?, ?)`,
    )
    .run(
      jobId,
      input.sessionId ?? null,
      input.kind,
      input.dedupeKey,
      input.nextAttemptAt ?? createdAt,
      canonicalizeJson(input.payload),
      createdAt,
    );
  return readJob(ctx, jobId);
}

export function leaseNextJob(ctx: ServiceCtx, kinds: string[], leaseOwner = newRequestId("worker")): JobLease | null {
  if (kinds.length === 0) {
    return null;
  }
  const now = ctx.clock.now().toISOString();
  const placeholders = kinds.map(() => "?").join(", ");
  ctx.db.sqlite.exec("BEGIN IMMEDIATE");
  try {
    const row = ctx.db.sqlite
      .prepare(
        `SELECT *
         FROM jobs
         WHERE status = 'queued'
           AND kind IN (${placeholders})
           AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
         ORDER BY created_at ASC, job_id ASC
         LIMIT 1`,
      )
      .get(...kinds, now) as Row | undefined;
    if (!row) {
      ctx.db.sqlite.exec("COMMIT");
      return null;
    }
    const leaseToken = hashJson({
      jobId: String(row.job_id),
      leaseOwner,
      now,
      requestId: newRequestId("lease"),
    });
    ctx.db.sqlite
      .prepare("UPDATE jobs SET status = 'leased', locked_at = ?, attempts = attempts + 1 WHERE job_id = ? AND status = 'queued'")
      .run(`${now}|${leaseOwner}|${leaseToken}`, String(row.job_id));
    ctx.db.sqlite.exec("COMMIT");
    return readJob(ctx, String(row.job_id));
  } catch (error) {
    ctx.db.sqlite.exec("ROLLBACK");
    throw error;
  }
}

export function completeJob(
  ctx: ServiceCtx,
  jobId: string,
  leaseToken: string,
  status: Extract<JobStatus, "succeeded" | "failed" | "blocked">,
): JobLease {
  const result = ctx.db.sqlite
    .prepare(
      `UPDATE jobs
       SET status = ?, locked_at = NULL
       WHERE job_id = ?
         AND status = 'leased'
         AND locked_at LIKE ?`,
    )
    .run(status, jobId, `%|${leaseToken}`);
  if (Number(result.changes) !== 1) {
    throw new Error("job lease token mismatch or job is no longer leased");
  }
  return readJob(ctx, jobId);
}

export function requeueExpiredLeases(ctx: ServiceCtx, olderThanIso: string): number {
  const result = ctx.db.sqlite
    .prepare(
      `UPDATE jobs
       SET status = 'queued', locked_at = NULL
       WHERE status = 'leased' AND locked_at < ?`,
    )
    .run(olderThanIso);
  return Number(result.changes);
}

function readJob(ctx: ServiceCtx, jobId: string): JobLease {
  const row = ctx.db.sqlite.prepare("SELECT * FROM jobs WHERE job_id = ?").get(jobId) as Row | undefined;
  if (!row) {
    throw new Error(`job not found: ${jobId}`);
  }
  return {
    jobId: String(row.job_id),
    sessionId: row.session_id === null ? null : String(row.session_id),
    kind: String(row.kind),
    status: row.status as JobStatus,
    dedupeKey: String(row.dedupe_key),
    attempts: Number(row.attempts),
    payload: JSON.parse(String(row.payload_json)) as Record<string, JsonValue>,
    lockedAt: row.locked_at === null ? null : String(row.locked_at),
    leaseToken: row.locked_at === null ? null : parseLeaseToken(String(row.locked_at)),
  };
}

function parseLeaseToken(lockedAt: string): string | null {
  const parts = lockedAt.split("|");
  return parts.length === 3 ? (parts[2] ?? null) : null;
}
