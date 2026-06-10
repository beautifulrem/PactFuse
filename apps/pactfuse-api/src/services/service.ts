import {
  AgentTranscriptViewSchema,
  ArtifactPreflightPayloadSchema,
  ArtifactRefundPayloadSchema,
  CawOperationBuildPayloadSchema,
  CawReceiptIngestPayloadSchema,
  CreateSessionInputSchema,
  EvidenceEventSchema,
  Hex32Schema,
  JudgeCheckViewSchema,
  LeaseExecutePayloadSchema,
  LOCKED_RUNTIME_MODES,
  QuotePayloadSchema,
  ReplayBundleViewSchema,
  RunnerHeartbeatViewSchema,
  SessionScopedEnvelopeSchema,
  SessionViewSchema,
  SourceChallengePayloadSchema,
  SourceRegisterPayloadSchema,
  SpendRegisterPayloadSchema,
  VerifierRunViewSchema,
  VerifyEvidencePayloadSchema,
  canonicalizeJson,
  type CreateSessionInput,
  type EvidenceEvent,
  type JsonValue,
  type JudgeCheckView,
  type ReplayBundleView,
  type SessionScopedEnvelope,
  type SessionView,
  type VerifierRunView,
} from "@pactfuse/evidence-schema";
import type { ServiceCtx, ServiceResult } from "../types.js";
import {
  ZERO_HASH,
  conflictError,
  hashJson,
  newRequestId,
  notFoundError,
  nowIso,
  parseStrict,
  proofPendingError,
  sha256Hex,
  toApiError,
} from "../util.js";

type Row = Record<string, unknown>;

const JUDGE_ROWS = [
  ["caw_boundary", "CAW boundary", "pending CAW deny/allow receipts are not live"],
  ["source_challenge", "Source challenge", "pending SourceChallenged public-chain log"],
  ["ab_trip", "A/B trip", "pending SpendTripped public-chain logs"],
  ["c_settlement", "C settlement", "pending SpendSettled public-chain log"],
  ["artifact_access", "Artifact access", "pending bearer-token artifact access proof"],
  ["lease_execution", "Lease execution", "pending MCP transcript and lease run proof"],
] as const;

const idempotencyLocks = new Map<string, Promise<void>>();

export async function createSession(input: CreateSessionInput, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const parsed = parseStrict(CreateSessionInputSchema, input);
  return withIdempotency(ctx, "sessions:create", parsed.idempotencyKey, parsed, async (requestId) => {
    const createdAt = ctx.clock.now().toISOString();
    const runConfigHash = hashJson(parsed.payload);
    const sessionId = sha256Hex(`pactfuse-session:${parsed.idempotencyKey}:${runConfigHash}`);
    ctx.db.sqlite
      .prepare(
        `INSERT OR IGNORE INTO sessions
          (session_id, run_config_hash, run_config_json, modes_json, created_at, latest_event_seq, latest_proof_event_hash)
         VALUES (?, ?, ?, ?, ?, 0, ?)`,
      )
      .run(
        sessionId,
        runConfigHash,
        canonicalizeJson(parsed.payload),
        canonicalizeJson(LOCKED_RUNTIME_MODES),
        createdAt,
        ZERO_HASH,
      );
    insertPendingJudgeRows(ctx, sessionId, createdAt);
    const event = appendEvidenceEvent(ctx, {
      sessionId,
      authority: "operator",
      kind: "session.created",
      payload: {
        runConfigHash,
        modes: LOCKED_RUNTIME_MODES,
        winnerClaimAllowed: false,
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        sessionId,
        runConfigHash,
        modes: LOCKED_RUNTIME_MODES,
        winnerClaimAllowed: false,
        createdAt,
      },
    };
  });
}

export async function getSession(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<SessionView>> {
  const requestId = newRequestId("get_session");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  const row = getSessionRow(ctx, parsedSessionId);
  if (!row) {
    return { ok: false, requestId, error: notFoundError(requestId, "session") };
  }
  return {
    ok: true,
    requestId,
    data: SessionViewSchema.parse({
      sessionId: row.session_id,
      runConfigHash: row.run_config_hash,
      modes: JSON.parse(String(row.modes_json)),
      winnerClaimAllowed: false,
      createdAt: row.created_at,
      eventCount: Number(row.latest_event_seq),
      latestEventSeq: Number(row.latest_event_seq),
    }),
  };
}

export async function registerSignedSource(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(SourceRegisterPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("sources:register", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    ctx.db.sqlite
      .prepare(
        `INSERT OR REPLACE INTO sources
          (source_id, session_id, source_hash, manifest_url, manifest_hash, issuer, signature, capability_vector_json, proof_status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
      )
      .run(
        payload.sourceId,
        envelope.sessionId,
        payload.sourceHash,
        payload.manifestUrl,
        payload.manifestHash,
        payload.issuer ?? null,
        payload.signature ?? null,
        canonicalizeJson(payload.capabilityVector),
        createdAt,
      );
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "source.registered",
      payload: {
        sourceId: payload.sourceId,
        sourceHash: payload.sourceHash,
        manifestHash: payload.manifestHash,
        proofStatus: "pending",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { sourceHash: payload.sourceHash, status: "pending", winnerClaimAllowed: false },
    };
  });
}

export async function challengeSource(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(SourceChallengePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("sources:challenge", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const challengeId = hashJson({ sessionId: envelope.sessionId, payload, createdAt });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO source_challenges
          (challenge_id, session_id, source_hash, reason_hash, evidence_ref, status, created_at)
         VALUES (?, ?, ?, ?, ?, 'pending_chain_log', ?)`,
      )
      .run(challengeId, envelope.sessionId, payload.sourceHash, payload.reasonHash, payload.evidenceRef ?? null, createdAt);
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "source.challenge.pending",
      payload: {
        challengeId,
        sourceHash: payload.sourceHash,
        reasonHash: payload.reasonHash,
        status: "pending_chain_log",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        challengeId,
        status: "pending_chain_log",
        proofAuthority: false,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function registerSourceBoundSpends(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(SpendRegisterPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("spends:register-batch", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    for (const spend of payload.spends) {
      ctx.db.sqlite
        .prepare(
          `INSERT OR REPLACE INTO spends
            (spend_id, session_id, pact_id, tool_id, payer, agent_wallet, source_hashes_json, max_price_atomic, nonce, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered_pending_chain_log', ?)`,
        )
        .run(
          spend.spendId,
          envelope.sessionId,
          spend.pactId,
          spend.toolId,
          spend.payer,
          spend.agentWallet,
          canonicalizeJson(spend.sourceHashes),
          spend.maxPriceAtomic,
          spend.nonce,
          createdAt,
        );
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "spend.registered",
      payload: {
        spendIds: payload.spends.map((spend) => spend.spendId),
        status: "registered_pending_chain_log",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        spendIds: payload.spends.map((spend) => spend.spendId),
        status: "registered_pending_chain_log",
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function buildCawOperation(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawOperationBuildPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:operations:build", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const operationId = hashJson({ sessionId: envelope.sessionId, payload, requestId });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO caw_receipt_operations
          (operation_id, session_id, spend_id, operation_kind, target, selector, value_atomic, request_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'built_mocked', ?)`,
      )
      .run(
        operationId,
        envelope.sessionId,
        payload.spendId,
        payload.operationKind,
        payload.target ?? null,
        payload.selector ?? null,
        payload.valueAtomic,
        canonicalizeJson(payload),
        createdAt,
      );
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "advisory",
      kind: "caw.operation.built",
      payload: {
        operationId,
        operationKind: payload.operationKind,
        status: "built_mocked",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { operationId, status: "built_mocked", winnerClaimAllowed: false },
    };
  });
}

export async function ingestCawReceiptBundle(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawReceiptIngestPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:receipts:ingest", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const receiptBundleHash = hashJson(payload.receipts);
    const createdAt = ctx.clock.now().toISOString();
    if (payload.operationId) {
      ctx.db.sqlite
        .prepare("UPDATE caw_receipt_operations SET receipt_bundle_hash = ?, status = ? WHERE operation_id = ? AND session_id = ?")
        .run(receiptBundleHash, payload.manual ? "fixture_manual_receipt" : "ingested_pending_proof", payload.operationId, envelope.sessionId);
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "advisory",
      kind: "caw.receipt.ingested.fixture",
      payload: {
        receiptBundleHash,
        sourceLabel: payload.sourceLabel,
        manual: payload.manual,
        proofAuthority: false,
        status: payload.manual ? "fixture_manual_receipt" : "ingested_pending_proof",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        receiptBundleHash,
        status: payload.manual ? "fixture_manual_receipt" : "ingested_pending_proof",
        proofAuthority: false,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function runArtifactPreflight(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(ArtifactPreflightPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("artifacts:preflight", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const preflightId = hashJson({ sessionId: envelope.sessionId, payload, requestId });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_preflights
          (preflight_id, session_id, spend_id, artifact_hash_preview, endpoint_url, price_disclosure_hash, source_state_snapshot_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_live_delivery', ?)`,
      )
      .run(
        preflightId,
        envelope.sessionId,
        payload.spendId,
        payload.artifactHashPreview,
        payload.endpointUrl,
        payload.priceDisclosureHash,
        payload.sourceStateSnapshotHash,
        createdAt,
      );
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "artifact.preflight.pending",
      payload: { preflightId, spendId: payload.spendId, status: "pending_live_delivery" },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { preflightId, status: "pending_live_delivery", winnerClaimAllowed: false },
    };
  });
}

export async function signArtifactQuote(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(QuotePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("quotes:sign", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const quoteHash = hashJson({
      sessionId: envelope.sessionId,
      ...payload,
      modes: LOCKED_RUNTIME_MODES,
    });
    const quoteId = hashJson({ quoteHash, requestId });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO quotes
          (quote_id, session_id, spend_id, artifact_commitment, price_atomic, quote_nonce, valid_until_block, quote_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'mocked_not_chain_settleable', ?)`,
      )
      .run(
        quoteId,
        envelope.sessionId,
        payload.spendId,
        payload.artifactCommitment,
        payload.priceAtomic,
        payload.quoteNonce,
        payload.validUntilBlock,
        quoteHash,
        createdAt,
      );
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "advisory",
      kind: "quote.signed.mocked",
      payload: { quoteId, quoteHash, status: "mocked_not_chain_settleable" },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { quoteId, quoteHash, status: "mocked_not_chain_settleable", winnerClaimAllowed: false },
    };
  });
}

export async function refundUndeliveredArtifact(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(ArtifactRefundPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("artifacts:refund", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "artifact.refund.pending",
      payload: { spendId: payload.spendId, reason: payload.reason, status: "pending_live_settlement" },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { status: "pending_live_settlement", winnerClaimAllowed: false },
    };
  });
}

export async function executeLease(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(LeaseExecutePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("lease:execute", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const leaseRunId = hashJson({ sessionId: envelope.sessionId, payload, requestId });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO lease_runs
          (lease_run_id, session_id, spend_id, target_repo, target_commit, status, transcript_hash, created_at)
         VALUES (?, ?, ?, ?, ?, 'blocked_missing_finalized_settlement', NULL, ?)`,
      )
      .run(leaseRunId, envelope.sessionId, payload.spendId, payload.targetRepo, payload.targetCommit, createdAt);
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "lease.execution.blocked",
      payload: {
        leaseRunId,
        spendId: payload.spendId,
        status: "blocked_missing_finalized_settlement",
        winnerClaimAllowed: false,
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        leaseRunId,
        status: "blocked_missing_finalized_settlement",
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function verifyEvidenceForSession(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<VerifierRunView>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(VerifyEvidencePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("evidence:verify", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const verifierInput = payload.receipt ?? payload.replayBundle ?? {};
    const raw =
      payload.receipt || payload.replayBundle
        ? await ctx.verifier.verify(verifierInput, { cliMode: payload.schemaOnly ? "schema-only" : "proof-chip" })
        : {
            schemaOk: false,
            proofChipAllowed: false,
            winnerClaimAllowed: false,
            requestedWinnerClaimAllowed: false,
            finalVerifierComplete: false,
            warnings: [],
            errors: ["missing receipt or replayBundle; fail closed"],
          };
    const eventLogErrors = verifyEventLogIntegrity(ctx, envelope.sessionId);
    const rawErrors = toStringArray(raw.errors);
    const view = VerifierRunViewSchema.parse({
      sessionId: envelope.sessionId,
      schemaOk: Boolean(raw.schemaOk) && eventLogErrors.length === 0,
      proofChipAllowed: false,
      winnerClaimAllowed: false,
      requestedWinnerClaimAllowed: Boolean(raw.requestedWinnerClaimAllowed),
      finalVerifierComplete: false,
      errors: [...rawErrors, ...eventLogErrors],
      warnings: [
        ...toStringArray(raw.warnings),
        "P0 route wraps the structural verifier fail-closed; final chain/signature/hash verifier is incomplete",
      ],
      raw: jsonRecord(raw),
    });
    const inputHash = hashJson(verifierInput);
    const verifierRunId = hashJson({ sessionId: envelope.sessionId, inputHash, requestId });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO verifier_runs
          (verifier_run_id, session_id, input_hash, result_json, schema_ok, proof_chip_allowed, winner_claim_allowed, final_verifier_complete, created_at)
         VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)`,
      )
      .run(verifierRunId, envelope.sessionId, inputHash, canonicalizeJson(view), view.schemaOk ? 1 : 0, ctx.clock.now().toISOString());
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "verifier.fail_closed",
      payload: {
        verifierRunId,
        schemaOk: view.schemaOk,
        proofChipAllowed: false,
        winnerClaimAllowed: false,
        finalVerifierComplete: false,
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: view,
    };
  });
}

export async function readJudgeCheck(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<JudgeCheckView>> {
  const requestId = newRequestId("judge_check");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  const data = readJudgeCheckData(parsedSessionId, ctx);
  return { ok: true, requestId, data };
}

export async function assembleReplayBundle(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<ReplayBundleView>> {
  const requestId = newRequestId("replay_bundle");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  const events = listEvents(ctx, parsedSessionId, 0, 200);
  const data = ReplayBundleViewSchema.parse({
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId: parsedSessionId,
    summaryMode: true,
    winnerClaimAllowed: false,
    eventRoot: hashJson(events.map((event) => event.eventHash)),
    events,
    judgeCheck: readJudgeCheckData(parsedSessionId, ctx),
  });
  return { ok: true, requestId, data };
}

export async function readRunnerHeartbeat(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("runner_heartbeat");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  return {
    ok: true,
    requestId,
    data: RunnerHeartbeatViewSchema.parse({
      sessionId: parsedSessionId,
      status: "pending",
      winnerClaimAllowed: false,
      updatedAt: nowIso(),
    }),
  };
}

export async function readAgentTranscript(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("agent_transcript");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  return {
    ok: true,
    requestId,
    data: AgentTranscriptViewSchema.parse({
      sessionId: parsedSessionId,
      status: "pending",
      transcriptHash: null,
      winnerClaimAllowed: false,
    }),
  };
}

export async function readArtifactAccess(
  input: {
    sessionId: string;
    spendId: string;
    payer: string;
    artifactHash: string;
    bearerToken: string | null;
  },
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("artifact_access");
  const sessionId = parseStrict(Hex32Schema, input.sessionId);
  const spendId = parseStrict(Hex32Schema, input.spendId);
  const artifactHash = parseStrict(Hex32Schema, input.artifactHash);
  assertSession(ctx, sessionId, requestId);
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT token_hash, status
       FROM artifact_access_tokens
       WHERE session_id = ? AND spend_id = ? AND payer = ? AND artifact_hash = ?`,
    )
    .all(sessionId, spendId, input.payer, artifactHash) as Row[];
  if (rows.length === 0) {
    return {
      ok: false,
      requestId,
      error: proofPendingError(requestId, "artifact access is pending live settlement and bearer-token proof"),
    };
  }
  if (!input.bearerToken) {
    return {
      ok: false,
      requestId,
      error: proofPendingError(requestId, "artifact bearer token is required but no proof-valid token is active"),
    };
  }
  const tokenHash = sha256Hex(input.bearerToken);
  const active = rows.find((row) => row.status === "active" && row.token_hash === tokenHash);
  if (!active) {
    return {
      ok: false,
      requestId,
      error: proofPendingError(requestId, "artifact bearer token is not backed by a proof-valid active access row"),
    };
  }
  return {
    ok: true,
    requestId,
    data: {
      sessionId,
      spendId,
      artifactHash,
      status: "available",
      winnerClaimAllowed: false,
    },
  };
}

export function listEventsAfterEventId(ctx: ServiceCtx, sessionId: string, afterEventId: string | null): EvidenceEvent[] {
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, newRequestId("stream"));
  let afterSeq = 0;
  if (afterEventId) {
    const row = ctx.db.sqlite
      .prepare("SELECT event_seq FROM evidence_events WHERE session_id = ? AND event_id = ?")
      .get(parsedSessionId, afterEventId) as Row | undefined;
    afterSeq = row ? Number(row.event_seq) : Number(afterEventId);
    if (!Number.isFinite(afterSeq)) {
      afterSeq = 0;
    }
  }
  return listEvents(ctx, parsedSessionId, afterSeq, 200);
}

export function appendEvidenceEvent(
  ctx: ServiceCtx,
  input: {
    sessionId: string;
    authority: "proof" | "delivery" | "operator" | "advisory";
    kind:
      | "session.created"
      | "source.registered"
      | "source.challenge.pending"
      | "spend.registered"
      | "caw.operation.built"
      | "caw.receipt.ingested.fixture"
      | "artifact.preflight.pending"
      | "quote.signed.mocked"
      | "artifact.refund.pending"
      | "lease.execution.blocked"
      | "verifier.fail_closed"
      | "judge_check.pending"
      | "runner.heartbeat"
      | "mcp.adapter.call";
    payload: Record<string, JsonValue>;
  },
): EvidenceEvent {
  ctx.db.sqlite.exec("BEGIN IMMEDIATE");
  try {
    const session = getSessionRow(ctx, input.sessionId);
    if (!session) {
      throw new Error("session not found for evidence append");
    }
    const eventSeq = Number(session.latest_event_seq) + 1;
    const createdAt = ctx.clock.now().toISOString();
    const payloadHash = hashJson(input.payload);
    const prevProofEventHash = input.authority === "proof" ? String(session.latest_proof_event_hash) : null;
    const eventHash = hashJson({
      sessionId: input.sessionId,
      eventSeq,
      authority: input.authority,
      kind: input.kind,
      payloadHash,
      prevProofEventHash,
    });
    const eventId = eventHash;
    const event = EvidenceEventSchema.parse({
      sessionId: input.sessionId,
      eventId,
      eventSeq,
      eventHash,
      prevProofEventHash,
      authority: input.authority,
      kind: input.kind,
      payloadHash,
      payload: input.payload,
      createdAt,
    });
    ctx.db.sqlite
      .prepare(
        `INSERT INTO evidence_events
          (event_id, session_id, event_seq, event_hash, prev_proof_event_hash, authority, kind, payload_hash, payload_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.eventId,
        event.sessionId,
        event.eventSeq,
        event.eventHash,
        event.prevProofEventHash,
        event.authority,
        event.kind,
        event.payloadHash,
        canonicalizeJson(event.payload),
        event.createdAt,
      );
    ctx.db.sqlite
      .prepare(
        `UPDATE sessions
         SET latest_event_seq = ?, latest_proof_event_hash = ?
         WHERE session_id = ?`,
      )
      .run(
        eventSeq,
        input.authority === "proof" ? eventHash : String(session.latest_proof_event_hash),
        input.sessionId,
      );
    ctx.db.sqlite.exec("COMMIT");
    return event;
  } catch (error) {
    ctx.db.sqlite.exec("ROLLBACK");
    throw error;
  }
}

async function withIdempotency<T>(
  ctx: ServiceCtx,
  actionScope: string,
  idempotencyKey: string,
  requestBody: unknown,
  executor: (requestId: string) => Promise<ServiceResult<T>> | ServiceResult<T>,
): Promise<ServiceResult<T>> {
  return withProcessLock(`${actionScope}:${idempotencyKey}`, async () =>
    withIdempotencyUnlocked(ctx, actionScope, idempotencyKey, requestBody, executor),
  );
}

async function withIdempotencyUnlocked<T>(
  ctx: ServiceCtx,
  actionScope: string,
  idempotencyKey: string,
  requestBody: unknown,
  executor: (requestId: string) => Promise<ServiceResult<T>> | ServiceResult<T>,
): Promise<ServiceResult<T>> {
  const requestHash = hashJson(requestBody);
  const existing = ctx.db.sqlite
    .prepare("SELECT request_id, request_hash, response_json FROM api_requests WHERE action_scope = ? AND idempotency_key = ?")
    .get(actionScope, idempotencyKey) as Row | undefined;
  if (existing) {
    if (existing.request_hash === requestHash) {
      return JSON.parse(String(existing.response_json)) as ServiceResult<T>;
    }
    const requestId = newRequestId("idem_conflict");
    return { ok: false, requestId, error: conflictError(requestId) };
  }

  const requestId = newRequestId("req");
  let result: ServiceResult<T>;
  try {
    result = await executor(requestId);
  } catch (error) {
    result = { ok: false, requestId, error: toApiError(error, requestId) };
  }
  ctx.db.sqlite
    .prepare(
      `INSERT INTO api_requests
        (request_id, action_scope, idempotency_key, request_hash, response_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(requestId, actionScope, idempotencyKey, requestHash, JSON.stringify(result), ctx.clock.now().toISOString());
  return result;
}

async function withProcessLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = idempotencyLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const next = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = previous.then(() => next, () => next);
  idempotencyLocks.set(key, chained);
  await previous.catch(() => undefined);
  try {
    return await fn();
  } finally {
    release();
    if (idempotencyLocks.get(key) === chained) {
      idempotencyLocks.delete(key);
    }
  }
}

function getSessionRow(ctx: ServiceCtx, sessionId: string): Row | undefined {
  return ctx.db.sqlite.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as Row | undefined;
}

function assertSession(ctx: ServiceCtx, sessionId: string, requestId: string): void {
  if (!getSessionRow(ctx, sessionId)) {
    throw Object.assign(new Error("session not found"), { apiError: notFoundError(requestId, "session") });
  }
}

function insertPendingJudgeRows(ctx: ServiceCtx, sessionId: string, createdAt: string): void {
  for (const [rowId, label, reason] of JUDGE_ROWS) {
    ctx.db.sqlite
      .prepare(
        `INSERT OR IGNORE INTO judge_check_rows
          (session_id, row_id, label, status, authority, reason, evidence_event_id, evidence_url, created_at)
         VALUES (?, ?, ?, 'pending', 'proof', ?, NULL, NULL, ?)`,
      )
      .run(sessionId, rowId, label, reason, createdAt);
  }
}

function readJudgeCheckData(sessionId: string, ctx: ServiceCtx): JudgeCheckView {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT row_id, label, status, authority, reason, evidence_event_id, evidence_url
       FROM judge_check_rows
       WHERE session_id = ?
       ORDER BY CASE row_id
         WHEN 'caw_boundary' THEN 1
         WHEN 'source_challenge' THEN 2
         WHEN 'ab_trip' THEN 3
         WHEN 'c_settlement' THEN 4
         WHEN 'artifact_access' THEN 5
         WHEN 'lease_execution' THEN 6
         ELSE 99
       END`,
    )
    .all(sessionId) as Row[];
  if (rows.length !== 6) {
    insertPendingJudgeRows(ctx, sessionId, nowIso());
    return readJudgeCheckData(sessionId, ctx);
  }
  return JudgeCheckViewSchema.parse({
    sessionId,
    winnerClaimAllowed: false,
    rows: rows.map((row) => ({
      rowId: row.row_id,
      label: row.label,
      status: row.status,
      authority: row.authority,
      reason: row.reason,
      evidenceEventId: row.evidence_event_id,
      evidenceUrl: row.evidence_url,
    })),
  });
}

function listEvents(ctx: ServiceCtx, sessionId: string, afterSeq: number, limit: number): EvidenceEvent[] {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM evidence_events
       WHERE session_id = ? AND event_seq > ?
       ORDER BY event_seq ASC
       LIMIT ?`,
    )
    .all(sessionId, afterSeq, limit) as Row[];
  return rows.map((row) =>
    EvidenceEventSchema.parse({
      sessionId: row.session_id,
      eventId: row.event_id,
      eventSeq: row.event_seq,
      eventHash: row.event_hash,
      prevProofEventHash: row.prev_proof_event_hash,
      authority: row.authority,
      kind: row.kind,
      payloadHash: row.payload_hash,
      payload: JSON.parse(String(row.payload_json)),
      createdAt: row.created_at,
    }),
  );
}

function verifyEventLogIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const events = listEvents(ctx, sessionId, 0, 200);
  const errors: string[] = [];
  let expectedSeq = 1;
  let expectedPrevProofHash: string = ZERO_HASH;
  for (const event of events) {
    if (event.eventSeq !== expectedSeq) {
      errors.push(`evidence event sequence gap: expected ${expectedSeq}, got ${event.eventSeq}`);
      expectedSeq = event.eventSeq;
    }
    if (event.authority === "proof") {
      if (event.prevProofEventHash !== expectedPrevProofHash) {
        errors.push(`proof chain fork/gap at event ${event.eventId}`);
      }
      expectedPrevProofHash = event.eventHash;
    } else if (event.prevProofEventHash !== null) {
      errors.push(`non-proof event carries proof predecessor at event ${event.eventId}`);
    }
    expectedSeq += 1;
  }
  return errors;
}

function scoped(scope: string, sessionId: string): string {
  return `${scope}:${sessionId}`;
}

function toStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function jsonRecord(value: unknown): Record<string, JsonValue> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return JSON.parse(JSON.stringify(value)) as Record<string, JsonValue>;
}
