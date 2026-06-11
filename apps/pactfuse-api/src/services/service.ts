import {
  AgentTranscriptViewSchema,
  ArtifactPreflightPayloadSchema,
  ArtifactRefundPayloadSchema,
  CawOperationBuildPayloadSchema,
  CawReceiptIngestPayloadSchema,
  CreateSessionInputSchema,
  EvidenceEventSchema,
  GateEventIngestPayloadSchema,
  Hex32Schema,
  JudgeCheckViewSchema,
  LeaseExecutePayloadSchema,
  LOCKED_RUNTIME_MODES,
  McpAdapterAuditPayloadSchema,
  McpAdapterCallViewSchema,
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
import type { ProofProviderStatus, ServiceCtx, ServiceResult } from "../types.js";
import {
  ZERO_HASH,
  badRequestError,
  conflictError,
  hashJson,
  keccakJson,
  newRequestId,
  notFoundError,
  nowIso,
  parseStrict,
  proofBlockedError,
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

const MAX_REPLAY_BUNDLE_BYTES = 2 * 1024 * 1024;
const idempotencyLocks = new Map<string, Promise<void>>();

export async function createSession(input: CreateSessionInput, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const parsed = parseStrict(CreateSessionInputSchema, input);
  return withIdempotency(ctx, "sessions:create", parsed.idempotencyKey, parsed, async (requestId) => {
    const createdAt = ctx.clock.now().toISOString();
    const runConfigHash = hashJson(parsed.payload);
    const sessionId = sha256Hex(`pactfuse-session:${parsed.idempotencyKey}:${runConfigHash}`);
    const pactTemplates = ctx.templates.list();
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
        pactTemplates,
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
        pactTemplates,
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
    const event = withImmediateTransaction(ctx, () => {
      ctx.db.sqlite
        .prepare(
          `INSERT INTO source_challenges
            (challenge_id, session_id, source_hash, reason_hash, evidence_ref, status, created_at)
           VALUES (?, ?, ?, ?, ?, 'pending_chain_log', ?)`,
        )
        .run(challengeId, envelope.sessionId, payload.sourceHash, payload.reasonHash, payload.evidenceRef ?? null, createdAt);
      recordOperatorKeyUse(ctx, {
        sessionId: envelope.sessionId,
        role: "challenge_submitter",
        method: "SourceStateRegistry.challengeSource",
        requestId,
        operationId: challengeId,
        authorizedMethods: ["SourceStateRegistry.challengeSource(bytes32,bytes32)"],
      });
      return appendEvidenceEvent(ctx, {
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
    const registeredSpends: Array<{
      spendId: string;
      sourceSetHash: string;
      sessionCommitment: string;
      spendPreimage: Record<string, JsonValue>;
    }> = [];
    const event = withImmediateTransaction(ctx, () => {
      const session = requireSessionRow(ctx, envelope.sessionId, requestId);
      for (const spend of payload.spends) {
        const sourceHashes = normalizedSourceHashes(spend.sourceHashes);
        requireRegisteredSources(ctx, envelope.sessionId, sourceHashes, requestId);
        const binding = spendBindingFor(session, envelope.sessionId, {
          pactId: spend.pactId,
          toolId: spend.toolId,
          sourceHashes,
          agentWallet: spend.agentWallet,
          nonce: spend.nonce,
        });
        if (spend.spendId.toLowerCase() !== binding.spendId) {
          throw Object.assign(new Error("spendId does not match the W8.1 source-bound spend preimage"), {
            apiError: proofBlockedError(requestId, "spendId does not match the W8.1 source-bound spend preimage", {
              expectedSpendId: binding.spendId,
              sourceSetHash: binding.sourceSetHash,
            }),
          });
        }
        ctx.db.sqlite
          .prepare(
            `INSERT OR REPLACE INTO spends
              (spend_id, session_id, pact_id, tool_id, payer, agent_wallet, source_hashes_json, source_set_hash, session_commitment,
               spend_preimage_json, max_price_atomic, nonce, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered_pending_chain_log', ?)`,
          )
          .run(
            binding.spendId,
            envelope.sessionId,
            spend.pactId,
            spend.toolId,
            spend.payer,
            spend.agentWallet,
            canonicalizeJson(sourceHashes),
            binding.sourceSetHash,
            binding.sessionCommitment,
            canonicalizeJson(binding.spendPreimage),
            spend.maxPriceAtomic,
            spend.nonce,
            createdAt,
          );
        registeredSpends.push({
          spendId: binding.spendId,
          sourceSetHash: binding.sourceSetHash,
          sessionCommitment: binding.sessionCommitment,
          spendPreimage: binding.spendPreimage,
        });
      }
      return appendEvidenceEvent(ctx, {
        sessionId: envelope.sessionId,
        authority: "operator",
        kind: "spend.registered",
        payload: {
          spendIds: registeredSpends.map((spend) => spend.spendId),
          sourceSetHashes: registeredSpends.map((spend) => spend.sourceSetHash),
          sessionCommitment: registeredSpends[0]?.sessionCommitment ?? null,
          spendIdBinding: "w8.1-keccak-jcs-v1",
          spendPreimages: registeredSpends.map((spend) => spend.spendPreimage),
          status: "registered_pending_chain_log",
        },
      });
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        spendIds: registeredSpends.map((spend) => spend.spendId),
        sourceSetHashes: registeredSpends.map((spend) => spend.sourceSetHash),
        sessionCommitment: registeredSpends[0]?.sessionCommitment ?? null,
        spendIdBinding: "w8.1-keccak-jcs-v1",
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
    if (payload.spendId) {
      assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    }
    const createdAt = ctx.clock.now().toISOString();
    const pactTemplate = ctx.templates.require("gate-paid-artifact-real");
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
        pactTemplateMode: pactTemplate.mode,
        pactTemplateHash: pactTemplate.templateHash,
        status: "built_mocked",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        operationId,
        status: "built_mocked",
        pactTemplateMode: pactTemplate.mode,
        pactTemplateHash: pactTemplate.templateHash,
        winnerClaimAllowed: false,
      },
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
    if (!payload.manual && !payload.operationId) {
      throw Object.assign(new Error("CAW receipt ingest requires operationId"), {
        apiError: badRequestError(requestId, "non-manual CAW receipt ingest requires operationId"),
      });
    }
    const receiptBundleHash = hashJson(payload.receipts);
    const createdAt = ctx.clock.now().toISOString();
    if (payload.operationId) {
      const result = ctx.db.sqlite
        .prepare("UPDATE caw_receipt_operations SET receipt_bundle_hash = ?, status = ? WHERE operation_id = ? AND session_id = ?")
        .run(receiptBundleHash, payload.manual ? "fixture_manual_receipt" : "ingested_pending_proof", payload.operationId, envelope.sessionId);
      if (result.changes === 0) {
        throw Object.assign(new Error("CAW operation not found for receipt ingest"), {
          apiError: notFoundError(requestId, "caw operation"),
        });
      }
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "advisory",
      kind: "caw.receipt.ingested.fixture",
      payload: {
        receiptBundleHash,
        operationId: payload.operationId ?? null,
        sourceLabel: payload.sourceLabel,
        receiptCount: payload.receipts.length,
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
        operationId: payload.operationId ?? null,
        receiptCount: payload.receipts.length,
        status: payload.manual ? "fixture_manual_receipt" : "ingested_pending_proof",
        proofAuthority: false,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function ingestGateEvent(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(GateEventIngestPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("gate:events:ingest", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    const session = requireSessionRow(ctx, envelope.sessionId, requestId);
    assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const finalityDepth = finalityDepthForSession(session);
    let certifiedPayload = payload;
    let confirmations = payload.reorged ? 0 : payload.currentBlockNumber - payload.blockNumber + 1;
    if (payload.reorged || confirmations >= finalityDepth) {
      const chainProof = await verifyGateEventWithChain(ctx, payload, requestId);
      certifiedPayload = { ...payload, currentBlockNumber: chainProof.currentBlockNumber };
      confirmations = payload.reorged ? 0 : chainProof.confirmations;
    }
    return withImmediateTransaction(ctx, () => {
      const gatePayload = certifiedPayload;
      const gateEventId = hashJson({
        sessionId: envelope.sessionId,
        event: gatePayload.event,
        spendId: gatePayload.spendId,
        txHash: gatePayload.txHash,
        logIndex: gatePayload.logIndex,
        chainId: gatePayload.chainId,
        rawLogHash: gatePayload.rawLogHash,
      });
      const existing = ctx.db.sqlite
        .prepare(
          `SELECT *
           FROM gate_chain_events
           WHERE session_id = ? AND tx_hash = ? AND log_index = ? AND event_kind = ?`,
        )
        .get(envelope.sessionId, gatePayload.txHash, gatePayload.logIndex, gatePayload.event) as Row | undefined;
      if (existing) {
        assertGateEventRowMatches(existing, gatePayload, gateEventId, requestId);
      }
      if (gatePayload.reorged) {
        return recordGateReorg(ctx, {
          requestId,
          sessionId: envelope.sessionId,
          payload: gatePayload,
          existing,
          gateEventId,
          finalityDepth,
          confirmations,
        });
      }
      if (existing && (existing.status === "reorg_invalidated" || typeof existing.reorg_event_id === "string")) {
        throw Object.assign(new Error("cannot revive a reorg-invalidated gate event"), {
          apiError: proofBlockedError(requestId, "cannot revive a reorg-invalidated gate event"),
        });
      }

      const observedEventId =
        typeof existing?.observed_event_id === "string"
          ? existing.observed_event_id
          : appendGateObservedEvent(ctx, envelope.sessionId, gatePayload, gateEventId, finalityDepth, confirmations).eventId;
      if (!existing) {
        ctx.db.sqlite
          .prepare(
            `INSERT INTO gate_chain_events
              (gate_event_id, session_id, spend_id, event_kind, tx_hash, log_index, chain_id, block_number, current_block_number,
               finality_depth, confirmations, raw_log_hash, status, observed_event_id, finalized_event_id, reorg_event_id, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed_finalizing', ?, NULL, NULL, ?, ?)`,
          )
          .run(
            gateEventId,
            envelope.sessionId,
            gatePayload.spendId,
            gatePayload.event,
            gatePayload.txHash,
            gatePayload.logIndex,
            gatePayload.chainId,
            gatePayload.blockNumber,
            gatePayload.currentBlockNumber,
            finalityDepth,
            confirmations,
            gatePayload.rawLogHash,
            observedEventId,
            ctx.clock.now().toISOString(),
            ctx.clock.now().toISOString(),
          );
      }

      if (confirmations < finalityDepth) {
        if (existing) {
          ctx.db.sqlite
            .prepare(
              `UPDATE gate_chain_events
               SET current_block_number = ?, confirmations = ?, updated_at = ?
               WHERE gate_event_id = ?`,
            )
            .run(gatePayload.currentBlockNumber, confirmations, ctx.clock.now().toISOString(), gateEventId);
        }
        return {
          ok: true,
          requestId,
          evidenceEventId: observedEventId,
          data: {
            gateEventId,
            spendId: gatePayload.spendId,
            event: gatePayload.event,
            finalityStatus: "observed_finalizing",
            confirmations,
            finalityDepth,
            observedEventId,
            finalizedEventId: null,
            proofAuthority: false,
            winnerClaimAllowed: false,
          },
        };
      }

      const finalizedEventId =
        typeof existing?.finalized_event_id === "string"
          ? existing.finalized_event_id
          : appendGateFinalizedEvent(ctx, envelope.sessionId, gatePayload, gateEventId, observedEventId, finalityDepth, confirmations).eventId;
      const finalizeResult = ctx.db.sqlite
        .prepare(
          `UPDATE gate_chain_events
           SET current_block_number = ?, confirmations = ?, status = 'finalized', finalized_event_id = ?, updated_at = ?
           WHERE gate_event_id = ?`,
        )
        .run(gatePayload.currentBlockNumber, confirmations, finalizedEventId, ctx.clock.now().toISOString(), gateEventId);
      if (finalizeResult.changes !== 1) {
        throw Object.assign(new Error("finalized gate event did not update the observed gate row"), {
          apiError: proofBlockedError(requestId, "finalized gate event did not update the observed gate row"),
        });
      }
      ctx.db.sqlite
        .prepare("UPDATE spends SET status = ? WHERE session_id = ? AND spend_id = ?")
        .run(gateSpendStatus(gatePayload.event, "finalized"), envelope.sessionId, gatePayload.spendId);
      return {
        ok: true,
        requestId,
        evidenceEventId: finalizedEventId,
        data: {
          gateEventId,
          spendId: gatePayload.spendId,
          event: gatePayload.event,
          finalityStatus: "finalized",
          confirmations,
          finalityDepth,
          observedEventId,
          finalizedEventId,
          proofAuthority: true,
          winnerClaimAllowed: false,
        },
      };
    });
  });
}

export async function runArtifactPreflight(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(ArtifactPreflightPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("artifacts:preflight", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
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
      payload: {
        preflightId,
        spendId: payload.spendId,
        artifactHashPreview: payload.artifactHashPreview,
        priceDisclosureHash: payload.priceDisclosureHash,
        sourceStateSnapshotHash: payload.sourceStateSnapshotHash,
        status: "pending_live_delivery",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        preflightId,
        artifactHashPreview: payload.artifactHashPreview,
        priceDisclosureHash: payload.priceDisclosureHash,
        sourceStateSnapshotHash: payload.sourceStateSnapshotHash,
        status: "pending_live_delivery",
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function signArtifactQuote(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(QuotePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("quotes:sign", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const preflight = requireQuotePreflight(ctx, envelope.sessionId, payload, requestId);
    const priceDisclosureHash = String(preflight.price_disclosure_hash);
    const sourceStateSnapshotHash = String(preflight.source_state_snapshot_hash);
    const createdAt = ctx.clock.now().toISOString();
    const quoteHash = hashJson({
      sessionId: envelope.sessionId,
      ...payload,
      priceDisclosureHash,
      sourceStateSnapshotHash,
      quoteSignedAfterPreflight: true,
      modes: LOCKED_RUNTIME_MODES,
    });
    const quoteId = hashJson({ quoteHash, requestId });
    const event = withImmediateTransaction(ctx, () => {
      ctx.db.sqlite
        .prepare(
          `INSERT INTO quotes
            (quote_id, session_id, spend_id, preflight_id, artifact_commitment, price_disclosure_hash, source_state_snapshot_hash,
             price_atomic, quote_nonce, valid_until_block, quote_hash, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'mocked_after_preflight_not_chain_settleable', ?)`,
        )
        .run(
          quoteId,
          envelope.sessionId,
          payload.spendId,
          payload.preflightId,
          payload.artifactCommitment,
          priceDisclosureHash,
          sourceStateSnapshotHash,
          payload.priceAtomic,
          payload.quoteNonce,
          payload.validUntilBlock,
          quoteHash,
          createdAt,
        );
      recordOperatorKeyUse(ctx, {
        sessionId: envelope.sessionId,
        role: "quote_signer",
        method: "ArtifactQuote.sign",
        requestId,
        operationId: quoteId,
        authorizedMethods: ["ArtifactQuote.sign(sessionId,spendId,artifactCommitment,priceAtomic,quoteNonce,validUntilBlock)"],
      });
      return appendEvidenceEvent(ctx, {
        sessionId: envelope.sessionId,
        authority: "advisory",
        kind: "quote.signed.mocked",
        payload: {
          quoteId,
          quoteHash,
          spendId: payload.spendId,
          preflightId: payload.preflightId,
          artifactCommitment: payload.artifactCommitment,
          priceDisclosureHash,
          sourceStateSnapshotHash,
          quoteSignedAfterPreflight: true,
          status: "mocked_after_preflight_not_chain_settleable",
        },
      });
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        quoteId,
        quoteHash,
        preflightId: payload.preflightId,
        priceDisclosureHash,
        sourceStateSnapshotHash,
        quoteSignedAfterPreflight: true,
        status: "mocked_after_preflight_not_chain_settleable",
        winnerClaimAllowed: false,
      },
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
    assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const quote = ctx.db.sqlite
      .prepare(
        `SELECT quote_id, preflight_id, artifact_commitment
         FROM quotes
         WHERE session_id = ? AND spend_id = ? AND quote_id = ?`,
      )
      .get(envelope.sessionId, payload.spendId, payload.quoteId) as Row | undefined;
    if (!quote) {
      throw Object.assign(new Error("artifact refund requires a quoted paid artifact commitment"), {
        apiError: proofPendingError(requestId, "artifact refund requires a quoted paid artifact commitment"),
      });
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "artifact.refund.pending",
      payload: {
        spendId: payload.spendId,
        quoteId: String(quote.quote_id),
        preflightId: String(quote.preflight_id),
        artifactCommitment: String(quote.artifact_commitment),
        reason: payload.reason,
        status: "pending_live_settlement",
        winnerClaimAllowed: false,
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        spendId: payload.spendId,
        quoteId: String(quote.quote_id),
        preflightId: String(quote.preflight_id),
        status: "pending_live_settlement",
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function executeLease(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
  bearerToken: string | null,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(LeaseExecutePayloadSchema, envelope.payload);
  return withIdempotency(
    ctx,
    scoped("lease:execute", envelope.sessionId),
    envelope.idempotencyKey,
    { envelope, bearerTokenHash: bearerToken ? sha256Hex(bearerToken) : null },
    async (requestId) => {
      assertSession(ctx, envelope.sessionId, requestId);
      const spend = assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
      const payer = requireSpendPayer(spend, payload.payer, requestId);
      requireFinalizedSettlement(ctx, envelope.sessionId, payload.spendId, requestId);
      requireActiveArtifactAccess(
        ctx,
        {
          sessionId: envelope.sessionId,
          spendId: payload.spendId,
          payer,
          artifactHash: payload.artifactHash,
          bearerToken,
        },
        requestId,
      );
      const createdAt = ctx.clock.now().toISOString();
      const leaseRunId = hashJson({ sessionId: envelope.sessionId, payload, requestId });
      ctx.db.sqlite
        .prepare(
          `INSERT INTO lease_runs
            (lease_run_id, session_id, spend_id, target_repo, target_commit, status, transcript_hash, created_at)
           VALUES (?, ?, ?, ?, ?, 'blocked_missing_runner_execution', NULL, ?)`,
        )
        .run(leaseRunId, envelope.sessionId, payload.spendId, payload.targetRepo, payload.targetCommit, createdAt);
      const event = appendEvidenceEvent(ctx, {
        sessionId: envelope.sessionId,
        authority: "operator",
        kind: "lease.execution.blocked",
        payload: {
          leaseRunId,
          spendId: payload.spendId,
          payer,
          artifactHash: payload.artifactHash,
          targetRepo: payload.targetRepo,
          targetCommit: payload.targetCommit,
          bearerBound: true,
          status: "blocked_missing_runner_execution",
          winnerClaimAllowed: false,
        },
      });
      return {
        ok: true,
        requestId,
        evidenceEventId: event.eventId,
        data: {
          leaseRunId,
          payer,
          artifactHash: payload.artifactHash,
          bearerBound: true,
          status: "blocked_missing_runner_execution",
          winnerClaimAllowed: false,
        },
      };
    },
  );
}

export async function verifyEvidenceForSession(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<VerifierRunView>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(VerifyEvidencePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("evidence:verify", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const proofProviders = await readProofProviderStatus(ctx);
    const verifierInput = payload.receipt ?? payload.replayBundle ?? {};
    const raw =
      payload.receipt || payload.replayBundle
        ? await ctx.verifier.verify(verifierInput, {
            cliMode: payload.schemaOnly ? "schema-only" : "proof-chip",
            proofProviders,
            pactTemplates: ctx.templates.list(),
          })
        : {
            schemaOk: false,
            proofChipAllowed: false,
            winnerClaimAllowed: false,
            requestedWinnerClaimAllowed: false,
            finalVerifierComplete: false,
            warnings: [],
            errors: ["missing receipt or replayBundle; fail closed"],
          };
    const eventLogErrors = [
      ...verifyEventLogIntegrity(ctx, envelope.sessionId),
      ...verifyMcpAdapterCallIntegrity(ctx, envelope.sessionId),
      ...verifyGateFinalityIntegrity(ctx, envelope.sessionId),
      ...verifyReplayBundleBindings(ctx, envelope.sessionId, payload),
    ];
    const rawErrors = toStringArray(raw.errors);
    const view = VerifierRunViewSchema.parse({
      sessionId: envelope.sessionId,
      proofLevel: payload.schemaOnly ? "schema_only_no_claim" : "fail_closed_no_claim",
      claimMode: ctx.config.claimMode,
      paymentMode: ctx.config.paymentMode,
      tokenMode: ctx.config.tokenMode,
      identityMode: ctx.config.identityMode,
      schemaOk: Boolean(raw.schemaOk) && eventLogErrors.length === 0,
      proofChipAllowed: false,
      winnerClaimAllowed: false,
      requestedWinnerClaimAllowed: Boolean(raw.requestedWinnerClaimAllowed),
      finalVerifierComplete: false,
      errors: [...rawErrors, ...eventLogErrors],
      warnings: [
        ...toStringArray(raw.warnings),
        ...proofProviderWarnings(proofProviders),
        "P0 route wraps the structural verifier fail-closed; final chain/signature/hash verifier is incomplete",
      ],
      raw: jsonRecord({ ...raw, proofProviders, pactTemplates: ctx.templates.list() }),
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

export async function readProofProviderStatus(ctx: ServiceCtx): Promise<ProofProviderStatus[]> {
  const [chain, caw] = await Promise.all([ctx.chain.status(), ctx.caw.status()]);
  return [chain, caw];
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
  const mcpAdapterCalls = listMcpAdapterCalls(ctx, parsedSessionId, 200);
  const agentTranscript = buildAgentTranscriptData(parsedSessionId, ctx, mcpAdapterCalls.length);
  const data = ReplayBundleViewSchema.parse({
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId: parsedSessionId,
    summaryMode: true,
    asOfEventSeq: events.at(-1)?.eventSeq ?? 0,
    asOfMcpAdapterCallCount: mcpAdapterCalls.length,
    winnerClaimAllowed: false,
    eventRoot: hashJson(events.map((event) => event.eventHash)),
    agentTranscriptHash: hashJson(agentTranscript),
    events,
    mcpAdapterCalls,
    judgeCheck: readJudgeCheckData(parsedSessionId, ctx),
  });
  const bundleBytes = Buffer.byteLength(canonicalizeJson(data), "utf8");
  if (bundleBytes > MAX_REPLAY_BUNDLE_BYTES) {
    return {
      ok: false,
      requestId,
      error: proofBlockedError(requestId, "replay bundle exceeds the 2 MiB response cap", {
        bundleBytes,
        maxBytes: MAX_REPLAY_BUNDLE_BYTES,
        eventCount: events.length,
      }),
    };
  }
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
    data: buildAgentTranscriptData(parsedSessionId, ctx),
  };
}

function buildAgentTranscriptData(sessionId: string, ctx: ServiceCtx, callLimit = 200): unknown {
  const calls = listMcpAdapterCalls(ctx, sessionId, Math.min(callLimit, 200));
  const callSummaries = calls.map((call) => ({
    callId: call.callId,
    auditNonce: call.auditNonce,
    toolName: call.toolName,
    requestHash: call.requestHash,
    responseHash: call.responseHash,
    status: call.status,
    createdAt: call.createdAt,
  }));
  const toolsListHash = calls.length > 0 ? hashJson([...new Set(calls.map((call) => call.toolName))].sort()) : null;
  const toolsCallHash = calls.length > 0 ? hashJson(callSummaries) : null;
  const transcriptHash =
    calls.length > 0
      ? hashJson({
          format: "mcp-json-rpc",
          sessionId,
          toolsListHash,
          toolsCallHash,
          callCount: calls.length,
        })
      : null;
  return AgentTranscriptViewSchema.parse({
    sessionId,
    status: calls.length > 0 ? "summarized" : "pending",
    format: "mcp-json-rpc",
    toolsListHash,
    toolsCallHash,
    transcriptHash,
    boundedToPinnedManifest: false,
    callCount: calls.length,
    calls: callSummaries,
    winnerClaimAllowed: false,
  });
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
  const spend = assertSpend(ctx, sessionId, spendId, requestId);
  const payer = requireSpendPayer(spend, input.payer, requestId);
  requireFinalizedSettlement(ctx, sessionId, spendId, requestId);
  requireActiveArtifactAccess(ctx, { ...input, sessionId, spendId, payer, artifactHash }, requestId);
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

export function recordMcpAdapterCall(
  input: {
    sessionId?: string | null;
    auditNonce?: string | null;
    toolName: string;
    request: Record<string, JsonValue>;
    response: Record<string, JsonValue>;
    status: "succeeded" | "failed" | "blocked";
  },
  ctx: ServiceCtx,
): { callId: string; requestHash: string; responseHash: string; evidenceEventId?: string } {
  const createdAt = ctx.clock.now().toISOString();
  const auditNonce = input.auditNonce ?? newRequestId("mcp_call");
  const requestHash = hashJson(input.request);
  const responseHash = hashJson(input.response);
  const callId = hashJson({
    sessionId: input.sessionId ?? null,
    auditNonce,
    toolName: input.toolName,
    requestHash,
    responseHash,
    createdAt,
  });
  return withImmediateTransaction(ctx, () => {
    const existing = ctx.db.sqlite
      .prepare(
        `SELECT call_id, session_id, tool_name, request_hash, response_hash, status
         FROM mcp_adapter_calls
         WHERE audit_nonce = ?`,
      )
      .get(auditNonce) as Row | undefined;
    if (existing) {
      const isSameCall =
        (existing.session_id ?? null) === (input.sessionId ?? null) &&
        existing.tool_name === input.toolName &&
        existing.request_hash === requestHash &&
        existing.response_hash === responseHash &&
        existing.status === input.status;
      if (!isSameCall) {
        const requestId = newRequestId("mcp_nonce_conflict");
        throw Object.assign(new Error("MCP audit nonce conflict"), {
          apiError: conflictError(requestId, "MCP audit nonce was already used for a different tool call"),
        });
      }
      return {
        callId: String(existing.call_id),
        requestHash: String(existing.request_hash),
        responseHash: String(existing.response_hash),
      };
    }
    ctx.db.sqlite
      .prepare(
        `INSERT INTO mcp_adapter_calls
          (call_id, session_id, audit_nonce, tool_name, request_hash, response_hash, request_json, response_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        callId,
        input.sessionId ?? null,
        auditNonce,
        input.toolName,
        requestHash,
        responseHash,
        canonicalizeJson(input.request),
        canonicalizeJson(input.response),
        input.status,
        createdAt,
      );
    if (!input.sessionId) {
      return { callId, requestHash, responseHash };
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: input.sessionId,
      authority: "operator",
      kind: "mcp.adapter.call",
      payload: {
        callId,
        auditNonce,
        toolName: input.toolName,
        requestHash,
        responseHash,
        status: input.status,
      },
    });
    return { callId, requestHash, responseHash, evidenceEventId: event.eventId };
  });
}

export function recordMcpAdapterAudit(input: unknown, ctx: ServiceCtx): ServiceResult<unknown> {
  const requestId = newRequestId("mcp_audit");
  const parsed = parseStrict(McpAdapterAuditPayloadSchema, input);
  const sessionId = resolveMcpAuditSessionId(parsed, requestId);
  if (sessionId) {
    assertSession(ctx, sessionId, requestId);
  }
  const audit = recordMcpAdapterCall(
    {
      sessionId,
      auditNonce: parsed.auditNonce,
      toolName: parsed.toolName,
      request: parsed.request,
      response: parsed.response,
      status: parsed.status,
    },
    ctx,
  );
  const result: ServiceResult<unknown> = {
    ok: true,
    requestId,
    data: {
      ...audit,
      proofAuthority: false,
      winnerClaimAllowed: false,
    },
  };
  if (audit.evidenceEventId) {
    return { ...result, evidenceEventId: audit.evidenceEventId };
  }
  return result;
}

function resolveMcpAuditSessionId(parsed: {
  sessionId?: string | undefined;
  request: Record<string, JsonValue>;
  response: Record<string, JsonValue>;
}): string | null;
function resolveMcpAuditSessionId(
  parsed: {
    sessionId?: string | undefined;
    request: Record<string, JsonValue>;
    response: Record<string, JsonValue>;
  },
  requestId: string,
): string | null;
function resolveMcpAuditSessionId(
  parsed: {
    sessionId?: string | undefined;
    request: Record<string, JsonValue>;
    response: Record<string, JsonValue>;
  },
  requestId = newRequestId("mcp_audit_session"),
): string | null {
  const candidates = [
    parsed.sessionId ?? null,
    mcpSessionCandidate(parsed.request, "request.sessionId", requestId),
    mcpSessionCandidate(parsed.response, "response.sessionId", requestId),
    mcpSessionCandidate(
      parsed.response.data && typeof parsed.response.data === "object" && !Array.isArray(parsed.response.data)
        ? parsed.response.data
        : {},
      "response.data.sessionId",
      requestId,
    ),
  ].filter((value): value is string => Boolean(value));
  const unique = [...new Set(candidates)];
  if (unique.length > 1) {
    throw Object.assign(new Error("MCP audit sessionId mismatch"), {
      apiError: badRequestError(requestId, "MCP audit sessionId values must match across request and response", {
        sessionIds: unique,
      }),
    });
  }
  return unique[0] ?? null;
}

function mcpSessionCandidate(value: Record<string, JsonValue>, path: string, requestId: string): string | null {
  const raw = value.sessionId;
  if (raw === undefined) {
    return null;
  }
  if (typeof raw !== "string" || !Hex32Schema.safeParse(raw).success) {
    throw Object.assign(new Error("MCP audit sessionId is invalid"), {
      apiError: badRequestError(requestId, `MCP audit ${path} must be a 32-byte hex string`),
    });
  }
  return raw;
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
      | "operator.key_used"
      | "gate.spend_tripped.observed"
      | "gate.spend_settled.observed"
      | "gate.spend_tripped"
      | "gate.spend_settled"
      | "reorg.invalidated"
      | "lease.execution.blocked"
      | "verifier.fail_closed"
      | "judge_check.pending"
      | "runner.heartbeat"
      | "mcp.adapter.call";
    payload: Record<string, JsonValue>;
  },
): EvidenceEvent {
  const ownsTransaction = !isInTransaction(ctx);
  if (ownsTransaction) {
    ctx.db.sqlite.exec("BEGIN IMMEDIATE");
  }
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
    if (ownsTransaction) {
      ctx.db.sqlite.exec("COMMIT");
    }
    return event;
  } catch (error) {
    if (ownsTransaction) {
      ctx.db.sqlite.exec("ROLLBACK");
    }
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
  const requestId = newRequestId("req");
  let transactionOpen = false;
  try {
    ctx.db.sqlite.exec("BEGIN IMMEDIATE");
    transactionOpen = true;
    const existing = ctx.db.sqlite
      .prepare(
        `SELECT request_id, request_hash, response_json, status
         FROM api_requests
         WHERE action_scope = ? AND idempotency_key = ?`,
      )
      .get(actionScope, idempotencyKey) as Row | undefined;
    if (existing) {
      ctx.db.sqlite.exec("COMMIT");
      transactionOpen = false;
      if (existing.request_hash === requestHash && String(existing.status ?? "completed") === "completed") {
        return JSON.parse(String(existing.response_json)) as ServiceResult<T>;
      }
      if (existing.request_hash === requestHash) {
        const completed = await waitForCompletedIdempotency<T>(ctx, actionScope, idempotencyKey, requestHash);
        if (completed) {
          return completed;
        }
        const pendingRequestId = newRequestId("idem_pending");
        return {
          ok: false,
          requestId: pendingRequestId,
          error: proofPendingError(pendingRequestId, "matching idempotent request is still running"),
        };
      }
      const conflictRequestId = newRequestId("idem_conflict");
      return { ok: false, requestId: conflictRequestId, error: conflictError(conflictRequestId) };
    }
    ctx.db.sqlite
      .prepare(
        `INSERT INTO api_requests
          (request_id, action_scope, idempotency_key, request_hash, response_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
      )
      .run(
        requestId,
        actionScope,
        idempotencyKey,
        requestHash,
        JSON.stringify(pendingIdempotencyResponse(requestId)),
        ctx.clock.now().toISOString(),
      );
    ctx.db.sqlite.exec("COMMIT");
    transactionOpen = false;
  } catch (error) {
    if (transactionOpen) {
      ctx.db.sqlite.exec("ROLLBACK");
    }
    throw error;
  }

  let result: ServiceResult<T>;
  try {
    result = await executor(requestId);
  } catch (error) {
    result = { ok: false, requestId, error: toApiError(error, requestId) };
  }
  if (shouldPersistIdempotencyResult(result)) {
    ctx.db.sqlite
      .prepare("UPDATE api_requests SET response_json = ?, status = 'completed' WHERE request_id = ? AND status = 'pending'")
      .run(JSON.stringify(result), requestId);
  } else {
    ctx.db.sqlite.prepare("DELETE FROM api_requests WHERE request_id = ? AND status = 'pending'").run(requestId);
  }
  return result;
}

async function waitForCompletedIdempotency<T>(
  ctx: ServiceCtx,
  actionScope: string,
  idempotencyKey: string,
  requestHash: string,
): Promise<ServiceResult<T> | null> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    await sleep(25);
    const row = ctx.db.sqlite
      .prepare(
        `SELECT request_hash, response_json, status
         FROM api_requests
         WHERE action_scope = ? AND idempotency_key = ?`,
      )
      .get(actionScope, idempotencyKey) as Row | undefined;
    if (!row || row.request_hash !== requestHash) {
      return null;
    }
    if (String(row.status ?? "completed") === "completed") {
      return JSON.parse(String(row.response_json)) as ServiceResult<T>;
    }
  }
  return null;
}

function pendingIdempotencyResponse(requestId: string): ServiceResult<never> {
  return {
    ok: false,
    requestId,
    error: proofPendingError(requestId, "idempotent request reserved but not completed yet"),
  };
}

function shouldPersistIdempotencyResult<T>(result: ServiceResult<T>): boolean {
  return result.ok || (!result.error.retryable && result.error.code !== "internal_error");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
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

function withImmediateTransaction<T>(ctx: ServiceCtx, fn: () => T): T {
  const ownsTransaction = !isInTransaction(ctx);
  if (ownsTransaction) {
    ctx.db.sqlite.exec("BEGIN IMMEDIATE");
  }
  try {
    const result = fn();
    if (ownsTransaction) {
      ctx.db.sqlite.exec("COMMIT");
    }
    return result;
  } catch (error) {
    if (ownsTransaction) {
      ctx.db.sqlite.exec("ROLLBACK");
    }
    throw error;
  }
}

function isInTransaction(ctx: ServiceCtx): boolean {
  return Boolean((ctx.db.sqlite as unknown as { isTransaction?: boolean }).isTransaction);
}

function getSessionRow(ctx: ServiceCtx, sessionId: string): Row | undefined {
  return ctx.db.sqlite.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as Row | undefined;
}

function requireSessionRow(ctx: ServiceCtx, sessionId: string, requestId: string): Row {
  const session = getSessionRow(ctx, sessionId);
  if (!session) {
    throw Object.assign(new Error("session not found"), { apiError: notFoundError(requestId, "session") });
  }
  return session;
}

function assertSession(ctx: ServiceCtx, sessionId: string, requestId: string): void {
  requireSessionRow(ctx, sessionId, requestId);
}

function assertSpend(ctx: ServiceCtx, sessionId: string, spendId: string, requestId: string): Row {
  const spend = ctx.db.sqlite
    .prepare("SELECT spend_id, payer FROM spends WHERE session_id = ? AND spend_id = ?")
    .get(sessionId, spendId) as Row | undefined;
  if (!spend) {
    throw Object.assign(new Error("spend not found"), { apiError: notFoundError(requestId, "spend") });
  }
  return spend;
}

function requireSpendPayer(spend: Row, payer: string, requestId: string): string {
  const registeredPayer = String(spend.payer);
  if (registeredPayer.toLowerCase() !== payer.toLowerCase()) {
    throw Object.assign(new Error("payer does not match registered spend payer"), {
      apiError: proofBlockedError(requestId, "payer does not match registered spend payer"),
    });
  }
  return registeredPayer;
}

function recordOperatorKeyUse(
  ctx: ServiceCtx,
  input: {
    sessionId: string;
    role: "challenge_submitter" | "quote_signer" | "artifact_signer";
    method: string;
    requestId: string;
    operationId: string;
    authorizedMethods: string[];
  },
): EvidenceEvent {
  const normalizedMethods = [...input.authorizedMethods].sort();
  const authorizedMethodsHash = hashJson(normalizedMethods);
  const keyId = hashJson({
    role: input.role,
    authority: "operator",
    authorizedMethodsHash,
  });
  const now = ctx.clock.now().toISOString();
  ctx.db.sqlite
    .prepare(
      `INSERT INTO operator_keys
        (key_id, role, authority, authorized_methods_hash, authorized_methods_json, status, use_count, created_at, last_used_at)
       VALUES (?, ?, 'operator', ?, ?, 'active_demo_key', 0, ?, NULL)
       ON CONFLICT(key_id) DO NOTHING`,
    )
    .run(keyId, input.role, authorizedMethodsHash, canonicalizeJson(normalizedMethods), now);
  ctx.db.sqlite
    .prepare("UPDATE operator_keys SET use_count = use_count + 1, last_used_at = ? WHERE key_id = ?")
    .run(now, keyId);
  return appendEvidenceEvent(ctx, {
    sessionId: input.sessionId,
    authority: "operator",
    kind: "operator.key_used",
    payload: {
      keyId,
      role: input.role,
      authority: "operator",
      method: input.method,
      operationId: input.operationId,
      requestId: input.requestId,
      authorizedMethodsHash,
      status: "active_demo_key",
      secretMaterialStored: false,
      winnerClaimAllowed: false,
    },
  });
}

function requireFinalizedSettlement(ctx: ServiceCtx, sessionId: string, spendId: string, requestId: string): void {
  const invalidated = ctx.db.sqlite
    .prepare(
      `SELECT tx_hash, log_index
       FROM gate_chain_events
       WHERE session_id = ? AND spend_id = ? AND event_kind = 'SpendSettled'
         AND (status = 'reorg_invalidated' OR reorg_event_id IS NOT NULL)
       LIMIT 1`,
    )
    .get(sessionId, spendId) as Row | undefined;
  if (invalidated) {
    throw Object.assign(new Error("settlement gate event was reorg-invalidated"), {
      apiError: proofBlockedError(requestId, "settlement gate event was reorg-invalidated"),
    });
  }

  const settlement = ctx.db.sqlite
    .prepare(
      `SELECT status, observed_event_id, finalized_event_id, finality_depth, confirmations
       FROM gate_chain_events
       WHERE session_id = ? AND spend_id = ? AND event_kind = 'SpendSettled'
       ORDER BY block_number DESC, log_index DESC
       LIMIT 1`,
    )
    .get(sessionId, spendId) as Row | undefined;
  if (!settlement || settlement.status !== "finalized" || typeof settlement.finalized_event_id !== "string") {
    throw Object.assign(new Error("finalized SpendSettled gate proof is required before artifact access"), {
      apiError: proofPendingError(requestId, "finalized SpendSettled gate proof is required before artifact access"),
    });
  }
  if (!settlement.observed_event_id || Number(settlement.confirmations) < Number(settlement.finality_depth)) {
    throw Object.assign(new Error("finalized SpendSettled gate proof is internally inconsistent"), {
      apiError: proofBlockedError(requestId, "finalized SpendSettled gate proof is internally inconsistent"),
    });
  }
}

async function verifyGateEventWithChain(
  ctx: ServiceCtx,
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
    currentBlockNumber: number;
    rawLogHash: string;
    reorged: boolean;
  },
  requestId: string,
): Promise<{ currentBlockNumber: number; confirmations: number }> {
  let status;
  try {
    status = await ctx.chain.status();
  } catch (error) {
    throw Object.assign(new Error("chain proof provider readiness check failed"), {
      apiError: proofPendingError(requestId, chainFailureMessage("chain proof provider readiness check failed", error)),
    });
  }
  if (!status.ready) {
    throw Object.assign(new Error("chain proof provider is not ready"), {
      apiError: proofPendingError(requestId, `chain proof provider is not ready: ${status.reason}`),
    });
  }

  let currentBlockNumber: number;
  try {
    currentBlockNumber = await ctx.chain.getBlockNumber();
  } catch (error) {
    throw Object.assign(new Error("failed to read current chain head"), {
      apiError: proofPendingError(requestId, chainFailureMessage("failed to read current chain head", error)),
    });
  }
  if (!Number.isInteger(currentBlockNumber) || currentBlockNumber < 0) {
    throw Object.assign(new Error("chain provider returned an invalid current block number"), {
      apiError: proofBlockedError(requestId, "chain provider returned an invalid current block number", { currentBlockNumber }),
    });
  }
  if (currentBlockNumber < payload.blockNumber) {
    throw Object.assign(new Error("chain head is behind the claimed gate event block"), {
      apiError: proofPendingError(requestId, "chain head is behind the claimed gate event block"),
    });
  }

  let logs: Record<string, unknown>[];
  try {
    logs = await ctx.chain.getLogs({
      chainId: payload.chainId,
      blockNumber: payload.blockNumber,
      txHash: payload.txHash,
      logIndex: payload.logIndex,
      event: payload.event,
      spendId: payload.spendId,
      rawLogHash: payload.rawLogHash,
      reorged: payload.reorged,
    });
  } catch (error) {
    throw Object.assign(new Error("failed to re-fetch gate event logs"), {
      apiError: proofPendingError(requestId, chainFailureMessage("failed to re-fetch gate event logs", error)),
    });
  }
  const matchingLog = logs.find((log) => chainLogMatchesGatePayload(log, payload));
  if (payload.reorged) {
    if (matchingLog) {
      throw Object.assign(new Error("cannot invalidate a gate event that is still present on chain"), {
        apiError: proofBlockedError(requestId, "cannot invalidate a gate event that is still present on chain"),
      });
    }
    return { currentBlockNumber, confirmations: 0 };
  }

  let receipt: Record<string, unknown>;
  try {
    receipt = await ctx.chain.getTransactionReceipt(payload.txHash);
  } catch (error) {
    throw Object.assign(new Error("failed to re-fetch gate transaction receipt"), {
      apiError: proofPendingError(requestId, chainFailureMessage("failed to re-fetch gate transaction receipt", error)),
    });
  }
  assertReceiptMatchesGatePayload(receipt, payload, requestId);
  if (!matchingLog) {
    throw Object.assign(new Error("claimed gate event log was not found on chain"), {
      apiError: proofPendingError(requestId, "claimed gate event log was not found on chain"),
    });
  }
  const chainRawLogHash = rawLogHashForChainLog(matchingLog);
  if (chainRawLogHash.toLowerCase() !== payload.rawLogHash.toLowerCase()) {
    throw Object.assign(new Error("claimed gate event rawLogHash does not match chain log"), {
      apiError: proofBlockedError(requestId, "claimed gate event rawLogHash does not match chain log", {
        expected: payload.rawLogHash,
        actual: chainRawLogHash,
      }),
    });
  }
  return {
    currentBlockNumber,
    confirmations: currentBlockNumber - payload.blockNumber + 1,
  };
}

function assertReceiptMatchesGatePayload(
  receipt: Record<string, unknown>,
  payload: { txHash: string; blockNumber: number },
  requestId: string,
): void {
  const txHash = optionalHex(receipt.transactionHash ?? receipt.txHash ?? receipt.hash);
  if (txHash && txHash.toLowerCase() !== payload.txHash.toLowerCase()) {
    throw Object.assign(new Error("gate transaction receipt hash mismatch"), {
      apiError: proofBlockedError(requestId, "gate transaction receipt hash mismatch", { expected: payload.txHash, actual: txHash }),
    });
  }
  const blockNumber = optionalChainNumber(receipt.blockNumber);
  if (blockNumber !== null && blockNumber !== payload.blockNumber) {
    throw Object.assign(new Error("gate transaction receipt block mismatch"), {
      apiError: proofBlockedError(requestId, "gate transaction receipt block mismatch", {
        expected: payload.blockNumber,
        actual: blockNumber,
      }),
    });
  }
  const status = receipt.status;
  if (status === "reverted" || status === "0x0" || status === 0 || status === false) {
    throw Object.assign(new Error("gate transaction receipt is reverted"), {
      apiError: proofBlockedError(requestId, "gate transaction receipt is reverted"),
    });
  }
}

function chainLogMatchesGatePayload(
  log: Record<string, unknown>,
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
  },
): boolean {
  const txHash = optionalHex(log.transactionHash ?? log.txHash);
  if (txHash && txHash.toLowerCase() !== payload.txHash.toLowerCase()) {
    return false;
  }
  const logIndex = optionalChainNumber(log.logIndex ?? log.index);
  if (logIndex !== null && logIndex !== payload.logIndex) {
    return false;
  }
  const blockNumber = optionalChainNumber(log.blockNumber);
  if (blockNumber !== null && blockNumber !== payload.blockNumber) {
    return false;
  }
  const chainId = optionalString(log.chainId);
  if (chainId && chainId !== payload.chainId) {
    return false;
  }
  const eventName = optionalString(log.eventName ?? log.event);
  if (eventName && eventName !== payload.event) {
    return false;
  }
  const args = log.args && typeof log.args === "object" ? (log.args as Record<string, unknown>) : {};
  const spendId = optionalHex(log.spendId ?? args.spendId);
  return !spendId || spendId.toLowerCase() === payload.spendId.toLowerCase();
}

function rawLogHashForChainLog(log: Record<string, unknown>): `0x${string}` {
  const explicit = optionalHex(log.rawLogHash ?? log.logHash);
  if (explicit && /^0x[0-9a-fA-F]{64}$/.test(explicit)) {
    return explicit as `0x${string}`;
  }
  return hashJson(normalizeChainJson(log));
}

function normalizeChainJson(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeChainJson(item));
  }
  if (value && typeof value === "object") {
    const result: Record<string, JsonValue> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child !== undefined) {
        result[key] = normalizeChainJson(child);
      }
    }
    return result;
  }
  return String(value);
}

function optionalHex(value: unknown): string | null {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value) ? value : null;
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function optionalChainNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return Number(value);
  }
  if (typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value)) {
    return Number.parseInt(value.slice(2), 16);
  }
  return null;
}

function chainFailureMessage(prefix: string, error: unknown): string {
  return error instanceof Error ? `${prefix}: ${error.message}` : prefix;
}

function finalityDepthForSession(session: Row): number {
  const parsed = JSON.parse(String(session.run_config_json)) as { finalityDepth?: unknown };
  return typeof parsed.finalityDepth === "number" && Number.isInteger(parsed.finalityDepth)
    ? Math.max(1, Math.min(parsed.finalityDepth, 128))
    : 2;
}

function assertGateEventRowMatches(
  existing: Row,
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
    rawLogHash: string;
  },
  gateEventId: string,
  requestId: string,
): void {
  const mismatches: Record<string, JsonValue> = {};
  const checkString = (field: string, expected: string, actual: unknown) => {
    if (String(actual) !== expected) {
      mismatches[field] = { expected, actual: actual === null || actual === undefined ? null : String(actual) };
    }
  };
  const checkNumber = (field: string, expected: number, actual: unknown) => {
    if (Number(actual) !== expected) {
      mismatches[field] = {
        expected,
        actual: actual === null || actual === undefined || Number.isNaN(Number(actual)) ? null : Number(actual),
      };
    }
  };

  checkString("gateEventId", gateEventId, existing.gate_event_id);
  checkString("spendId", payload.spendId, existing.spend_id);
  checkString("event", payload.event, existing.event_kind);
  checkString("txHash", payload.txHash, existing.tx_hash);
  checkNumber("logIndex", payload.logIndex, existing.log_index);
  checkString("chainId", payload.chainId, existing.chain_id);
  checkNumber("blockNumber", payload.blockNumber, existing.block_number);
  checkString("rawLogHash", payload.rawLogHash, existing.raw_log_hash);
  if (Object.keys(mismatches).length > 0) {
    throw Object.assign(new Error("gate event replay does not match the previously observed log"), {
      apiError: proofBlockedError(requestId, "gate event replay does not match the previously observed log", { mismatches }),
    });
  }
}

function gateObservedKind(event: "SpendTripped" | "SpendSettled"): "gate.spend_tripped.observed" | "gate.spend_settled.observed" {
  return event === "SpendTripped" ? "gate.spend_tripped.observed" : "gate.spend_settled.observed";
}

function gateFinalizedKind(event: "SpendTripped" | "SpendSettled"): "gate.spend_tripped" | "gate.spend_settled" {
  return event === "SpendTripped" ? "gate.spend_tripped" : "gate.spend_settled";
}

function gateSpendStatus(event: "SpendTripped" | "SpendSettled", finality: "observed" | "finalized" | "reorg"): string {
  const prefix = event === "SpendTripped" ? "tripped" : "settled";
  if (finality === "reorg") {
    return `${prefix}_reorg_invalidated`;
  }
  return `${prefix}_${finality === "observed" ? "observed_finalizing" : "finalized"}`;
}

function gateEventPayload(
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
    currentBlockNumber: number;
    rawLogHash: string;
  },
  gateEventId: string,
  finalityDepth: number,
  confirmations: number,
  finalityStatus: "observed_finalizing" | "finalized",
  observedEventId: string | null,
): Record<string, JsonValue> {
  return {
    gateEventId,
    event: payload.event,
    spendId: payload.spendId,
    txHash: payload.txHash,
    logIndex: payload.logIndex,
    chainId: payload.chainId,
    blockNumber: payload.blockNumber,
    currentBlockNumber: payload.currentBlockNumber,
    rawLogHash: payload.rawLogHash,
    confirmations,
    finalityDepth,
    finalityStatus,
    observedEventId,
    proofAuthority: finalityStatus === "finalized",
    winnerClaimAllowed: false,
  };
}

function appendGateObservedEvent(
  ctx: ServiceCtx,
  sessionId: string,
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
    currentBlockNumber: number;
    rawLogHash: string;
  },
  gateEventId: string,
  finalityDepth: number,
  confirmations: number,
): EvidenceEvent {
  const event = appendEvidenceEvent(ctx, {
    sessionId,
    authority: "delivery",
    kind: gateObservedKind(payload.event),
    payload: gateEventPayload(payload, gateEventId, finalityDepth, confirmations, "observed_finalizing", null),
  });
  ctx.db.sqlite
    .prepare("UPDATE spends SET status = ? WHERE session_id = ? AND spend_id = ?")
    .run(gateSpendStatus(payload.event, "observed"), sessionId, payload.spendId);
  return event;
}

function appendGateFinalizedEvent(
  ctx: ServiceCtx,
  sessionId: string,
  payload: {
    event: "SpendTripped" | "SpendSettled";
    spendId: string;
    txHash: string;
    logIndex: number;
    chainId: string;
    blockNumber: number;
    currentBlockNumber: number;
    rawLogHash: string;
  },
  gateEventId: string,
  observedEventId: string,
  finalityDepth: number,
  confirmations: number,
): EvidenceEvent {
  return appendEvidenceEvent(ctx, {
    sessionId,
    authority: "proof",
    kind: gateFinalizedKind(payload.event),
    payload: gateEventPayload(payload, gateEventId, finalityDepth, confirmations, "finalized", observedEventId),
  });
}

function recordGateReorg(
  ctx: ServiceCtx,
  input: {
    requestId: string;
    sessionId: string;
    payload: {
      event: "SpendTripped" | "SpendSettled";
      spendId: string;
      txHash: string;
      logIndex: number;
      chainId: string;
      blockNumber: number;
      currentBlockNumber: number;
      rawLogHash: string;
    };
    existing: Row | undefined;
    gateEventId: string;
    finalityDepth: number;
    confirmations: number;
  },
): ServiceResult<unknown> {
  if (!input.existing) {
    throw Object.assign(new Error("cannot invalidate a gate event that was never observed"), {
      apiError: proofPendingError(input.requestId, "cannot invalidate a gate event that was never observed"),
    });
  }
  if (typeof input.existing.reorg_event_id === "string") {
    return {
      ok: true,
      requestId: input.requestId,
      evidenceEventId: input.existing.reorg_event_id,
      data: {
        gateEventId: input.gateEventId,
        spendId: input.payload.spendId,
        event: input.payload.event,
        finalityStatus: "reorg_invalidated",
        reorgEventId: input.existing.reorg_event_id,
        proofAuthority: typeof input.existing.finalized_event_id === "string",
        winnerClaimAllowed: false,
      },
    };
  }
  const finalizedEventId = typeof input.existing.finalized_event_id === "string" ? input.existing.finalized_event_id : null;
  const observedEventId = typeof input.existing.observed_event_id === "string" ? input.existing.observed_event_id : null;
  const invalidatedEventId =
    typeof input.existing.finalized_event_id === "string" ? input.existing.finalized_event_id : observedEventId;
  if (!invalidatedEventId) {
    throw Object.assign(new Error("gate event has no observed or finalized evidence event to invalidate"), {
      apiError: proofPendingError(input.requestId, "gate event has no observed or finalized evidence event to invalidate"),
    });
  }
  const reorgAuthority = finalizedEventId ? "proof" : "delivery";
  const reorgEvent = appendEvidenceEvent(ctx, {
    sessionId: input.sessionId,
    authority: reorgAuthority,
    kind: "reorg.invalidated",
    payload: {
      gateEventId: input.gateEventId,
      event: input.payload.event,
      spendId: input.payload.spendId,
      txHash: input.payload.txHash,
      logIndex: input.payload.logIndex,
      chainId: input.payload.chainId,
      invalidatedEventId,
      invalidatedFinalizedEventId: finalizedEventId,
      invalidatedObservedEventId: observedEventId,
      finalityDepth: input.finalityDepth,
      confirmations: input.confirmations,
      finalityStatus: "reorg_invalidated",
      winnerClaimAllowed: false,
    },
  });
  ctx.db.sqlite
    .prepare(
      `UPDATE gate_chain_events
       SET status = 'reorg_invalidated', reorg_event_id = ?, current_block_number = ?, confirmations = 0, updated_at = ?
       WHERE gate_event_id = ?`,
    )
    .run(reorgEvent.eventId, input.payload.currentBlockNumber, ctx.clock.now().toISOString(), input.gateEventId);
  ctx.db.sqlite
    .prepare("UPDATE spends SET status = ? WHERE session_id = ? AND spend_id = ?")
    .run(gateSpendStatus(input.payload.event, "reorg"), input.sessionId, input.payload.spendId);
  return {
    ok: true,
    requestId: input.requestId,
    evidenceEventId: reorgEvent.eventId,
    data: {
      gateEventId: input.gateEventId,
      spendId: input.payload.spendId,
      event: input.payload.event,
      finalityStatus: "reorg_invalidated",
      reorgEventId: reorgEvent.eventId,
      invalidatedEventId,
      proofAuthority: reorgAuthority === "proof",
      winnerClaimAllowed: false,
    },
  };
}

function normalizedSourceHashes(sourceHashes: string[]): string[] {
  return [...sourceHashes].map((sourceHash) => sourceHash.toLowerCase()).sort();
}

function requireRegisteredSources(ctx: ServiceCtx, sessionId: string, sourceHashes: string[], requestId: string): void {
  const missing = sourceHashes.filter((sourceHash) => {
    const row = ctx.db.sqlite
      .prepare("SELECT source_hash FROM sources WHERE session_id = ? AND LOWER(source_hash) = ?")
      .get(sessionId, sourceHash) as Row | undefined;
    return !row;
  });
  if (missing.length > 0) {
    throw Object.assign(new Error("spend references unregistered source hashes"), {
      apiError: proofPendingError(requestId, "spend registration requires all source hashes to be registered first"),
    });
  }
}

function spendBindingFor(
  session: Row,
  sessionId: string,
  spend: { pactId: string; toolId: string; sourceHashes: string[]; agentWallet: string; nonce: string },
): {
  spendId: string;
  sourceSetHash: string;
  sessionCommitment: string;
  spendPreimage: Record<string, JsonValue>;
} {
  const runConfigHash = String(session.run_config_hash);
  const sourceSetHash = keccakJson(spend.sourceHashes);
  const sessionCommitment = keccakJson({ sessionId: sessionId.toLowerCase(), runConfigHash });
  const spendPreimage: Record<string, JsonValue> = {
    runConfigHash,
    sessionCommitment,
    pactId: spend.pactId,
    toolId: spend.toolId,
    sourceSetHash,
    agentWallet: spend.agentWallet.toLowerCase(),
    nonce: spend.nonce,
  };
  return {
    spendId: keccakJson(spendPreimage),
    sourceSetHash,
    sessionCommitment,
    spendPreimage,
  };
}

function requireActiveArtifactAccess(
  ctx: ServiceCtx,
  input: {
    sessionId: string;
    spendId: string;
    payer: string;
    artifactHash: string;
    bearerToken: string | null;
  },
  requestId: string,
): Row {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT token_id, token_hash, status
       FROM artifact_access_tokens
       WHERE session_id = ? AND spend_id = ? AND payer = ? AND artifact_hash = ?`,
    )
    .all(input.sessionId, input.spendId, input.payer, input.artifactHash) as Row[];
  if (rows.length === 0) {
    throw Object.assign(new Error("artifact access is pending live settlement and bearer-token proof"), {
      apiError: proofPendingError(requestId, "artifact access is pending live settlement and bearer-token proof"),
    });
  }
  if (!input.bearerToken) {
    throw Object.assign(new Error("artifact bearer token is required"), {
      apiError: proofPendingError(requestId, "artifact bearer token is required but no proof-valid token is active"),
    });
  }
  const tokenHash = sha256Hex(input.bearerToken);
  const active = rows.find((row) => row.status === "active" && row.token_hash === tokenHash);
  if (!active) {
    throw Object.assign(new Error("artifact bearer token is not active for tuple"), {
      apiError: proofPendingError(requestId, "artifact bearer token is not backed by a proof-valid active access row"),
    });
  }
  return active;
}

function requireQuotePreflight(
  ctx: ServiceCtx,
  sessionId: string,
  payload: { spendId: string; preflightId: string; artifactCommitment: string },
  requestId: string,
): Row {
  const preflight = ctx.db.sqlite
    .prepare(
      `SELECT preflight_id, spend_id, artifact_hash_preview, price_disclosure_hash, source_state_snapshot_hash, status
       FROM artifact_preflights
       WHERE session_id = ? AND preflight_id = ? AND spend_id = ?`,
    )
    .get(sessionId, payload.preflightId, payload.spendId) as Row | undefined;
  if (!preflight) {
    throw Object.assign(new Error("artifact preflight is required before quote signing"), {
      apiError: proofPendingError(requestId, "artifact preflight is required before quote signing"),
    });
  }
  if (preflight.status !== "pending_live_delivery") {
    throw Object.assign(new Error("artifact preflight is not quote-eligible"), {
      apiError: proofBlockedError(requestId, "artifact preflight is not quote-eligible", {
        status: String(preflight.status),
      }),
    });
  }
  if (preflight.artifact_hash_preview !== payload.artifactCommitment) {
    throw Object.assign(new Error("quote artifact commitment does not match preflight preview"), {
      apiError: proofBlockedError(requestId, "quote artifact commitment must match the artifact preflight preview", {
        preflightId: payload.preflightId,
      }),
    });
  }
  return preflight;
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

function evidenceEventFromRow(row: Row): EvidenceEvent {
  return EvidenceEventSchema.parse({
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
  return rows.map(evidenceEventFromRow);
}

function listMcpAdapterCalls(ctx: ServiceCtx, sessionId: string, limit: number) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM mcp_adapter_calls
       WHERE session_id = ?
       ORDER BY created_at ASC, call_id ASC
       LIMIT ?`,
    )
    .all(sessionId, limit) as Row[];
  return rows.map((row) =>
    McpAdapterCallViewSchema.parse({
      callId: row.call_id,
      sessionId: row.session_id,
      auditNonce: row.audit_nonce ?? `legacy:${row.call_id}`,
      toolName: row.tool_name,
      requestHash: row.request_hash,
      responseHash: row.response_hash,
      request: JSON.parse(String(row.request_json)),
      response: JSON.parse(String(row.response_json)),
      status: row.status,
      createdAt: row.created_at,
      proofAuthority: false,
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

function verifyMcpAdapterCallIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const events = listEvents(ctx, sessionId, 0, 200).filter((event) => event.kind === "mcp.adapter.call");
  const calls = new Map(listMcpAdapterCalls(ctx, sessionId, 200).map((call) => [call.callId, call]));
  const errors: string[] = [];
  for (const event of events) {
    const payload = event.payload;
    const callId = typeof payload.callId === "string" ? payload.callId : null;
    if (!callId) {
      errors.push(`mcp adapter event ${event.eventId} is missing callId`);
      continue;
    }
    const call = calls.get(callId);
    if (!call) {
      errors.push(`mcp adapter event ${event.eventId} has no matching adapter call row`);
      continue;
    }
    if (hashJson(call.request) !== call.requestHash) {
      errors.push(`mcp adapter call request body hash mismatch for ${callId}`);
    }
    if (hashJson(call.response) !== call.responseHash) {
      errors.push(`mcp adapter call response body hash mismatch for ${callId}`);
    }
    for (const field of ["auditNonce", "toolName", "requestHash", "responseHash", "status"] as const) {
      if (payload[field] !== call[field]) {
        errors.push(`mcp adapter call mismatch at ${field} for ${callId}`);
      }
    }
  }
  const eventCallIds = new Set(events.map((event) => (typeof event.payload.callId === "string" ? event.payload.callId : null)));
  for (const callId of calls.keys()) {
    if (!eventCallIds.has(callId)) {
      errors.push(`mcp adapter call row ${callId} has no matching evidence event`);
    }
  }
  return errors;
}

function verifyGateFinalityIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const errors: string[] = [];
  const gateEvents = (
    ctx.db.sqlite
      .prepare(
        `SELECT *
         FROM evidence_events
         WHERE session_id = ?
           AND kind IN ('reorg.invalidated', 'gate.spend_tripped', 'gate.spend_settled')
         ORDER BY event_seq ASC`,
      )
      .all(sessionId) as Row[]
  ).map(evidenceEventFromRow);
  const reorgs = gateEvents.filter((event) => event.kind === "reorg.invalidated");
  for (const reorg of reorgs) {
    errors.push(`session contains reorg.invalidated event ${reorg.eventId}; winner claim is blocked`);
  }
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT gate_event_id, spend_id, event_kind, tx_hash, log_index, chain_id, block_number, raw_log_hash,
              status, observed_event_id, finalized_event_id, reorg_event_id, finality_depth, confirmations
       FROM gate_chain_events
       WHERE session_id = ?`,
    )
    .all(sessionId) as Row[];
  const rowsByFinalizedEventId = new Map<string, Row>();
  for (const row of rows) {
    if (typeof row.finalized_event_id === "string") {
      rowsByFinalizedEventId.set(row.finalized_event_id, row);
    }
    if (row.status === "reorg_invalidated" || row.reorg_event_id) {
      errors.push(`gate ${row.event_kind} ${row.tx_hash}:${row.log_index} is reorg_invalidated; winner claim is blocked`);
    }
    if (row.status === "finalized" && !row.finalized_event_id) {
      errors.push(`gate ${row.event_kind} ${row.tx_hash}:${row.log_index} is finalized without a proof event`);
    }
    if (row.finalized_event_id && Number(row.confirmations) < Number(row.finality_depth)) {
      errors.push(`gate ${row.event_kind} ${row.tx_hash}:${row.log_index} finalized below required finality depth`);
    }
    if (!row.observed_event_id) {
      errors.push(`gate ${row.event_kind} ${row.tx_hash}:${row.log_index} has no observed delivery event`);
    }
  }
  for (const event of gateEvents.filter((candidate) => candidate.kind === "gate.spend_tripped" || candidate.kind === "gate.spend_settled")) {
    const row = rowsByFinalizedEventId.get(event.eventId);
    if (!row) {
      errors.push(`gate proof event ${event.eventId} has no matching finalized gate row`);
      continue;
    }
    const payload = event.payload;
    const expectedKind = row.event_kind === "SpendTripped" ? "gate.spend_tripped" : "gate.spend_settled";
    if (event.kind !== expectedKind) {
      errors.push(`gate proof event ${event.eventId} kind does not match row event kind`);
    }
    const stringChecks = [
      ["gateEventId", row.gate_event_id],
      ["spendId", row.spend_id],
      ["event", row.event_kind],
      ["txHash", row.tx_hash],
      ["chainId", row.chain_id],
      ["rawLogHash", row.raw_log_hash],
      ["observedEventId", row.observed_event_id],
    ] as const;
    for (const [field, expected] of stringChecks) {
      if (payload[field] !== expected) {
        errors.push(`gate proof event ${event.eventId} payload.${field} does not match gate row`);
      }
    }
    const numberChecks = [
      ["logIndex", row.log_index],
      ["blockNumber", row.block_number],
      ["finalityDepth", row.finality_depth],
    ] as const;
    for (const [field, expected] of numberChecks) {
      if (Number(payload[field]) !== Number(expected)) {
        errors.push(`gate proof event ${event.eventId} payload.${field} does not match gate row`);
      }
    }
    if (payload.finalityStatus !== "finalized" || payload.proofAuthority !== true) {
      errors.push(`gate proof event ${event.eventId} does not carry finalized proof authority payload`);
    }
  }
  return errors;
}

function verifyReplayBundleBindings(
  ctx: ServiceCtx,
  sessionId: string,
  payload: {
    receipt?: Record<string, JsonValue> | undefined;
    replayBundle?: Record<string, JsonValue> | undefined;
  },
): string[] {
  const bundle = replayBundleFromVerifierPayload(payload);
  if (!bundle) {
    return [];
  }
  const errors: string[] = [];
  if (typeof bundle.sessionId === "string" && bundle.sessionId !== sessionId) {
    errors.push("replayBundle.sessionId must match verifier sessionId");
  }
  if (typeof bundle.agentTranscriptHash !== "string") {
    return errors;
  }
  const asOfCount =
    typeof bundle.asOfMcpAdapterCallCount === "number" && Number.isInteger(bundle.asOfMcpAdapterCallCount)
      ? Math.max(0, Math.min(bundle.asOfMcpAdapterCallCount, 200))
      : 200;
  const expectedAgentTranscriptHash = hashJson(buildAgentTranscriptData(sessionId, ctx, asOfCount));
  if (bundle.agentTranscriptHash !== expectedAgentTranscriptHash) {
    errors.push("replayBundle.agentTranscriptHash does not match the server transcript snapshot");
  }
  return errors;
}

function replayBundleFromVerifierPayload(payload: {
  receipt?: Record<string, JsonValue> | undefined;
  replayBundle?: Record<string, JsonValue> | undefined;
}): Record<string, JsonValue> | null {
  if (payload.replayBundle) {
    return payload.replayBundle;
  }
  const receiptBundle = payload.receipt?.replayBundle;
  return receiptBundle && typeof receiptBundle === "object" && !Array.isArray(receiptBundle) ? receiptBundle : null;
}

function scoped(scope: string, sessionId: string): string {
  return `${scope}:${sessionId}`;
}

function toStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function proofProviderWarnings(statuses: ProofProviderStatus[]): string[] {
  return statuses
    .filter((status) => !status.ready)
    .map((status) => `${status.name} proof provider is ${status.mode}: ${status.reason}`);
}

function jsonRecord(value: unknown): Record<string, JsonValue> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return JSON.parse(JSON.stringify(value)) as Record<string, JsonValue>;
}
