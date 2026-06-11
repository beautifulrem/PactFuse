import {
  AgentTranscriptViewSchema,
  ArtifactAccessTokenViewSchema,
  ArtifactPreflightViewSchema,
  ArtifactAccessIssuePayloadSchema,
  ArtifactPreflightPayloadSchema,
  ArtifactRefundPayloadSchema,
  CawOperationBuildPayloadSchema,
  ChainIndexedLogViewSchema,
  ChainIndexerBackfillInputSchema,
  ChainIndexerBackfillResultSchema,
  ChainIndexerStatusViewSchema,
  CanonicalCawReceiptViewSchema,
  CawLiveAuditSyncPayloadSchema,
  CawLiveInteractionViewSchema,
  CawLivePactSubmitPayloadSchema,
  CawLivePactSyncPayloadSchema,
  CawLiveTransferSubmitPayloadSchema,
  CawReceiptIngestPayloadSchema,
  CawReceiptOperationViewSchema,
  CreateSessionInputSchema,
  EvidenceEventSchema,
  GateEventIngestPayloadSchema,
  Hex32Schema,
  HexSchema,
  IsoDateStringSchema,
  JudgeCheckViewSchema,
  LeaseExecutePayloadSchema,
  LeaseRunViewSchema,
  LOCKED_RUNTIME_MODES,
  McpAdapterAuditPayloadSchema,
  McpAdapterCallViewSchema,
  QuoteViewSchema,
  QuotePayloadSchema,
  RawCawReceiptBundleViewSchema,
  ReplayBundleViewSchema,
  ReplayPageViewSchema,
  RunnerHeartbeatViewSchema,
  SessionScopedEnvelopeSchema,
  SessionViewSchema,
  SourceViewSchema,
  SourceChallengePayloadSchema,
  SourceRegisterPayloadSchema,
  SpendViewSchema,
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
  type ChainIndexerBackfillInput,
  type CawLiveAuditSyncPayload,
  type CawLivePactSubmitPayload,
  type CawLiveTransferSubmitPayload,
  type VerifierRunView,
} from "@pactfuse/evidence-schema";
import { encodeAbiParameters, keccak256, recoverMessageAddress } from "viem";
import type { CawLiveAuditInput, McpLeaseExecutionResult, ProofProviderStatus, ServiceCtx, ServiceResult } from "../types.js";
import {
  ZERO_HASH,
  badRequestError,
  conflictError,
  forbiddenError,
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
  unauthorizedError,
} from "../util.js";

type Row = Record<string, unknown>;
type PinnedMcpManifest = {
  sourceHashes: string[];
  manifestHashes: string[];
  tools: Array<Record<string, unknown>>;
  toolsHash: string;
};
type ReplayCollectionName =
  | "events"
  | "sources"
  | "spends"
  | "artifactPreflights"
  | "quotes"
  | "artifactAccessTokens"
  | "mcpAdapterCalls"
  | "cawReceiptOperations"
  | "cawLiveInteractions"
  | "rawCawReceiptBundles"
  | "canonicalCawReceipts"
  | "leaseRuns";
const REPLAY_SUMMARY_LIMIT = 200;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const REPLAY_COLLECTION_NAMES: ReplayCollectionName[] = [
  "artifactAccessTokens",
  "artifactPreflights",
  "canonicalCawReceipts",
  "cawLiveInteractions",
  "cawReceiptOperations",
  "events",
  "leaseRuns",
  "mcpAdapterCalls",
  "quotes",
  "rawCawReceiptBundles",
  "sources",
  "spends",
];
const ARTIFACT_PAYLOAD_REPLAY_MAX_BYTES = 256 * 1024;
const ARTIFACT_TOKEN_LEASE_CLAIM_TTL_MS = 5 * 60 * 1000;
type ChainIndexerBackfillPayload = ChainIndexerBackfillInput["payload"];
type NormalizedIndexedChainLog = {
  logId: `0x${string}`;
  cursorId: string;
  chainId: string;
  blockNumber: number;
  txHash: `0x${string}`;
  logIndex: number;
  address: string | null;
  topics: string[];
  data: string | null;
  rawLogHash: `0x${string}`;
  createdAt: string;
  raw: JsonValue;
};
type IndexedLogProofRef = {
  indexedLogId: `0x${string}`;
  cursorId: string;
  indexedRawLogHash: `0x${string}`;
  finalizedHeadBlock: number;
  latestHeadBlock: number;
};
type GateContractStateProof = {
  contractStateVerified: true;
  contractAddress: string;
  contractFunction: "registeredSpend";
  contractSessionId: string;
  contractPactId: string;
  contractToolId: string;
  contractSourceSetHash: string;
  contractAgentWallet: string;
  contractPaymentToken: string;
  contractPrice: string;
  contractArtifactHash: string;
  contractMarket: string;
  contractSpendState: "Tripped" | "Settled";
};
type SourceContractStateProof = {
  contractStateVerified: true;
  sourceRegistryAddress: string;
  contractFunction: "sourceState";
  contractSourceState: "Challenged";
};
type CawReceiptIngestData = {
  receiptBundleHash: `0x${string}`;
  rawReceiptBundleHash?: `0x${string}`;
  operationId: string | null;
  receiptCount: number;
  canonicalReceiptCount: number;
  status: "fixture_manual_receipt" | "raw_ingested_pending_proof" | "verified_policy_authority_structural";
  proofAuthority: boolean;
  winnerClaimAllowed: false;
};
type CanonicalCawReceiptData = {
  rawReceiptHash: `0x${string}`;
  canonicalReceiptHash: `0x${string}`;
  bundleId: `0x${string}`;
  sessionId: `0x${string}`;
  operationId: `0x${string}`;
  operationKind: "deny_probe" | "approve" | "activate_tool";
  sourceLabel: string;
  walletAddress: string;
  target: string | null;
  selector: string | null;
  requestId: string;
  effect: "allow" | "deny";
  status: string;
  policyDigest: `0x${string}`;
  paramsDigest: `0x${string}`;
  txHash: `0x${string}` | null;
  txCount: string;
  expiry: string;
  fetchedAt: string;
  createdAt: string;
};

const PROCUREMENT_GATE_STATE_ABI = [
  {
    type: "function",
    name: "registeredSpend",
    stateMutability: "view",
    inputs: [{ name: "spendId", type: "bytes32" }],
    outputs: [
      { name: "sessionId", type: "bytes32" },
      { name: "pactId", type: "bytes32" },
      { name: "toolId", type: "bytes32" },
      { name: "sourceSetHash", type: "bytes32" },
      { name: "agentWallet", type: "address" },
      { name: "paymentToken", type: "address" },
      { name: "price", type: "uint256" },
      { name: "artifactHash", type: "bytes32" },
      { name: "market", type: "address" },
      { name: "state", type: "uint8" },
    ],
  },
] as const;
const SOURCE_REGISTRY_STATE_ABI = [
  {
    type: "function",
    name: "sourceState",
    stateMutability: "view",
    inputs: [{ name: "sourceHash", type: "bytes32" }],
    outputs: [{ name: "state", type: "uint8" }],
  },
] as const;
const GATE_SPEND_STATE = {
  Tripped: 2,
  Settled: 3,
} as const;
const SOURCE_STATE_CHALLENGED = 2;
const CAW_STRUCTURAL_AUTHORITY_STATUS = "verified_policy_authority_structural";

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
    const sourceHash = payload.sourceHash.toLowerCase();
    const sourceIdentity = await verifyOptionalSourceIdentity(payload, sourceHash, requestId);
    const createdAt = ctx.clock.now().toISOString();
    const capabilityVectorJson = canonicalizeJson(payload.capabilityVector);
    const existing = ctx.db.sqlite
      .prepare("SELECT * FROM sources WHERE session_id = ? AND LOWER(source_hash) = ?")
      .get(envelope.sessionId, sourceHash) as Row | undefined;
    if (existing) {
      assertExistingSourceMatches(
        existing,
        {
          sourceId: payload.sourceId,
          manifestUrl: payload.manifestUrl,
          manifestHash: payload.manifestHash,
          issuer: payload.issuer ?? null,
          signature: payload.signature ?? null,
          capabilityVectorJson,
        },
        requestId,
      );
    } else {
      ctx.db.sqlite
        .prepare(
          `INSERT INTO sources
            (source_id, session_id, source_hash, manifest_url, manifest_hash, issuer, signature, capability_vector_json, proof_status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
        )
        .run(
          payload.sourceId,
          envelope.sessionId,
          sourceHash,
          payload.manifestUrl,
          payload.manifestHash,
          payload.issuer ?? null,
          payload.signature ?? null,
          capabilityVectorJson,
          createdAt,
        );
    }
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "operator",
      kind: "source.registered",
      payload: {
        sourceId: payload.sourceId,
        sourceHash,
        manifestHash: payload.manifestHash,
        sourceIdentityHash: sourceIdentity.sourceIdentityHash,
        identityVerified: sourceIdentity.identityVerified,
        proofStatus: "pending",
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: { sourceHash, status: "pending", winnerClaimAllowed: false },
    };
  });
}

async function verifyOptionalSourceIdentity(
  payload: {
    sourceId: string;
    manifestUrl: string;
    manifestHash: string;
    issuer?: string | undefined;
    signature?: string | undefined;
    capabilityVector: unknown;
  },
  sourceHash: string,
  requestId: string,
): Promise<{ sourceIdentityHash: `0x${string}`; identityVerified: boolean }> {
  const sourceIdentityHash = sourceIdentityHashFor(payload);
  const hasIssuer = typeof payload.issuer === "string" && payload.issuer.length > 0;
  const hasSignature = typeof payload.signature === "string" && payload.signature.length > 0;
  if (hasIssuer !== hasSignature) {
    throw Object.assign(new Error("source issuer and signature must be provided together"), {
      apiError: proofBlockedError(requestId, "source issuer and signature must be provided together"),
    });
  }
  if (!hasIssuer || !hasSignature) {
    return { sourceIdentityHash, identityVerified: false };
  }
  const issuer = payload.issuer as string;
  const signature = payload.signature as `0x${string}`;
  if (sourceHash.toLowerCase() !== sourceIdentityHash.toLowerCase()) {
    throw Object.assign(new Error("sourceHash does not match signed source identity"), {
      apiError: proofBlockedError(requestId, "sourceHash does not match signed source identity", {
        expected: sourceIdentityHash,
        actual: sourceHash,
      }),
    });
  }
  let recovered: string;
  try {
    recovered = await recoverMessageAddress({
      message: sourceIdentityMessage(sourceIdentityHash),
      signature,
    });
  } catch (error) {
    throw Object.assign(new Error("source signature cannot be recovered"), {
      apiError: proofBlockedError(requestId, chainFailureMessage("source signature cannot be recovered", error)),
    });
  }
  if (recovered.toLowerCase() !== issuer.toLowerCase()) {
    throw Object.assign(new Error("source signature does not recover issuer"), {
      apiError: proofBlockedError(requestId, "source signature does not recover issuer", {
        expected: issuer,
        actual: recovered,
      }),
    });
  }
  return { sourceIdentityHash, identityVerified: true };
}

function sourceIdentityHashFor(payload: {
  sourceId: string;
  manifestUrl: string;
  manifestHash: string;
  capabilityVector: unknown;
}): `0x${string}` {
  return hashJson({
    version: "pactfuse-source-identity-v1",
    sourceId: payload.sourceId,
    manifestUrl: payload.manifestUrl,
    manifestHash: payload.manifestHash.toLowerCase(),
    capabilityVector: payload.capabilityVector,
  });
}

function sourceIdentityMessage(sourceIdentityHash: `0x${string}`): string {
  return `PactFuse source identity v1:${sourceIdentityHash}`;
}

export async function challengeSource(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(SourceChallengePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("sources:challenge", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const sourceHash = payload.sourceHash.toLowerCase();
    const reasonHash = payload.reasonHash.toLowerCase();
    const createdAt = ctx.clock.now().toISOString();
    const normalizedPayload = { ...payload, sourceHash, reasonHash };
    const challengeId = hashJson({ sessionId: envelope.sessionId, payload: normalizedPayload, createdAt });
    const event = withImmediateTransaction(ctx, () => {
      ctx.db.sqlite
        .prepare(
          `INSERT INTO source_challenges
            (challenge_id, session_id, source_hash, reason_hash, evidence_ref, status, created_at)
           VALUES (?, ?, ?, ?, ?, 'pending_chain_log', ?)`,
        )
        .run(challengeId, envelope.sessionId, sourceHash, reasonHash, payload.evidenceRef ?? null, createdAt);
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
          sourceHash,
          reasonHash,
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
        if (spend.payer.toLowerCase() !== spend.agentWallet.toLowerCase()) {
          throw Object.assign(new Error("payer must equal agentWallet for ProcurementGate settlement binding"), {
            apiError: proofBlockedError(requestId, "payer must equal agentWallet for ProcurementGate settlement binding", {
              payer: spend.payer,
              agentWallet: spend.agentWallet,
            }),
          });
        }
        assertNonZeroProcurementGateSpend(spend, requestId);
        const sourceCapabilitySnapshot = sourceCapabilitySnapshotFor(ctx, envelope.sessionId, sourceHashes);
        const binding = spendBindingFor(session, envelope.sessionId, {
          pactId: spend.pactId,
          toolId: spend.toolId,
          sourceHashes,
          sourceCapabilitySnapshotHash: sourceCapabilitySnapshot.hash,
          payer: spend.payer,
          agentWallet: spend.agentWallet,
          paymentToken: spend.paymentToken,
          artifactHash: spend.artifactHash,
          market: spend.market,
          maxPriceAtomic: spend.maxPriceAtomic,
          nonce: spend.nonce,
        });
        if (spend.spendId.toLowerCase() !== binding.spendId) {
          throw Object.assign(new Error("spendId does not match the ProcurementGate ABI spend preimage"), {
            apiError: proofBlockedError(requestId, "spendId does not match the ProcurementGate ABI spend preimage", {
              expectedSpendId: binding.spendId,
              sourceSetHash: binding.sourceSetHash,
            }),
          });
        }
        const sourceHashesJson = canonicalizeJson(sourceHashes);
        const spendPreimageJson = canonicalizeJson(binding.spendPreimage);
        const existingSpend = ctx.db.sqlite
          .prepare("SELECT * FROM spends WHERE session_id = ? AND spend_id = ?")
          .get(envelope.sessionId, binding.spendId) as Row | undefined;
        if (existingSpend) {
          assertExistingSpendMatches(
            existingSpend,
            {
              pactId: spend.pactId,
              toolId: spend.toolId,
              payer: spend.payer,
              agentWallet: spend.agentWallet,
              paymentToken: spend.paymentToken,
              artifactHash: spend.artifactHash,
              market: spend.market,
              sourceHashesJson,
              sourceSetHash: binding.sourceSetHash,
              sessionCommitment: binding.sessionCommitment,
              spendPreimageJson,
              maxPriceAtomic: spend.maxPriceAtomic,
              nonce: spend.nonce,
            },
            requestId,
          );
        } else {
          ctx.db.sqlite
            .prepare(
              `INSERT INTO spends
                (spend_id, session_id, pact_id, tool_id, payer, agent_wallet, payment_token, artifact_hash, market,
                 source_hashes_json, source_set_hash, session_commitment,
                 spend_preimage_json, max_price_atomic, nonce, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered_pending_chain_log', ?)`,
            )
            .run(
              binding.spendId,
              envelope.sessionId,
              spend.pactId,
              spend.toolId,
              spend.payer,
              spend.agentWallet,
              spend.paymentToken,
              spend.artifactHash,
              spend.market,
              sourceHashesJson,
              binding.sourceSetHash,
              binding.sessionCommitment,
              spendPreimageJson,
              spend.maxPriceAtomic,
              spend.nonce,
              createdAt,
            );
        }
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
          spendIdBinding: "procurement-gate-abi-v1",
          spendPreimages: registeredSpends.map((spend) => spend.spendPreimage),
          sourceCapabilitySnapshotHashes: registeredSpends.map((spend) => String(spend.spendPreimage.sourceCapabilitySnapshotHash)),
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
        spendIdBinding: "procurement-gate-abi-v1",
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
): Promise<ServiceResult<CawReceiptIngestData>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawReceiptIngestPayloadSchema, envelope.payload);
  return withIdempotency<CawReceiptIngestData>(ctx, scoped("caw:receipts:ingest", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    if (!payload.manual && !payload.operationId) {
      throw Object.assign(new Error("CAW receipt ingest requires operationId"), {
        apiError: badRequestError(requestId, "non-manual CAW receipt ingest requires operationId"),
      });
    }
    const operation = payload.operationId
      ? (ctx.db.sqlite
          .prepare(
            `SELECT operation_id, session_id, operation_kind, target, selector, request_json, receipt_bundle_hash, status
             FROM caw_receipt_operations
             WHERE operation_id = ? AND session_id = ?`,
          )
          .get(payload.operationId, envelope.sessionId) as Row | undefined)
      : undefined;
    if (payload.operationId && !operation) {
      throw Object.assign(new Error("CAW operation not found for receipt ingest"), {
        apiError: notFoundError(requestId, "caw operation"),
      });
    }
    if (payload.operationId) {
      assertCawOperationCanAcceptReceipt(operation, requestId);
    }

    if (payload.manual) {
      const receiptBundleHash = hashJson(payload.receipts);
      const event = withImmediateTransaction(ctx, () => {
        if (payload.operationId) {
          const result = ctx.db.sqlite
            .prepare("UPDATE caw_receipt_operations SET receipt_bundle_hash = ?, status = ? WHERE operation_id = ? AND session_id = ?")
            .run(receiptBundleHash, "fixture_manual_receipt", payload.operationId, envelope.sessionId);
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
            canonicalReceiptCount: 0,
            manual: true,
            proofAuthority: false,
            status: "fixture_manual_receipt",
          },
        });
        updateJudgeCheckRow(ctx, envelope.sessionId, {
          rowId: "caw_boundary",
          status: "manual",
          authority: "fixture",
          reason: "manual CAW receipt rows are recorded but cannot prove the CAW boundary",
          evidenceEventId: event.eventId,
        });
        return event;
      });
      return {
        ok: true,
        requestId,
        evidenceEventId: event.eventId,
        data: {
          receiptBundleHash,
          operationId: payload.operationId ?? null,
          receiptCount: payload.receipts.length,
          canonicalReceiptCount: 0,
          status: "fixture_manual_receipt",
          proofAuthority: false,
          winnerClaimAllowed: false,
        },
      };
    }

    const operationId = String(payload.operationId);
    const rawBundle = await fetchAndValidateCawRawBundle(ctx, {
      requestId,
      sessionId: envelope.sessionId,
      sourceLabel: payload.sourceLabel,
      operationId,
      expectedReceipts: payload.receipts,
      operation,
    });
    const createdAt = ctx.clock.now().toISOString();
    const rawReceiptBundleHash = hashJson(rawBundle.bundle);
    const rawBundleId = hashJson({ sessionId: envelope.sessionId, operationId, rawReceiptBundleHash });
    const canonicalReceipts = buildCanonicalCawReceipts({
      bundleId: rawBundleId,
      sessionId: envelope.sessionId,
      operationId,
      sourceLabel: payload.sourceLabel,
      operation,
      receipts: rawBundle.receipts,
      fetchedAt: rawBundle.fetchedAt,
      createdAt,
      requestId,
    });
    const cawAuthorityProof = cawStructuralAuthorityProof({
      sessionId: envelope.sessionId,
      operationId,
      sourceLabel: payload.sourceLabel,
      rawReceiptBundleHash,
      operation,
      canonicalReceipts,
      now: ctx.clock.now().toISOString(),
      requestId,
    });
    const event = withImmediateTransaction(ctx, () => {
      const result = ctx.db.sqlite
        .prepare("UPDATE caw_receipt_operations SET receipt_bundle_hash = ?, status = ? WHERE operation_id = ? AND session_id = ?")
        .run(rawReceiptBundleHash, CAW_STRUCTURAL_AUTHORITY_STATUS, operationId, envelope.sessionId);
      if (result.changes === 0) {
        throw Object.assign(new Error("CAW operation not found for receipt ingest"), {
          apiError: notFoundError(requestId, "caw operation"),
        });
      }
      ctx.db.sqlite
        .prepare(
          `INSERT OR IGNORE INTO caw_raw_receipt_bundles
            (bundle_id, session_id, operation_id, source_label, fetched_at, raw_bundle_hash, raw_bundle_json, receipt_count, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          rawBundleId,
          envelope.sessionId,
          operationId,
          payload.sourceLabel,
          rawBundle.fetchedAt,
          rawReceiptBundleHash,
          canonicalizeJson(rawBundle.bundle),
          rawBundle.receipts.length,
          createdAt,
        );
      for (const receipt of canonicalReceipts) {
        ctx.db.sqlite
          .prepare(
            `INSERT INTO caw_canonical_receipts
              (raw_receipt_hash, canonical_receipt_hash, bundle_id, session_id, operation_id, operation_kind, source_label,
               wallet_address, target, selector, request_id, effect, status, policy_digest, params_digest, tx_hash,
               tx_count, expiry, fetched_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            receipt.rawReceiptHash,
            receipt.canonicalReceiptHash,
            receipt.bundleId,
            receipt.sessionId,
            receipt.operationId,
            receipt.operationKind,
            receipt.sourceLabel,
            receipt.walletAddress,
            receipt.target,
            receipt.selector,
            receipt.requestId,
            receipt.effect,
            receipt.status,
            receipt.policyDigest,
            receipt.paramsDigest,
            receipt.txHash,
            receipt.txCount,
            receipt.expiry,
            receipt.fetchedAt,
            receipt.createdAt,
          );
      }
      const event = appendEvidenceEvent(ctx, {
        sessionId: envelope.sessionId,
        authority: "proof",
        kind: "caw.receipt.ingested.raw",
        payload: {
          rawBundleId,
          rawReceiptBundleHash,
          receiptBundleHash: rawReceiptBundleHash,
          operationId,
          sourceLabel: payload.sourceLabel,
          rawSource: rawBundle.source,
          fetchedAt: rawBundle.fetchedAt,
          receiptCount: rawBundle.receipts.length,
          canonicalReceiptCount: canonicalReceipts.length,
          canonicalReceiptHashes: canonicalReceipts.map((receipt) => receipt.canonicalReceiptHash),
          expectedReceiptCount: payload.receipts.length,
          authorityProofHash: cawAuthorityProof.authorityProofHash,
          authorityProofStatus: cawAuthorityProof.status,
          manual: false,
          proofAuthority: true,
          status: CAW_STRUCTURAL_AUTHORITY_STATUS,
          finalVerifierComplete: false,
        },
      });
      updateJudgeCheckRow(ctx, envelope.sessionId, {
        rowId: "caw_boundary",
        status: "pass",
        authority: "proof",
        reason: "CAW raw receipt bundle is structurally bound to the built operation; final verifier remains fail-closed",
        evidenceEventId: event.eventId,
      });
      return event;
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        receiptBundleHash: rawReceiptBundleHash,
        rawReceiptBundleHash,
        operationId,
        receiptCount: rawBundle.receipts.length,
        canonicalReceiptCount: canonicalReceipts.length,
        status: CAW_STRUCTURAL_AUTHORITY_STATUS,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function submitCawLivePact(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawLivePactSubmitPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:live:pact:submit", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    await requireCawLiveReady(ctx, requestId);
    const request = cawLivePactSubmitRequest(payload);
    const pactInput: {
      walletId: string;
      intent: string;
      originalIntent?: string;
      name?: string;
      recipeSlugs?: string[];
      spec: Record<string, unknown>;
    } = {
      walletId: payload.walletId,
      intent: payload.intent,
      spec: payload.spec,
    };
    if (payload.originalIntent) {
      pactInput.originalIntent = payload.originalIntent;
    }
    if (payload.name) {
      pactInput.name = payload.name;
    }
    if (payload.recipeSlugs.length > 0) {
      pactInput.recipeSlugs = payload.recipeSlugs;
    }
    const response = await ctx.cawLive.submitPact(pactInput);
    const pactId = requireCawResponseId(response, ["pact_id", "id"], requestId, "CAW pact submit");
    const status = normalizeCawLivePactStatus(response);
    const saved = recordCawLiveInteraction(ctx, {
      sessionId: envelope.sessionId,
      kind: "pact_submit",
      walletId: payload.walletId,
      pactId,
      cawRequestId: null,
      request,
      response,
      status,
      authKeyHash: null,
    });
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "proof",
      kind: "caw.live.pact.submitted",
      payload: {
        interactionId: saved.interactionId,
        walletId: payload.walletId,
        pactId,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        status,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });
    updateJudgeCheckRow(ctx, envelope.sessionId, {
      rowId: "caw_boundary",
      status: status === "live_active" ? "pass" : "pending",
      authority: "proof",
      reason: status === "live_active" ? "CAW pact is active from the live Agentic Wallet API" : "CAW pact is submitted but not active yet",
      evidenceEventId: event.eventId,
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        interactionId: saved.interactionId,
        pactId,
        walletId: payload.walletId,
        status,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function syncCawLivePact(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawLivePactSyncPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:live:pact:sync", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    await requireCawLiveReady(ctx, requestId);
    const request = { pact_id: payload.pactId };
    const response = await ctx.cawLive.getPact(payload.pactId);
    const walletId = optionalStringFromCaw(response, ["wallet_id", "walletId"]);
    const status = normalizeCawLivePactStatus(response);
    const pactApiKey = optionalStringFromCaw(response, ["api_key", "apiKey"]);
    const saved = recordCawLiveInteraction(ctx, {
      sessionId: envelope.sessionId,
      kind: "pact_sync",
      walletId,
      pactId: payload.pactId,
      cawRequestId: null,
      request,
      response: redactCawLiveSecrets(response),
      status: status === "live_submitted" ? "live_synced" : status,
      authKeyHash: pactApiKey ? sha256Hex(pactApiKey) : null,
    });
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "proof",
      kind: "caw.live.pact.synced",
      payload: {
        interactionId: saved.interactionId,
        walletId,
        pactId: payload.pactId,
        pactScopedApiKeyHash: pactApiKey ? sha256Hex(pactApiKey) : null,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        status: saved.status,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });
    updateJudgeCheckRow(ctx, envelope.sessionId, {
      rowId: "caw_boundary",
      status: status === "live_active" ? "pass" : "pending",
      authority: "proof",
      reason: status === "live_active" ? "CAW pact sync reports active live status" : "CAW pact sync does not yet report active status",
      evidenceEventId: event.eventId,
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        interactionId: saved.interactionId,
        pactId: payload.pactId,
        walletId,
        status: saved.status,
        pactScopedApiKeyHash: pactApiKey ? sha256Hex(pactApiKey) : null,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function submitCawLiveTransfer(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
  pactApiKey: string | null,
): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawLiveTransferSubmitPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:live:transfer:submit", envelope.sessionId), envelope.idempotencyKey, { envelope, pactKeyHash: pactApiKey ? sha256Hex(pactApiKey) : null }, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    if (!pactApiKey) {
      throw Object.assign(new Error("missing CAW pact-scoped API key"), {
        apiError: unauthorizedError(requestId, "missing x-pactfuse-caw-pact-api-key header"),
      });
    }
    await requireCawLiveReady(ctx, requestId);
    const spend = assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const pactKeyHash = sha256Hex(pactApiKey);
    requireActiveCawLivePact(ctx, envelope.sessionId, payload.pactId, payload.walletId, pactKeyHash, requestId);
    assertSpendPaymentToken(spend, payload.paymentToken, "CAW live transfer", requestId);
    assertSpendPrice(spend, payload.amount, "CAW live transfer", requestId);
    assertSpendMarket(spend, payload.destinationAddress, "CAW live transfer", requestId);
    if (payload.tokenId && payload.tokenId.toLowerCase() !== payload.paymentToken.toLowerCase()) {
      throw Object.assign(new Error("CAW live transfer tokenId must match registered ProcurementGate paymentToken"), {
        apiError: proofBlockedError(requestId, "CAW live transfer tokenId must match registered ProcurementGate paymentToken", {
          spendId: payload.spendId,
          paymentToken: payload.paymentToken.toLowerCase(),
          tokenId: payload.tokenId,
        }),
      });
    }
    if (payload.sourceAddress) {
      requireSpendPayer(spend, payload.sourceAddress, requestId);
    }
    const cawTokenId = payload.tokenId ?? payload.paymentToken;
    const request = cawLiveTransferRequest(payload);
    const transferInput: {
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
    } = {
      walletId: payload.walletId,
      destinationAddress: payload.destinationAddress,
      amount: payload.amount,
      tokenId: cawTokenId,
      pactApiKey,
    };
    if (payload.chainId) {
      transferInput.chainId = payload.chainId;
    }
    if (payload.requestId) {
      transferInput.requestId = payload.requestId;
    }
    if (payload.sourceAddress) {
      transferInput.sourceAddress = payload.sourceAddress;
    }
    if (payload.sponsor !== undefined) {
      transferInput.sponsor = payload.sponsor;
    }
    if (payload.gasProvider) {
      transferInput.gasProvider = payload.gasProvider;
    }
    if (payload.description) {
      transferInput.description = payload.description;
    }
    if (payload.fee !== undefined) {
      transferInput.fee = payload.fee;
    }
    const response = await ctx.cawLive.transferToken(transferInput);
    const cawRequestId = payload.requestId ?? optionalStringFromCaw(response, ["request_id", "requestId"]);
    const status = normalizeCawLiveTransferStatus(response);
    const saved = recordCawLiveInteraction(ctx, {
      sessionId: envelope.sessionId,
      kind: "transfer_submit",
      walletId: payload.walletId,
      pactId: payload.pactId,
      cawRequestId,
      request,
      response,
      status,
      authKeyHash: pactKeyHash,
    });
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "proof",
      kind: "caw.live.transfer.submitted",
      payload: {
        interactionId: saved.interactionId,
        walletId: payload.walletId,
        pactId: payload.pactId,
        spendId: payload.spendId,
        cawRequestId,
        tokenId: cawTokenId,
        paymentToken: payload.paymentToken.toLowerCase(),
        amount: payload.amount,
        destinationAddress: payload.destinationAddress,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        pactScopedApiKeyHash: saved.authKeyHash,
        status,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });
    if (status === "live_denied" || status === "live_failed") {
      updateJudgeCheckRow(ctx, envelope.sessionId, {
        rowId: "caw_boundary",
        status: "blocked",
        authority: "proof",
        reason: status === "live_denied" ? "CAW live policy denied the transfer" : "CAW live transfer failed",
        evidenceEventId: event.eventId,
      });
    }
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        interactionId: saved.interactionId,
        walletId: payload.walletId,
        pactId: payload.pactId,
        spendId: payload.spendId,
        cawRequestId,
        tokenId: cawTokenId,
        paymentToken: payload.paymentToken.toLowerCase(),
        amount: payload.amount,
        destinationAddress: payload.destinationAddress,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        pactScopedApiKeyHash: saved.authKeyHash,
        status,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    };
  });
}

export async function syncCawLiveAudit(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(CawLiveAuditSyncPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("caw:live:audit:sync", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    await requireCawLiveReady(ctx, requestId);
    const request = cawLiveAuditRequest(payload);
    const auditInput: CawLiveAuditInput = { limit: payload.limit };
    if (payload.walletId) {
      auditInput.walletId = payload.walletId;
    }
    if (payload.principalId) {
      auditInput.principalId = payload.principalId;
    }
    if (payload.action) {
      auditInput.action = payload.action;
    }
    if (payload.result) {
      auditInput.result = payload.result;
    }
    if (payload.startTime) {
      auditInput.startTime = payload.startTime;
    }
    if (payload.endTime) {
      auditInput.endTime = payload.endTime;
    }
    if (payload.after) {
      auditInput.after = payload.after;
    }
    if (payload.before) {
      auditInput.before = payload.before;
    }
    const response = await ctx.cawLive.listAuditLogs(auditInput);
    const saved = recordCawLiveInteraction(ctx, {
      sessionId: envelope.sessionId,
      kind: "audit_sync",
      walletId: payload.walletId ?? null,
      pactId: null,
      cawRequestId: null,
      request,
      response,
      status: "live_synced",
      authKeyHash: null,
    });
    const event = appendEvidenceEvent(ctx, {
      sessionId: envelope.sessionId,
      authority: "proof",
      kind: "caw.live.audit.synced",
      payload: {
        interactionId: saved.interactionId,
        walletId: payload.walletId ?? null,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        status: "live_synced",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });
    return {
      ok: true,
      requestId,
      evidenceEventId: event.eventId,
      data: {
        interactionId: saved.interactionId,
        walletId: payload.walletId ?? null,
        requestHash: saved.requestHash,
        responseHash: saved.responseHash,
        status: "live_synced",
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    };
  });
}

async function requireCawLiveReady(ctx: ServiceCtx, requestId: string): Promise<ProofProviderStatus> {
  let status: ProofProviderStatus;
  try {
    status = await ctx.cawLive.status();
  } catch (error) {
    throw Object.assign(new Error("CAW live API readiness check failed"), {
      apiError: proofPendingError(requestId, cawLiveFailureMessage("CAW live API readiness check failed", error)),
    });
  }
  if (!status.ready) {
    throw Object.assign(new Error("CAW live API is not ready"), {
      apiError: proofPendingError(requestId, `CAW live API is not ready: ${status.reason}`),
    });
  }
  return status;
}

function cawLivePactSubmitRequest(payload: CawLivePactSubmitPayload): Record<string, JsonValue> {
  return jsonRecord({
    wallet_id: payload.walletId,
    intent: payload.intent,
    original_intent: payload.originalIntent,
    name: payload.name,
    recipe_slugs: payload.recipeSlugs,
    spec: payload.spec,
  });
}

function cawLiveTransferRequest(payload: CawLiveTransferSubmitPayload): Record<string, JsonValue> {
  return jsonRecord({
    spend_id: payload.spendId,
    pact_id: payload.pactId,
    wallet_id: payload.walletId,
    dst_addr: payload.destinationAddress,
    amount: payload.amount,
    payment_token: payload.paymentToken.toLowerCase(),
    token_id: payload.tokenId ?? payload.paymentToken,
    chain_id: payload.chainId,
    request_id: payload.requestId,
    src_addr: payload.sourceAddress,
    sponsor: payload.sponsor,
    gas_provider: payload.gasProvider,
    description: payload.description,
    fee: payload.fee,
  });
}

function cawLiveAuditRequest(payload: CawLiveAuditSyncPayload): Record<string, JsonValue> {
  return jsonRecord({
    wallet_id: payload.walletId,
    principal_id: payload.principalId,
    action: payload.action,
    result: payload.result,
    start_time: payload.startTime,
    end_time: payload.endTime,
    after: payload.after,
    before: payload.before,
    limit: payload.limit,
  });
}

function recordCawLiveInteraction(
  ctx: ServiceCtx,
  input: {
    sessionId: string;
    kind: "pact_submit" | "pact_sync" | "transfer_submit" | "audit_sync";
    walletId: string | null;
    pactId: string | null;
    cawRequestId: string | null;
    request: Record<string, JsonValue>;
    response: Record<string, unknown>;
    status: "live_submitted" | "live_active" | "live_pending" | "live_denied" | "live_failed" | "live_synced";
    authKeyHash: `0x${string}` | null;
  },
): {
  interactionId: `0x${string}`;
  requestHash: `0x${string}`;
  responseHash: `0x${string}`;
  status: "live_submitted" | "live_active" | "live_pending" | "live_denied" | "live_failed" | "live_synced";
  authKeyHash: `0x${string}` | null;
} {
  const responseRecord = jsonRecord(redactCawLiveSecrets(input.response));
  const requestHash = hashJson(input.request);
  const responseHash = hashJson(responseRecord);
  const interactionId = hashJson({
    sessionId: input.sessionId,
    kind: input.kind,
    walletId: input.walletId,
    pactId: input.pactId,
    cawRequestId: input.cawRequestId,
    requestHash,
    responseHash,
  });
  ctx.db.sqlite
    .prepare(
      `INSERT INTO caw_live_interactions
        (interaction_id, session_id, kind, wallet_id, pact_id, caw_request_id, request_hash, request_json,
         response_hash, response_json, status, auth_key_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      interactionId,
      input.sessionId,
      input.kind,
      input.walletId,
      input.pactId,
      input.cawRequestId,
      requestHash,
      canonicalizeJson(input.request),
      responseHash,
      canonicalizeJson(responseRecord),
      input.status,
      input.authKeyHash,
      ctx.clock.now().toISOString(),
    );
  return { interactionId, requestHash, responseHash, status: input.status, authKeyHash: input.authKeyHash };
}

function requireCawResponseId(response: Record<string, unknown>, keys: string[], requestId: string, label: string): string {
  const value = optionalStringFromCaw(response, keys);
  if (!value) {
    throw Object.assign(new Error(`${label} response is missing id`), {
      apiError: proofBlockedError(requestId, `${label} response is missing required id`, { keys }),
    });
  }
  return value;
}

function requireActiveCawLivePact(
  ctx: ServiceCtx,
  sessionId: string,
  pactId: string,
  walletId: string,
  authKeyHash: string,
  requestId: string,
): Row {
  const row = ctx.db.sqlite
    .prepare(
      `SELECT interaction_id, wallet_id, pact_id, auth_key_hash, status
       FROM caw_live_interactions
       WHERE session_id = ?
         AND kind = 'pact_sync'
         AND pact_id = ?
         AND wallet_id = ?
         AND status = 'live_active'
       ORDER BY created_at DESC, interaction_id DESC
       LIMIT 1`,
    )
    .get(sessionId, pactId, walletId) as Row | undefined;
  if (!row) {
    throw Object.assign(new Error("CAW live transfer requires an active synced Pact for this wallet"), {
      apiError: proofBlockedError(requestId, "CAW live transfer requires an active synced Pact for this wallet", {
        pactId,
        walletId,
      }),
    });
  }
  if (String(row.auth_key_hash).toLowerCase() !== authKeyHash.toLowerCase()) {
    throw Object.assign(new Error("CAW live transfer pact API key does not match the active synced Pact"), {
      apiError: proofBlockedError(requestId, "CAW live transfer pact API key does not match the active synced Pact", {
        pactId,
        walletId,
      }),
    });
  }
  return row;
}

function optionalStringFromCaw(response: Record<string, unknown>, keys: string[]): string | null {
  const roots = [response, objectChild(response, "result"), objectChild(objectChild(response, "result"), "pact"), objectChild(objectChild(response, "result"), "transaction")];
  for (const root of roots) {
    if (!root) {
      continue;
    }
    for (const key of keys) {
      const value = root[key];
      if (typeof value === "string" && value.length > 0) {
        return value;
      }
    }
  }
  return null;
}

function objectChild(parent: Record<string, unknown> | null, key: string): Record<string, unknown> | null {
  const value = parent?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function normalizeCawLivePactStatus(response: Record<string, unknown>): "live_submitted" | "live_active" | "live_pending" | "live_failed" {
  const status = (optionalStringFromCaw(response, ["status"]) ?? "").toLowerCase();
  if (["active", "approved"].includes(status)) {
    return "live_active";
  }
  if (["rejected", "expired", "revoked", "completed", "failed", "error"].includes(status)) {
    return "live_failed";
  }
  if (status.includes("pending") || status.includes("approval")) {
    return "live_pending";
  }
  return "live_submitted";
}

function normalizeCawLiveTransferStatus(response: Record<string, unknown>): "live_submitted" | "live_pending" | "live_denied" | "live_failed" {
  const status = (optionalStringFromCaw(response, ["status", "status_display"]) ?? "").toLowerCase();
  const errorCode = optionalStringFromCaw(response, ["code", "reason"]);
  if (errorCode && /deny|denied|policy/.test(errorCode.toLowerCase())) {
    return "live_denied";
  }
  if (/deny|denied|blocked/.test(status)) {
    return "live_denied";
  }
  if (/fail|error|rejected|cancel/.test(status)) {
    return "live_failed";
  }
  if (/pending|approval|submitted|broadcast/.test(status)) {
    return "live_pending";
  }
  return "live_submitted";
}

function redactCawLiveSecrets(value: unknown): Record<string, unknown> {
  return redactCawLiveSecretsValue(value) as Record<string, unknown>;
}

function redactCawLiveSecretsValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactCawLiveSecretsValue(item));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/api[_-]?key|token|secret|authorization/i.test(key)) {
        output[key] = typeof child === "string" && child.length > 0 ? { redacted: true, sha256: sha256Hex(child) } : { redacted: true };
      } else {
        output[key] = redactCawLiveSecretsValue(child);
      }
    }
    return output;
  }
  return value;
}

function cawLiveFailureMessage(message: string, error: unknown): string {
  return error instanceof Error ? `${message}: ${error.message}` : message;
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
          if (existing.status === "finalized") {
            if (typeof existing.finalized_event_id !== "string") {
              throw Object.assign(new Error("finalized gate event is missing its proof event id"), {
                apiError: proofBlockedError(requestId, "finalized gate event is missing its proof event id"),
              });
            }
            return {
              ok: true,
              requestId,
              evidenceEventId: existing.finalized_event_id,
              data: {
                gateEventId,
                spendId: gatePayload.spendId,
                event: gatePayload.event,
                finalityStatus: "finalized",
                confirmations: Number(existing.confirmations),
                finalityDepth: Number(existing.finality_depth),
                observedEventId,
                finalizedEventId: existing.finalized_event_id,
                proofAuthority: true,
                winnerClaimAllowed: false,
              },
            };
          }
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

      if (existing?.status === "finalized") {
        if (typeof existing.finalized_event_id !== "string") {
          throw Object.assign(new Error("finalized gate event is missing its proof event id"), {
            apiError: proofBlockedError(requestId, "finalized gate event is missing its proof event id"),
          });
        }
        return {
          ok: true,
          requestId,
          evidenceEventId: existing.finalized_event_id,
          data: {
            gateEventId,
            spendId: gatePayload.spendId,
            event: gatePayload.event,
            finalityStatus: "finalized",
            confirmations: Number(existing.confirmations),
            finalityDepth: Number(existing.finality_depth),
            observedEventId,
            finalizedEventId: existing.finalized_event_id,
            proofAuthority: true,
            winnerClaimAllowed: false,
          },
        };
      }
      const observedUpdate = ctx.db.sqlite
        .prepare(
          `UPDATE gate_chain_events
           SET current_block_number = ?, confirmations = ?, status = 'observed_finalizing', updated_at = ?
           WHERE gate_event_id = ?`,
        )
        .run(gatePayload.currentBlockNumber, confirmations, ctx.clock.now().toISOString(), gateEventId);
      if (observedUpdate.changes !== 1) {
        throw Object.assign(new Error("gate observation did not update its gate row"), {
          apiError: proofBlockedError(requestId, "gate observation did not update its gate row"),
        });
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
    });
  });
}

export async function indexChainWindow(input: ChainIndexerBackfillInput, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const parsed = parseStrict(ChainIndexerBackfillInputSchema, input);
  return withProcessLock(`indexer:cursor:${parsed.payload.cursorId}`, () =>
    withIdempotency(ctx, `indexer:backfill:${parsed.payload.cursorId}`, parsed.idempotencyKey, parsed, async (requestId) => {
      const payload = parsed.payload;
      const cursor = readIndexerCursor(ctx, payload.cursorId);
      assertIndexerCursorMatchesPayload(cursor, payload, requestId);
      const lastIndexedBlock = optionalChainNumber(cursor?.last_indexed_block);
      const provider = await safeChainProviderStatus(ctx);
      if (!provider.ready) {
        markIndexerCursorDegraded(ctx, payload, 0, 0, lastIndexedBlock, requestId, `chain indexer provider is not ready: ${provider.reason}`);
        throw Object.assign(new Error("chain indexer provider is not ready"), {
          apiError: proofPendingError(requestId, `chain indexer provider is not ready: ${provider.reason}`),
        });
      }
      assertProviderChainMatchesPayload(provider, payload.chainId, requestId, "chain indexer");
      let latestHeadBlock: number;
      try {
        latestHeadBlock = await ctx.chain.getBlockNumber();
      } catch (error) {
        markIndexerCursorDegraded(ctx, payload, 0, 0, lastIndexedBlock, requestId, chainFailureMessage("failed to read chain head", error));
        throw Object.assign(new Error("failed to read chain head for indexer backfill"), {
          apiError: proofPendingError(requestId, chainFailureMessage("failed to read chain head for indexer backfill", error)),
        });
      }
      if (!Number.isInteger(latestHeadBlock) || latestHeadBlock < 0) {
        markIndexerCursorDegraded(ctx, payload, 0, 0, lastIndexedBlock, requestId, "chain provider returned an invalid head block");
        throw Object.assign(new Error("chain provider returned an invalid head block"), {
          apiError: proofBlockedError(requestId, "chain provider returned an invalid head block", { latestHeadBlock }),
        });
      }

      const finalizedHeadBlock = Math.max(0, latestHeadBlock - payload.finalityDepth + 1);
      const { fromBlock, cappedToBlock } = resolveIndexerWindow(payload, lastIndexedBlock, finalizedHeadBlock, requestId);
      if (cappedToBlock < fromBlock) {
        const cursorView = upsertIndexerCursor(ctx, {
          payload,
          lastIndexedBlock,
          latestHeadBlock,
          finalizedHeadBlock,
          reason: "indexer cursor is already at or ahead of the finalized head",
          requestId,
        });
        return {
          ok: true,
          requestId,
          data: ChainIndexerBackfillResultSchema.parse({
            cursor: cursorView,
            fromBlock,
            toBlock: fromBlock,
            indexedLogCount: 0,
            insertedLogCount: 0,
            proofAuthority: false,
            winnerClaimAllowed: false,
          }),
        };
      }

      let logs: Record<string, unknown>[];
      try {
        logs = await ctx.chain.getLogs({
          chainId: payload.chainId,
          fromBlock,
          toBlock: cappedToBlock,
          address: payload.address,
          topics: payload.topics,
        });
      } catch (error) {
        markIndexerCursorDegraded(
          ctx,
          payload,
          latestHeadBlock,
          finalizedHeadBlock,
          lastIndexedBlock,
          requestId,
          chainFailureMessage("chain log backfill failed", error),
        );
        throw Object.assign(new Error("chain log backfill failed"), {
          apiError: proofPendingError(requestId, chainFailureMessage("chain log backfill failed", error)),
        });
      }

      let insertedLogCount = 0;
      const createdAt = ctx.clock.now().toISOString();
      const normalizedLogs = logs.map((log) => normalizeIndexedChainLog(payload.cursorId, payload.chainId, log, requestId, createdAt));
      const cursorView = withImmediateTransaction(ctx, () => {
        assertIndexerCursorMatchesPayload(readIndexerCursor(ctx, payload.cursorId), payload, requestId);
        for (const log of normalizedLogs) {
          insertedLogCount += insertIndexedChainLogExactOnce(ctx, log, requestId);
        }
        return upsertIndexerCursor(ctx, {
          payload,
          lastIndexedBlock: cappedToBlock,
          latestHeadBlock,
          finalizedHeadBlock,
          reason:
            cappedToBlock < finalizedHeadBlock
              ? "indexer backfilled a capped window and remains behind finalized head"
              : "indexer cursor caught up to finalized head",
          requestId,
        });
      });
      return {
        ok: true,
        requestId,
        data: ChainIndexerBackfillResultSchema.parse({
          cursor: cursorView,
          fromBlock,
          toBlock: cappedToBlock,
          indexedLogCount: normalizedLogs.length,
          insertedLogCount,
          proofAuthority: false,
          winnerClaimAllowed: false,
        }),
      };
    }),
  );
}

export async function reconcileIndexedEvents(
  ctx: ServiceCtx,
  input: { cursorId?: string; requestId?: string; limit?: number } = {},
): Promise<{ reconciledEventCount: number }> {
  const requestId = input.requestId ?? newRequestId("indexer_reconcile");
  const limit = input.limit ?? 500;
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT l.*, c.address AS cursor_address, c.latest_head_block, c.finalized_head_block, c.finality_depth
       FROM chain_indexed_logs l
       JOIN chain_indexer_cursors c ON c.cursor_id = l.cursor_id
       WHERE (? IS NULL OR l.cursor_id = ?)
       ORDER BY l.block_number ASC, l.log_index ASC, l.log_id ASC
       LIMIT ?`,
    )
    .all(input.cursorId ?? null, input.cursorId ?? null, limit) as Row[];
  let reconciledEventCount = 0;
  for (const row of rows) {
    const semantic = indexedLogSemanticEvent(row);
    if (!semantic) {
      continue;
    }
    if (semantic.event === "SourceChallenged") {
      reconciledEventCount += await reconcileIndexedSourceChallenge(ctx, row, semantic, requestId);
    } else {
      reconciledEventCount += await reconcileIndexedGateEvent(ctx, row, semantic, requestId);
    }
  }
  return { reconciledEventCount };
}

export async function readChainIndexerStatus(ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("indexer_status");
  const provider = await safeChainProviderStatus(ctx);
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM chain_indexer_cursors
       ORDER BY updated_at DESC, cursor_id ASC
       LIMIT 50`,
    )
    .all() as Row[];
  const cursorViews = rows.map(indexerCursorViewFromRow);
  for (const required of ctx.requiredIndexerCursors) {
    if (!cursorViews.some((cursor) => cursor.cursorId === required.cursorId)) {
      cursorViews.push(requiredIndexerCursorView(required));
    }
  }
  return {
    ok: true,
    requestId,
    data: {
      provider,
      cursors: cursorViews,
      proofAuthority: false,
      winnerClaimAllowed: false,
    },
  };
}

export async function runArtifactPreflight(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(ArtifactPreflightPayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("artifacts:preflight", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const spend = assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const artifactHashPreview = payload.artifactHashPreview.toLowerCase();
    const artifactCid = payload.artifactCid.toLowerCase();
    const createdAt = ctx.clock.now().toISOString();
    const preflightId = hashJson({ sessionId: envelope.sessionId, payload, requestId });
    assertSpendArtifactHash(spend, artifactHashPreview, "artifact preflight", requestId);
    assertArtifactCidMatchesHash(artifactCid, artifactHashPreview, requestId);
    ctx.db.sqlite
      .prepare(
        `INSERT INTO artifact_preflights
          (preflight_id, session_id, spend_id, artifact_hash_preview, artifact_cid, endpoint_url, price_disclosure_hash, source_state_snapshot_hash, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending_live_delivery', ?)`,
      )
      .run(
        preflightId,
        envelope.sessionId,
        payload.spendId,
        artifactHashPreview,
        artifactCid,
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
        artifactHashPreview,
        artifactCid,
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
        artifactHashPreview,
        artifactCid,
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
    const spend = assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const preflight = requireQuotePreflight(ctx, envelope.sessionId, payload, requestId);
    const artifactCid = String(preflight.artifact_cid);
    const artifactCommitment = payload.artifactCommitment.toLowerCase();
    assertSpendArtifactHash(spend, artifactCommitment, "artifact quote", requestId);
    assertSpendPrice(spend, payload.priceAtomic, "artifact quote", requestId);
    const priceDisclosureHash = String(preflight.price_disclosure_hash);
    const sourceStateSnapshotHash = String(preflight.source_state_snapshot_hash);
    const createdAt = ctx.clock.now().toISOString();
    const quoteHash = hashJson({
      sessionId: envelope.sessionId,
      spendId: payload.spendId,
      preflightId: payload.preflightId,
      artifactCommitment,
      priceAtomic: payload.priceAtomic,
      quoteNonce: payload.quoteNonce,
      validUntilBlock: payload.validUntilBlock,
      artifactCid,
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
            (quote_id, session_id, spend_id, preflight_id, artifact_commitment, artifact_cid, price_disclosure_hash, source_state_snapshot_hash,
             price_atomic, quote_nonce, valid_until_block, quote_hash, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'mocked_after_preflight_not_chain_settleable', ?)`,
        )
        .run(
          quoteId,
          envelope.sessionId,
          payload.spendId,
          payload.preflightId,
          artifactCommitment,
          artifactCid,
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
          artifactCommitment,
          artifactCid,
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
        artifactCid,
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
    assertNoActiveArtifactToken(ctx, envelope.sessionId, payload.spendId, requestId);
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

export async function issueArtifactAccessToken(input: SessionScopedEnvelope, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(ArtifactAccessIssuePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("artifacts:access-token:issue", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const spend = assertSpend(ctx, envelope.sessionId, payload.spendId, requestId);
    const payer = requireSpendPayer(spend, payload.payer, requestId);
    const artifactHash = payload.artifactHash.toLowerCase();
    assertSpendArtifactHash(spend, artifactHash, "artifact access", requestId);
    const settlement = requireFinalizedSettlement(ctx, envelope.sessionId, payload.spendId, requestId);
    assertNoArtifactRefundPending(ctx, envelope.sessionId, payload.spendId, requestId);
    return withProcessLock(`artifact-token:${envelope.sessionId}:${payload.spendId}`, async () => {
      assertNoActiveArtifactToken(ctx, envelope.sessionId, payload.spendId, requestId);
      const artifactPayloadHash = hashJson(payload.artifactPayload);
      const artifactPayloadJson = canonicalizeJson(payload.artifactPayload);
      assertArtifactPayloadReplaySize(artifactPayloadJson, requestId);
      if (artifactPayloadHash !== artifactHash) {
        throw Object.assign(new Error("artifact payload hash does not match requested artifactHash"), {
          apiError: proofBlockedError(requestId, "artifact payload hash does not match requested artifactHash", {
            artifactHash,
            artifactPayloadHash,
          }),
        });
      }
      const quoteBinding = requireArtifactQuoteBinding(
        ctx,
        envelope.sessionId,
        {
          spendId: payload.spendId,
          quoteId: payload.quoteId,
          artifactHash,
          settlementBlockNumber: settlement.blockNumber,
          spendMaxPriceAtomic: String(spend.max_price_atomic),
          spendArtifactHash: String(spend.artifact_hash),
        },
        requestId,
      );
      const replayBundle = assembleReplayBundleData(envelope.sessionId, ctx);
      const { view, verifierInput } = await buildVerifierRunView(ctx, envelope.sessionId, {
        replayBundle: replayBundle as unknown as Record<string, JsonValue>,
        schemaOnly: false,
      });
      if (!view.schemaOk) {
        throw Object.assign(new Error("artifact access token requires a replay-clean verifier run"), {
          apiError: proofBlockedError(requestId, "artifact access token requires a replay-clean verifier run", { errors: view.errors }),
        });
      }
      assertReplaySummaryRoomForArtifactIssue(ctx, envelope.sessionId, requestId);

      const inputHash = hashJson(verifierInput);
      const verifierRunId = hashJson({ sessionId: envelope.sessionId, inputHash, scope: "artifact_access_token", requestId });
      const normalizedPayload = { ...payload, artifactHash };
      const accessToken = `pf_at_${hashJson({ sessionId: envelope.sessionId, payload: normalizedPayload, verifierRunId, requestId }).slice(2)}`;
      const tokenHash = sha256Hex(accessToken);
      const tokenId = hashJson({ sessionId: envelope.sessionId, spendId: payload.spendId, payer, artifactHash, tokenHash });
      const event = withImmediateTransaction(ctx, () => {
        ctx.db.sqlite
          .prepare(
            `INSERT INTO verifier_runs
              (verifier_run_id, session_id, input_hash, result_json, schema_ok, proof_chip_allowed, winner_claim_allowed, final_verifier_complete, created_at)
             VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)`,
          )
          .run(verifierRunId, envelope.sessionId, inputHash, canonicalizeJson(view), view.schemaOk ? 1 : 0, ctx.clock.now().toISOString());
        ctx.db.sqlite
          .prepare(
            `INSERT INTO artifact_access_tokens
              (token_id, session_id, spend_id, payer, quote_id, preflight_id, artifact_hash, artifact_cid,
               artifact_payload_hash, artifact_payload_json, token_hash, status, issued_by_verifier_run_id, settlement_event_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
          )
          .run(
            tokenId,
            envelope.sessionId,
            payload.spendId,
            payer,
            payload.quoteId,
            quoteBinding.preflightId,
            artifactHash,
            quoteBinding.artifactCid,
            artifactPayloadHash,
            artifactPayloadJson,
            tokenHash,
            verifierRunId,
            settlement.finalizedEventId,
            ctx.clock.now().toISOString(),
          );
        const issued = appendEvidenceEvent(ctx, {
          sessionId: envelope.sessionId,
          authority: "delivery",
          kind: "artifact.access_token.issued",
          payload: {
            tokenId,
            spendId: payload.spendId,
            payer,
            quoteId: payload.quoteId,
            preflightId: quoteBinding.preflightId,
            artifactHash,
            artifactCid: quoteBinding.artifactCid,
            artifactPayloadHash,
            tokenHash,
            verifierRunId,
            settlementEventId: settlement.finalizedEventId,
            status: "active_demo_verifier_gated",
            accessProofLevel: "delivery_access_only",
            proofChipAllowed: false,
            finalVerifierComplete: false,
            proofAuthority: false,
            winnerClaimAllowed: false,
          },
        });
        updateJudgeCheckRow(ctx, envelope.sessionId, {
          rowId: "artifact_access",
          status: "pass",
          authority: "delivery",
          reason: "bearer token issued after finalized settlement, quote binding, and replay-clean verifier run",
          evidenceEventId: issued.eventId,
        });
        return issued;
      });

      return {
        ok: true,
        requestId,
        evidenceEventId: event.eventId,
        data: {
          tokenId,
          accessToken,
          tokenHash,
          spendId: payload.spendId,
          payer,
          quoteId: payload.quoteId,
          preflightId: quoteBinding.preflightId,
          artifactHash,
          artifactCid: quoteBinding.artifactCid,
          artifactPayloadHash,
          verifierRunId,
          settlementEventId: settlement.finalizedEventId,
          bearerBound: true,
          status: "active_demo_verifier_gated",
          accessProofLevel: "delivery_access_only",
          proofChipAllowed: false,
          finalVerifierComplete: false,
          proofAuthority: false,
          winnerClaimAllowed: false,
        },
      };
    });
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
      const artifactHash = payload.artifactHash.toLowerCase();
      assertSpendArtifactHash(spend, artifactHash, "lease execution", requestId);
      const settlement = requireFinalizedSettlement(ctx, envelope.sessionId, payload.spendId, requestId);
      assertNoArtifactRefundPending(ctx, envelope.sessionId, payload.spendId, requestId);
      const activeToken = requireActiveArtifactAccess(
        ctx,
        {
          sessionId: envelope.sessionId,
          spendId: payload.spendId,
          payer,
          artifactHash,
          bearerToken,
        },
        requestId,
      );
      return withProcessLock(`artifact-token-lease:${envelope.sessionId}:${String(activeToken.token_id)}`, async () => {
        const artifactTokenId = String(activeToken.token_id);
        assertArtifactTokenUnusedForLease(ctx, envelope.sessionId, artifactTokenId, requestId);
        const leaseRunId = hashJson({ sessionId: envelope.sessionId, payload: { ...payload, artifactHash }, requestId });
        const pinnedManifest = requirePinnedMcpManifestForSpend(ctx, envelope.sessionId, payload.spendId, requestId);
        claimArtifactTokenForLease(
          ctx,
          envelope.sessionId,
          artifactTokenId,
          {
            requestId,
            leaseRunId,
            spendId: payload.spendId,
            payer,
            artifactHash,
            targetRepo: payload.targetRepo,
            targetCommit: payload.targetCommit,
            settlementEventId: settlement.finalizedEventId,
          },
          requestId,
        );
        let leaseExecution: McpLeaseExecutionResult;
        try {
          leaseExecution = await ctx.mcpLease.executeCleanLease({
            sessionId: envelope.sessionId,
            leaseRunId,
            spendId: payload.spendId,
            payer,
            artifactHash,
            targetRepo: payload.targetRepo,
            targetCommit: payload.targetCommit,
            pinnedManifestTools: pinnedManifest.tools,
          });
        } catch (error) {
          const failedStage = mcpLeaseFailureStage(error);
          if (failedStage === "tools/list") {
            releaseArtifactTokenLeaseClaim(ctx, envelope.sessionId, artifactTokenId);
          } else {
            blockArtifactTokenLeaseClaim(ctx, envelope.sessionId, artifactTokenId, requestId);
          }
          return recordBlockedLeaseExecution(ctx, {
            requestId,
            sessionId: envelope.sessionId,
            spendId: payload.spendId,
            payer,
            artifactHash,
            targetRepo: payload.targetRepo,
            targetCommit: payload.targetCommit,
            leaseRunId,
            settlementEventId: settlement.finalizedEventId,
            artifactTokenId,
            status: error instanceof Error && !error.message.includes("unconfigured") ? "blocked_mcp_execution_failed" : "blocked_missing_runner_execution",
            reason: error instanceof Error ? error.message : "lease MCP execution failed",
          });
        }

        const listCall = recordMcpAdapterCall(
          {
            sessionId: envelope.sessionId,
            auditNonce: `lease_${leaseRunId.slice(2, 22)}_tools_list`,
            toolName: "tools/list",
            request: jsonRecord(leaseExecution.toolsList.request),
            response: jsonRecord(leaseExecution.toolsList.response),
            status: "succeeded",
          },
          ctx,
        );
        const toolCall = recordMcpAdapterCall(
          {
            sessionId: envelope.sessionId,
            auditNonce: `lease_${leaseRunId.slice(2, 22)}_tools_call`,
            toolName: "tools/call",
            request: jsonRecord(leaseExecution.toolsCall.request),
            response: jsonRecord(leaseExecution.toolsCall.response),
            status: "succeeded",
          },
          ctx,
        );
        const transcriptHash = hashJson({
          format: "mcp-json-rpc",
          sessionId: envelope.sessionId,
          leaseRunId,
          frameCallIds: [listCall.callId, toolCall.callId],
          frames: [
            { method: "tools/list", requestHash: listCall.requestHash, responseHash: listCall.responseHash },
            { method: "tools/call", requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
          ],
        });
        const toolsListHash = hashJson({ requestHash: listCall.requestHash, responseHash: listCall.responseHash });
        const toolsCallHash = hashJson({ requestHash: toolCall.requestHash, responseHash: toolCall.responseHash });
        const outputHash = hashJson(leaseExecution.output);
        const manifestBindingHash = hashJson({
          sessionId: envelope.sessionId,
          leaseRunId,
          spendId: payload.spendId,
          sourceHashes: pinnedManifest.sourceHashes,
          manifestHashes: pinnedManifest.manifestHashes,
          pinnedManifestToolsHash: pinnedManifest.toolsHash,
          toolsListHash,
          toolsCallHash,
        });
        const leaseRunHash = hashJson({
          sessionId: envelope.sessionId,
          leaseRunId,
          spendId: payload.spendId,
          payer,
          artifactHash,
          targetRepo: payload.targetRepo,
          targetCommit: payload.targetCommit,
          settlementEventId: settlement.finalizedEventId,
          artifactTokenId,
          transcriptHash,
          outputHash,
        });
        const now = ctx.clock.now().toISOString();
        const event = withImmediateTransaction(ctx, () => {
          markArtifactTokenConsumed(ctx, envelope.sessionId, artifactTokenId, requestId);
          ctx.db.sqlite
            .prepare(
              `INSERT INTO lease_runs
                (lease_run_id, session_id, spend_id, payer, artifact_hash, target_repo, target_commit, status, transcript_hash,
                 tools_list_hash, tools_call_hash, output_hash, lease_run_hash, settlement_event_id, artifact_token_id, completed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'succeeded_live_mcp_transcript', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(
              leaseRunId,
              envelope.sessionId,
              payload.spendId,
              payer,
              artifactHash,
              payload.targetRepo,
              payload.targetCommit,
              transcriptHash,
              toolsListHash,
              toolsCallHash,
              outputHash,
              leaseRunHash,
              settlement.finalizedEventId,
              artifactTokenId,
              now,
              now,
            );
          const event = appendEvidenceEvent(ctx, {
            sessionId: envelope.sessionId,
            authority: "delivery",
            kind: "lease.execution.succeeded",
            payload: {
              leaseRunId,
              spendId: payload.spendId,
              payer,
              artifactHash,
              targetRepo: payload.targetRepo,
              targetCommit: payload.targetCommit,
              settlementEventId: settlement.finalizedEventId,
              artifactTokenId,
              transcriptHash,
              toolsListHash,
              toolsCallHash,
              outputHash,
              leaseRunHash,
              mcpToolName: leaseExecution.toolName,
              boundedToPinnedManifest: true,
              pinnedManifestToolsHash: pinnedManifest.toolsHash,
              pinnedManifestHashes: pinnedManifest.manifestHashes,
              manifestBindingHash,
              bearerBound: true,
              status: "succeeded_live_mcp_transcript",
              proofAuthority: false,
              winnerClaimAllowed: false,
            },
          });
          appendEvidenceEvent(ctx, {
            sessionId: envelope.sessionId,
            authority: "delivery",
            kind: "runner.heartbeat",
            payload: {
              step: "lease_executed",
              leaseRunId,
              transcriptHash,
              leaseRunHash,
              evidenceEventId: event.eventId,
              winnerClaimAllowed: false,
            },
          });
          updateJudgeCheckRow(ctx, envelope.sessionId, {
            rowId: "lease_execution",
            status: "pass",
            authority: "delivery",
            reason: "MCP tools/list and tools/call transcript recorded for bearer-bound clean lease",
            evidenceEventId: event.eventId,
          });
          return event;
        });
        return {
          ok: true,
          requestId,
          evidenceEventId: event.eventId,
          data: {
            leaseRunId,
            payer,
            artifactHash,
            bearerBound: true,
            transcriptHash,
            toolsListHash,
            toolsCallHash,
            outputHash,
            leaseRunHash,
            boundedToPinnedManifest: true,
            manifestBindingHash,
            settlementEventId: settlement.finalizedEventId,
            status: "succeeded_live_mcp_transcript",
            winnerClaimAllowed: false,
          },
        };
      });
    },
  );
}

function recordBlockedLeaseExecution(
  ctx: ServiceCtx,
  input: {
    requestId: string;
    sessionId: string;
    spendId: string;
    payer: string;
    artifactHash: string;
    targetRepo: string;
    targetCommit: string;
    leaseRunId: string;
    settlementEventId: string;
    artifactTokenId: string;
    status: "blocked_missing_runner_execution" | "blocked_mcp_execution_failed";
    reason: string;
  },
): ServiceResult<unknown> {
  const createdAt = ctx.clock.now().toISOString();
  ctx.db.sqlite
    .prepare(
      `INSERT INTO lease_runs
        (lease_run_id, session_id, spend_id, payer, artifact_hash, target_repo, target_commit, status, transcript_hash,
         tools_list_hash, tools_call_hash, output_hash, lease_run_hash, settlement_event_id, artifact_token_id, completed_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, ?)`,
    )
    .run(
      input.leaseRunId,
      input.sessionId,
      input.spendId,
      input.payer,
      input.artifactHash,
      input.targetRepo,
      input.targetCommit,
      input.status,
      input.settlementEventId,
      input.artifactTokenId,
      createdAt,
    );
  const event = appendEvidenceEvent(ctx, {
    sessionId: input.sessionId,
    authority: "operator",
    kind: "lease.execution.blocked",
    payload: {
      leaseRunId: input.leaseRunId,
      spendId: input.spendId,
      payer: input.payer,
      artifactHash: input.artifactHash,
      targetRepo: input.targetRepo,
      targetCommit: input.targetCommit,
      settlementEventId: input.settlementEventId,
      artifactTokenId: input.artifactTokenId,
      bearerBound: true,
      status: input.status,
      reason: input.reason,
      winnerClaimAllowed: false,
    },
  });
  updateJudgeCheckRow(ctx, input.sessionId, {
    rowId: "lease_execution",
    status: "blocked",
    authority: "operator",
    reason: input.reason,
    evidenceEventId: event.eventId,
  });
  return {
    ok: true,
    requestId: input.requestId,
    evidenceEventId: event.eventId,
    data: {
      leaseRunId: input.leaseRunId,
      payer: input.payer,
      artifactHash: input.artifactHash,
      bearerBound: true,
      transcriptHash: null,
      toolsListHash: null,
      toolsCallHash: null,
      outputHash: null,
      leaseRunHash: null,
      boundedToPinnedManifest: false,
      manifestBindingHash: null,
      settlementEventId: input.settlementEventId,
      status: input.status,
      winnerClaimAllowed: false,
    },
  };
}

export async function verifyEvidenceForSession(
  input: SessionScopedEnvelope,
  ctx: ServiceCtx,
): Promise<ServiceResult<VerifierRunView>> {
  const envelope = parseStrict(SessionScopedEnvelopeSchema, input);
  const payload = parseStrict(VerifyEvidencePayloadSchema, envelope.payload);
  return withIdempotency(ctx, scoped("evidence:verify", envelope.sessionId), envelope.idempotencyKey, envelope, async (requestId) => {
    assertSession(ctx, envelope.sessionId, requestId);
    const { view, verifierInput } = await buildVerifierRunView(ctx, envelope.sessionId, payload);
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

export async function previewVerifyEvidenceForSession(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<VerifierRunView>> {
  const requestId = newRequestId("verify_preview");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  const replayBundle = assembleReplayBundleData(parsedSessionId, ctx);
  const { view } = await buildVerifierRunView(ctx, parsedSessionId, {
    replayBundle: replayBundle as unknown as Record<string, JsonValue>,
    schemaOnly: false,
  });
  return { ok: true, requestId, data: view };
}

async function buildVerifierRunView(
  ctx: ServiceCtx,
  sessionId: string,
  payload: {
    receipt?: Record<string, JsonValue> | undefined;
    replayBundle?: Record<string, JsonValue> | undefined;
    schemaOnly?: boolean | undefined;
  },
): Promise<{ view: VerifierRunView; verifierInput: unknown }> {
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
    ...verifyReplaySummaryCapIntegrity(ctx, sessionId),
    ...verifyEventLogIntegrity(ctx, sessionId),
    ...verifySpendBindingIntegrity(ctx, sessionId),
    ...verifyMcpAdapterCallIntegrity(ctx, sessionId),
    ...verifyCawLiveInteractionIntegrity(ctx, sessionId),
    ...verifyGateFinalityIntegrity(ctx, sessionId),
    ...verifyArtifactAccessTokenIntegrity(ctx, sessionId),
    ...verifyLeaseRunIntegrity(ctx, sessionId),
    ...(await verifyIndexerCursorIntegrity(ctx, proofProviders)),
    ...verifyReplayBundleBindings(ctx, sessionId, payload),
  ];
  const rawErrors = toStringArray(raw.errors);
  const view = VerifierRunViewSchema.parse({
    sessionId,
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
  return { view, verifierInput };
}

export async function readProofProviderStatus(ctx: ServiceCtx): Promise<ProofProviderStatus[]> {
  const [chain, caw, cawLive, mcpLease] = await Promise.all([ctx.chain.status(), ctx.caw.status(), ctx.cawLive.status(), ctx.mcpLease.status()]);
  return [chain, caw, cawLive, mcpLease];
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
  assertReplaySummaryWithinCap(ctx, parsedSessionId, requestId);
  const data = assembleReplayBundleData(parsedSessionId, ctx);
  const bundleBytes = Buffer.byteLength(canonicalizeJson(data), "utf8");
  if (bundleBytes > MAX_REPLAY_BUNDLE_BYTES) {
    return {
      ok: false,
      requestId,
      error: proofBlockedError(requestId, "replay bundle exceeds the 2 MiB response cap", {
        bundleBytes,
        maxBytes: MAX_REPLAY_BUNDLE_BYTES,
        eventCount: data.events.length,
      }),
    };
  }
  return { ok: true, requestId, data };
}

function assembleReplayBundleData(sessionId: string, ctx: ServiceCtx): ReplayBundleView {
  const events = listEvents(ctx, sessionId, 0, REPLAY_SUMMARY_LIMIT);
  const mcpAdapterCalls = listMcpAdapterCalls(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const sources = listSources(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const spends = listSpends(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const artifactPreflights = listArtifactPreflights(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const quotes = listQuotes(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const artifactAccessTokens = listArtifactAccessTokens(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const cawReceiptOperations = listCawReceiptOperations(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const cawLiveInteractions = listCawLiveInteractions(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const rawCawReceiptBundles = listRawCawReceiptBundles(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const canonicalCawReceipts = listCanonicalCawReceipts(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const leaseRuns = listLeaseRuns(ctx, sessionId, REPLAY_SUMMARY_LIMIT);
  const agentTranscript = buildAgentTranscriptData(sessionId, ctx, mcpAdapterCalls.length);
  return ReplayBundleViewSchema.parse({
    bundleType: "PACTFUSE_EVIDENCE_V1",
    sessionId,
    summaryMode: true,
    asOfEventSeq: events.at(-1)?.eventSeq ?? 0,
    asOfMcpAdapterCallCount: mcpAdapterCalls.length,
    winnerClaimAllowed: false,
    eventRoot: hashJson(events.map((event) => event.eventHash)),
    agentTranscriptHash: hashJson(agentTranscript),
    events,
    sources,
    spends,
    artifactPreflights,
    quotes,
    artifactAccessTokens,
    mcpAdapterCalls,
    cawReceiptOperations,
    cawLiveInteractions,
    rawCawReceiptBundles,
    canonicalCawReceipts,
    leaseRuns,
    judgeCheck: readJudgeCheckData(sessionId, ctx),
    replayPageIndex: replayPageIndexFor(ctx, sessionId),
  });
}

export async function readRunnerHeartbeat(sessionId: string, ctx: ServiceCtx): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("runner_heartbeat");
  const parsedSessionId = parseStrict(Hex32Schema, sessionId);
  assertSession(ctx, parsedSessionId, requestId);
  const latestLease = listLeaseRuns(ctx, parsedSessionId, 1)[0] ?? null;
  const status = latestLease
    ? latestLease.status === "succeeded_live_mcp_transcript"
      ? "lease_executed"
      : latestLease.status.startsWith("blocked_")
        ? "blocked"
        : "pending"
    : "pending";
  return {
    ok: true,
    requestId,
    data: RunnerHeartbeatViewSchema.parse({
      sessionId: parsedSessionId,
      status,
      latestLeaseRunId: latestLease?.leaseRunId ?? null,
      transcriptHash: latestLease?.transcriptHash ?? null,
      leaseRunHash: latestLease?.leaseRunHash ?? null,
      winnerClaimAllowed: false,
      updatedAt: latestLease?.completedAt ?? latestLease?.createdAt ?? nowIso(),
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
  const boundedToPinnedManifest = agentTranscriptBoundedToPinnedManifest(ctx, sessionId, calls);
  const transcriptHash =
    calls.length > 0
      ? hashJson({
          format: "mcp-json-rpc",
          sessionId,
          toolsListHash,
          toolsCallHash,
          boundedToPinnedManifest,
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
    boundedToPinnedManifest,
    callCount: calls.length,
    calls: callSummaries,
    winnerClaimAllowed: false,
  });
}

function agentTranscriptBoundedToPinnedManifest(
  ctx: ServiceCtx,
  sessionId: string,
  calls: ReturnType<typeof listMcpAdapterCalls>,
): boolean {
  const successfulLeases = listLeaseRuns(ctx, sessionId, REPLAY_SUMMARY_LIMIT).filter((lease) => lease.status === "succeeded_live_mcp_transcript");
  const successfulLeaseCount = countRows(ctx, "lease_runs", "session_id = ? AND status = 'succeeded_live_mcp_transcript'", [sessionId]);
  if (successfulLeaseCount === 0) {
    return false;
  }
  if (successfulLeaseCount !== successfulLeases.length) {
    return false;
  }
  const expectedAuditNonces = new Set<string>();
  for (const lease of successfulLeases) {
    const prefix = lease.leaseRunId.slice(2, 22);
    expectedAuditNonces.add(`lease_${prefix}_tools_list`);
    expectedAuditNonces.add(`lease_${prefix}_tools_call`);
  }
  if (replayCollectionRowCount(ctx, sessionId, "mcpAdapterCalls") !== expectedAuditNonces.size) {
    return false;
  }
  if (calls.length !== expectedAuditNonces.size || calls.some((call) => !expectedAuditNonces.has(call.auditNonce))) {
    return false;
  }
  const callsByAuditNonce = new Map(calls.map((call) => [call.auditNonce, call]));
  return successfulLeases.every((lease) => {
    const prefix = lease.leaseRunId.slice(2, 22);
    const listCall = callsByAuditNonce.get(`lease_${prefix}_tools_list`);
    const toolCall = callsByAuditNonce.get(`lease_${prefix}_tools_call`);
    if (!listCall || !toolCall || typeof lease.spendId !== "string") {
      return false;
    }
    let pinnedManifest: PinnedMcpManifest;
    try {
      pinnedManifest = requirePinnedMcpManifestForSpend(ctx, sessionId, lease.spendId, newRequestId("agent_manifest_bound"));
    } catch {
      return false;
    }
    const actualTools = mcpToolsFromToolsListResponse(listCall.response);
    const requestedToolName =
      toolCall.request.params && typeof toolCall.request.params === "object" && !Array.isArray(toolCall.request.params)
        ? (toolCall.request.params as Record<string, JsonValue>).name
        : null;
    return (
      Array.isArray(actualTools) &&
      hashJson(actualTools) === pinnedManifest.toolsHash &&
      pinnedManifest.tools.length === 1 &&
      requestedToolName === pinnedManifest.tools[0]?.name
    );
  });
}

function mcpToolsFromToolsListResponse(response: Record<string, JsonValue>): Array<Record<string, unknown>> | null {
  const result = response.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    return null;
  }
  const tools = (result as Record<string, unknown>).tools;
  if (!Array.isArray(tools) || tools.some((tool) => !tool || typeof tool !== "object" || Array.isArray(tool))) {
    return null;
  }
  return tools as Array<Record<string, unknown>>;
}

function replayPageIndexFor(ctx: ServiceCtx, sessionId: string) {
  const collections = Object.fromEntries(
    REPLAY_COLLECTION_NAMES.map((collection) => [collection, replayPageCollection(ctx, sessionId, collection)]),
  );
  return {
    pageSize: REPLAY_SUMMARY_LIMIT,
    pageRoot: hashJson(Object.entries(collections).map(([name, collection]) => ({ name, pageRoot: collection.pageRoot }))),
    collections,
  };
}

function replayPageCollection(ctx: ServiceCtx, sessionId: string, collection: ReplayCollectionName) {
  const totalRows = replayCollectionRowCount(ctx, sessionId, collection);
  const pageCount = Math.ceil(totalRows / REPLAY_SUMMARY_LIMIT);
  const pageHashes: string[] = [];
  const orderBy = replayCollectionOrderBy(collection);
  for (let pageIndex = 0; pageIndex < pageCount; pageIndex += 1) {
    const rows = replayCollectionRows(ctx, sessionId, collection, pageIndex);
    pageHashes.push(replayPageHash(sessionId, collection, pageIndex, orderBy, rows));
  }
  return {
    totalRows,
    pageCount,
    orderBy,
    firstPageHash: pageHashes[0] ?? replayPageHash(sessionId, collection, 0, orderBy, []),
    pageRoot: hashJson(pageHashes),
    pageHashes,
  };
}

export async function readReplayPage(
  input: { sessionId: string; collection: string; page: string | number },
  ctx: ServiceCtx,
): Promise<ServiceResult<unknown>> {
  const requestId = newRequestId("replay_page");
  const sessionId = parseStrict(Hex32Schema, input.sessionId);
  assertSession(ctx, sessionId, requestId);
  if (!isReplayCollectionName(input.collection)) {
    return { ok: false, requestId, error: badRequestError(requestId, "replay collection is not supported") };
  }
  const pageIndex = typeof input.page === "number" ? input.page : Number(input.page);
  if (!Number.isInteger(pageIndex) || pageIndex < 0) {
    return { ok: false, requestId, error: badRequestError(requestId, "replay page must be a non-negative integer") };
  }
  const totalRows = replayCollectionRowCount(ctx, sessionId, input.collection);
  const pageCount = Math.ceil(totalRows / REPLAY_SUMMARY_LIMIT);
  if (pageIndex >= Math.max(pageCount, 1)) {
    return { ok: false, requestId, error: badRequestError(requestId, "replay page is out of range") };
  }
  const orderBy = replayCollectionOrderBy(input.collection);
  const rows = replayCollectionRows(ctx, sessionId, input.collection, pageIndex);
  const data = ReplayPageViewSchema.parse({
    bundleType: "PACTFUSE_REPLAY_PAGE_V1",
    sessionId,
    collection: input.collection,
    pageIndex,
    pageSize: REPLAY_SUMMARY_LIMIT,
    orderBy,
    rows,
    pageHash: replayPageHash(sessionId, input.collection, pageIndex, orderBy, rows),
  });
  return { ok: true, requestId, data };
}

function replayPageHash(sessionId: string, collection: ReplayCollectionName, pageIndex: number, orderBy: string[], rows: unknown[]): string {
  return hashJson({ sessionId, collection, pageIndex, pageSize: REPLAY_SUMMARY_LIMIT, orderBy, rows });
}

function isReplayCollectionName(value: string): value is ReplayCollectionName {
  return (REPLAY_COLLECTION_NAMES as string[]).includes(value);
}

function replayCollectionRows(ctx: ServiceCtx, sessionId: string, collection: ReplayCollectionName, pageIndex: number) {
  const offset = pageIndex * REPLAY_SUMMARY_LIMIT;
  switch (collection) {
    case "events":
      return listEvents(ctx, sessionId, 0, REPLAY_SUMMARY_LIMIT, offset);
    case "sources":
      return listSources(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "spends":
      return listSpends(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "artifactPreflights":
      return listArtifactPreflights(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "quotes":
      return listQuotes(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "artifactAccessTokens":
      return listArtifactAccessTokens(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "mcpAdapterCalls":
      return listMcpAdapterCalls(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "cawReceiptOperations":
      return listCawReceiptOperations(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "cawLiveInteractions":
      return listCawLiveInteractions(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "rawCawReceiptBundles":
      return listRawCawReceiptBundles(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "canonicalCawReceipts":
      return listCanonicalCawReceipts(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
    case "leaseRuns":
      return listLeaseRuns(ctx, sessionId, REPLAY_SUMMARY_LIMIT, offset);
  }
}

function replayCollectionRowCount(ctx: ServiceCtx, sessionId: string, collection: ReplayCollectionName): number {
  const table = replayCollectionTable(collection);
  const row = ctx.db.sqlite.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE session_id = ?`).get(sessionId) as Row;
  return Number(row.count ?? 0);
}

function replayCollectionTable(collection: ReplayCollectionName): string {
  switch (collection) {
    case "events":
      return "evidence_events";
    case "sources":
      return "sources";
    case "spends":
      return "spends";
    case "artifactPreflights":
      return "artifact_preflights";
    case "quotes":
      return "quotes";
    case "artifactAccessTokens":
      return "artifact_access_tokens";
    case "mcpAdapterCalls":
      return "mcp_adapter_calls";
    case "cawReceiptOperations":
      return "caw_receipt_operations";
    case "cawLiveInteractions":
      return "caw_live_interactions";
    case "rawCawReceiptBundles":
      return "caw_raw_receipt_bundles";
    case "canonicalCawReceipts":
      return "caw_canonical_receipts";
    case "leaseRuns":
      return "lease_runs";
  }
}

function replayCollectionOrderBy(collection: ReplayCollectionName): string[] {
  switch (collection) {
    case "events":
      return ["eventSeq ASC"];
    case "sources":
      return ["createdAt ASC", "sourceHash ASC"];
    case "spends":
      return ["createdAt ASC", "spendId ASC"];
    case "artifactPreflights":
      return ["createdAt ASC", "preflightId ASC"];
    case "quotes":
      return ["createdAt ASC", "quoteId ASC"];
    case "artifactAccessTokens":
      return ["createdAt ASC", "tokenId ASC"];
    case "mcpAdapterCalls":
      return ["createdAt ASC", "toolName tools/list before tools/call", "callId ASC"];
    case "cawReceiptOperations":
      return ["createdAt ASC", "operationId ASC"];
    case "cawLiveInteractions":
      return ["createdAt ASC", "interactionId ASC"];
    case "rawCawReceiptBundles":
      return ["createdAt ASC", "bundleId ASC"];
    case "canonicalCawReceipts":
      return ["createdAt ASC", "rawReceiptHash ASC"];
    case "leaseRuns":
      return ["createdAt DESC", "leaseRunId ASC"];
  }
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
  const access = requireActiveArtifactAccess(ctx, { ...input, sessionId, spendId, payer, artifactHash }, requestId);
  return {
    ok: true,
    requestId,
    data: {
      sessionId,
      spendId,
      artifactHash,
      artifactCid: access.artifact_cid,
      artifactPayloadHash: access.artifact_payload_hash,
      artifactPayload: JSON.parse(String(access.artifact_payload_json)),
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
  const requestId = newRequestId("stream");
  assertSession(ctx, parsedSessionId, requestId);
  let afterSeq = 0;
  if (afterEventId) {
    const row = ctx.db.sqlite
      .prepare("SELECT event_seq FROM evidence_events WHERE session_id = ? AND event_id = ?")
      .get(parsedSessionId, afterEventId) as Row | undefined;
    if (row) {
      afterSeq = Number(row.event_seq);
    } else if (Hex32Schema.safeParse(afterEventId).success) {
      throw Object.assign(new Error("stream cursor event does not belong to this session"), {
        apiError: badRequestError(requestId, "afterEventId does not belong to this session"),
      });
    } else if (/^(0|[1-9][0-9]*)$/.test(afterEventId)) {
      afterSeq = Number(afterEventId);
    } else {
      throw Object.assign(new Error("invalid stream cursor"), {
        apiError: badRequestError(requestId, "afterEventId must be an event id for this session or an event sequence number"),
      });
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
      | "source.challenge.confirmed"
      | "spend.registered"
      | "caw.operation.built"
      | "caw.live.pact.submitted"
      | "caw.live.pact.synced"
      | "caw.live.transfer.submitted"
      | "caw.live.audit.synced"
      | "caw.receipt.ingested.fixture"
      | "caw.receipt.ingested.raw"
      | "artifact.preflight.pending"
      | "artifact.access_token.issued"
      | "quote.signed.mocked"
      | "artifact.refund.pending"
      | "operator.key_used"
      | "gate.spend_tripped.observed"
      | "gate.spend_settled.observed"
      | "gate.spend_tripped"
      | "gate.spend_settled"
      | "reorg.invalidated"
      | "lease.execution.blocked"
      | "lease.execution.succeeded"
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

async function safeChainProviderStatus(ctx: ServiceCtx): Promise<ProofProviderStatus> {
  try {
    return await ctx.chain.status();
  } catch (error) {
    return {
      name: "chain",
      mode: "live",
      ready: false,
      reason: error instanceof Error ? error.message : "chain proof provider readiness check failed",
    };
  }
}

function readIndexerCursor(ctx: ServiceCtx, cursorId: string): Row | undefined {
  return ctx.db.sqlite.prepare("SELECT * FROM chain_indexer_cursors WHERE cursor_id = ?").get(cursorId) as Row | undefined;
}

function assertProviderChainMatchesPayload(status: ProofProviderStatus, expectedChainId: string, requestId: string, purpose: string): void {
  if (!status.chainId) {
    throw Object.assign(new Error(`${purpose} provider did not report a chainId`), {
      apiError: proofPendingError(requestId, `${purpose} provider did not report a chainId`),
    });
  }
  if (status.chainId !== expectedChainId) {
    throw Object.assign(new Error(`${purpose} chainId mismatch`), {
      apiError: proofBlockedError(requestId, `${purpose} chainId mismatch`, {
        expected: expectedChainId,
        actual: status.chainId,
      }),
    });
  }
}

function assertIndexerCursorMatchesPayload(cursor: Row | undefined, payload: ChainIndexerBackfillPayload, requestId: string): void {
  if (!cursor) {
    return;
  }
  const expectedTopics = canonicalIndexerTopicsJson(payload.topics);
  const cursorAddress = typeof cursor.address === "string" ? cursor.address.toLowerCase() : null;
  const payloadAddress = payload.address ? payload.address.toLowerCase() : null;
  const mismatches: Record<string, JsonValue> = {};
  if (String(cursor.chain_id) !== payload.chainId) {
    mismatches.chainId = { existing: String(cursor.chain_id), requested: payload.chainId };
  }
  if (cursorAddress !== payloadAddress) {
    mismatches.address = { existing: cursor.address === null ? null : String(cursor.address), requested: payload.address ?? null };
  }
  if (String(cursor.topics_json) !== expectedTopics) {
    mismatches.topics = { existing: JSON.parse(String(cursor.topics_json)) as JsonValue, requested: payload.topics };
  }
  if (Number(cursor.finality_depth) !== payload.finalityDepth) {
    mismatches.finalityDepth = { existing: Number(cursor.finality_depth), requested: payload.finalityDepth };
  }
  if (Object.keys(mismatches).length > 0) {
    throw Object.assign(new Error("chain indexer cursor configuration cannot change without a new cursorId"), {
      apiError: proofBlockedError(requestId, "chain indexer cursor configuration cannot change without a new cursorId", mismatches),
    });
  }
}

function canonicalIndexerTopicsJson(topics: Array<string | null> = []): string {
  return canonicalizeJson(topics.map((topic) => (typeof topic === "string" ? topic.toLowerCase() : null)));
}

function resolveIndexerWindow(
  payload: ChainIndexerBackfillPayload,
  lastIndexedBlock: number | null,
  finalizedHeadBlock: number,
  requestId: string,
): { fromBlock: number; cappedToBlock: number } {
  const requestedToBlock = payload.toBlock ?? finalizedHeadBlock;
  if (lastIndexedBlock !== null && payload.fromBlock !== undefined) {
    const expectedNextBlock = lastIndexedBlock + 1;
    if (payload.fromBlock > expectedNextBlock) {
      throw Object.assign(new Error("chain indexer backfill cannot skip a cursor gap"), {
        apiError: proofBlockedError(requestId, "chain indexer backfill cannot skip a cursor gap", {
          cursorId: payload.cursorId,
          lastIndexedBlock,
          requestedFromBlock: payload.fromBlock,
          expectedNextBlock,
        }),
      });
    }
    if (payload.fromBlock < expectedNextBlock && requestedToBlock > lastIndexedBlock) {
      throw Object.assign(new Error("chain indexer overlapping backfill cannot advance the cursor"), {
        apiError: proofBlockedError(requestId, "chain indexer overlapping backfill cannot advance the cursor", {
          cursorId: payload.cursorId,
          lastIndexedBlock,
          requestedFromBlock: payload.fromBlock,
          requestedToBlock,
          expectedNextBlock,
        }),
      });
    }
  }
  const fromBlock = payload.fromBlock ?? (lastIndexedBlock === null ? 0 : lastIndexedBlock + 1);
  return {
    fromBlock,
    cappedToBlock: Math.min(requestedToBlock, finalizedHeadBlock, fromBlock + payload.maxWindowBlocks - 1),
  };
}

function insertIndexedChainLogExactOnce(ctx: ServiceCtx, log: NormalizedIndexedChainLog, requestId: string): number {
  const rawLogJson = canonicalizeJson(log.raw);
  const existing = ctx.db.sqlite
    .prepare(
      `SELECT log_id, raw_log_hash, raw_log_json
       FROM chain_indexed_logs
       WHERE chain_id = ? AND tx_hash = ? AND log_index = ?`,
    )
    .get(log.chainId, log.txHash, log.logIndex) as Row | undefined;
  if (existing) {
    if (String(existing.log_id).toLowerCase() !== log.logId.toLowerCase()) {
      throw Object.assign(new Error("indexed chain log id conflict"), {
        apiError: proofBlockedError(requestId, "indexed chain log id conflict", {
          expected: log.logId,
          actual: String(existing.log_id),
        }),
      });
    }
    if (String(existing.raw_log_hash).toLowerCase() !== log.rawLogHash.toLowerCase()) {
      throw Object.assign(new Error("indexed chain log rawLogHash conflict"), {
        apiError: proofBlockedError(requestId, "indexed chain log rawLogHash conflict", {
          chainId: log.chainId,
          txHash: log.txHash,
          logIndex: log.logIndex,
          expected: String(existing.raw_log_hash),
          actual: log.rawLogHash,
        }),
      });
    }
    if (String(existing.raw_log_json) !== rawLogJson) {
      throw Object.assign(new Error("indexed chain log raw JSON conflict"), {
        apiError: proofBlockedError(requestId, "indexed chain log raw JSON conflict", {
          chainId: log.chainId,
          txHash: log.txHash,
          logIndex: log.logIndex,
        }),
      });
    }
    return 0;
  }
  const result = ctx.db.sqlite
    .prepare(
      `INSERT INTO chain_indexed_logs
        (log_id, cursor_id, chain_id, block_number, tx_hash, log_index, address, topics_json, data, raw_log_hash, raw_log_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      log.logId,
      log.cursorId,
      log.chainId,
      log.blockNumber,
      log.txHash,
      log.logIndex,
      log.address,
      canonicalizeJson(log.topics),
      log.data,
      log.rawLogHash,
      rawLogJson,
      log.createdAt,
    );
  return Number(result.changes);
}

function markIndexerCursorDegraded(
  ctx: ServiceCtx,
  payload: ChainIndexerBackfillPayload,
  latestHeadBlock: number,
  finalizedHeadBlock: number,
  lastIndexedBlock: number | null,
  requestId: string,
  reason: string,
): void {
  upsertIndexerCursor(ctx, {
    payload,
    lastIndexedBlock,
    latestHeadBlock,
    finalizedHeadBlock,
    reason,
    requestId,
    forceStatus: "degraded",
  });
}

function upsertIndexerCursor(
  ctx: ServiceCtx,
  input: {
    payload: ChainIndexerBackfillPayload;
    lastIndexedBlock: number | null;
    latestHeadBlock: number;
    finalizedHeadBlock: number;
    reason: string;
    requestId: string;
    forceStatus?: "degraded" | undefined;
  },
) {
  const existing = readIndexerCursor(ctx, input.payload.cursorId);
  assertIndexerCursorMatchesPayload(existing, input.payload, input.requestId);
  const createdAt = typeof existing?.created_at === "string" ? existing.created_at : ctx.clock.now().toISOString();
  const updatedAt = ctx.clock.now().toISOString();
  const existingLastIndexedBlock = optionalChainNumber(existing?.last_indexed_block);
  const nextLastIndexedBlock =
    existingLastIndexedBlock === null
      ? input.lastIndexedBlock
      : input.lastIndexedBlock === null
        ? existingLastIndexedBlock
        : Math.max(existingLastIndexedBlock, input.lastIndexedBlock);
  const lagBlocks =
    nextLastIndexedBlock === null ? input.finalizedHeadBlock + 1 : Math.max(0, input.finalizedHeadBlock - nextLastIndexedBlock);
  const status = input.forceStatus ?? (lagBlocks === 0 ? "caught_up" : "degraded");
  ctx.db.sqlite
    .prepare(
      `INSERT INTO chain_indexer_cursors
        (cursor_id, chain_id, address, topics_json, last_indexed_block, latest_head_block, finalized_head_block,
         finality_depth, lag_blocks, status, reason, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(cursor_id) DO UPDATE SET
         chain_id = excluded.chain_id,
         address = excluded.address,
         topics_json = excluded.topics_json,
         last_indexed_block = excluded.last_indexed_block,
         latest_head_block = excluded.latest_head_block,
         finalized_head_block = excluded.finalized_head_block,
         finality_depth = excluded.finality_depth,
         lag_blocks = excluded.lag_blocks,
         status = excluded.status,
         reason = excluded.reason,
         updated_at = excluded.updated_at`,
    )
    .run(
      input.payload.cursorId,
      input.payload.chainId,
      input.payload.address ?? null,
      canonicalIndexerTopicsJson(input.payload.topics),
      nextLastIndexedBlock,
      input.latestHeadBlock,
      input.finalizedHeadBlock,
      input.payload.finalityDepth,
      lagBlocks,
      status,
      input.reason,
      createdAt,
      updatedAt,
    );
  return indexerCursorViewFromRow(readIndexerCursor(ctx, input.payload.cursorId) as Row);
}

function indexerCursorViewFromRow(row: Row) {
  return ChainIndexerStatusViewSchema.parse({
    cursorId: row.cursor_id,
    chainId: row.chain_id,
    address: row.address ?? null,
    topics: JSON.parse(String(row.topics_json)),
    lastIndexedBlock: row.last_indexed_block ?? null,
    latestHeadBlock: Number(row.latest_head_block),
    finalizedHeadBlock: Number(row.finalized_head_block),
    finalityDepth: Number(row.finality_depth),
    lagBlocks: Number(row.lag_blocks),
    status: row.status,
    reason: row.reason,
    updatedAt: row.updated_at,
  });
}

function requiredIndexerCursorView(cursor: ServiceCtx["requiredIndexerCursors"][number]) {
  return ChainIndexerStatusViewSchema.parse({
    cursorId: cursor.cursorId,
    chainId: cursor.chainId,
    address: cursor.address ?? null,
    topics: cursor.topics ?? [],
    lastIndexedBlock: null,
    latestHeadBlock: 0,
    finalizedHeadBlock: 0,
    finalityDepth: cursor.finalityDepth ?? 2,
    lagBlocks: 0,
    status: "unconfigured",
    reason: "required chain indexer cursor has not been initialized by the worker",
    updatedAt: nowIso(),
  });
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
    .prepare("SELECT * FROM spends WHERE session_id = ? AND spend_id = ?")
    .get(sessionId, spendId) as Row | undefined;
  if (!spend) {
    throw Object.assign(new Error("spend not found"), { apiError: notFoundError(requestId, "spend") });
  }
  return spend;
}

function assertGateContractStateMatchesSpend(spend: Row, proof: GateContractStateProof, requestId: string): void {
  const expected = {
    sessionId: String(spend.session_id).toLowerCase(),
    pactId: String(spend.pact_id).toLowerCase(),
    toolId: String(spend.tool_id).toLowerCase(),
    sourceSetHash: String(spend.source_set_hash).toLowerCase(),
    agentWallet: String(spend.agent_wallet).toLowerCase(),
    paymentToken: String(spend.payment_token).toLowerCase(),
    price: BigInt(String(spend.max_price_atomic)).toString(),
    artifactHash: String(spend.artifact_hash).toLowerCase(),
    market: String(spend.market).toLowerCase(),
  };
  const actual = {
    sessionId: proof.contractSessionId.toLowerCase(),
    pactId: proof.contractPactId.toLowerCase(),
    toolId: proof.contractToolId.toLowerCase(),
    sourceSetHash: proof.contractSourceSetHash.toLowerCase(),
    agentWallet: proof.contractAgentWallet.toLowerCase(),
    paymentToken: proof.contractPaymentToken.toLowerCase(),
    price: proof.contractPrice,
    artifactHash: proof.contractArtifactHash.toLowerCase(),
    market: proof.contractMarket.toLowerCase(),
  };
  const mismatches = Object.fromEntries(
    (Object.keys(expected) as Array<keyof typeof expected>)
      .filter((field) => expected[field] !== actual[field])
      .map((field) => [field, { expected: expected[field], actual: actual[field] }]),
  );
  if (Object.keys(mismatches).length > 0) {
    throw Object.assign(new Error("ProcurementGate registeredSpend state does not match backend spend binding"), {
      apiError: proofBlockedError(requestId, "ProcurementGate registeredSpend state does not match backend spend binding", { mismatches }),
    });
  }
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

function assertSpendArtifactHash(spend: Row, artifactHash: string, scope: string, requestId: string): void {
  const expected = String(spend.artifact_hash).toLowerCase();
  const actual = artifactHash.toLowerCase();
  if (actual !== expected) {
    throw Object.assign(new Error(`${scope} artifactHash does not match registered ProcurementGate artifactHash`), {
      apiError: proofBlockedError(requestId, `${scope} artifactHash does not match registered ProcurementGate artifactHash`, {
        spendId: String(spend.spend_id),
        expectedArtifactHash: expected,
        actualArtifactHash: actual,
      }),
    });
  }
}

function assertSpendPrice(spend: Row, priceAtomic: string, scope: string, requestId: string): void {
  const expected = BigInt(String(spend.max_price_atomic)).toString();
  const actual = BigInt(priceAtomic).toString();
  if (actual !== expected) {
    throw Object.assign(new Error(`${scope} priceAtomic does not match registered ProcurementGate price`), {
      apiError: proofBlockedError(requestId, `${scope} priceAtomic does not match registered ProcurementGate price`, {
        spendId: String(spend.spend_id),
        expectedPriceAtomic: expected,
        actualPriceAtomic: actual,
      }),
    });
  }
}

function assertSpendPaymentToken(spend: Row, paymentToken: string, scope: string, requestId: string): void {
  const expected = String(spend.payment_token).toLowerCase();
  const actual = paymentToken.toLowerCase();
  if (actual !== expected) {
    throw Object.assign(new Error(`${scope} paymentToken does not match registered ProcurementGate paymentToken`), {
      apiError: proofBlockedError(requestId, `${scope} paymentToken does not match registered ProcurementGate paymentToken`, {
        spendId: String(spend.spend_id),
        expectedPaymentToken: expected,
        actualPaymentToken: actual,
      }),
    });
  }
}

function assertSpendMarket(spend: Row, market: string, scope: string, requestId: string): void {
  const expected = String(spend.market).toLowerCase();
  const actual = market.toLowerCase();
  if (actual !== expected) {
    throw Object.assign(new Error(`${scope} destinationAddress does not match registered ProcurementGate market`), {
      apiError: proofBlockedError(requestId, `${scope} destinationAddress does not match registered ProcurementGate market`, {
        spendId: String(spend.spend_id),
        expectedMarket: expected,
        actualDestinationAddress: actual,
      }),
    });
  }
}

function assertCawOperationCanAcceptReceipt(operation: Row | undefined, requestId: string): void {
  if (!operation) {
    return;
  }
  if (operation.receipt_bundle_hash || operation.status !== "built_mocked") {
    throw Object.assign(new Error("CAW operation already has an attached receipt bundle"), {
      apiError: conflictError(requestId, "CAW operation already has an attached receipt bundle"),
    });
  }
}

async function fetchAndValidateCawRawBundle(
  ctx: ServiceCtx,
  input: {
    requestId: string;
    sessionId: string;
    sourceLabel: string;
    operationId: string;
    expectedReceipts: Array<Record<string, JsonValue>>;
    operation: Row | undefined;
  },
): Promise<{ bundle: Record<string, JsonValue>; receipts: Array<Record<string, JsonValue>>; source: string; fetchedAt: string }> {
  if (!input.operation) {
    throw Object.assign(new Error("CAW operation not found for raw receipt ingest"), {
      apiError: notFoundError(input.requestId, "caw operation"),
    });
  }
  let status;
  try {
    status = await ctx.caw.status();
  } catch (error) {
    throw Object.assign(new Error("CAW receipt source readiness check failed"), {
      apiError: proofPendingError(input.requestId, cawFailureMessage("CAW receipt source readiness check failed", error)),
    });
  }
  if (!status.ready) {
    throw Object.assign(new Error("CAW receipt source is not ready"), {
      apiError: proofPendingError(input.requestId, `CAW receipt source is not ready: ${status.reason}`),
    });
  }

  let raw;
  try {
    raw = await ctx.caw.fetchReceiptBundle({
      sessionId: input.sessionId,
      sourceLabel: input.sourceLabel,
      operationId: input.operationId,
      operationKind: input.operation.operation_kind,
      target: input.operation.target,
      selector: input.operation.selector,
      request: JSON.parse(String(input.operation.request_json)),
    });
  } catch (error) {
    throw Object.assign(new Error("failed to fetch raw CAW receipt bundle"), {
      apiError: proofPendingError(input.requestId, cawFailureMessage("failed to fetch raw CAW receipt bundle", error)),
    });
  }
  const bundle = normalizeCawRawBundle(raw, input.requestId);
  const receipts = cawBundleReceipts(bundle);
  if (receipts.length === 0) {
    throw Object.assign(new Error("raw CAW receipt bundle is empty"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle is empty"),
    });
  }
  assertCawBundleMetadata(bundle, input);
  assertCawOperationMembership(receipts, input);
  assertExpectedCawReceipts(receipts, input.expectedReceipts, input.requestId);
  return {
    bundle,
    receipts,
    source: cawBundleSource(bundle, input.sourceLabel),
    fetchedAt: cawBundleFetchedAt(bundle, ctx.clock.now().toISOString()),
  };
}

function normalizeCawRawBundle(value: unknown, requestId: string): Record<string, JsonValue> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw Object.assign(new Error("raw CAW receipt bundle must be a JSON object"), {
      apiError: proofBlockedError(requestId, "raw CAW receipt bundle must be a JSON object"),
    });
  }
  return normalizeChainJson(value) as Record<string, JsonValue>;
}

function cawBundleReceipts(bundle: Record<string, JsonValue>): Array<Record<string, JsonValue>> {
  const candidates = [
    bundle.receipts,
    bundle.rawReceipts,
    bundle.operations,
    bundle.records,
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate.filter((item): item is Record<string, JsonValue> => Boolean(item && typeof item === "object" && !Array.isArray(item)));
    }
  }
  return [];
}

function assertCawBundleMetadata(
  bundle: Record<string, JsonValue>,
  input: { requestId: string; sessionId: string; sourceLabel: string },
): void {
  const sessionId = asOptionalString(bundle.sessionId);
  if (sessionId && sessionId !== input.sessionId) {
    throw Object.assign(new Error("raw CAW receipt bundle sessionId mismatch"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle sessionId mismatch", {
        expected: input.sessionId,
        actual: sessionId,
      }),
    });
  }
  const source = asOptionalString(bundle.source ?? bundle.sourceLabel);
  if (source && source !== input.sourceLabel) {
    throw Object.assign(new Error("raw CAW receipt bundle source mismatch"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle source mismatch", {
        expected: input.sourceLabel,
        actual: source,
      }),
    });
  }
}

function assertCawOperationMembership(
  receipts: Array<Record<string, JsonValue>>,
  input: {
    requestId: string;
    sessionId: string;
    operationId: string;
    operation: Row | undefined;
  },
): void {
  const matching = receipts.find((receipt) => cawReceiptMatchesOperation(receipt, input));
  if (!matching) {
    throw Object.assign(new Error("raw CAW receipt bundle does not contain the requested operation"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle does not contain the requested operation", {
        operationId: input.operationId,
      }),
    });
  }
}

function cawReceiptMatchesOperation(
  receipt: Record<string, JsonValue>,
  input: { sessionId: string; operationId: string; operation: Row | undefined },
): boolean {
  const operationId = asOptionalString(receipt.operationId ?? receipt.cawOperationId ?? receipt.requestId);
  if (!operationId || operationId !== input.operationId) {
    return false;
  }
  const sessionId = asOptionalString(receipt.sessionId);
  if (!sessionId || sessionId !== input.sessionId) {
    return false;
  }
  const operationKind = asOptionalString(receipt.operationKind ?? receipt.kind);
  if (!operationKind || operationKind !== String(input.operation?.operation_kind)) {
    return false;
  }
  const target = asOptionalString(receipt.target);
  if (input.operation?.target && (!target || target.toLowerCase() !== String(input.operation.target).toLowerCase())) {
    return false;
  }
  const selector = asOptionalString(receipt.selector);
  if (input.operation?.selector && (!selector || selector.toLowerCase() !== String(input.operation.selector).toLowerCase())) {
    return false;
  }
  return true;
}

function buildCanonicalCawReceipts(input: {
  bundleId: `0x${string}`;
  sessionId: string;
  operationId: string;
  sourceLabel: string;
  operation: Row | undefined;
  receipts: Array<Record<string, JsonValue>>;
  fetchedAt: string;
  createdAt: string;
  requestId: string;
}): CanonicalCawReceiptData[] {
  const matching = input.receipts.filter((receipt) => cawReceiptMatchesOperation(receipt, input));
  if (matching.length === 0) {
    throw Object.assign(new Error("raw CAW receipt bundle has no canonicalizable receipt for the requested operation"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle has no canonicalizable receipt for the requested operation", {
        operationId: input.operationId,
      }),
    });
  }
  const rawHashes = matching.map((receipt) => hashJson(receipt));
  if (new Set(rawHashes).size !== rawHashes.length) {
    throw Object.assign(new Error("raw CAW receipt bundle contains duplicate canonical receipt rows"), {
      apiError: proofBlockedError(input.requestId, "raw CAW receipt bundle contains duplicate canonical receipt rows", {
        operationId: input.operationId,
      }),
    });
  }
  return matching.map((receipt) => canonicalizeCawReceipt(receipt, input));
}

function canonicalizeCawReceipt(
  receipt: Record<string, JsonValue>,
  input: {
    bundleId: `0x${string}`;
    sessionId: string;
    operationId: string;
    sourceLabel: string;
    operation: Row | undefined;
    fetchedAt: string;
    createdAt: string;
    requestId: string;
  },
): CanonicalCawReceiptData {
  const effect = cawReceiptEffect(receipt, input.requestId);
  const status = cawRequiredText(receipt.status ?? receipt.statusDisplay ?? receipt.status_display ?? receipt.result ?? receipt.effect, "status", input.requestId);
  const walletAddress = cawRequiredHex(
    receipt.walletAddress ?? receipt.wallet_address ?? receipt.wallet ?? receipt.owner ?? receipt.payer ?? receipt.agentWallet,
    "walletAddress",
    input.requestId,
  );
  const policyDigest = cawRequiredHex32(receipt.policyDigest ?? receipt.policy_digest ?? receipt.cawPolicyDigest, "policyDigest", input.requestId);
  const paramsDigest = cawRequiredHex32(
    receipt.paramsDigest ?? receipt.params_digest ?? receipt.requestDigest ?? receipt.request_digest ?? receipt.typedDataHash,
    "paramsDigest",
    input.requestId,
  );
  const requestId = cawRequiredText(receipt.cawRequestId ?? receipt.requestId ?? receipt.request_id ?? receipt.id, "requestId", input.requestId);
  const txCount = cawRequiredDecimal(receipt.txCount ?? receipt.tx_count ?? receipt.policyTxCount ?? receipt.policy_tx_count, "txCount", input.requestId);
  const expiry = cawRequiredIso(receipt.expiry ?? receipt.expiresAt ?? receipt.expires_at ?? receipt.expiration, "expiry", input.requestId);
  const target = input.operation?.target ? cawRequiredHex(receipt.target, "target", input.requestId) : cawOptionalHex(receipt.target, "target", input.requestId);
  const selector = input.operation?.selector
    ? cawRequiredSelector(receipt.selector, "selector", input.requestId)
    : cawOptionalSelector(receipt.selector, "selector", input.requestId);
  const txHash = cawOptionalHex32(receipt.txHash ?? receipt.tx_hash ?? receipt.transactionHash ?? receipt.transaction_hash, "txHash", input.requestId);
  if (effect === "allow" && !txHash) {
    throw Object.assign(new Error("canonical CAW allow receipt requires txHash"), {
      apiError: proofBlockedError(input.requestId, "canonical CAW allow receipt requires txHash"),
    });
  }
  const operationKind = String(input.operation?.operation_kind);
  const canonicalBase = {
    bundleId: input.bundleId,
    sessionId: Hex32Schema.parse(input.sessionId),
    operationId: Hex32Schema.parse(input.operationId),
    operationKind: CawOperationBuildPayloadSchema.shape.operationKind.parse(operationKind),
    sourceLabel: input.sourceLabel,
    walletAddress,
    target,
    selector,
    requestId,
    effect,
    status,
    policyDigest,
    paramsDigest,
    txHash,
    txCount,
    expiry,
    fetchedAt: IsoDateStringSchema.parse(input.fetchedAt),
    createdAt: IsoDateStringSchema.parse(input.createdAt),
  };
  return CanonicalCawReceiptViewSchema.parse({
    rawReceiptHash: hashJson(receipt),
    canonicalReceiptHash: hashJson(canonicalBase),
    ...canonicalBase,
  }) as CanonicalCawReceiptData;
}

function cawStructuralAuthorityProof(input: {
  sessionId: string;
  operationId: string;
  sourceLabel: string;
  rawReceiptBundleHash: `0x${string}`;
  operation: Row | undefined;
  canonicalReceipts: CanonicalCawReceiptData[];
  now: string;
  requestId: string;
}): { status: typeof CAW_STRUCTURAL_AUTHORITY_STATUS; authorityProofHash: `0x${string}` } {
  if (input.sourceLabel !== "caw-api" && input.sourceLabel !== "caw-export") {
    throw Object.assign(new Error("CAW structural authority requires a raw CAW API/export source"), {
      apiError: proofBlockedError(input.requestId, "CAW structural authority requires a raw CAW API/export source"),
    });
  }
  if (!input.operation) {
    throw Object.assign(new Error("CAW structural authority requires a built operation"), {
      apiError: proofBlockedError(input.requestId, "CAW structural authority requires a built operation"),
    });
  }
  if (input.canonicalReceipts.length === 0) {
    throw Object.assign(new Error("CAW structural authority requires at least one canonical receipt"), {
      apiError: proofBlockedError(input.requestId, "CAW structural authority requires at least one canonical receipt"),
    });
  }
  const operationRequest = parseCawOperationRequest(input.operation, input.requestId);
  for (const receipt of input.canonicalReceipts) {
    if (receipt.sessionId !== input.sessionId || receipt.operationId !== input.operationId) {
      throw Object.assign(new Error("CAW structural authority receipt is not bound to the operation session"), {
        apiError: proofBlockedError(input.requestId, "CAW structural authority receipt is not bound to the operation session"),
      });
    }
    if (receipt.sourceLabel !== input.sourceLabel) {
      throw Object.assign(new Error("CAW structural authority receipt sourceLabel mismatch"), {
        apiError: proofBlockedError(input.requestId, "CAW structural authority receipt sourceLabel mismatch"),
      });
    }
    if (receipt.effect === "allow" && !receipt.txHash) {
      throw Object.assign(new Error("CAW structural authority allow receipt requires txHash"), {
        apiError: proofBlockedError(input.requestId, "CAW structural authority allow receipt requires txHash"),
      });
    }
    const expiryMs = Date.parse(receipt.expiry);
    const nowMs = Date.parse(input.now);
    if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs) || expiryMs <= nowMs) {
      throw Object.assign(new Error("CAW structural authority receipt is expired"), {
        apiError: proofBlockedError(input.requestId, "CAW structural authority receipt is expired"),
      });
    }
  }
  const authorityProofHash = hashJson({
    status: CAW_STRUCTURAL_AUTHORITY_STATUS,
    sessionId: input.sessionId,
    operationId: input.operationId,
    sourceLabel: input.sourceLabel,
    rawReceiptBundleHash: input.rawReceiptBundleHash,
    operationRequest,
    canonicalReceiptHashes: input.canonicalReceipts.map((receipt) => receipt.canonicalReceiptHash).sort(),
    policyDigests: [...new Set(input.canonicalReceipts.map((receipt) => receipt.policyDigest))].sort(),
    paramsDigests: [...new Set(input.canonicalReceipts.map((receipt) => receipt.paramsDigest))].sort(),
    txHashes: input.canonicalReceipts.map((receipt) => receipt.txHash).filter(Boolean).sort(),
  });
  return { status: CAW_STRUCTURAL_AUTHORITY_STATUS, authorityProofHash };
}

function parseCawOperationRequest(operation: Row, requestId: string): Record<string, JsonValue> {
  try {
    const parsed = JSON.parse(String(operation.request_json)) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, JsonValue>;
    }
  } catch {
    // Fall through to the proof-blocked error below.
  }
  throw Object.assign(new Error("CAW operation request JSON is not canonicalizable"), {
    apiError: proofBlockedError(requestId, "CAW operation request JSON is not canonicalizable"),
  });
}

function cawReceiptEffect(receipt: Record<string, JsonValue>, requestId: string): "allow" | "deny" {
  const raw = asOptionalString(receipt.effect ?? receipt.result ?? receipt.status)?.toLowerCase();
  if (raw && ["allow", "allowed", "success", "succeeded", "executed", "confirmed", "completed"].includes(raw)) {
    return "allow";
  }
  if (raw && ["deny", "denied", "blocked", "rejected", "policy_denied", "policydenied", "failed"].includes(raw)) {
    return "deny";
  }
  throw Object.assign(new Error("canonical CAW receipt requires effect/result/status allow or deny"), {
    apiError: proofBlockedError(requestId, "canonical CAW receipt requires effect/result/status allow or deny"),
  });
}

function cawRequiredText(value: unknown, field: string, requestId: string): string {
  const text = asOptionalString(value);
  if (!text) {
    throw Object.assign(new Error(`canonical CAW receipt missing ${field}`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt missing ${field}`),
    });
  }
  return text;
}

function cawRequiredHex(value: unknown, field: string, requestId: string): string {
  const text = cawRequiredText(value, field, requestId);
  if (!HexSchema.safeParse(text).success) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be hex`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be hex`),
    });
  }
  return text;
}

function cawOptionalHex(value: unknown, field: string, requestId: string): string | null {
  const text = asOptionalString(value);
  if (!text) {
    return null;
  }
  if (!HexSchema.safeParse(text).success) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be hex`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be hex`),
    });
  }
  return text;
}

function cawRequiredHex32(value: unknown, field: string, requestId: string): `0x${string}` {
  const text = cawRequiredText(value, field, requestId);
  if (!Hex32Schema.safeParse(text).success) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be 32-byte hex`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be 32-byte hex`),
    });
  }
  return text as `0x${string}`;
}

function cawOptionalHex32(value: unknown, field: string, requestId: string): `0x${string}` | null {
  const text = asOptionalString(value);
  if (!text) {
    return null;
  }
  if (!Hex32Schema.safeParse(text).success) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be 32-byte hex`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be 32-byte hex`),
    });
  }
  return text as `0x${string}`;
}

function cawRequiredSelector(value: unknown, field: string, requestId: string): string {
  const text = cawRequiredText(value, field, requestId);
  if (!/^0x[0-9a-fA-F]{8}$/.test(text)) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be a 4-byte selector`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be a 4-byte selector`),
    });
  }
  return text;
}

function cawOptionalSelector(value: unknown, field: string, requestId: string): string | null {
  const text = asOptionalString(value);
  if (!text) {
    return null;
  }
  return cawRequiredSelector(text, field, requestId);
}

function cawRequiredDecimal(value: unknown, field: string, requestId: string): string {
  const text = cawRequiredText(value, field, requestId);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be a decimal string`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be a decimal string`),
    });
  }
  return text;
}

function cawRequiredIso(value: unknown, field: string, requestId: string): string {
  const text = cawRequiredText(value, field, requestId);
  if (!IsoDateStringSchema.safeParse(text).success) {
    throw Object.assign(new Error(`canonical CAW receipt ${field} must be an ISO datetime`), {
      apiError: proofBlockedError(requestId, `canonical CAW receipt ${field} must be an ISO datetime`),
    });
  }
  return text;
}

function assertExpectedCawReceipts(
  rawReceipts: Array<Record<string, JsonValue>>,
  expectedReceipts: Array<Record<string, JsonValue>>,
  requestId: string,
): void {
  if (expectedReceipts.length === 0) {
    return;
  }
  const rawHashes = new Set(rawReceipts.map((receipt) => hashJson(receipt)));
  const missing = expectedReceipts.map((receipt) => hashJson(receipt)).filter((receiptHash) => !rawHashes.has(receiptHash));
  if (missing.length > 0) {
    throw Object.assign(new Error("expected CAW receipt rows are not members of the raw bundle"), {
      apiError: proofBlockedError(requestId, "expected CAW receipt rows are not members of the raw bundle", {
        missingReceiptHashes: missing,
      }),
    });
  }
}

function cawBundleSource(bundle: Record<string, JsonValue>, fallback: string): string {
  return asOptionalString(bundle.source ?? bundle.sourceLabel) ?? fallback;
}

function cawBundleFetchedAt(bundle: Record<string, JsonValue>, fallback: string): string {
  return asOptionalString(bundle.fetchedAt ?? bundle.exportedAt ?? bundle.createdAt) ?? fallback;
}

function asOptionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function cawFailureMessage(prefix: string, error: unknown): string {
  return error instanceof Error ? `${prefix}: ${error.message}` : prefix;
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

function requireFinalizedSettlement(
  ctx: ServiceCtx,
  sessionId: string,
  spendId: string,
  requestId: string,
): { finalizedEventId: string; observedEventId: string; blockNumber: number } {
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
      `SELECT status, observed_event_id, finalized_event_id, finality_depth, confirmations, block_number
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
  return {
    finalizedEventId: String(settlement.finalized_event_id),
    observedEventId: String(settlement.observed_event_id),
    blockNumber: Number(settlement.block_number),
  };
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
  assertProviderChainMatchesPayload(status, payload.chainId, requestId, "gate proof");

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

function normalizeIndexedChainLog(
  cursorId: string,
  chainId: string,
  log: Record<string, unknown>,
  requestId: string,
  createdAt: string,
): NormalizedIndexedChainLog {
  const blockNumber = optionalChainNumber(log.blockNumber);
  if (blockNumber === null) {
    throw Object.assign(new Error("indexed chain log is missing blockNumber"), {
      apiError: proofBlockedError(requestId, "indexed chain log is missing blockNumber"),
    });
  }
  const txHash = requiredChainHex32(log.transactionHash ?? log.txHash ?? log.hash, "transactionHash", requestId);
  const logIndex = optionalChainNumber(log.logIndex ?? log.index);
  if (logIndex === null) {
    throw Object.assign(new Error("indexed chain log is missing logIndex"), {
      apiError: proofBlockedError(requestId, "indexed chain log is missing logIndex"),
    });
  }
  const logChainId = optionalString(log.chainId);
  if (logChainId && logChainId !== chainId) {
    throw Object.assign(new Error("indexed chain log chainId mismatch"), {
      apiError: proofBlockedError(requestId, "indexed chain log chainId mismatch", { expected: chainId, actual: logChainId }),
    });
  }
  const topics = chainLogTopics(log.topics, requestId);
  const data = optionalHex(log.data) ?? null;
  const address = optionalHex(log.address) ?? null;
  const raw = normalizeChainJson(log);
  const view = ChainIndexedLogViewSchema.parse({
    logId: hashJson({ chainId, txHash, logIndex }),
    cursorId,
    chainId,
    blockNumber,
    txHash,
    logIndex,
    address,
    topics,
    data,
    rawLogHash: rawLogHashForChainLog(log),
    createdAt,
  }) as Omit<NormalizedIndexedChainLog, "raw">;
  return {
    ...view,
    raw,
  };
}

function chainLogTopics(value: unknown, requestId: string): string[] {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw Object.assign(new Error("indexed chain log topics must be an array"), {
      apiError: proofBlockedError(requestId, "indexed chain log topics must be an array"),
    });
  }
  return value.map((topic) => requiredChainHex(topic, "topic", requestId));
}

function requiredChainHex(value: unknown, field: string, requestId: string): string {
  const hex = optionalHex(value);
  if (!hex) {
    throw Object.assign(new Error(`indexed chain log ${field} must be hex`), {
      apiError: proofBlockedError(requestId, `indexed chain log ${field} must be hex`),
    });
  }
  return hex;
}

function requiredChainHex32(value: unknown, field: string, requestId: string): `0x${string}` {
  const hex = requiredChainHex(value, field, requestId);
  if (!Hex32Schema.safeParse(hex).success) {
    throw Object.assign(new Error(`indexed chain log ${field} must be 32-byte hex`), {
      apiError: proofBlockedError(requestId, `indexed chain log ${field} must be 32-byte hex`),
    });
  }
  return hex as `0x${string}`;
}

function optionalHex32(value: unknown): `0x${string}` | null {
  return typeof value === "string" && Hex32Schema.safeParse(value).success ? (value as `0x${string}`) : null;
}

function indexedLogSemanticEvent(
  row: Row,
):
  | {
      event: "SpendTripped" | "SpendSettled";
      sessionId: `0x${string}`;
      spendId: `0x${string}`;
    }
  | {
      event: "SourceChallenged";
      sessionId: `0x${string}`;
      sourceHash: `0x${string}`;
      reasonHash: `0x${string}`;
    }
  | null {
  let raw: Record<string, unknown>;
  try {
    const parsed = JSON.parse(String(row.raw_log_json)) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    raw = parsed as Record<string, unknown>;
  } catch {
    return null;
  }
  const args = raw.args && typeof raw.args === "object" && !Array.isArray(raw.args) ? (raw.args as Record<string, unknown>) : {};
  const event = semanticEventName(raw.event ?? raw.eventName ?? raw.name);
  const sessionId = optionalHex32(raw.sessionId ?? args.sessionId);
  if (!event || !sessionId) {
    return null;
  }
  if (event === "SpendTripped" || event === "SpendSettled") {
    const spendId = optionalHex32(raw.spendId ?? args.spendId);
    return spendId ? { event, sessionId, spendId } : null;
  }
  const sourceHash = optionalHex32(raw.sourceHash ?? args.sourceHash);
  const reasonHash = optionalHex32(raw.reasonHash ?? args.reasonHash);
  return sourceHash && reasonHash ? { event, sessionId, sourceHash, reasonHash } : null;
}

function semanticEventName(value: unknown): "SpendTripped" | "SpendSettled" | "SourceChallenged" | null {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  if (normalized === "spendtripped") {
    return "SpendTripped";
  }
  if (normalized === "spendsettled") {
    return "SpendSettled";
  }
  if (normalized === "sourcechallenged") {
    return "SourceChallenged";
  }
  return null;
}

function indexedLogProofRef(row: Row): IndexedLogProofRef {
  return {
    indexedLogId: String(row.log_id) as `0x${string}`,
    cursorId: String(row.cursor_id),
    indexedRawLogHash: String(row.raw_log_hash) as `0x${string}`,
    finalizedHeadBlock: Number(row.finalized_head_block),
    latestHeadBlock: Number(row.latest_head_block),
  };
}

async function verifyGateContractState(
  ctx: ServiceCtx,
  row: Row,
  semantic: { event: "SpendTripped" | "SpendSettled"; sessionId: `0x${string}`; spendId: `0x${string}` },
  requestId: string,
): Promise<GateContractStateProof> {
  const contractAddress = indexedContractAddress(row, requestId, "ProcurementGate");
  let result: unknown;
  try {
    result = await ctx.chain.readContract({
      address: contractAddress,
      abi: PROCUREMENT_GATE_STATE_ABI,
      functionName: "registeredSpend",
      args: [semantic.spendId],
      blockNumber: Number(row.block_number),
    });
  } catch (error) {
    throw contractReadApiError("failed to read ProcurementGate registeredSpend state", error, requestId);
  }

  const contractSessionId = requiredContractHex32(contractTupleValue(result, 0, "sessionId"), "registeredSpend.sessionId", requestId);
  const contractPactId = requiredContractHex32(contractTupleValue(result, 1, "pactId"), "registeredSpend.pactId", requestId);
  const contractToolId = requiredContractHex32(contractTupleValue(result, 2, "toolId"), "registeredSpend.toolId", requestId);
  const contractSourceSetHash = requiredContractHex32(
    contractTupleValue(result, 3, "sourceSetHash"),
    "registeredSpend.sourceSetHash",
    requestId,
  );
  const contractAgentWallet = requiredContractAddress(contractTupleValue(result, 4, "agentWallet"), "registeredSpend.agentWallet", requestId);
  const contractPaymentToken = requiredContractAddress(contractTupleValue(result, 5, "paymentToken"), "registeredSpend.paymentToken", requestId);
  const contractPrice = requiredContractUintString(contractTupleValue(result, 6, "price"), "registeredSpend.price", requestId);
  const contractArtifactHash = requiredContractHex32(contractTupleValue(result, 7, "artifactHash"), "registeredSpend.artifactHash", requestId);
  const contractMarket = requiredContractAddress(contractTupleValue(result, 8, "market"), "registeredSpend.market", requestId);
  const contractState = contractStateNumber(contractTupleValue(result, 9, "state"));
  const expectedState = semantic.event === "SpendTripped" ? GATE_SPEND_STATE.Tripped : GATE_SPEND_STATE.Settled;
  if (contractSessionId.toLowerCase() !== semantic.sessionId.toLowerCase()) {
    throw Object.assign(new Error("indexed gate event session does not match ProcurementGate state"), {
      apiError: proofBlockedError(requestId, "indexed gate event session does not match ProcurementGate state", {
        expected: semantic.sessionId,
        actual: contractSessionId,
      }),
    });
  }
  if (contractState !== expectedState) {
    throw Object.assign(new Error("indexed gate event does not match ProcurementGate spend state"), {
      apiError: proofBlockedError(requestId, "indexed gate event does not match ProcurementGate spend state", {
        event: semantic.event,
        expectedState,
        actualState: contractState,
      }),
    });
  }
  return {
    contractStateVerified: true,
    contractAddress,
    contractFunction: "registeredSpend",
    contractSessionId,
    contractPactId,
    contractToolId,
    contractSourceSetHash,
    contractAgentWallet,
    contractPaymentToken,
    contractPrice,
    contractArtifactHash,
    contractMarket,
    contractSpendState: semantic.event === "SpendTripped" ? "Tripped" : "Settled",
  };
}

async function verifySourceChallengeContractState(
  ctx: ServiceCtx,
  row: Row,
  sourceHash: `0x${string}`,
  requestId: string,
): Promise<SourceContractStateProof> {
  const sourceRegistryAddress = indexedContractAddress(row, requestId, "SourceStateRegistry");
  let result: unknown;
  try {
    result = await ctx.chain.readContract({
      address: sourceRegistryAddress,
      abi: SOURCE_REGISTRY_STATE_ABI,
      functionName: "sourceState",
      args: [sourceHash],
      blockNumber: Number(row.block_number),
    });
  } catch (error) {
    throw contractReadApiError("failed to read SourceStateRegistry sourceState", error, requestId);
  }
  const contractState = contractStateNumber(result);
  if (contractState !== SOURCE_STATE_CHALLENGED) {
    throw Object.assign(new Error("indexed SourceChallenged event does not match SourceStateRegistry state"), {
      apiError: proofBlockedError(requestId, "indexed SourceChallenged event does not match SourceStateRegistry state", {
        expectedState: SOURCE_STATE_CHALLENGED,
        actualState: contractState,
      }),
    });
  }
  return {
    contractStateVerified: true,
    sourceRegistryAddress,
    contractFunction: "sourceState",
    contractSourceState: "Challenged",
  };
}

function indexedContractAddress(row: Row, requestId: string, contractName: string): string {
  const address = optionalHex(row.address);
  if (!address) {
    throw Object.assign(new Error(`${contractName} indexed log is missing contract address`), {
      apiError: proofBlockedError(requestId, `${contractName} indexed log is missing contract address`),
    });
  }
  const cursorAddress = optionalHex(row.cursor_address);
  if (!cursorAddress) {
    throw Object.assign(new Error(`${contractName} proof cursor is missing configured contract address`), {
      apiError: proofBlockedError(requestId, `${contractName} proof cursor is missing configured contract address`),
    });
  }
  if (address.toLowerCase() !== cursorAddress.toLowerCase()) {
    throw Object.assign(new Error(`${contractName} indexed log address does not match proof cursor address`), {
      apiError: proofBlockedError(requestId, `${contractName} indexed log address does not match proof cursor address`, {
        expected: cursorAddress,
        actual: address,
      }),
    });
  }
  return address;
}

function contractReadApiError(message: string, error: unknown, requestId: string): Error {
  const detail = chainFailureMessage(message, error);
  return Object.assign(new Error(message), {
    apiError: isTransientContractReadError(error) ? proofPendingError(requestId, detail) : proofBlockedError(requestId, detail),
  });
}

function isTransientContractReadError(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return /(timeout|timed out|network|fetch|econn|etimedout|eai_again|429|rate limit|temporar|gateway|503|502|500|server error)/.test(
    message,
  );
}

function contractTupleValue(result: unknown, index: number, key: string): unknown {
  if (Array.isArray(result)) {
    return result[index];
  }
  if (result && typeof result === "object") {
    return (result as Record<string, unknown>)[key];
  }
  return undefined;
}

function contractStateNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value)) {
    return value;
  }
  if (typeof value === "bigint") {
    return Number(value);
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return Number(value);
  }
  return null;
}

function requiredContractHex32(value: unknown, field: string, requestId: string): `0x${string}` {
  const hex = optionalHex32(value);
  if (!hex) {
    throw Object.assign(new Error(`${field} must be 32-byte hex in contract state`), {
      apiError: proofBlockedError(requestId, `${field} must be 32-byte hex in contract state`),
    });
  }
  return hex;
}

function requiredContractAddress(value: unknown, field: string, requestId: string): `0x${string}` {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw Object.assign(new Error(`${field} must be a 20-byte address in contract state`), {
      apiError: proofBlockedError(requestId, `${field} must be a 20-byte address in contract state`),
    });
  }
  return value.toLowerCase() as `0x${string}`;
}

function requiredContractUintString(value: unknown, field: string, requestId: string): string {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return String(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) {
    return BigInt(value).toString();
  }
  throw Object.assign(new Error(`${field} must be a uint string in contract state`), {
    apiError: proofBlockedError(requestId, `${field} must be a uint string in contract state`),
  });
}

async function reconcileIndexedGateEvent(
  ctx: ServiceCtx,
  row: Row,
  semantic: { event: "SpendTripped" | "SpendSettled"; sessionId: `0x${string}`; spendId: `0x${string}` },
  requestId: string,
): Promise<number> {
  const session = requireSessionRow(ctx, semantic.sessionId, requestId);
  const spend = assertSpend(ctx, semantic.sessionId, semantic.spendId, requestId);
  const blockNumber = Number(row.block_number);
  const latestHeadBlock = Number(row.latest_head_block);
  const finalizedHeadBlock = Number(row.finalized_head_block);
  const finalityDepth = Math.max(Number(row.finality_depth), finalityDepthForSession(session));
  const confirmations = latestHeadBlock >= blockNumber ? latestHeadBlock - blockNumber + 1 : 0;
  if (blockNumber > finalizedHeadBlock || confirmations < finalityDepth) {
    return 0;
  }
  const gatePayload = {
    event: semantic.event,
    spendId: semantic.spendId,
    txHash: String(row.tx_hash),
    logIndex: Number(row.log_index),
    chainId: String(row.chain_id),
    blockNumber,
    currentBlockNumber: latestHeadBlock,
    rawLogHash: String(row.raw_log_hash),
  };
  const gateEventId = hashJson({
    sessionId: semantic.sessionId,
    event: semantic.event,
    spendId: semantic.spendId,
    txHash: gatePayload.txHash,
    logIndex: gatePayload.logIndex,
    chainId: gatePayload.chainId,
    rawLogHash: gatePayload.rawLogHash,
  });
  const contractStateProof = await verifyGateContractState(ctx, row, semantic, requestId);
  assertGateContractStateMatchesSpend(spend, contractStateProof, requestId);
  return withImmediateTransaction(ctx, () => {
    const existing = ctx.db.sqlite
      .prepare(
        `SELECT *
         FROM gate_chain_events
         WHERE session_id = ? AND tx_hash = ? AND log_index = ? AND event_kind = ?`,
      )
      .get(semantic.sessionId, gatePayload.txHash, gatePayload.logIndex, semantic.event) as Row | undefined;
    if (existing) {
      assertGateEventRowMatches(existing, gatePayload, gateEventId, requestId);
      if (existing.status === "reorg_invalidated" || typeof existing.reorg_event_id === "string") {
        throw Object.assign(new Error("cannot reconcile a reorg-invalidated gate event"), {
          apiError: proofBlockedError(requestId, "cannot reconcile a reorg-invalidated gate event"),
        });
      }
      if (typeof existing.finalized_event_id === "string") {
        return 0;
      }
    }
    const observedEventId =
      typeof existing?.observed_event_id === "string"
        ? existing.observed_event_id
        : appendGateObservedEvent(ctx, semantic.sessionId, gatePayload, gateEventId, finalityDepth, confirmations).eventId;
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
          semantic.sessionId,
          semantic.spendId,
          semantic.event,
          gatePayload.txHash,
          gatePayload.logIndex,
          gatePayload.chainId,
          blockNumber,
          latestHeadBlock,
          finalityDepth,
          confirmations,
          gatePayload.rawLogHash,
          observedEventId,
          ctx.clock.now().toISOString(),
          ctx.clock.now().toISOString(),
        );
    }
    const proofEvent = appendGateFinalizedEvent(
      ctx,
      semantic.sessionId,
      gatePayload,
      gateEventId,
      observedEventId,
      finalityDepth,
      confirmations,
      indexedLogProofRef(row),
      contractStateProof,
    );
    const finalizeResult = ctx.db.sqlite
      .prepare(
        `UPDATE gate_chain_events
         SET current_block_number = ?, confirmations = ?, status = 'finalized', finalized_event_id = ?, updated_at = ?
         WHERE gate_event_id = ?`,
      )
      .run(latestHeadBlock, confirmations, proofEvent.eventId, ctx.clock.now().toISOString(), gateEventId);
    if (finalizeResult.changes !== 1) {
      throw Object.assign(new Error("indexed gate event did not update its gate row"), {
        apiError: proofBlockedError(requestId, "indexed gate event did not update its gate row"),
      });
    }
    ctx.db.sqlite
      .prepare("UPDATE spends SET status = ? WHERE session_id = ? AND spend_id = ?")
      .run(gateSpendStatus(semantic.event, "finalized"), semantic.sessionId, semantic.spendId);
    updateJudgeCheckRow(ctx, semantic.sessionId, {
      rowId: semantic.event === "SpendTripped" ? "ab_trip" : "c_settlement",
      status: "pass",
      authority: "proof",
      reason: `indexed public-chain ${semantic.event} log finalized from cursor ${row.cursor_id}`,
      evidenceEventId: proofEvent.eventId,
    });
    return 1;
  });
}

async function reconcileIndexedSourceChallenge(
  ctx: ServiceCtx,
  row: Row,
  semantic: { event: "SourceChallenged"; sessionId: `0x${string}`; sourceHash: `0x${string}`; reasonHash: `0x${string}` },
  requestId: string,
): Promise<number> {
  requireSessionRow(ctx, semantic.sessionId, requestId);
  const sourceHash = semantic.sourceHash.toLowerCase() as `0x${string}`;
  const reasonHash = semantic.reasonHash.toLowerCase() as `0x${string}`;
  const existingProof = indexedProofEventExists(ctx, semantic.sessionId, "source.challenge.confirmed", String(row.log_id));
  if (existingProof) {
    return 0;
  }
  assertChallengedSourceBound(ctx, semantic.sessionId, sourceHash, requestId);
  const pendingChallenge = requirePendingSourceChallenge(ctx, semantic.sessionId, sourceHash, reasonHash, requestId);
  const contractStateProof = await verifySourceChallengeContractState(ctx, row, sourceHash, requestId);
  return withImmediateTransaction(ctx, () => {
    const challengeId = String(pendingChallenge.challenge_id);
    const proofEvent = appendEvidenceEvent(ctx, {
      sessionId: semantic.sessionId,
      authority: "proof",
      kind: "source.challenge.confirmed",
      payload: {
        challengeId,
        sourceHash,
        reasonHash,
        txHash: String(row.tx_hash),
        logIndex: Number(row.log_index),
        chainId: String(row.chain_id),
        blockNumber: Number(row.block_number),
        indexedLogId: String(row.log_id),
        cursorId: String(row.cursor_id),
        indexedRawLogHash: String(row.raw_log_hash),
        finalizedHeadBlock: Number(row.finalized_head_block),
        latestHeadBlock: Number(row.latest_head_block),
        finalityStatus: "finalized",
        ...contractStateProof,
        proofAuthority: true,
        winnerClaimAllowed: false,
      },
    });
    ctx.db.sqlite
      .prepare("UPDATE source_challenges SET status = 'indexed_confirmed' WHERE challenge_id = ?")
      .run(challengeId);
    ctx.db.sqlite
      .prepare("UPDATE sources SET proof_status = 'challenged' WHERE session_id = ? AND source_hash = ?")
      .run(semantic.sessionId, sourceHash);
    updateJudgeCheckRow(ctx, semantic.sessionId, {
      rowId: "source_challenge",
      status: "pass",
      authority: "proof",
      reason: `indexed public-chain SourceChallenged log finalized from cursor ${row.cursor_id}`,
      evidenceEventId: proofEvent.eventId,
    });
    return 1;
  });
}

function indexedProofEventExists(ctx: ServiceCtx, sessionId: string, kind: "source.challenge.confirmed", indexedLogId: string): boolean {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT payload_json
       FROM evidence_events
       WHERE session_id = ? AND kind = ?
       ORDER BY event_seq ASC`,
    )
    .all(sessionId, kind) as Row[];
  return rows.some((row) => {
    try {
      const payload = JSON.parse(String(row.payload_json)) as { indexedLogId?: unknown };
      return payload.indexedLogId === indexedLogId;
    } catch {
      return false;
    }
  });
}

function assertChallengedSourceBound(ctx: ServiceCtx, sessionId: string, sourceHash: string, requestId: string): void {
  const source = ctx.db.sqlite
    .prepare("SELECT source_hash FROM sources WHERE session_id = ? AND LOWER(source_hash) = ?")
    .get(sessionId, sourceHash.toLowerCase()) as Row | undefined;
  if (!source) {
    throw Object.assign(new Error("SourceChallenged log references an unregistered source"), {
      apiError: proofBlockedError(requestId, "SourceChallenged log references an unregistered source", { sourceHash }),
    });
  }
  const spends = ctx.db.sqlite
    .prepare("SELECT spend_id, source_hashes_json FROM spends WHERE session_id = ?")
    .all(sessionId) as Row[];
  const bound = spends.some((row) => {
    try {
      return (JSON.parse(String(row.source_hashes_json)) as string[]).map((hash) => hash.toLowerCase()).includes(sourceHash.toLowerCase());
    } catch {
      return false;
    }
  });
  if (!bound) {
    throw Object.assign(new Error("SourceChallenged log references a source that is not bound to any spend"), {
      apiError: proofBlockedError(requestId, "SourceChallenged log references a source that is not bound to any spend", { sourceHash }),
    });
  }
}

function requirePendingSourceChallenge(ctx: ServiceCtx, sessionId: string, sourceHash: string, reasonHash: string, requestId: string): Row {
  const challenge = ctx.db.sqlite
    .prepare(
      `SELECT challenge_id, status
       FROM source_challenges
       WHERE session_id = ? AND LOWER(source_hash) = ? AND LOWER(reason_hash) = ?
       ORDER BY created_at ASC
       LIMIT 1`,
    )
    .get(sessionId, sourceHash.toLowerCase(), reasonHash.toLowerCase()) as Row | undefined;
  if (!challenge || challenge.status !== "pending_chain_log") {
    throw Object.assign(new Error("SourceChallenged log requires a pending source challenge"), {
      apiError: proofBlockedError(requestId, "SourceChallenged log requires a pending source challenge", { sourceHash, reasonHash }),
    });
  }
  return challenge;
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
  if (!txHash || txHash.toLowerCase() !== payload.txHash.toLowerCase()) {
    return false;
  }
  const logIndex = optionalChainNumber(log.logIndex ?? log.index);
  if (logIndex === null || logIndex !== payload.logIndex) {
    return false;
  }
  const blockNumber = optionalChainNumber(log.blockNumber);
  if (blockNumber === null || blockNumber !== payload.blockNumber) {
    return false;
  }
  const chainId = optionalString(log.chainId);
  if (chainId && chainId !== payload.chainId) {
    return false;
  }
  const eventName = semanticEventName(log.eventName ?? log.event ?? log.name);
  if (eventName !== payload.event) {
    return false;
  }
  const args = log.args && typeof log.args === "object" ? (log.args as Record<string, unknown>) : {};
  const spendId = optionalHex32(log.spendId ?? args.spendId);
  return Boolean(spendId && spendId.toLowerCase() === payload.spendId.toLowerCase());
}

function rawLogHashForChainLog(log: Record<string, unknown>): `0x${string}` {
  const explicit = optionalHex(log.rawRpcLogHash ?? log.rawLogHash ?? log.logHash);
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
  indexedLogRef?: IndexedLogProofRef,
  contractStateProof?: GateContractStateProof | null,
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
    ...(indexedLogRef
      ? {
          indexedLogId: indexedLogRef.indexedLogId,
          cursorId: indexedLogRef.cursorId,
          indexedRawLogHash: indexedLogRef.indexedRawLogHash,
          finalizedHeadBlock: indexedLogRef.finalizedHeadBlock,
          latestHeadBlock: indexedLogRef.latestHeadBlock,
        }
      : {}),
    ...(contractStateProof ?? {}),
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
  indexedLogRef: IndexedLogProofRef,
  contractStateProof: GateContractStateProof,
): EvidenceEvent {
  return appendEvidenceEvent(ctx, {
    sessionId,
    authority: "proof",
    kind: gateFinalizedKind(payload.event),
    payload: gateEventPayload(
      payload,
      gateEventId,
      finalityDepth,
      confirmations,
      "finalized",
      observedEventId,
      indexedLogRef,
      contractStateProof,
    ),
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
  blockJudgeCheckRow(ctx, input.sessionId, {
    rowId: input.payload.event === "SpendTripped" ? "ab_trip" : "c_settlement",
    reason: `reorg invalidated finalized ${input.payload.event} proof`,
    evidenceEventId: reorgEvent.eventId,
  });
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

function assertExistingSourceMatches(
  row: Row,
  expected: {
    sourceId: string;
    manifestUrl: string;
    manifestHash: string;
    issuer: string | null;
    signature: string | null;
    capabilityVectorJson: string;
  },
  requestId: string,
): void {
  const checks = [
    ["source_id", expected.sourceId],
    ["manifest_url", expected.manifestUrl],
    ["manifest_hash", expected.manifestHash],
    ["issuer", expected.issuer],
    ["signature", expected.signature],
    ["capability_vector_json", expected.capabilityVectorJson],
  ] as const;
  const changed = checks.find(([column, expectedValue]) => (row[column] ?? null) !== expectedValue);
  if (changed) {
    throw Object.assign(new Error("registered source cannot be rebound with different manifest or capabilities"), {
      apiError: proofBlockedError(requestId, "registered source cannot be rebound with different manifest or capabilities", {
        sourceHash: String(row.source_hash),
        field: changed[0],
      }),
    });
  }
}

function sourceCapabilitySnapshotFor(ctx: ServiceCtx, sessionId: string, sourceHashes: string[]): { hash: string; entries: JsonValue[] } {
  const entries = sourceHashes.map((sourceHash) => {
    const row = ctx.db.sqlite
      .prepare(
        `SELECT source_hash, manifest_hash, capability_vector_json
         FROM sources
         WHERE session_id = ? AND LOWER(source_hash) = ?`,
      )
      .get(sessionId, sourceHash) as Row | undefined;
    return {
      sourceHash,
      manifestHash: String(row?.manifest_hash ?? ZERO_HASH),
      capabilityVector: JSON.parse(String(row?.capability_vector_json ?? "{}")),
    };
  });
  return { hash: hashJson(entries), entries };
}

function requirePinnedMcpManifestForSpend(ctx: ServiceCtx, sessionId: string, spendId: string, requestId: string): PinnedMcpManifest {
  const spend = ctx.db.sqlite
    .prepare("SELECT source_hashes_json FROM spends WHERE session_id = ? AND spend_id = ?")
    .get(sessionId, spendId) as Row | undefined;
  if (!spend) {
    throw Object.assign(new Error("lease execution requires a registered spend"), {
      apiError: proofPendingError(requestId, "lease execution requires a registered spend"),
    });
  }
  const sourceHashes = normalizedSourceHashes(JSON.parse(String(spend.source_hashes_json)) as string[]);
  const manifestHashes: string[] = [];
  const tools: Array<Record<string, unknown>> = [];
  for (const sourceHash of sourceHashes) {
    const source = ctx.db.sqlite
      .prepare(
        `SELECT source_hash, manifest_hash, capability_vector_json
         FROM sources
         WHERE session_id = ? AND LOWER(source_hash) = ?`,
      )
      .get(sessionId, sourceHash) as Row | undefined;
    if (!source) {
      throw Object.assign(new Error("lease execution requires registered source manifests"), {
        apiError: proofPendingError(requestId, `lease execution requires registered source manifests: ${sourceHash}`),
      });
    }
    const capabilityVector = JSON.parse(String(source.capability_vector_json));
    if (!capabilityVector || typeof capabilityVector !== "object" || Array.isArray(capabilityVector)) {
      throw Object.assign(new Error("source capability vector must be an object"), {
        apiError: proofBlockedError(requestId, "source capability vector must be an object", { sourceHash }),
      });
    }
    if ((capabilityVector as Record<string, unknown>).has_write_file === true) {
      throw Object.assign(new Error("pinned source manifest advertises write-file capability"), {
        apiError: proofBlockedError(requestId, "pinned source manifest advertises write-file capability", { sourceHash }),
      });
    }
    const mcpTools = (capabilityVector as Record<string, unknown>).mcpTools;
    if (!Array.isArray(mcpTools) || mcpTools.length === 0) {
      throw Object.assign(new Error("source capability vector must pin MCP tools"), {
        apiError: proofBlockedError(requestId, "source capability vector must pin MCP tools", { sourceHash }),
      });
    }
    for (const tool of mcpTools) {
      if (!tool || typeof tool !== "object" || Array.isArray(tool) || typeof (tool as Record<string, unknown>).name !== "string") {
        throw Object.assign(new Error("source capability vector contains an invalid MCP tool definition"), {
          apiError: proofBlockedError(requestId, "source capability vector contains an invalid MCP tool definition", { sourceHash }),
        });
      }
      tools.push(tool as Record<string, unknown>);
    }
    manifestHashes.push(String(source.manifest_hash).toLowerCase());
  }
  if (tools.length !== 1) {
    throw Object.assign(new Error("pinned source manifest must expose exactly one PactFuse lease tool"), {
      apiError: proofBlockedError(requestId, "pinned source manifest must expose exactly one PactFuse lease tool", {
        toolCount: tools.length,
      }),
    });
  }
  return {
    sourceHashes,
    manifestHashes,
    tools,
    toolsHash: hashJson(tools),
  };
}

function assertExistingSpendMatches(
  row: Row,
  expected: {
    pactId: string;
    toolId: string;
    payer: string;
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    sourceHashesJson: string;
    sourceSetHash: string;
    sessionCommitment: string;
    spendPreimageJson: string;
    maxPriceAtomic: string;
    nonce: string;
  },
  requestId: string,
): void {
  const checks = [
    ["pact_id", expected.pactId],
    ["tool_id", expected.toolId],
    ["payer", expected.payer],
    ["agent_wallet", expected.agentWallet],
    ["payment_token", expected.paymentToken],
    ["artifact_hash", expected.artifactHash],
    ["market", expected.market],
    ["source_hashes_json", expected.sourceHashesJson],
    ["source_set_hash", expected.sourceSetHash],
    ["session_commitment", expected.sessionCommitment],
    ["spend_preimage_json", expected.spendPreimageJson],
    ["max_price_atomic", expected.maxPriceAtomic],
    ["nonce", expected.nonce],
  ] as const;
  const changed = checks.find(([column, expectedValue]) => String(row[column]) !== expectedValue);
  if (changed) {
    throw Object.assign(new Error("registered spend cannot be rebound with different fields"), {
      apiError: proofBlockedError(requestId, "registered spend cannot be rebound with different fields", {
        spendId: String(row.spend_id),
        field: changed[0],
      }),
    });
  }
}

function assertNonZeroProcurementGateSpend(
  spend: {
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    maxPriceAtomic: string;
  },
  requestId: string,
): void {
  const zeroFields: string[] = [];
  if (spend.agentWallet.toLowerCase() === ZERO_ADDRESS) {
    zeroFields.push("agentWallet");
  }
  if (spend.paymentToken.toLowerCase() === ZERO_ADDRESS) {
    zeroFields.push("paymentToken");
  }
  if (spend.market.toLowerCase() === ZERO_ADDRESS) {
    zeroFields.push("market");
  }
  if (spend.artifactHash.toLowerCase() === ZERO_HASH) {
    zeroFields.push("artifactHash");
  }
  let priceValid = false;
  try {
    priceValid = BigInt(spend.maxPriceAtomic) > 0n && BigInt(spend.maxPriceAtomic) <= (1n << 256n) - 1n;
  } catch {
    priceValid = false;
  }
  if (!priceValid) {
    zeroFields.push("maxPriceAtomic");
  }
  if (zeroFields.length > 0) {
    throw Object.assign(new Error("ProcurementGate spend fields must be non-zero and chain-registerable"), {
      apiError: proofBlockedError(requestId, "ProcurementGate spend fields must be non-zero and chain-registerable", { fields: zeroFields }),
    });
  }
}

function spendBindingFor(
  session: Row,
  sessionId: string,
  spend: {
    pactId: string;
    toolId: string;
    sourceHashes: string[];
    sourceCapabilitySnapshotHash: string;
    payer: string;
    agentWallet: string;
    paymentToken: string;
    artifactHash: string;
    market: string;
    maxPriceAtomic: string;
    nonce: string;
  },
): {
  spendId: string;
  sourceSetHash: string;
  sessionCommitment: string;
  spendPreimage: Record<string, JsonValue>;
} {
  const runConfigHash = String(session.run_config_hash);
  const pactId = spend.pactId.toLowerCase();
  const toolId = spend.toolId.toLowerCase();
  const payer = evmAddress(spend.payer, "payer");
  const agentWallet = evmAddress(spend.agentWallet, "agentWallet");
  const paymentToken = evmAddress(spend.paymentToken, "paymentToken");
  const artifactHash = spend.artifactHash.toLowerCase();
  const market = evmAddress(spend.market, "market");
  const priceAtomic = uint256Decimal(spend.maxPriceAtomic, "maxPriceAtomic");
  const sourceSetHash = procurementGateSourceSetHash(spend.sourceHashes);
  const sessionCommitment = keccakJson({ sessionId: sessionId.toLowerCase(), runConfigHash });
  const spendId = procurementGateSpendId({
    sessionId: sessionId.toLowerCase(),
    pactId,
    toolId,
    sourceSetHash,
    agentWallet,
    paymentToken,
    priceAtomic,
    artifactHash,
    market,
  });
  const spendPreimage: Record<string, JsonValue> = {
    binding: "procurement-gate-abi-v1",
    solidity: "keccak256(abi.encode(bytes32 sessionId, bytes32 pactId, bytes32 toolId, bytes32 sourceSetHash, address agentWallet, address paymentToken, uint256 price, bytes32 artifactHash, address market))",
    sourceSetBinding: "procurement-gate-source-set-abi-v1",
    sourceSetSolidity: "keccak256(abi.encode(bytes32[] sourceHashes))",
    runConfigHash,
    sessionCommitment,
    sessionId: sessionId.toLowerCase(),
    pactId,
    toolId,
    sourceSetHash,
    sourceCapabilitySnapshotHash: spend.sourceCapabilitySnapshotHash,
    payer,
    agentWallet,
    paymentToken,
    priceAtomic,
    artifactHash,
    market,
    maxPriceAtomic: priceAtomic,
    nonce: spend.nonce,
    abiTypes: ["bytes32", "bytes32", "bytes32", "bytes32", "address", "address", "uint256", "bytes32", "address"],
    abiValues: [sessionId.toLowerCase(), pactId, toolId, sourceSetHash, agentWallet, paymentToken, priceAtomic, artifactHash, market],
  };
  return {
    spendId,
    sourceSetHash,
    sessionCommitment,
    spendPreimage,
  };
}

function procurementGateSourceSetHash(sourceHashes: string[]): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32[]" }],
      [sourceHashes.map((sourceHash) => sourceHash.toLowerCase() as `0x${string}`)],
    ),
  );
}

function procurementGateSpendId(input: {
  sessionId: string;
  pactId: string;
  toolId: string;
  sourceSetHash: string;
  agentWallet: string;
  paymentToken: string;
  priceAtomic: string;
  artifactHash: string;
  market: string;
}): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "address" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "address" },
      ],
      [
        input.sessionId as `0x${string}`,
        input.pactId as `0x${string}`,
        input.toolId as `0x${string}`,
        input.sourceSetHash as `0x${string}`,
        input.agentWallet as `0x${string}`,
        input.paymentToken as `0x${string}`,
        BigInt(input.priceAtomic),
        input.artifactHash as `0x${string}`,
        input.market as `0x${string}`,
      ],
    ),
  );
}

function evmAddress(value: string, field: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${field} must be a 20-byte EVM address`);
  }
  return value.toLowerCase() as `0x${string}`;
}

function uint256Decimal(value: string, field: string): string {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${field} must be a decimal uint256 string`);
  }
  const parsed = BigInt(value);
  if (parsed <= 0n || parsed > (1n << 256n) - 1n) {
    throw new Error(`${field} must fit uint256 and be greater than zero`);
  }
  return parsed.toString();
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
  reconcileExpiredArtifactTokenLeaseClaims(ctx, input.sessionId, requestId);
  const requestedArtifactHash = input.artifactHash.toLowerCase();
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT token_id, token_hash, status, issued_by_verifier_run_id, settlement_event_id
              , quote_id, preflight_id, artifact_cid, artifact_payload_hash, artifact_payload_json
       FROM artifact_access_tokens
       WHERE session_id = ? AND spend_id = ? AND payer = ? AND LOWER(artifact_hash) = ?`,
    )
    .all(input.sessionId, input.spendId, input.payer, requestedArtifactHash) as Row[];
  if (rows.length === 0) {
    throw Object.assign(new Error("artifact access is pending live settlement and bearer-token proof"), {
      apiError: proofPendingError(requestId, "artifact access is pending live settlement and bearer-token proof"),
    });
  }
  if (!input.bearerToken) {
    throw Object.assign(new Error("artifact bearer token is required"), {
      apiError: unauthorizedError(requestId, "artifact bearer token is required"),
    });
  }
  const tokenHash = sha256Hex(input.bearerToken);
  const matchingToken = rows.find((row) => row.token_hash === tokenHash);
  if (matchingToken?.status === "consuming") {
    throw Object.assign(new Error("artifact access token is already being consumed by a lease execution"), {
      apiError: proofBlockedError(requestId, "artifact access token is already being consumed by a lease execution", {
        tokenId: String(matchingToken.token_id),
      }),
    });
  }
  if (matchingToken?.status === "consumed") {
    throw Object.assign(new Error("artifact access token has already been consumed by a successful lease"), {
      apiError: proofBlockedError(requestId, "artifact access token has already been consumed by a successful lease", {
        tokenId: String(matchingToken.token_id),
      }),
    });
  }
  if (matchingToken?.status === "blocked") {
    throw Object.assign(new Error("artifact access token was terminated after an untrusted lease attempt"), {
      apiError: proofBlockedError(requestId, "artifact access token was terminated after an untrusted lease attempt", {
        tokenId: String(matchingToken.token_id),
      }),
    });
  }
  const active = rows.find(
    (row) =>
      row.status === "active" &&
      row.token_hash === tokenHash &&
      typeof row.issued_by_verifier_run_id === "string" &&
      typeof row.settlement_event_id === "string",
  );
  if (!active) {
    throw Object.assign(new Error("artifact bearer token is not active for tuple"), {
      apiError: forbiddenError(requestId, "artifact bearer token is not active for this access tuple"),
    });
  }
  const recomputedPayloadHash = hashJson(JSON.parse(String(active.artifact_payload_json)));
  if (recomputedPayloadHash !== String(active.artifact_payload_hash).toLowerCase() || recomputedPayloadHash !== requestedArtifactHash) {
    throw Object.assign(new Error("artifact bearer token payload hash is inconsistent"), {
      apiError: proofBlockedError(requestId, "artifact bearer token payload hash is inconsistent"),
    });
  }
  assertArtifactCidMatchesHash(String(active.artifact_cid), input.artifactHash, requestId);
  const activeVerifierRunId = String(active.issued_by_verifier_run_id);
  const verifierRun = ctx.db.sqlite
    .prepare("SELECT schema_ok FROM verifier_runs WHERE session_id = ? AND verifier_run_id = ?")
    .get(input.sessionId, activeVerifierRunId) as Row | undefined;
  if (!verifierRun || Number(verifierRun.schema_ok) !== 1) {
    throw Object.assign(new Error("artifact bearer token verifier run is missing or failed"), {
      apiError: proofBlockedError(requestId, "artifact bearer token verifier run is missing or failed"),
    });
  }
  return active;
}

function assertNoArtifactRefundPending(ctx: ServiceCtx, sessionId: string, spendId: string, requestId: string): void {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT payload_json
       FROM evidence_events
       WHERE session_id = ? AND kind = 'artifact.refund.pending'
       ORDER BY event_seq ASC`,
    )
    .all(sessionId) as Row[];
  const hasRefund = rows.some((row) => {
    try {
      const payload = JSON.parse(String(row.payload_json)) as { spendId?: unknown };
      return payload.spendId === spendId;
    } catch {
      return false;
    }
  });
  if (hasRefund) {
    throw Object.assign(new Error("artifact access token cannot be issued after refund evidence exists"), {
      apiError: proofBlockedError(requestId, "artifact access token cannot be issued after refund evidence exists"),
    });
  }
}

function assertArtifactCidMatchesHash(artifactCid: string, artifactHash: string, requestId: string): void {
  const expected = `sha256:${artifactHash.toLowerCase()}`;
  if (artifactCid.toLowerCase() !== expected) {
    throw Object.assign(new Error("artifactCid must be the sha256 content address of artifactHash"), {
      apiError: proofBlockedError(requestId, "artifactCid must be the sha256 content address of artifactHash", {
        artifactCid,
        expected,
      }),
    });
  }
}

function assertNoActiveArtifactToken(ctx: ServiceCtx, sessionId: string, spendId: string, requestId: string): void {
  reconcileExpiredArtifactTokenLeaseClaims(ctx, sessionId, requestId);
  const row = ctx.db.sqlite
    .prepare(
      `SELECT token_id
       FROM artifact_access_tokens
       WHERE session_id = ? AND spend_id = ? AND status IN ('active', 'consuming', 'consumed', 'blocked')
       LIMIT 1`,
    )
    .get(sessionId, spendId) as Row | undefined;
  if (row) {
    throw Object.assign(new Error("active artifact access token already exists for spend"), {
      apiError: conflictError(requestId, "active artifact access token already exists for spend"),
    });
  }
}

function claimArtifactTokenForLease(
  ctx: ServiceCtx,
  sessionId: string,
  artifactTokenId: string,
  leaseClaim: Record<string, JsonValue>,
  requestId: string,
): void {
  const result = ctx.db.sqlite
    .prepare(
      `UPDATE artifact_access_tokens
       SET status = 'consuming', lease_claim_json = ?, lease_claimed_at = ?
       WHERE session_id = ? AND token_id = ? AND status = 'active'`,
    )
    .run(canonicalizeJson(leaseClaim), ctx.clock.now().toISOString(), sessionId, artifactTokenId);
  if (Number(result.changes) !== 1) {
    throw Object.assign(new Error("artifact access token could not be claimed for lease execution"), {
      apiError: proofBlockedError(requestId, "artifact access token could not be claimed for lease execution", {
        artifactTokenId,
      }),
    });
  }
}

function releaseArtifactTokenLeaseClaim(ctx: ServiceCtx, sessionId: string, artifactTokenId: string): void {
  ctx.db.sqlite
    .prepare(
      `UPDATE artifact_access_tokens
       SET status = 'active', lease_claim_json = NULL, lease_claimed_at = NULL
       WHERE session_id = ? AND token_id = ? AND status = 'consuming'`,
    )
    .run(sessionId, artifactTokenId);
}

function blockArtifactTokenLeaseClaim(ctx: ServiceCtx, sessionId: string, artifactTokenId: string, requestId: string): void {
  const result = ctx.db.sqlite
    .prepare(
      `UPDATE artifact_access_tokens
       SET status = 'blocked'
       WHERE session_id = ? AND token_id = ? AND status = 'consuming'`,
    )
    .run(sessionId, artifactTokenId);
  if (Number(result.changes) !== 1) {
    throw Object.assign(new Error("artifact access token claim could not be terminated"), {
      apiError: proofBlockedError(requestId, "artifact access token claim could not be terminated", {
        artifactTokenId,
      }),
    });
  }
}

function markArtifactTokenConsumed(ctx: ServiceCtx, sessionId: string, artifactTokenId: string, requestId: string): void {
  const result = ctx.db.sqlite
    .prepare(
      `UPDATE artifact_access_tokens
       SET status = 'consumed'
       WHERE session_id = ? AND token_id = ? AND status = 'consuming'`,
    )
    .run(sessionId, artifactTokenId);
  if (Number(result.changes) !== 1) {
    throw Object.assign(new Error("artifact access token claim was not open during lease completion"), {
      apiError: proofBlockedError(requestId, "artifact access token claim was not open during lease completion", {
        artifactTokenId,
      }),
    });
  }
}

function reconcileExpiredArtifactTokenLeaseClaims(ctx: ServiceCtx, sessionId: string, requestId: string): void {
  const nowMs = ctx.clock.now().getTime();
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT token_id, lease_claim_json, lease_claimed_at
       FROM artifact_access_tokens
       WHERE session_id = ? AND status = 'consuming'`,
    )
    .all(sessionId) as Row[];
  for (const row of rows) {
    const claimedAt = new Date(String(row.lease_claimed_at ?? "")).getTime();
    if (!Number.isFinite(claimedAt) || nowMs - claimedAt < ARTIFACT_TOKEN_LEASE_CLAIM_TTL_MS) {
      continue;
    }
    let claim: Record<string, JsonValue> | null = null;
    try {
      const parsed = JSON.parse(String(row.lease_claim_json ?? "{}")) as unknown;
      claim = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, JsonValue>) : null;
    } catch {
      claim = null;
    }
    blockArtifactTokenLeaseClaim(ctx, sessionId, String(row.token_id), requestId);
    recordBlockedLeaseExecution(ctx, {
      requestId,
      sessionId,
      spendId: String(claim?.spendId ?? ZERO_HASH),
      payer: String(claim?.payer ?? "0x0"),
      artifactHash: String(claim?.artifactHash ?? ZERO_HASH),
      targetRepo: String(claim?.targetRepo ?? "unknown"),
      targetCommit: String(claim?.targetCommit ?? "unknown"),
      leaseRunId: String(claim?.leaseRunId ?? hashJson({ sessionId, tokenId: row.token_id, expiredLeaseClaim: true })),
      settlementEventId: String(claim?.settlementEventId ?? ZERO_HASH),
      artifactTokenId: String(row.token_id),
      status: "blocked_mcp_execution_failed",
      reason: "artifact access token lease claim expired before completed MCP transcript evidence",
    });
  }
}

function mcpLeaseFailureStage(error: unknown): string | null {
  return error && typeof error === "object" && typeof (error as { leaseStage?: unknown }).leaseStage === "string"
    ? (error as { leaseStage: string }).leaseStage
    : null;
}

function assertArtifactTokenUnusedForLease(ctx: ServiceCtx, sessionId: string, artifactTokenId: string, requestId: string): void {
  const row = ctx.db.sqlite
    .prepare(
      `SELECT lease_run_id
       FROM lease_runs
       WHERE session_id = ? AND artifact_token_id = ? AND status = 'succeeded_live_mcp_transcript'
       LIMIT 1`,
    )
    .get(sessionId, artifactTokenId) as Row | undefined;
  if (row) {
    throw Object.assign(new Error("artifact access token has already been consumed by a successful lease"), {
      apiError: proofBlockedError(requestId, "artifact access token has already been consumed by a successful lease", {
        leaseRunId: String(row.lease_run_id),
      }),
    });
  }
}

function requireQuotePreflight(
  ctx: ServiceCtx,
  sessionId: string,
  payload: { spendId: string; preflightId: string; artifactCommitment: string },
  requestId: string,
): Row {
  const preflight = ctx.db.sqlite
    .prepare(
      `SELECT preflight_id, spend_id, artifact_hash_preview, artifact_cid, price_disclosure_hash, source_state_snapshot_hash, status
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
  if (String(preflight.artifact_hash_preview).toLowerCase() !== payload.artifactCommitment.toLowerCase()) {
    throw Object.assign(new Error("quote artifact commitment does not match preflight preview"), {
      apiError: proofBlockedError(requestId, "quote artifact commitment must match the artifact preflight preview", {
        preflightId: payload.preflightId,
      }),
    });
  }
  return preflight;
}

function requireArtifactQuoteBinding(
  ctx: ServiceCtx,
  sessionId: string,
  input: {
    spendId: string;
    quoteId: string;
    artifactHash: string;
    settlementBlockNumber: number;
    spendMaxPriceAtomic: string;
    spendArtifactHash: string;
  },
  requestId: string,
): { preflightId: string; artifactCid: string } {
  const quote = ctx.db.sqlite
    .prepare(
      `SELECT quote_id, preflight_id, artifact_commitment, artifact_cid, price_atomic, valid_until_block, status
       FROM quotes
       WHERE session_id = ? AND spend_id = ? AND quote_id = ?`,
    )
    .get(sessionId, input.spendId, input.quoteId) as Row | undefined;
  if (!quote) {
    throw Object.assign(new Error("artifact access requires a signed quote for the spend"), {
      apiError: proofPendingError(requestId, "artifact access requires a signed quote for the spend"),
    });
  }
  if (quote.status !== "mocked_after_preflight_not_chain_settleable") {
    throw Object.assign(new Error("artifact quote is not in an issuable state"), {
      apiError: proofBlockedError(requestId, "artifact quote is not in an issuable state"),
    });
  }
  if (String(quote.artifact_commitment).toLowerCase() !== input.artifactHash.toLowerCase()) {
    throw Object.assign(new Error("artifact quote commitment does not match requested artifactHash"), {
      apiError: proofBlockedError(requestId, "artifact quote commitment does not match requested artifactHash", {
        quoteId: input.quoteId,
      }),
    });
  }
  if (String(quote.artifact_commitment).toLowerCase() !== input.spendArtifactHash.toLowerCase()) {
    throw Object.assign(new Error("artifact quote commitment does not match registered ProcurementGate artifactHash"), {
      apiError: proofBlockedError(requestId, "artifact quote commitment does not match registered ProcurementGate artifactHash", {
        quoteId: input.quoteId,
        expectedArtifactHash: input.spendArtifactHash.toLowerCase(),
        actualArtifactHash: String(quote.artifact_commitment).toLowerCase(),
      }),
    });
  }
  const artifactCid = String(quote.artifact_cid);
  assertArtifactCidMatchesHash(artifactCid, input.artifactHash, requestId);
  if (BigInt(String(quote.price_atomic)) !== BigInt(input.spendMaxPriceAtomic)) {
    throw Object.assign(new Error("artifact quote price must match registered ProcurementGate price"), {
      apiError: proofBlockedError(requestId, "artifact quote price must match registered ProcurementGate price", {
        expectedPriceAtomic: BigInt(input.spendMaxPriceAtomic).toString(),
        actualPriceAtomic: BigInt(String(quote.price_atomic)).toString(),
      }),
    });
  }
  if (BigInt(String(quote.valid_until_block)) < BigInt(input.settlementBlockNumber)) {
    throw Object.assign(new Error("artifact quote expired before finalized settlement"), {
      apiError: proofBlockedError(requestId, "artifact quote expired before finalized settlement", {
        validUntilBlock: String(quote.valid_until_block),
        settlementBlockNumber: input.settlementBlockNumber,
      }),
    });
  }
  const preflight = ctx.db.sqlite
    .prepare(
      `SELECT artifact_hash_preview, artifact_cid, status
       FROM artifact_preflights
       WHERE session_id = ? AND spend_id = ? AND preflight_id = ?`,
    )
    .get(sessionId, input.spendId, String(quote.preflight_id)) as Row | undefined;
  if (
    !preflight ||
    preflight.status !== "pending_live_delivery" ||
    String(preflight.artifact_hash_preview).toLowerCase() !== input.artifactHash.toLowerCase() ||
    String(preflight.artifact_cid).toLowerCase() !== artifactCid.toLowerCase()
  ) {
    throw Object.assign(new Error("artifact quote is not bound to a matching preflight"), {
      apiError: proofBlockedError(requestId, "artifact quote is not bound to a matching preflight", {
        quoteId: input.quoteId,
      }),
    });
  }
  return { preflightId: String(quote.preflight_id), artifactCid };
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

function updateJudgeCheckRow(
  ctx: ServiceCtx,
  sessionId: string,
  input: {
    rowId: "caw_boundary" | "source_challenge" | "ab_trip" | "c_settlement" | "artifact_access" | "lease_execution";
    status: "pass" | "pending" | "blocked" | "manual" | "fixture";
    authority: "proof" | "delivery" | "operator" | "advisory" | "fixture";
    reason: string;
    evidenceEventId: string;
  },
): void {
  ctx.db.sqlite
    .prepare(
      `UPDATE judge_check_rows
       SET status = ?, authority = ?, reason = ?, evidence_event_id = ?
       WHERE session_id = ?
         AND row_id = ?
         AND status IN ('pending', 'blocked', 'manual', 'fixture')`,
    )
    .run(input.status, input.authority, input.reason, input.evidenceEventId, sessionId, input.rowId);
}

function blockJudgeCheckRow(
  ctx: ServiceCtx,
  sessionId: string,
  input: {
    rowId: "ab_trip" | "c_settlement";
    reason: string;
    evidenceEventId: string;
  },
): void {
  ctx.db.sqlite
    .prepare(
      `UPDATE judge_check_rows
       SET status = 'blocked', authority = 'proof', reason = ?, evidence_event_id = ?
       WHERE session_id = ? AND row_id = ?`,
    )
    .run(input.reason, input.evidenceEventId, sessionId, input.rowId);
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

function listEvents(ctx: ServiceCtx, sessionId: string, afterSeq: number, limit: number, offset = 0): EvidenceEvent[] {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM evidence_events
       WHERE session_id = ? AND event_seq > ?
       ORDER BY event_seq ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, afterSeq, limit, offset) as Row[];
  return rows.map(evidenceEventFromRow);
}

function listSources(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM sources
       WHERE session_id = ?
       ORDER BY created_at ASC, source_hash ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    SourceViewSchema.parse({
      sourceId: row.source_id,
      sessionId: row.session_id,
      sourceHash: row.source_hash,
      manifestUrl: row.manifest_url,
      manifestHash: row.manifest_hash,
      issuer: row.issuer ?? null,
      signature: row.signature ?? null,
      capabilityVector: JSON.parse(String(row.capability_vector_json)),
      proofStatus: row.proof_status,
      createdAt: row.created_at,
    }),
  );
}

function listSpends(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM spends
       WHERE session_id = ?
       ORDER BY created_at ASC, spend_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    SpendViewSchema.parse({
      spendId: row.spend_id,
      sessionId: row.session_id,
      pactId: row.pact_id,
      toolId: row.tool_id,
      payer: row.payer,
      agentWallet: row.agent_wallet,
      paymentToken: row.payment_token,
      artifactHash: row.artifact_hash,
      market: row.market,
      sourceHashes: JSON.parse(String(row.source_hashes_json)),
      sourceSetHash: row.source_set_hash,
      sessionCommitment: row.session_commitment,
      spendPreimage: JSON.parse(String(row.spend_preimage_json)),
      maxPriceAtomic: row.max_price_atomic,
      nonce: row.nonce,
      status: row.status,
      createdAt: row.created_at,
    }),
  );
}

function listArtifactPreflights(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM artifact_preflights
       WHERE session_id = ?
       ORDER BY created_at ASC, preflight_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    ArtifactPreflightViewSchema.parse({
      preflightId: row.preflight_id,
      sessionId: row.session_id,
      spendId: row.spend_id,
      artifactHashPreview: row.artifact_hash_preview,
      artifactCid: row.artifact_cid,
      endpointUrl: row.endpoint_url,
      priceDisclosureHash: row.price_disclosure_hash,
      sourceStateSnapshotHash: row.source_state_snapshot_hash,
      status: row.status,
      createdAt: row.created_at,
    }),
  );
}

function listQuotes(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM quotes
       WHERE session_id = ?
       ORDER BY created_at ASC, quote_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    QuoteViewSchema.parse({
      quoteId: row.quote_id,
      sessionId: row.session_id,
      spendId: row.spend_id,
      preflightId: row.preflight_id,
      artifactCommitment: row.artifact_commitment,
      artifactCid: row.artifact_cid,
      priceDisclosureHash: row.price_disclosure_hash,
      sourceStateSnapshotHash: row.source_state_snapshot_hash,
      priceAtomic: row.price_atomic,
      quoteNonce: row.quote_nonce,
      validUntilBlock: row.valid_until_block,
      quoteHash: row.quote_hash,
      status: row.status,
      createdAt: row.created_at,
    }),
  );
}

function listArtifactAccessTokens(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM artifact_access_tokens
       WHERE session_id = ?
       ORDER BY created_at ASC, token_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    ArtifactAccessTokenViewSchema.parse({
      tokenId: row.token_id,
      sessionId: row.session_id,
      spendId: row.spend_id,
      payer: row.payer,
      quoteId: row.quote_id,
      preflightId: row.preflight_id,
      artifactHash: row.artifact_hash,
      artifactCid: row.artifact_cid,
      artifactPayloadHash: row.artifact_payload_hash,
      artifactPayload: JSON.parse(String(row.artifact_payload_json)),
      tokenHash: row.token_hash,
      status: row.status,
      issuedByVerifierRunId: row.issued_by_verifier_run_id ?? null,
      settlementEventId: row.settlement_event_id ?? null,
      createdAt: row.created_at,
    }),
  );
}

function mcpAdapterCallFromRow(row: Row) {
  return McpAdapterCallViewSchema.parse({
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
  });
}

function listMcpAdapterCalls(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM mcp_adapter_calls
       WHERE session_id = ?
       ORDER BY created_at ASC,
         CASE tool_name
           WHEN 'tools/list' THEN 1
           WHEN 'tools/call' THEN 2
           ELSE 3
         END,
         call_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map(mcpAdapterCallFromRow);
}

function mcpCallByAuditNonce(ctx: ServiceCtx, auditNonce: string): ReturnType<typeof listMcpAdapterCalls>[number] | null {
  const row = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM mcp_adapter_calls
       WHERE audit_nonce = ?
       LIMIT 1`,
    )
    .get(auditNonce) as Row | undefined;
  if (!row) {
    return null;
  }
  return mcpAdapterCallFromRow(row);
}

function listCawReceiptOperations(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM caw_receipt_operations
       WHERE session_id = ?
       ORDER BY created_at ASC, operation_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    CawReceiptOperationViewSchema.parse({
      operationId: row.operation_id,
      sessionId: row.session_id,
      spendId: row.spend_id ?? null,
      operationKind: row.operation_kind,
      target: row.target ?? null,
      selector: row.selector ?? null,
      valueAtomic: row.value_atomic,
      request: JSON.parse(String(row.request_json)),
      receiptBundleHash: row.receipt_bundle_hash ?? null,
      status: row.status,
      createdAt: row.created_at,
    }),
  );
}

function listCawLiveInteractions(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM caw_live_interactions
       WHERE session_id = ?
       ORDER BY created_at ASC, interaction_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    CawLiveInteractionViewSchema.parse({
      interactionId: row.interaction_id,
      sessionId: row.session_id,
      kind: row.kind,
      walletId: row.wallet_id ?? null,
      pactId: row.pact_id ?? null,
      cawRequestId: row.caw_request_id ?? null,
      requestHash: row.request_hash,
      request: JSON.parse(String(row.request_json)),
      responseHash: row.response_hash,
      response: JSON.parse(String(row.response_json)),
      status: row.status,
      authKeyHash: row.auth_key_hash ?? null,
      proofAuthority: true,
      winnerClaimAllowed: false,
      createdAt: row.created_at,
    }),
  );
}

function listRawCawReceiptBundles(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM caw_raw_receipt_bundles
       WHERE session_id = ?
       ORDER BY created_at ASC, bundle_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    RawCawReceiptBundleViewSchema.parse({
      bundleId: row.bundle_id,
      sessionId: row.session_id,
      operationId: row.operation_id,
      sourceLabel: row.source_label,
      fetchedAt: row.fetched_at,
      rawBundleHash: row.raw_bundle_hash,
      rawBundle: JSON.parse(String(row.raw_bundle_json)),
      receiptCount: row.receipt_count,
      createdAt: row.created_at,
    }),
  );
}

function listCanonicalCawReceipts(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM caw_canonical_receipts
       WHERE session_id = ?
       ORDER BY created_at ASC, raw_receipt_hash ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    CanonicalCawReceiptViewSchema.parse({
      rawReceiptHash: row.raw_receipt_hash,
      canonicalReceiptHash: row.canonical_receipt_hash,
      bundleId: row.bundle_id,
      sessionId: row.session_id,
      operationId: row.operation_id,
      operationKind: row.operation_kind,
      sourceLabel: row.source_label,
      walletAddress: row.wallet_address,
      target: row.target ?? null,
      selector: row.selector ?? null,
      requestId: row.request_id,
      effect: row.effect,
      status: row.status,
      policyDigest: row.policy_digest,
      paramsDigest: row.params_digest,
      txHash: row.tx_hash ?? null,
      txCount: row.tx_count,
      expiry: row.expiry,
      fetchedAt: row.fetched_at,
      createdAt: row.created_at,
    }),
  );
}

function listLeaseRuns(ctx: ServiceCtx, sessionId: string, limit: number, offset = 0) {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT *
       FROM lease_runs
       WHERE session_id = ?
       ORDER BY created_at DESC, lease_run_id ASC
       LIMIT ? OFFSET ?`,
    )
    .all(sessionId, limit, offset) as Row[];
  return rows.map((row) =>
    LeaseRunViewSchema.parse({
      leaseRunId: row.lease_run_id,
      sessionId: row.session_id,
      spendId: row.spend_id,
      payer: row.payer ?? null,
      artifactHash: row.artifact_hash ?? null,
      targetRepo: row.target_repo,
      targetCommit: row.target_commit,
      status: row.status,
      transcriptHash: row.transcript_hash ?? null,
      toolsListHash: row.tools_list_hash ?? null,
      toolsCallHash: row.tools_call_hash ?? null,
      outputHash: row.output_hash ?? null,
      leaseRunHash: row.lease_run_hash ?? null,
      settlementEventId: row.settlement_event_id ?? null,
      artifactTokenId: row.artifact_token_id ?? null,
      createdAt: row.created_at,
      completedAt: row.completed_at ?? null,
    }),
  );
}

function verifyReplaySummaryCapIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  replayPageIndexFor(ctx, sessionId);
  return [];
}

function assertReplaySummaryRoomForArtifactIssue(ctx: ServiceCtx, sessionId: string, requestId: string): void {
  void ctx;
  void sessionId;
  void requestId;
}

function assertReplaySummaryWithinCap(ctx: ServiceCtx, sessionId: string, requestId: string): void {
  replayPageIndexFor(ctx, sessionId);
  void requestId;
}

function assertArtifactPayloadReplaySize(artifactPayloadJson: string, requestId: string): void {
  const payloadBytes = Buffer.byteLength(artifactPayloadJson, "utf8");
  if (payloadBytes > ARTIFACT_PAYLOAD_REPLAY_MAX_BYTES) {
    throw Object.assign(new Error("artifact payload exceeds replay-safe size"), {
      apiError: proofBlockedError(requestId, "artifact payload exceeds replay-safe size", {
        payloadBytes,
        maxPayloadBytes: ARTIFACT_PAYLOAD_REPLAY_MAX_BYTES,
      }),
    });
  }
}

function replaySummaryCounts(ctx: ServiceCtx, sessionId: string): Record<string, number> {
  return {
    "replayBundle.events": countRows(ctx, "evidence_events", "session_id = ?", [sessionId]),
    "replayBundle.sources": countRows(ctx, "sources", "session_id = ?", [sessionId]),
    "replayBundle.spends": countRows(ctx, "spends", "session_id = ?", [sessionId]),
    "replayBundle.artifactPreflights": countRows(ctx, "artifact_preflights", "session_id = ?", [sessionId]),
    "replayBundle.quotes": countRows(ctx, "quotes", "session_id = ?", [sessionId]),
    "replayBundle.artifactAccessTokens": countRows(ctx, "artifact_access_tokens", "session_id = ?", [sessionId]),
    "replayBundle.mcpAdapterCalls": countRows(ctx, "mcp_adapter_calls", "session_id = ?", [sessionId]),
    "replayBundle.cawReceiptOperations": countRows(ctx, "caw_receipt_operations", "session_id = ?", [sessionId]),
    "replayBundle.cawLiveInteractions": countRows(ctx, "caw_live_interactions", "session_id = ?", [sessionId]),
    "replayBundle.rawCawReceiptBundles": countRows(ctx, "caw_raw_receipt_bundles", "session_id = ?", [sessionId]),
    "replayBundle.canonicalCawReceipts": countRows(ctx, "caw_canonical_receipts", "session_id = ?", [sessionId]),
    "replayBundle.leaseRuns": countRows(ctx, "lease_runs", "session_id = ?", [sessionId]),
  };
}

function countRows(ctx: ServiceCtx, table: string, where: string, values: string[]): number {
  const row = ctx.db.sqlite.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${where}`).get(...values) as Row;
  return Number(row.count ?? 0);
}

function verifyEventLogIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const events = listEvents(ctx, sessionId, 0, REPLAY_SUMMARY_LIMIT);
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

function verifySpendBindingIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const errors: string[] = [];
  const session = ctx.db.sqlite.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId) as Row | undefined;
  if (!session) {
    return ["session row is missing during spend binding verification"];
  }
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT spend_id, pact_id, tool_id, payer, agent_wallet, payment_token, artifact_hash, market,
              source_hashes_json, source_set_hash, session_commitment, spend_preimage_json, max_price_atomic, nonce
       FROM spends
       WHERE session_id = ?
       ORDER BY created_at ASC, spend_id ASC`,
    )
    .all(sessionId) as Row[];
  for (const row of rows) {
    const sourceHashes = JSON.parse(String(row.source_hashes_json)) as string[];
    const sourceCapabilitySnapshot = sourceCapabilitySnapshotFor(ctx, sessionId, sourceHashes);
    const binding = spendBindingFor(session, sessionId, {
      pactId: String(row.pact_id),
      toolId: String(row.tool_id),
      sourceHashes,
      sourceCapabilitySnapshotHash: sourceCapabilitySnapshot.hash,
      payer: String(row.payer),
      agentWallet: String(row.agent_wallet),
      paymentToken: String(row.payment_token),
      artifactHash: String(row.artifact_hash),
      market: String(row.market),
      maxPriceAtomic: String(row.max_price_atomic),
      nonce: String(row.nonce),
    });
    const checks = [
      ["spend_id", binding.spendId],
      ["source_set_hash", binding.sourceSetHash],
      ["session_commitment", binding.sessionCommitment],
      ["spend_preimage_json", canonicalizeJson(binding.spendPreimage)],
    ] as const;
    for (const [field, expected] of checks) {
      if (String(row[field]) !== expected) {
        errors.push(`spend ${row.spend_id} ${field} does not match recomputed source/capability binding`);
      }
    }
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

function verifyCawLiveInteractionIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const errors: string[] = [];
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT interaction_id, kind, wallet_id, pact_id, caw_request_id, request_hash, request_json,
              response_hash, response_json, status, auth_key_hash
       FROM caw_live_interactions
       WHERE session_id = ?
       ORDER BY created_at ASC, interaction_id ASC`,
    )
    .all(sessionId) as Row[];
  const events = listEvents(ctx, sessionId, 0, 200).filter((event) => event.kind.startsWith("caw.live."));
  const eventsByInteractionId = new Map(
    events
      .map((event) => {
        const interactionId = typeof event.payload.interactionId === "string" ? event.payload.interactionId : null;
        return interactionId ? [interactionId, event] : null;
      })
      .filter((entry): entry is [string, EvidenceEvent] => Boolean(entry)),
  );
  const activePacts = new Set<string>();
  for (const row of rows) {
    if (row.kind === "pact_sync" && row.status === "live_active" && row.wallet_id && row.pact_id && row.auth_key_hash) {
      activePacts.add(`${String(row.wallet_id)}:${String(row.pact_id)}:${String(row.auth_key_hash).toLowerCase()}`);
    }
  }
  for (const row of rows) {
    const interactionId = String(row.interaction_id);
    let request: Record<string, JsonValue> | null = null;
    let response: Record<string, JsonValue> | null = null;
    try {
      request = JSON.parse(String(row.request_json)) as Record<string, JsonValue>;
    } catch {
      errors.push(`CAW live interaction ${interactionId} has invalid request_json`);
    }
    try {
      response = JSON.parse(String(row.response_json)) as Record<string, JsonValue>;
    } catch {
      errors.push(`CAW live interaction ${interactionId} has invalid response_json`);
    }
    if (request && hashJson(request) !== String(row.request_hash).toLowerCase()) {
      errors.push(`CAW live interaction ${interactionId} requestHash does not match request_json`);
    }
    if (response && hashJson(response) !== String(row.response_hash).toLowerCase()) {
      errors.push(`CAW live interaction ${interactionId} responseHash does not match response_json`);
    }
    const event = eventsByInteractionId.get(interactionId);
    if (!event) {
      errors.push(`CAW live interaction ${interactionId} has no matching evidence event`);
      continue;
    }
    const expectedKind =
      row.kind === "pact_submit"
        ? "caw.live.pact.submitted"
        : row.kind === "pact_sync"
          ? "caw.live.pact.synced"
          : row.kind === "transfer_submit"
            ? "caw.live.transfer.submitted"
            : "caw.live.audit.synced";
    if (event.kind !== expectedKind) {
      errors.push(`CAW live interaction ${interactionId} event kind does not match row kind`);
    }
    for (const [field, expected] of [
      ["walletId", row.wallet_id ?? null],
      ["pactId", row.pact_id ?? null],
      ["requestHash", row.request_hash],
      ["responseHash", row.response_hash],
      ["status", row.status],
    ] as const) {
      if ((event.payload[field] ?? null) !== expected) {
        errors.push(`CAW live event ${event.eventId} payload.${field} does not match interaction row`);
      }
    }
    if (event.authority !== "proof" || event.payload.proofAuthority !== true || event.payload.winnerClaimAllowed !== false) {
      errors.push(`CAW live event ${event.eventId} does not carry fail-closed proof payload`);
    }
    if (row.kind !== "transfer_submit" || !request) {
      continue;
    }
    const spendId = typeof request.spend_id === "string" ? request.spend_id : null;
    if (!spendId) {
      errors.push(`CAW live transfer ${interactionId} is missing spend_id`);
      continue;
    }
    const spend = ctx.db.sqlite
      .prepare(
        `SELECT spend_id, payer, payment_token, market, max_price_atomic
         FROM spends
         WHERE session_id = ? AND spend_id = ?`,
      )
      .get(sessionId, spendId) as Row | undefined;
    if (!spend) {
      errors.push(`CAW live transfer ${interactionId} references missing registered spend`);
      continue;
    }
    const checks = [
      ["payment_token", String(spend.payment_token).toLowerCase()],
      ["dst_addr", String(spend.market).toLowerCase()],
      ["amount", BigInt(String(spend.max_price_atomic)).toString()],
    ] as const;
    for (const [field, expected] of checks) {
      const actual = field === "amount" ? safeDecimalString(request[field]) : String(request[field] ?? "").toLowerCase();
      if (actual !== expected) {
        errors.push(`CAW live transfer ${interactionId} request.${field} does not match registered spend`);
      }
    }
    if (typeof request.token_id === "string" && request.token_id.toLowerCase() !== String(spend.payment_token).toLowerCase()) {
      errors.push(`CAW live transfer ${interactionId} request.token_id does not match registered spend payment token`);
    }
    if (typeof request.src_addr === "string" && request.src_addr.toLowerCase() !== String(spend.payer).toLowerCase()) {
      errors.push(`CAW live transfer ${interactionId} request.src_addr does not match registered spend payer`);
    }
    if (!activePacts.has(`${String(row.wallet_id)}:${String(row.pact_id)}:${String(row.auth_key_hash).toLowerCase()}`)) {
      errors.push(`CAW live transfer ${interactionId} is not bound to an active synced CAW Pact and key hash`);
    }
    for (const [field, expected] of [
      ["spendId", spendId],
      ["paymentToken", String(spend.payment_token).toLowerCase()],
      ["amount", BigInt(String(spend.max_price_atomic)).toString()],
      ["destinationAddress", String(spend.market)],
    ] as const) {
      if (String(event.payload[field] ?? "").toLowerCase() !== String(expected).toLowerCase()) {
        errors.push(`CAW live event ${event.eventId} payload.${field} does not match registered spend transfer`);
      }
    }
  }
  return errors;
}

function safeDecimalString(value: unknown): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    return "";
  }
  return BigInt(value).toString();
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
    const indexedLogId = typeof payload.indexedLogId === "string" ? payload.indexedLogId : null;
    if (!indexedLogId) {
      errors.push(`gate proof event ${event.eventId} is missing indexedLogId`);
    } else {
      const indexedLog = ctx.db.sqlite
        .prepare(
          `SELECT log_id, cursor_id, chain_id, tx_hash, log_index, block_number, raw_log_hash
           FROM chain_indexed_logs
           WHERE log_id = ?`,
        )
        .get(indexedLogId) as Row | undefined;
      if (!indexedLog) {
        errors.push(`gate proof event ${event.eventId} references missing indexed log ${indexedLogId}`);
      } else {
        const indexedChecks = [
          ["cursorId", indexedLog.cursor_id],
          ["chainId", indexedLog.chain_id],
          ["txHash", indexedLog.tx_hash],
          ["indexedRawLogHash", indexedLog.raw_log_hash],
        ] as const;
        for (const [field, expected] of indexedChecks) {
          if (payload[field] !== expected) {
            errors.push(`gate proof event ${event.eventId} payload.${field} does not match indexed log`);
          }
        }
        if (Number(payload.logIndex) !== Number(indexedLog.log_index) || Number(payload.blockNumber) !== Number(indexedLog.block_number)) {
          errors.push(`gate proof event ${event.eventId} log position does not match indexed log`);
        }
      }
    }
  }
  return errors;
}

function verifyArtifactAccessTokenIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const errors: string[] = [];
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT token_id, spend_id, payer, artifact_hash, token_hash, status, issued_by_verifier_run_id, settlement_event_id
              , quote_id, preflight_id, artifact_cid, artifact_payload_hash, artifact_payload_json
       FROM artifact_access_tokens
       WHERE session_id = ? AND status IN ('active', 'consuming', 'consumed')
       ORDER BY created_at ASC`,
    )
    .all(sessionId) as Row[];
  const issuedEvents = listEvents(ctx, sessionId, 0, 200).filter((event) => event.kind === "artifact.access_token.issued");
  const issuedByTokenId = new Map(
    issuedEvents
      .map((event) => {
        const tokenId = typeof event.payload.tokenId === "string" ? event.payload.tokenId : null;
        return tokenId ? [tokenId, event] : null;
      })
      .filter((entry): entry is [string, EvidenceEvent] => Boolean(entry)),
  );
  for (const row of rows) {
    const tokenId = String(row.token_id);
    const tokenStatus = String(row.status);
    const rowArtifactHash = String(row.artifact_hash).toLowerCase();
    const rowArtifactCid = String(row.artifact_cid).toLowerCase();
    const rowArtifactPayloadHash = String(row.artifact_payload_hash).toLowerCase();
    const verifierRunId = typeof row.issued_by_verifier_run_id === "string" ? row.issued_by_verifier_run_id : null;
    const settlementEventId = typeof row.settlement_event_id === "string" ? row.settlement_event_id : null;
    if (tokenStatus === "consuming") {
      errors.push(`artifact token ${tokenId} is stuck in consuming state without completed lease evidence`);
    }
    if (tokenStatus === "consumed") {
      const lease = ctx.db.sqlite
        .prepare(
          `SELECT lease_run_id
           FROM lease_runs
           WHERE session_id = ? AND artifact_token_id = ? AND status = 'succeeded_live_mcp_transcript'
           LIMIT 1`,
        )
        .get(sessionId, tokenId) as Row | undefined;
      if (!lease) {
        errors.push(`consumed artifact token ${tokenId} has no successful lease run`);
      }
    }
    if (tokenStatus === "blocked") {
      const lease = ctx.db.sqlite
        .prepare(
          `SELECT lease_run_id
           FROM lease_runs
           WHERE session_id = ? AND artifact_token_id = ? AND status IN ('blocked_missing_runner_execution', 'blocked_mcp_execution_failed')
           LIMIT 1`,
        )
        .get(sessionId, tokenId) as Row | undefined;
      if (!lease) {
        errors.push(`blocked artifact token ${tokenId} has no blocked lease run`);
      }
    }
    if (!verifierRunId) {
      errors.push(`artifact token ${tokenId} is missing issued_by_verifier_run_id`);
      continue;
    }
    if (!settlementEventId) {
      errors.push(`artifact token ${tokenId} is missing settlement_event_id`);
      continue;
    }
    const verifierRun = ctx.db.sqlite
      .prepare("SELECT schema_ok FROM verifier_runs WHERE session_id = ? AND verifier_run_id = ?")
      .get(sessionId, verifierRunId) as Row | undefined;
    if (!verifierRun || Number(verifierRun.schema_ok) !== 1) {
      errors.push(`artifact token ${tokenId} references missing or failed verifier run`);
    }
    let artifactPayloadHash: string | null = null;
    try {
      artifactPayloadHash = hashJson(JSON.parse(String(row.artifact_payload_json)));
    } catch {
      errors.push(`artifact token ${tokenId} has invalid artifact_payload_json`);
    }
    if (artifactPayloadHash && (artifactPayloadHash !== rowArtifactPayloadHash || artifactPayloadHash !== rowArtifactHash)) {
      errors.push(`artifact token ${tokenId} artifact payload hash does not match artifactHash`);
    }
    const expectedCid = `sha256:${rowArtifactHash}`;
    if (rowArtifactCid !== expectedCid) {
      errors.push(`artifact token ${tokenId} artifact_cid does not match artifactHash`);
    }
    const quote = ctx.db.sqlite
      .prepare(
        `SELECT quote_id, preflight_id, artifact_commitment, artifact_cid
         FROM quotes
         WHERE session_id = ? AND spend_id = ? AND quote_id = ?`,
      )
      .get(sessionId, String(row.spend_id), String(row.quote_id)) as Row | undefined;
    if (
      !quote ||
      String(quote.artifact_commitment).toLowerCase() !== rowArtifactHash ||
      String(quote.preflight_id) !== row.preflight_id ||
      String(quote.artifact_cid).toLowerCase() !== rowArtifactCid
    ) {
      errors.push(`artifact token ${tokenId} is not bound to its quote artifact commitment`);
    }
    const settlement = ctx.db.sqlite
      .prepare(
        `SELECT spend_id, event_kind, status, finalized_event_id
         FROM gate_chain_events
         WHERE session_id = ? AND finalized_event_id = ?`,
      )
      .get(sessionId, settlementEventId) as Row | undefined;
    if (
      !settlement ||
      settlement.spend_id !== row.spend_id ||
      settlement.event_kind !== "SpendSettled" ||
      settlement.status !== "finalized"
    ) {
      errors.push(`artifact token ${tokenId} is not bound to a finalized SpendSettled event`);
    }
    const event = issuedByTokenId.get(tokenId);
    if (!event) {
      errors.push(`artifact token ${tokenId} has no artifact.access_token.issued evidence event`);
      continue;
    }
    const expectedFields = [
      ["spendId", row.spend_id],
      ["payer", row.payer],
      ["quoteId", row.quote_id],
      ["preflightId", row.preflight_id],
      ["artifactHash", row.artifact_hash],
      ["artifactCid", row.artifact_cid],
      ["artifactPayloadHash", row.artifact_payload_hash],
      ["tokenHash", row.token_hash],
      ["verifierRunId", verifierRunId],
      ["settlementEventId", settlementEventId],
      ["status", "active_demo_verifier_gated"],
    ] as const;
    for (const [field, expected] of expectedFields) {
      if (event.payload[field] !== expected) {
        errors.push(`artifact access token event ${event.eventId} payload.${field} does not match active token row`);
      }
    }
    if (event.authority !== "delivery" || event.payload.proofAuthority !== false || event.payload.winnerClaimAllowed !== false) {
      errors.push(`artifact access token event ${event.eventId} does not carry delivery-only fail-closed payload`);
    }
  }
  return errors;
}

function verifyLeaseRunIntegrity(ctx: ServiceCtx, sessionId: string): string[] {
  const errors: string[] = [];
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT lease_run_id, spend_id, payer, artifact_hash, target_repo, target_commit, status, transcript_hash,
              tools_list_hash, tools_call_hash, output_hash, lease_run_hash, settlement_event_id, artifact_token_id
       FROM lease_runs
       WHERE session_id = ?
       ORDER BY created_at ASC`,
    )
    .all(sessionId) as Row[];
  const events = listEvents(ctx, sessionId, 0, 200);
  for (const row of rows) {
    const leaseRunId = String(row.lease_run_id);
    if (row.status !== "succeeded_live_mcp_transcript") {
      const blockedEvent = events.find(
        (event) => event.kind === "lease.execution.blocked" && event.payload.leaseRunId === leaseRunId,
      );
      if (!blockedEvent) {
        errors.push(`blocked lease run ${leaseRunId} has no lease.execution.blocked evidence event`);
      }
      continue;
    }
    const required = [
      "payer",
      "artifact_hash",
      "transcript_hash",
      "tools_list_hash",
      "tools_call_hash",
      "output_hash",
      "lease_run_hash",
      "settlement_event_id",
      "artifact_token_id",
    ] as const;
    for (const field of required) {
      if (typeof row[field] !== "string") {
        errors.push(`succeeded lease run ${leaseRunId} is missing ${field}`);
      }
    }
    if (required.some((field) => typeof row[field] !== "string")) {
      continue;
    }
    const listCall = mcpCallByAuditNonce(ctx, `lease_${leaseRunId.slice(2, 22)}_tools_list`);
    const toolCall = mcpCallByAuditNonce(ctx, `lease_${leaseRunId.slice(2, 22)}_tools_call`);
    if (!listCall || !toolCall) {
      errors.push(`succeeded lease run ${leaseRunId} is missing MCP transcript frames`);
      continue;
    }
    const expectedToolsListHash = hashJson({ requestHash: listCall.requestHash, responseHash: listCall.responseHash });
    const expectedToolsCallHash = hashJson({ requestHash: toolCall.requestHash, responseHash: toolCall.responseHash });
    const expectedOutputHash = hashJson(toolCall.response);
    const expectedTranscriptHash = hashJson({
      format: "mcp-json-rpc",
      sessionId,
      leaseRunId,
      frameCallIds: [listCall.callId, toolCall.callId],
      frames: [
        { method: "tools/list", requestHash: listCall.requestHash, responseHash: listCall.responseHash },
        { method: "tools/call", requestHash: toolCall.requestHash, responseHash: toolCall.responseHash },
      ],
    });
    const expectedLeaseRunHash = hashJson({
      sessionId,
      leaseRunId,
      spendId: row.spend_id,
      payer: row.payer,
      artifactHash: row.artifact_hash,
      targetRepo: row.target_repo,
      targetCommit: row.target_commit,
      settlementEventId: row.settlement_event_id,
      artifactTokenId: row.artifact_token_id,
      transcriptHash: expectedTranscriptHash,
      outputHash: expectedOutputHash,
    });
    const checks = [
      ["tools_list_hash", expectedToolsListHash],
      ["tools_call_hash", expectedToolsCallHash],
      ["output_hash", expectedOutputHash],
      ["transcript_hash", expectedTranscriptHash],
      ["lease_run_hash", expectedLeaseRunHash],
    ] as const;
    for (const [field, expected] of checks) {
      if (row[field] !== expected) {
        errors.push(`succeeded lease run ${leaseRunId} ${field} does not match recomputed transcript data`);
      }
    }
    const event = events.find((candidate) => candidate.kind === "lease.execution.succeeded" && candidate.payload.leaseRunId === leaseRunId);
    if (!event) {
      errors.push(`succeeded lease run ${leaseRunId} has no lease.execution.succeeded evidence event`);
      continue;
    }
    const eventFields = [
      ["spendId", row.spend_id],
      ["payer", row.payer],
      ["artifactHash", row.artifact_hash],
      ["targetRepo", row.target_repo],
      ["targetCommit", row.target_commit],
      ["settlementEventId", row.settlement_event_id],
      ["artifactTokenId", row.artifact_token_id],
      ["transcriptHash", row.transcript_hash],
      ["toolsListHash", row.tools_list_hash],
      ["toolsCallHash", row.tools_call_hash],
      ["outputHash", row.output_hash],
      ["leaseRunHash", row.lease_run_hash],
      ["status", "succeeded_live_mcp_transcript"],
    ] as const;
    for (const [field, expected] of eventFields) {
      if (event.payload[field] !== expected) {
        errors.push(`lease execution event ${event.eventId} payload.${field} does not match lease run row`);
      }
    }
    if (event.authority !== "delivery" || event.payload.proofAuthority !== false || event.payload.winnerClaimAllowed !== false) {
      errors.push(`lease execution event ${event.eventId} does not carry delivery-only fail-closed payload`);
    }
  }
  return errors;
}

async function verifyIndexerCursorIntegrity(ctx: ServiceCtx, proofProviders: ProofProviderStatus[]): Promise<string[]> {
  const rows = ctx.db.sqlite
    .prepare(
      `SELECT cursor_id, chain_id, address, topics_json, last_indexed_block, finalized_head_block, finality_depth, lag_blocks, status, reason
       FROM chain_indexer_cursors
       ORDER BY cursor_id ASC`,
    )
    .all() as Row[];
  const errors: string[] = [];
  const chainProvider = proofProviders.find((provider) => provider.name === "chain");
  let providerHead: number | null = null;
  if (chainProvider?.ready) {
    try {
      providerHead = await ctx.chain.getBlockNumber();
    } catch (error) {
      errors.push(`chain indexer provider head check failed; proof path is fail-closed: ${chainFailureMessage("failed to read chain head", error)}`);
    }
  }
  const rowsByCursorId = new Map(rows.map((row) => [String(row.cursor_id), row]));
  for (const required of ctx.requiredIndexerCursors) {
    const row = rowsByCursorId.get(required.cursorId);
    if (!row) {
      errors.push(`required chain indexer cursor ${required.cursorId} is missing; proof path is fail-closed`);
      continue;
    }
    const requiredAddress = required.address ?? null;
    const requiredTopics = canonicalIndexerTopicsJson(required.topics ?? []);
    const requiredFinalityDepth = required.finalityDepth ?? 2;
    const cursorAddress = typeof row.address === "string" ? String(row.address).toLowerCase() : null;
    const expectedAddress = typeof requiredAddress === "string" ? requiredAddress.toLowerCase() : null;
    if (String(row.chain_id) !== required.chainId) {
      errors.push(
        `required chain indexer cursor ${required.cursorId} is for chain ${row.chain_id} but required chain is ${required.chainId}; proof path is fail-closed`,
      );
    }
    if (cursorAddress !== expectedAddress) {
      errors.push(
        `required chain indexer cursor ${required.cursorId} address mismatch; expected ${expectedAddress ?? "null"}, got ${cursorAddress ?? "null"}; proof path is fail-closed`,
      );
    }
    if (String(row.topics_json) !== requiredTopics) {
      errors.push(`required chain indexer cursor ${required.cursorId} topics mismatch; proof path is fail-closed`);
    }
    if (Number(row.finality_depth) !== requiredFinalityDepth) {
      errors.push(
        `required chain indexer cursor ${required.cursorId} finalityDepth mismatch; expected ${requiredFinalityDepth}, got ${Number(row.finality_depth)}; proof path is fail-closed`,
      );
    }
  }
  for (const row of rows) {
    if (chainProvider?.ready && chainProvider.chainId && String(row.chain_id) !== chainProvider.chainId) {
      errors.push(
        `chain indexer cursor ${row.cursor_id} is for chain ${row.chain_id} but provider is on chain ${chainProvider.chainId}; proof path is fail-closed`,
      );
    }
    if (providerHead !== null) {
      const finalizedHeadBlock = Math.max(0, providerHead - Number(row.finality_depth) + 1);
      const lastIndexedBlock = row.last_indexed_block === null ? null : Number(row.last_indexed_block);
      if (lastIndexedBlock !== null && lastIndexedBlock > finalizedHeadBlock) {
        errors.push(
          `chain indexer cursor ${row.cursor_id} is ahead of provider finalized head ${finalizedHeadBlock}; proof path is fail-closed`,
        );
      }
    }
    const lagBlocks = Number(row.lag_blocks);
    if (row.status !== "caught_up" || lagBlocks > 0) {
      errors.push(
        `chain indexer cursor ${row.cursor_id} is ${row.status} with lagBlocks=${lagBlocks}; proof path is fail-closed: ${row.reason}`,
      );
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
  const asOfCount =
    typeof bundle.asOfMcpAdapterCallCount === "number" && Number.isInteger(bundle.asOfMcpAdapterCallCount)
      ? Math.max(0, Math.min(bundle.asOfMcpAdapterCallCount, REPLAY_SUMMARY_LIMIT))
      : REPLAY_SUMMARY_LIMIT;
  const asOfEventSeq =
    typeof bundle.asOfEventSeq === "number" && Number.isInteger(bundle.asOfEventSeq)
      ? Math.max(0, Math.min(bundle.asOfEventSeq, REPLAY_SUMMARY_LIMIT))
      : REPLAY_SUMMARY_LIMIT;
  const expectedEvents = listEvents(ctx, sessionId, 0, REPLAY_SUMMARY_LIMIT).filter((event) => event.eventSeq <= asOfEventSeq);
  const expectedEventRoot = hashJson(expectedEvents.map((event) => event.eventHash));
  if (bundle.eventRoot !== expectedEventRoot) {
    errors.push("replayBundle.eventRoot does not match the server event snapshot");
  }
  if (bundle.agentTranscriptHash !== hashJson(buildAgentTranscriptData(sessionId, ctx, asOfCount))) {
    errors.push("replayBundle.agentTranscriptHash does not match the server transcript snapshot");
  }
  compareReplaySnapshot(errors, "replayBundle.events", bundle.events, expectedEvents);
  compareReplaySnapshot(errors, "replayBundle.sources", bundle.sources, listSources(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.spends", bundle.spends, listSpends(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.artifactPreflights", bundle.artifactPreflights, listArtifactPreflights(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.quotes", bundle.quotes, listQuotes(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.artifactAccessTokens", bundle.artifactAccessTokens, listArtifactAccessTokens(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.mcpAdapterCalls", bundle.mcpAdapterCalls, listMcpAdapterCalls(ctx, sessionId, asOfCount));
  compareReplaySnapshot(errors, "replayBundle.cawReceiptOperations", bundle.cawReceiptOperations, listCawReceiptOperations(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.cawLiveInteractions", bundle.cawLiveInteractions, listCawLiveInteractions(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.rawCawReceiptBundles", bundle.rawCawReceiptBundles, listRawCawReceiptBundles(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.canonicalCawReceipts", bundle.canonicalCawReceipts, listCanonicalCawReceipts(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.leaseRuns", bundle.leaseRuns, listLeaseRuns(ctx, sessionId, REPLAY_SUMMARY_LIMIT));
  compareReplaySnapshot(errors, "replayBundle.judgeCheck", bundle.judgeCheck, readJudgeCheckData(sessionId, ctx));
  compareReplaySnapshot(errors, "replayBundle.replayPageIndex", bundle.replayPageIndex, replayPageIndexFor(ctx, sessionId));
  return errors;
}

function compareReplaySnapshot(errors: string[], label: string, actual: unknown, expected: unknown): void {
  if (actual === undefined) {
    errors.push(`${label} is missing from the verifier replay bundle`);
    return;
  }
  if (hashJson(actual) !== hashJson(expected)) {
    errors.push(`${label} does not match the server snapshot`);
  }
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
