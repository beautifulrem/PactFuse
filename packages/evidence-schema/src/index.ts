import { z } from "zod";

export const LOCKED_RUNTIME_MODES = {
  CLAIM_MODE: "simulated",
  PAYMENT_MODE: "mocked",
  TOKEN_MODE: "local-mocked",
  IDENTITY_MODE: "pending",
  WINNER_CLAIM_ALLOWED: false,
} as const;

export const HexSchema = z.string().regex(/^0x[0-9a-fA-F]+$/);
export const Hex32Schema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
export const IdempotencyKeySchema = z.string().min(4).max(160).regex(/^[a-z][a-z0-9:_-]+$/);
export const DecimalStringSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);
export const IsoDateStringSchema = z.string().datetime({ offset: true });

export const JsonPrimitiveSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export type JsonPrimitive = z.infer<typeof JsonPrimitiveSchema>;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([JsonPrimitiveSchema, z.array(JsonValueSchema), z.record(z.string(), JsonValueSchema)]),
);
export const JsonObjectSchema = z.record(z.string(), JsonValueSchema);

export const RuntimeModesSchema = z
  .object({
    CLAIM_MODE: z.literal("simulated"),
    PAYMENT_MODE: z.literal("mocked"),
    TOKEN_MODE: z.literal("local-mocked"),
    IDENTITY_MODE: z.literal("pending"),
    WINNER_CLAIM_ALLOWED: z.literal(false),
  })
  .strict();

export const RunConfigSchema = z
  .object({
    label: z.string().min(1).max(120).optional(),
    targetRepo: z.string().min(1).max(400).optional(),
    targetCommit: z.string().min(6).max(128).optional(),
    authorizedQuoteSignerSetHash: Hex32Schema.optional(),
    finalityDepth: z.number().int().min(1).max(128).default(2),
    modes: RuntimeModesSchema.default(LOCKED_RUNTIME_MODES),
    metadata: JsonObjectSchema.default({}),
  })
  .strict();

export const ApiErrorCodeSchema = z.enum([
  "bad_request",
  "unauthorized",
  "forbidden",
  "not_found",
  "idempotency_conflict",
  "proof_pending",
  "proof_blocked",
  "verifier_failed_closed",
  "mode_locked",
  "rate_limited",
  "internal_error",
]);

export const ApiErrorSchema = z
  .object({
    code: ApiErrorCodeSchema,
    message: z.string(),
    requestId: z.string().min(1),
    retryable: z.boolean(),
    downgrade: z.enum(["pending", "blocked", "failed", "none"]),
    details: JsonObjectSchema.optional(),
  })
  .strict();

export type ApiError = z.infer<typeof ApiErrorSchema>;

export const CreateSessionInputSchema = z
  .object({
    idempotencyKey: IdempotencyKeySchema,
    payload: RunConfigSchema,
  })
  .strict();

export const SessionScopedEnvelopeSchema = z
  .object({
    sessionId: Hex32Schema,
    idempotencyKey: IdempotencyKeySchema,
    payload: JsonObjectSchema.default({}),
  })
  .strict();

export const SourceRegisterPayloadSchema = z
  .object({
    sourceId: z.string().min(1).max(120),
    sourceHash: Hex32Schema,
    manifestUrl: z.string().min(1).max(500),
    manifestHash: Hex32Schema,
    issuer: HexSchema.optional(),
    signature: HexSchema.optional(),
    capabilityVector: JsonObjectSchema.default({}),
  })
  .strict();

export const SourceChallengePayloadSchema = z
  .object({
    sourceHash: Hex32Schema,
    reasonHash: Hex32Schema,
    evidenceRef: z.string().min(1).max(500).optional(),
  })
  .strict();

export const SpendRegisterPayloadSchema = z
  .object({
    spends: z
      .array(
        z
          .object({
            spendId: Hex32Schema,
            pactId: z.string().min(1).max(120),
            toolId: z.string().min(1).max(120),
            payer: HexSchema,
            agentWallet: HexSchema,
            sourceHashes: z.array(Hex32Schema).min(1).max(16),
            maxPriceAtomic: DecimalStringSchema,
            nonce: z.string().min(1).max(128),
          })
          .strict(),
      )
      .min(1)
      .max(32),
  })
  .strict();

export const CawOperationBuildPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    operationKind: z.enum(["deny_probe", "approve", "activate_tool"]),
    target: HexSchema.optional(),
    selector: z.string().regex(/^0x[0-9a-fA-F]{8}$/).optional(),
    valueAtomic: DecimalStringSchema.default("0"),
  })
  .strict();

export const CawReceiptIngestPayloadSchema = z
  .object({
    sourceLabel: z.string().min(1).max(120),
    operationId: z.string().min(1).max(160).optional(),
    receipts: z.array(JsonObjectSchema).max(64).default([]),
    manual: z.boolean().default(false),
  })
  .strict()
  .refine((payload) => !payload.manual || payload.receipts.length > 0, {
    message: "manual CAW receipt ingest requires at least one receipt row",
    path: ["receipts"],
  });

export const ArtifactPreflightPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    artifactHashPreview: Hex32Schema,
    endpointUrl: z.string().min(1).max(500),
    priceDisclosureHash: Hex32Schema,
    sourceStateSnapshotHash: Hex32Schema,
  })
  .strict();

export const QuotePayloadSchema = z
  .object({
    spendId: Hex32Schema,
    preflightId: Hex32Schema,
    artifactCommitment: Hex32Schema,
    priceAtomic: DecimalStringSchema,
    quoteNonce: z.string().min(1).max(128),
    validUntilBlock: z.string().regex(/^[0-9]+$/),
  })
  .strict();

export const ArtifactRefundPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    quoteId: Hex32Schema,
    reason: z.string().min(1).max(240),
  })
  .strict();

export const LeaseExecutePayloadSchema = z
  .object({
    spendId: Hex32Schema,
    payer: HexSchema,
    artifactHash: Hex32Schema,
    targetRepo: z.string().min(1).max(500),
    targetCommit: z.string().min(6).max(128),
  })
  .strict();

export const LeaseExecuteEnvelopeSchema = SessionScopedEnvelopeSchema.extend({
  payload: LeaseExecutePayloadSchema,
}).strict();

export const GateEventIngestPayloadSchema = z
  .object({
    event: z.enum(["SpendTripped", "SpendSettled"]),
    spendId: Hex32Schema,
    txHash: Hex32Schema,
    logIndex: z.number().int().min(0).max(1_000_000),
    chainId: DecimalStringSchema,
    blockNumber: z.number().int().min(0),
    currentBlockNumber: z.number().int().min(0),
    rawLogHash: Hex32Schema,
    reorged: z.boolean().default(false),
  })
  .strict()
  .refine((payload) => payload.reorged || payload.currentBlockNumber >= payload.blockNumber, {
    message: "currentBlockNumber must be >= blockNumber unless the log is reorged",
    path: ["currentBlockNumber"],
  });

export const VerifyEvidencePayloadSchema = z
  .object({
    receipt: JsonObjectSchema.optional(),
    replayBundle: JsonObjectSchema.optional(),
    schemaOnly: z.boolean().default(false),
  })
  .strict();

export const McpAdapterAuditPayloadSchema = z
  .object({
    sessionId: Hex32Schema.optional(),
    auditNonce: z.string().min(12).max(160).regex(/^[a-zA-Z0-9:_-]+$/),
    toolName: z.string().min(1).max(160),
    request: JsonObjectSchema,
    response: JsonObjectSchema,
    status: z.enum(["succeeded", "failed", "blocked"]),
  })
  .strict();

export const EvidenceAuthoritySchema = z.enum(["proof", "delivery", "operator", "advisory"]);
export const EvidenceEventKindSchema = z.enum([
  "session.created",
  "source.registered",
  "source.challenge.pending",
  "spend.registered",
  "caw.operation.built",
  "caw.receipt.ingested.fixture",
  "caw.receipt.ingested.raw",
  "artifact.preflight.pending",
  "quote.signed.mocked",
  "artifact.refund.pending",
  "operator.key_used",
  "gate.spend_tripped.observed",
  "gate.spend_settled.observed",
  "gate.spend_tripped",
  "gate.spend_settled",
  "reorg.invalidated",
  "lease.execution.blocked",
  "verifier.fail_closed",
  "judge_check.pending",
  "runner.heartbeat",
  "mcp.adapter.call",
]);

export const EvidenceEventSchema = z
  .object({
    sessionId: Hex32Schema,
    eventId: Hex32Schema,
    eventSeq: z.number().int().min(1),
    eventHash: Hex32Schema,
    prevProofEventHash: Hex32Schema.nullable(),
    authority: EvidenceAuthoritySchema,
    kind: EvidenceEventKindSchema,
    payloadHash: Hex32Schema,
    payload: JsonObjectSchema,
    createdAt: IsoDateStringSchema,
  })
  .strict();

export type EvidenceEvent = z.infer<typeof EvidenceEventSchema>;

export const SessionCreatedSchema = z
  .object({
    sessionId: Hex32Schema,
    runConfigHash: Hex32Schema,
    modes: RuntimeModesSchema,
    winnerClaimAllowed: z.literal(false),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const SessionViewSchema = SessionCreatedSchema.extend({
  eventCount: z.number().int().min(0),
  latestEventSeq: z.number().int().min(0),
}).strict();

export const JudgeCheckRowIdSchema = z.enum([
  "caw_boundary",
  "source_challenge",
  "ab_trip",
  "c_settlement",
  "artifact_access",
  "lease_execution",
]);

export const JudgeCheckRowSchema = z
  .object({
    rowId: JudgeCheckRowIdSchema,
    label: z.string(),
    status: z.enum(["pending", "pass", "fail", "blocked", "fixture", "manual"]),
    authority: z.enum(["proof", "delivery", "operator", "advisory", "fixture"]),
    reason: z.string(),
    evidenceEventId: Hex32Schema.nullable(),
    evidenceUrl: z.string().nullable(),
  })
  .strict();

export const JudgeCheckViewSchema = z
  .object({
    sessionId: Hex32Schema,
    winnerClaimAllowed: z.literal(false),
    rows: z.array(JudgeCheckRowSchema).length(6),
  })
  .strict();

export const McpAdapterCallViewSchema = z
  .object({
    callId: Hex32Schema,
    sessionId: Hex32Schema.nullable(),
    auditNonce: z.string().min(12),
    toolName: z.string().min(1),
    requestHash: Hex32Schema,
    responseHash: Hex32Schema,
    request: JsonObjectSchema,
    response: JsonObjectSchema,
    status: z.enum(["succeeded", "failed", "blocked"]),
    createdAt: IsoDateStringSchema,
    proofAuthority: z.literal(false),
  })
  .strict();

export const CawReceiptOperationViewSchema = z
  .object({
    operationId: Hex32Schema,
    sessionId: Hex32Schema,
    spendId: Hex32Schema.nullable(),
    operationKind: z.enum(["deny_probe", "approve", "activate_tool"]),
    target: HexSchema.nullable(),
    selector: z.string().regex(/^0x[0-9a-fA-F]{8}$/).nullable(),
    valueAtomic: DecimalStringSchema,
    request: JsonObjectSchema,
    receiptBundleHash: Hex32Schema.nullable(),
    status: z.enum(["built_mocked", "fixture_manual_receipt", "raw_ingested_pending_proof"]),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const RawCawReceiptBundleViewSchema = z
  .object({
    bundleId: Hex32Schema,
    sessionId: Hex32Schema,
    operationId: Hex32Schema,
    sourceLabel: z.string().min(1).max(120),
    fetchedAt: IsoDateStringSchema,
    rawBundleHash: Hex32Schema,
    rawBundle: JsonObjectSchema,
    receiptCount: z.number().int().min(1).max(64),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const ReplayBundleViewSchema = z
  .object({
    bundleType: z.literal("PACTFUSE_EVIDENCE_V1"),
    sessionId: Hex32Schema,
    summaryMode: z.literal(true),
    asOfEventSeq: z.number().int().min(0).max(200),
    asOfMcpAdapterCallCount: z.number().int().min(0).max(200),
    winnerClaimAllowed: z.literal(false),
    eventRoot: Hex32Schema,
    agentTranscriptHash: Hex32Schema,
    events: z.array(EvidenceEventSchema).max(200),
    mcpAdapterCalls: z.array(McpAdapterCallViewSchema).max(200),
    cawReceiptOperations: z.array(CawReceiptOperationViewSchema).max(200),
    rawCawReceiptBundles: z.array(RawCawReceiptBundleViewSchema).max(200),
    judgeCheck: JudgeCheckViewSchema,
  })
  .strict();

export const RunnerHeartbeatViewSchema = z
  .object({
    sessionId: Hex32Schema,
    status: z.enum(["pending", "blocked", "idle"]),
    winnerClaimAllowed: z.literal(false),
    updatedAt: IsoDateStringSchema,
  })
  .strict();

export const AgentTranscriptCallSummarySchema = z
  .object({
    callId: Hex32Schema,
    auditNonce: z.string().min(12),
    toolName: z.string().min(1),
    requestHash: Hex32Schema,
    responseHash: Hex32Schema,
    status: z.enum(["succeeded", "failed", "blocked"]),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const AgentTranscriptViewSchema = z
  .object({
    sessionId: Hex32Schema,
    status: z.enum(["pending", "blocked", "summarized"]),
    format: z.literal("mcp-json-rpc"),
    toolsListHash: Hex32Schema.nullable(),
    toolsCallHash: Hex32Schema.nullable(),
    transcriptHash: Hex32Schema.nullable(),
    boundedToPinnedManifest: z.literal(false),
    callCount: z.number().int().min(0).max(200),
    calls: z.array(AgentTranscriptCallSummarySchema).max(200),
    winnerClaimAllowed: z.literal(false),
  })
  .strict();

export const VerifierRunViewSchema = z
  .object({
    sessionId: Hex32Schema.optional(),
    proofLevel: z.enum(["schema_only_no_claim", "fail_closed_no_claim"]),
    claimMode: RuntimeModesSchema.shape.CLAIM_MODE,
    paymentMode: RuntimeModesSchema.shape.PAYMENT_MODE,
    tokenMode: RuntimeModesSchema.shape.TOKEN_MODE,
    identityMode: RuntimeModesSchema.shape.IDENTITY_MODE,
    schemaOk: z.boolean(),
    proofChipAllowed: z.literal(false),
    winnerClaimAllowed: z.literal(false),
    requestedWinnerClaimAllowed: z.boolean().default(false),
    finalVerifierComplete: z.literal(false),
    errors: z.array(z.string()),
    warnings: z.array(z.string()),
    raw: JsonObjectSchema.optional(),
  })
  .strict();

export const ServiceOkSchema = <T extends z.ZodTypeAny>(data: T) =>
  z
    .object({
      ok: z.literal(true),
      requestId: z.string().min(1),
      data,
      evidenceEventId: Hex32Schema.optional(),
    })
    .strict();

export const ServiceErrorSchema = z
  .object({
    ok: z.literal(false),
    requestId: z.string().min(1),
    error: ApiErrorSchema,
  })
  .strict();

export function canonicalizeJson(value: unknown): string {
  return JSON.stringify(sortForJcs(value));
}

function sortForJcs(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS canonicalization rejects non-finite numbers");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sortForJcs(item));
  }
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child !== undefined) {
        sorted[key] = sortForJcs(child);
      }
    }
    return sorted;
  }
  throw new Error(`JCS canonicalization rejects ${typeof value}`);
}

export type CreateSessionInput = z.infer<typeof CreateSessionInputSchema>;
export type SessionScopedEnvelope = z.infer<typeof SessionScopedEnvelopeSchema>;
export type RunConfig = z.infer<typeof RunConfigSchema>;
export type SessionCreated = z.infer<typeof SessionCreatedSchema>;
export type SessionView = z.infer<typeof SessionViewSchema>;
export type JudgeCheckView = z.infer<typeof JudgeCheckViewSchema>;
export type VerifierRunView = z.infer<typeof VerifierRunViewSchema>;
export type ReplayBundleView = z.infer<typeof ReplayBundleViewSchema>;
