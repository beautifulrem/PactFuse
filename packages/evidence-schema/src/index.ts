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
export const AddressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
export const ArtifactCidSchema = z.string().regex(/^sha256:0x[0-9a-fA-F]{64}$/);
export const IdempotencyKeySchema = z.string().min(4).max(160).regex(/^[a-z][a-z0-9:_-]+$/);
export const DecimalStringSchema = z.string().regex(/^(0|[1-9][0-9]*)$/);
export const CawAmountStringSchema = z.string().regex(/^(0|[1-9][0-9]*)(\.[0-9]{1,18})?$/);
export const IsoDateStringSchema = z.string().datetime({ offset: true });

export const JsonPrimitiveSchema = z.union([z.string(), z.number(), z.boolean(), z.null()]);
export type JsonPrimitive = z.infer<typeof JsonPrimitiveSchema>;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([JsonPrimitiveSchema, z.array(JsonValueSchema), z.record(z.string(), JsonValueSchema)]),
);
export const JsonObjectSchema = z.record(z.string(), JsonValueSchema);

export const ClaimModeSchema = z.enum(["simulated", "caw-target-real", "caw-stable-params-real"]);
export const PaymentModeSchema = z.enum(["mocked", "gate-paid-artifact-real", "permit-payment-real"]);
export const TokenModeSchema = z.enum(["local-mocked", "mock-test-token", "official-testnet-usdc"]);
export const IdentityModeSchema = z.enum(["pending", "p0-floor-one-wallet", "p0-win-separate-identities"]);
export const QuoteStatusSchema = z.enum(["mocked_after_preflight_not_chain_settleable", "chain_settleable_after_preflight"]);

export const DeploymentRegistryEntrySchema = z
  .object({
    contractName: z.enum(["SourceStateRegistry", "ProcurementGate", "PaidArtifactMarket", "PaymentToken"]),
    chainId: z.string().min(1).max(80),
    address: AddressSchema,
    deploymentTxHash: Hex32Schema,
    explorerUrl: z.string().min(1).max(1000),
    codeHash: Hex32Schema,
    tokenMode: TokenModeSchema.optional(),
    symbol: z.string().min(1).max(40).optional(),
    decimals: z.number().int().min(0).max(255).optional(),
  })
  .strict();

export const DeploymentRegistrySchema = z
  .object({
    mode: z.enum(["pending", "live"]),
    chainId: z.string().min(1).max(80),
    officialUsdcProbe: z
      .object({
        status: z.enum(["not_attempted", "failed", "passed"]),
        reason: z.string().min(1).max(500),
      })
      .strict()
      .optional(),
    entries: z.array(DeploymentRegistryEntrySchema).max(64).default([]),
  })
  .strict();

export const RuntimeModesSchema = z
  .object({
    CLAIM_MODE: ClaimModeSchema,
    PAYMENT_MODE: PaymentModeSchema,
    TOKEN_MODE: TokenModeSchema,
    IDENTITY_MODE: IdentityModeSchema,
    WINNER_CLAIM_ALLOWED: z.boolean(),
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
            pactId: Hex32Schema,
            toolId: Hex32Schema,
            payer: AddressSchema,
            agentWallet: AddressSchema,
            paymentToken: AddressSchema,
            artifactHash: Hex32Schema,
            market: AddressSchema,
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
    target: AddressSchema.optional(),
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

export const CawLivePactSubmitPayloadSchema = z
  .object({
    walletId: z.string().min(1).max(160),
    intent: z.string().min(1).max(500),
    originalIntent: z.string().min(1).max(2000).optional(),
    name: z.string().min(1).max(160).optional(),
    recipeSlugs: z.array(z.string().min(1).max(120)).max(16).default([]),
    spec: JsonObjectSchema,
  })
  .strict();

export const CawLivePactSyncPayloadSchema = z
  .object({
    pactId: z.string().min(1).max(160),
  })
  .strict();

export const CawLiveIdentityProbePayloadSchema = z
  .object({
    walletId: z.string().min(1).max(160),
    expectedWalletAddress: AddressSchema.optional(),
    identityMode: IdentityModeSchema.default("p0-floor-one-wallet"),
  })
  .strict();

export const CawLiveTransferSubmitPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    pactId: z.string().min(1).max(160),
    walletId: z.string().min(1).max(160),
    destinationAddress: z.string().min(1).max(160),
    amount: CawAmountStringSchema,
    paymentToken: AddressSchema,
    tokenId: z.string().min(1).max(80).optional(),
    chainId: z.string().min(1).max(80).optional(),
    requestId: z.string().min(1).max(160).optional(),
    sourceAddress: z.string().min(1).max(160).optional(),
    sponsor: z.boolean().optional(),
    gasProvider: z.string().min(1).max(120).optional(),
    description: z.string().min(1).max(240).optional(),
    fee: JsonObjectSchema.nullable().optional(),
  })
  .strict();

export const CawLiveContractCallSubmitPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    operationKind: z.enum(["deny_probe", "approve", "activate_tool"]),
    pactId: z.string().min(1).max(160),
    walletId: z.string().min(1).max(160),
    chainId: z.string().min(1).max(80),
    contractAddress: AddressSchema,
    calldata: HexSchema,
    valueAtomic: DecimalStringSchema.default("0"),
    procurementGateAddress: AddressSchema.optional(),
    requestId: z.string().min(1).max(160).optional(),
    sponsor: z.boolean().optional(),
    gasProvider: z.string().min(1).max(120).optional(),
    description: z.string().min(1).max(240).optional(),
    fee: JsonObjectSchema.nullable().optional(),
  })
  .strict();

export const CawAllowanceVerifyPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    approveInteractionId: Hex32Schema.optional(),
  })
  .strict();

export const CawLiveAuditSyncPayloadSchema = z
  .object({
    walletId: z.string().min(1).max(160).optional(),
    principalId: z.string().min(1).max(160).optional(),
    action: z.string().min(1).max(160).optional(),
    result: z.enum(["allowed", "denied", "pending", "error"]).optional(),
    startTime: IsoDateStringSchema.optional(),
    endTime: IsoDateStringSchema.optional(),
    after: z.string().min(1).max(500).optional(),
    before: z.string().min(1).max(500).optional(),
    limit: z.number().int().min(1).max(200).default(50),
  })
  .strict()
  .refine((payload) => !payload.startTime || !payload.endTime || payload.endTime >= payload.startTime, {
    message: "endTime must be >= startTime",
    path: ["endTime"],
  });

export const ArtifactPreflightPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    artifactHashPreview: Hex32Schema,
    artifactCid: ArtifactCidSchema,
    endpointUrl: z.string().min(1).max(500),
    priceDisclosureHash: Hex32Schema,
    sourceStateSnapshotHash: Hex32Schema,
  })
  .strict();

export const ArtifactPreflightVerifyPayloadSchema = z
  .object({
    preflightId: Hex32Schema,
    artifactPayloadHash: Hex32Schema,
    artifactCid: ArtifactCidSchema,
    manifestFetchHash: Hex32Schema,
    endpointResponseHash: Hex32Schema,
    leaseDryRunHash: Hex32Schema,
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
    settlementMode: QuoteStatusSchema.default("mocked_after_preflight_not_chain_settleable"),
  })
  .strict();

export const ArtifactRefundPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    quoteId: Hex32Schema,
    reason: z.string().min(1).max(240),
  })
  .strict();

export const ArtifactAccessIssuePayloadSchema = z
  .object({
    spendId: Hex32Schema,
    payer: HexSchema,
    quoteId: Hex32Schema,
    artifactHash: Hex32Schema,
    artifactPayload: JsonObjectSchema,
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

export const TokenBalanceDeltaVerifyPayloadSchema = z
  .object({
    spendId: Hex32Schema,
    settlementEventId: Hex32Schema.optional(),
  })
  .strict();

export const ChainIndexerBackfillPayloadSchema = z
  .object({
    cursorId: z.string().min(1).max(160).regex(/^[a-z][a-z0-9:_-]+$/),
    chainId: DecimalStringSchema,
    fromBlock: z.number().int().min(0).optional(),
    toBlock: z.number().int().min(0).optional(),
    finalityDepth: z.number().int().min(1).max(128).default(2),
    maxWindowBlocks: z.number().int().min(1).max(10_000).default(2_000),
    address: HexSchema.optional(),
    topics: z.array(HexSchema.nullable()).max(4).default([]),
  })
  .strict()
  .refine((payload) => payload.fromBlock === undefined || payload.toBlock === undefined || payload.toBlock >= payload.fromBlock, {
    message: "toBlock must be >= fromBlock",
    path: ["toBlock"],
  });

export const ChainIndexerBackfillInputSchema = z
  .object({
    idempotencyKey: IdempotencyKeySchema,
    payload: ChainIndexerBackfillPayloadSchema,
  })
  .strict();

export const ChainIndexerStatusViewSchema = z
  .object({
    cursorId: z.string().min(1).max(160),
    chainId: DecimalStringSchema,
    address: HexSchema.nullable(),
    topics: z.array(HexSchema.nullable()).max(4),
    lastIndexedBlock: z.number().int().min(0).nullable(),
    latestHeadBlock: z.number().int().min(0),
    finalizedHeadBlock: z.number().int().min(0),
    finalityDepth: z.number().int().min(1).max(128),
    lagBlocks: z.number().int().min(0),
    status: z.enum(["unconfigured", "degraded", "caught_up"]),
    reason: z.string().min(1).max(500),
    updatedAt: IsoDateStringSchema,
  })
  .strict();

export const ChainIndexedLogViewSchema = z
  .object({
    logId: Hex32Schema,
    cursorId: z.string().min(1).max(160),
    chainId: DecimalStringSchema,
    blockNumber: z.number().int().min(0),
    txHash: Hex32Schema,
    logIndex: z.number().int().min(0),
    address: HexSchema.nullable(),
    topics: z.array(HexSchema).max(8),
    data: HexSchema.nullable(),
    rawLogHash: Hex32Schema,
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const ChainIndexerBackfillResultSchema = z
  .object({
    cursor: ChainIndexerStatusViewSchema,
    fromBlock: z.number().int().min(0),
    toBlock: z.number().int().min(0),
    indexedLogCount: z.number().int().min(0),
    insertedLogCount: z.number().int().min(0),
    proofAuthority: z.literal(false),
    winnerClaimAllowed: z.literal(false),
  })
  .strict();

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
  "source.challenge.confirmed",
  "spend.registered",
  "caw.operation.built",
  "caw.identity.probed",
  "caw.live.pact.submitted",
  "caw.live.pact.synced",
  "caw.live.transfer.submitted",
  "caw.live.contract_call.submitted",
  "caw.allowance.verified",
  "caw.activation.verified",
  "caw.live.audit.synced",
  "caw.live.audit.usage.verified",
  "caw.receipt.ingested.fixture",
  "caw.receipt.ingested.raw",
  "artifact.preflight.pending",
  "artifact.preflight.verified",
  "artifact.access_token.issued",
  "quote.signed.mocked",
  "quote.signed.chain_settleable",
  "artifact.refund.pending",
  "operator.key_used",
  "gate.spend_tripped.observed",
  "gate.spend_settled.observed",
  "gate.spend_tripped",
  "gate.spend_settled",
  "token.balance_delta.verified",
  "reorg.invalidated",
  "lease.execution.blocked",
  "lease.execution.succeeded",
  "verifier.fail_closed",
  "verifier.final_replay_claim",
  "public.claim.authorized",
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
    status: z.enum(["built_mocked", "fixture_manual_receipt", "raw_ingested_pending_proof", "verified_policy_authority_structural"]),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const CawLiveInteractionViewSchema = z
  .object({
    interactionId: Hex32Schema,
    sessionId: Hex32Schema,
    kind: z.enum(["pact_submit", "pact_sync", "transfer_submit", "contract_call", "audit_sync"]),
    walletId: z.string().min(1).max(160).nullable(),
    pactId: z.string().min(1).max(160).nullable(),
    cawRequestId: z.string().min(1).max(160).nullable(),
    requestHash: Hex32Schema,
    request: JsonObjectSchema,
    responseHash: Hex32Schema,
    response: JsonObjectSchema,
    status: z.enum(["live_submitted", "live_active", "live_pending", "live_denied", "live_failed", "live_synced"]),
    authKeyHash: Hex32Schema.nullable(),
    proofAuthority: z.literal(true),
    winnerClaimAllowed: z.literal(false),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const SourceViewSchema = z
  .object({
    sourceId: z.string().min(1).max(120),
    sessionId: Hex32Schema,
    sourceHash: Hex32Schema,
    manifestUrl: z.string().min(1).max(500),
    manifestHash: Hex32Schema,
    issuer: HexSchema.nullable(),
    signature: HexSchema.nullable(),
    capabilityVector: JsonObjectSchema,
    proofStatus: z.enum(["pending", "challenged", "active"]),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const SpendViewSchema = z
  .object({
    spendId: Hex32Schema,
    sessionId: Hex32Schema,
    pactId: Hex32Schema,
    toolId: Hex32Schema,
    payer: AddressSchema,
    agentWallet: AddressSchema,
    paymentToken: AddressSchema,
    artifactHash: Hex32Schema,
    market: AddressSchema,
    sourceHashes: z.array(Hex32Schema).min(1).max(16),
    sourceSetHash: Hex32Schema,
    sessionCommitment: Hex32Schema,
    spendPreimage: JsonObjectSchema,
    maxPriceAtomic: DecimalStringSchema,
    nonce: z.string().min(1).max(128),
    status: z.string().min(1).max(120),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const ArtifactPreflightViewSchema = z
  .object({
    preflightId: Hex32Schema,
    sessionId: Hex32Schema,
    spendId: Hex32Schema,
    artifactHashPreview: Hex32Schema,
    artifactCid: ArtifactCidSchema,
    endpointUrl: z.string().min(1).max(500),
    priceDisclosureHash: Hex32Schema,
    sourceStateSnapshotHash: Hex32Schema,
    deliveryProofHash: Hex32Schema.nullable().default(null),
    manifestFetchHash: Hex32Schema.nullable().default(null),
    endpointResponseHash: Hex32Schema.nullable().default(null),
    leaseDryRunHash: Hex32Schema.nullable().default(null),
    verifiedAt: IsoDateStringSchema.nullable().default(null),
    verifiedEventId: Hex32Schema.nullable().default(null),
    status: z.enum(["pending_live_delivery", "passed_live_delivery"]),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const QuoteViewSchema = z
  .object({
    quoteId: Hex32Schema,
    sessionId: Hex32Schema,
    spendId: Hex32Schema,
    preflightId: Hex32Schema,
    artifactCommitment: Hex32Schema,
    artifactCid: ArtifactCidSchema,
    priceDisclosureHash: Hex32Schema,
    sourceStateSnapshotHash: Hex32Schema,
    priceAtomic: DecimalStringSchema,
    quoteNonce: z.string().min(1).max(128),
    validUntilBlock: z.string().regex(/^[0-9]+$/),
    quoteHash: Hex32Schema,
    status: QuoteStatusSchema,
    chainId: z.string().min(1).nullable().default(null),
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const ArtifactAccessTokenViewSchema = z
  .object({
    tokenId: Hex32Schema,
    sessionId: Hex32Schema,
    spendId: Hex32Schema,
    payer: HexSchema,
    quoteId: Hex32Schema,
    preflightId: Hex32Schema,
    artifactHash: Hex32Schema,
    artifactCid: ArtifactCidSchema,
    artifactPayloadHash: Hex32Schema,
    artifactPayload: JsonObjectSchema,
    tokenHash: Hex32Schema,
    status: z.enum(["active", "consuming", "consumed", "blocked"]),
    issuedByVerifierRunId: Hex32Schema.nullable(),
    settlementEventId: Hex32Schema.nullable(),
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

export const CanonicalCawReceiptViewSchema = z
  .object({
    rawReceiptHash: Hex32Schema,
    canonicalReceiptHash: Hex32Schema,
    bundleId: Hex32Schema,
    sessionId: Hex32Schema,
    operationId: Hex32Schema,
    operationKind: z.enum(["deny_probe", "approve", "activate_tool"]),
    sourceLabel: z.string().min(1).max(120),
    walletAddress: HexSchema,
    target: HexSchema.nullable(),
    selector: z.string().regex(/^0x[0-9a-fA-F]{8}$/).nullable(),
    requestId: z.string().min(1).max(200),
    effect: z.enum(["allow", "deny"]),
    status: z.string().min(1).max(120),
    policyDigest: Hex32Schema,
    paramsDigest: Hex32Schema,
    txHash: Hex32Schema.nullable(),
    txCount: DecimalStringSchema,
    expiry: IsoDateStringSchema,
    fetchedAt: IsoDateStringSchema,
    createdAt: IsoDateStringSchema,
  })
  .strict();

export const LeaseRunViewSchema = z
  .object({
    leaseRunId: Hex32Schema,
    sessionId: Hex32Schema,
    spendId: Hex32Schema,
    payer: HexSchema.nullable(),
    artifactHash: Hex32Schema.nullable(),
    consumedArtifactPayloadHash: Hex32Schema.nullable(),
    targetRepo: z.string().min(1).max(500),
    targetCommit: z.string().min(6).max(128),
    status: z.enum(["blocked_missing_runner_execution", "blocked_mcp_execution_failed", "succeeded_live_mcp_transcript"]),
    transcriptHash: Hex32Schema.nullable(),
    toolsListHash: Hex32Schema.nullable(),
    toolsCallHash: Hex32Schema.nullable(),
    outputHash: Hex32Schema.nullable(),
    leaseRunHash: Hex32Schema.nullable(),
    settlementEventId: Hex32Schema.nullable(),
    artifactTokenId: Hex32Schema.nullable(),
    createdAt: IsoDateStringSchema,
    completedAt: IsoDateStringSchema.nullable(),
  })
  .strict();

export const ReplayPageViewSchema = z
  .object({
    bundleType: z.literal("PACTFUSE_REPLAY_PAGE_V1"),
    sessionId: Hex32Schema,
    collection: z.enum([
      "events",
      "sources",
      "spends",
      "artifactPreflights",
      "quotes",
      "artifactAccessTokens",
      "mcpAdapterCalls",
      "cawReceiptOperations",
      "cawLiveInteractions",
      "rawCawReceiptBundles",
      "canonicalCawReceipts",
      "leaseRuns",
    ]),
    pageIndex: z.number().int().min(0),
    pageSize: z.literal(200),
    orderBy: z.array(z.string().min(1)).min(1).max(4),
    rows: z.array(JsonValueSchema).max(200),
    pageHash: Hex32Schema,
  })
  .strict();

export const ReplayBundleViewSchema = z
  .object({
    bundleType: z.literal("PACTFUSE_EVIDENCE_V1"),
    sessionId: Hex32Schema,
    summaryMode: z.literal(true),
    asOfEventSeq: z.number().int().min(0).max(200),
    asOfMcpAdapterCallCount: z.number().int().min(0).max(200),
    winnerClaimAllowed: z.boolean(),
    eventRoot: Hex32Schema,
    agentTranscriptHash: Hex32Schema,
    fullReplayRoot: Hex32Schema,
    deploymentRegistry: DeploymentRegistrySchema.nullable(),
    deploymentRegistryHash: Hex32Schema.nullable(),
    events: z.array(EvidenceEventSchema).max(200),
    sources: z.array(SourceViewSchema).max(200),
    spends: z.array(SpendViewSchema).max(200),
    artifactPreflights: z.array(ArtifactPreflightViewSchema).max(200),
    quotes: z.array(QuoteViewSchema).max(200),
    artifactAccessTokens: z.array(ArtifactAccessTokenViewSchema).max(200),
    mcpAdapterCalls: z.array(McpAdapterCallViewSchema).max(200),
    cawReceiptOperations: z.array(CawReceiptOperationViewSchema).max(200),
    cawLiveInteractions: z.array(CawLiveInteractionViewSchema).max(200),
    rawCawReceiptBundles: z.array(RawCawReceiptBundleViewSchema).max(200),
    canonicalCawReceipts: z.array(CanonicalCawReceiptViewSchema).max(200),
    leaseRuns: z.array(LeaseRunViewSchema).max(200),
    judgeCheck: JudgeCheckViewSchema,
    replayPageIndex: z
      .object({
        pageSize: z.literal(200),
        pageRoot: Hex32Schema,
        collections: z.record(
          z.string(),
          z.object({
            totalRows: z.number().int().min(0),
            pageCount: z.number().int().min(0),
            orderBy: z.array(z.string().min(1)).min(1).max(4),
            firstPageHash: Hex32Schema,
            pageRoot: Hex32Schema,
            pageHashes: z.array(Hex32Schema).max(5000),
          }),
        ),
      })
      .strict(),
    replayPages: z.record(z.string(), z.array(ReplayPageViewSchema).max(5000)),
  })
  .strict();

export const RunnerHeartbeatViewSchema = z
  .object({
    sessionId: Hex32Schema,
    status: z.enum(["pending", "blocked", "idle", "lease_executed"]),
    latestLeaseRunId: Hex32Schema.nullable(),
    transcriptHash: Hex32Schema.nullable(),
    leaseRunHash: Hex32Schema.nullable(),
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
    boundedToPinnedManifest: z.boolean(),
    callCount: z.number().int().min(0).max(200),
    calls: z.array(AgentTranscriptCallSummarySchema).max(200),
    winnerClaimAllowed: z.literal(false),
  })
  .strict();

export const VerifierRunViewSchema = z
  .object({
    sessionId: Hex32Schema.optional(),
    proofLevel: z.enum(["schema_only_no_claim", "fail_closed_no_claim", "final_replay_claim"]),
    claimMode: RuntimeModesSchema.shape.CLAIM_MODE,
    paymentMode: RuntimeModesSchema.shape.PAYMENT_MODE,
    tokenMode: RuntimeModesSchema.shape.TOKEN_MODE,
    identityMode: RuntimeModesSchema.shape.IDENTITY_MODE,
    schemaOk: z.boolean(),
    proofChipAllowed: z.boolean(),
    winnerClaimAllowed: z.boolean(),
    requestedWinnerClaimAllowed: z.boolean().default(false),
    finalVerifierComplete: z.boolean(),
    errors: z.array(z.string()),
    warnings: z.array(z.string()),
    raw: JsonObjectSchema.optional(),
  })
  .strict();

export const ProofProviderStatusSchema = z
  .object({
    name: z.enum(["chain", "caw", "caw_live", "mcp_lease"]),
    mode: z.enum(["unconfigured", "fixture", "live"]),
    ready: z.boolean(),
    reason: z.string().min(1).max(1000),
    chainId: z.string().min(1).max(80).optional(),
    endpoint: z.string().min(1).max(1000).optional(),
  })
  .strict();

export const ClaimReadinessGateSchema = z
  .object({
    gateId: z.string().min(1).max(80),
    label: z.string().min(1).max(160),
    status: z.enum(["pass", "pending", "blocked"]),
    blocks: z.array(z.enum(["claimMode", "paymentMode", "tokenMode", "identityMode", "winnerClaimAllowed"])).min(1),
    reason: z.string().min(1).max(400),
    evidenceEventId: Hex32Schema.nullable(),
  })
  .strict();

export const ClaimReadinessViewSchema = z
  .object({
    sessionId: Hex32Schema,
    claimMode: ClaimModeSchema,
    paymentMode: PaymentModeSchema,
    tokenMode: TokenModeSchema,
    identityMode: IdentityModeSchema,
    targetClaimMode: ClaimModeSchema.nullable(),
    targetPaymentMode: PaymentModeSchema.nullable(),
    targetTokenMode: TokenModeSchema.nullable(),
    targetIdentityMode: IdentityModeSchema.nullable(),
    proofChipAllowed: z.boolean(),
    finalVerifierComplete: z.boolean(),
    winnerClaimAllowed: z.boolean(),
    gates: z.array(ClaimReadinessGateSchema),
    blockers: z.array(z.string()),
    requiredExternalInputs: z.array(z.string()),
    replayBundleHash: Hex32Schema.nullable(),
    verifierRun: VerifierRunViewSchema,
  })
  .strict();

export const PublicClaimViewSchema = z
  .object({
    sessionId: Hex32Schema,
    claimStatus: z.literal("authorized_public_claim"),
    claimMode: z.literal("caw-target-real"),
    paymentMode: z.literal("gate-paid-artifact-real"),
    tokenMode: z.enum(["mock-test-token", "official-testnet-usdc"]),
    identityMode: z.enum(["p0-floor-one-wallet", "p0-win-separate-identities"]),
    replayBundleHash: Hex32Schema,
    verifierRun: VerifierRunViewSchema,
    proofChipAllowed: z.literal(true),
    finalVerifierComplete: z.literal(true),
    winnerClaimAllowed: z.literal(true),
    publicClaimHash: Hex32Schema,
  })
  .strict();

export const ProofBundleProviderStatusSchema = ProofProviderStatusSchema.extend({
  endpoint: z.string().min(1).max(1000).nullable(),
}).strict();

export const ProofBundleServerSchema = z
  .object({
    proofBundleVersion: z.literal("PACTFUSE_PUBLIC_PROOF_BUNDLE_V1"),
    commit: z.string().min(1).max(160).nullable(),
    buildTime: IsoDateStringSchema.nullable(),
    generatedAt: IsoDateStringSchema,
  })
  .strict();

export const ProofBundleAuthorizationSnapshotSchema = z
  .object({
    providerStatuses: z.array(ProofBundleProviderStatusSchema),
    providerStatusHash: Hex32Schema,
    deploymentRegistry: DeploymentRegistrySchema.nullable(),
    deploymentRegistryHash: Hex32Schema.nullable(),
    server: ProofBundleServerSchema,
    serverHash: Hex32Schema,
  })
  .strict();

export const PublicClaimAuthorizedPayloadSchema = ProofBundleAuthorizationSnapshotSchema.extend({
  claim: PublicClaimViewSchema,
  publicClaimHash: Hex32Schema,
  replayBundleHash: Hex32Schema,
  verifierRunHash: Hex32Schema,
  asOfEventSeq: z.number().int().min(0),
  proofAuthority: z.literal(true),
  winnerClaimAllowed: z.literal(true),
}).strict();

export const ProofBundleViewSchema = z
  .object({
    bundleType: z.literal("PACTFUSE_PUBLIC_PROOF_BUNDLE_V1"),
    sessionId: Hex32Schema,
    proofBundleHash: Hex32Schema,
    publicClaimHash: Hex32Schema,
    publicClaimEventId: Hex32Schema,
    publicClaimEventHash: Hex32Schema,
    publicClaimEventSeq: z.number().int().min(1),
    claimInputReplayBundleHash: Hex32Schema,
    replayBundleHash: Hex32Schema,
    verifierRunHash: Hex32Schema,
    providerStatusHash: Hex32Schema,
    deploymentRegistryHash: Hex32Schema.nullable(),
    serverHash: Hex32Schema,
    publicClaim: PublicClaimViewSchema,
    replayBundle: ReplayBundleViewSchema,
    providerStatuses: z.array(ProofBundleProviderStatusSchema),
    deploymentRegistry: DeploymentRegistrySchema.nullable(),
    server: ProofBundleServerSchema,
    winnerClaimAllowed: z.literal(true),
  })
  .strict();

export const LiveProofPreflightCheckSchema = z
  .object({
    checkId: z.string().min(1).max(100),
    label: z.string().min(1).max(160),
    status: z.enum(["pass", "pending", "blocked"]),
    reason: z.string().min(1).max(600),
    requiredExternalInputs: z.array(z.string().min(1).max(300)),
    evidenceEventId: Hex32Schema.nullable(),
  })
  .strict();

export const LiveProofPreflightSecuritySchema = z
  .object({
    operatorTokenConfigured: z.boolean(),
    challengeSubmitterTokenConfigured: z.boolean(),
    artifactSignerTokenConfigured: z.boolean(),
    roleTokenFallbackToOperator: z.boolean(),
    allowInsecureMissingRoleTokens: z.boolean(),
    cawIngestTokenConfigured: z.boolean(),
    mcpAuditSecretConfigured: z.boolean(),
    gateIngestSecretConfigured: z.boolean(),
  })
  .strict();

export const LiveProofPreflightIndexerSchema = z
  .object({
    requiredCursorCount: z.number().int().min(0).max(32),
    status: z.enum(["pass", "pending", "blocked"]),
    reasons: z.array(z.string().min(1).max(600)),
  })
  .strict();

export const LiveProofPreflightViewSchema = z
  .object({
    sessionId: Hex32Schema,
    status: z.enum(["ready", "blocked"]),
    readyForPublicClaim: z.boolean(),
    providerStatuses: z.array(ProofProviderStatusSchema),
    security: LiveProofPreflightSecuritySchema,
    indexer: LiveProofPreflightIndexerSchema,
    checks: z.array(LiveProofPreflightCheckSchema),
    blockingReasons: z.array(z.string()),
    requiredExternalInputs: z.array(z.string()),
    claimReadiness: ClaimReadinessViewSchema,
    winnerClaimAllowed: z.boolean(),
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
export type ClaimReadinessView = z.infer<typeof ClaimReadinessViewSchema>;
export type PublicClaimView = z.infer<typeof PublicClaimViewSchema>;
export type DeploymentRegistry = z.infer<typeof DeploymentRegistrySchema>;
export type DeploymentRegistryEntry = z.infer<typeof DeploymentRegistryEntrySchema>;
export type ProofBundleAuthorizationSnapshot = z.infer<typeof ProofBundleAuthorizationSnapshotSchema>;
export type ProofBundleView = z.infer<typeof ProofBundleViewSchema>;
export type LiveProofPreflightView = z.infer<typeof LiveProofPreflightViewSchema>;
export type ReplayBundleView = z.infer<typeof ReplayBundleViewSchema>;
export type QuoteStatus = z.infer<typeof QuoteStatusSchema>;
export type ChainIndexerBackfillInput = z.infer<typeof ChainIndexerBackfillInputSchema>;
export type CawOperationBuildPayload = z.infer<typeof CawOperationBuildPayloadSchema>;
export type CawLivePactSubmitPayload = z.infer<typeof CawLivePactSubmitPayloadSchema>;
export type CawLivePactSyncPayload = z.infer<typeof CawLivePactSyncPayloadSchema>;
export type CawLiveIdentityProbePayload = z.infer<typeof CawLiveIdentityProbePayloadSchema>;
export type CawLiveTransferSubmitPayload = z.infer<typeof CawLiveTransferSubmitPayloadSchema>;
export type CawLiveContractCallSubmitPayload = z.infer<typeof CawLiveContractCallSubmitPayloadSchema>;
export type CawAllowanceVerifyPayload = z.infer<typeof CawAllowanceVerifyPayloadSchema>;
export type CawLiveAuditSyncPayload = z.infer<typeof CawLiveAuditSyncPayloadSchema>;
export type TokenBalanceDeltaVerifyPayload = z.infer<typeof TokenBalanceDeltaVerifyPayloadSchema>;
