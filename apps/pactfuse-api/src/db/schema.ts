import { integer, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const sessions = sqliteTable("sessions", {
  sessionId: text("session_id").primaryKey(),
  runConfigHash: text("run_config_hash").notNull(),
  runConfigJson: text("run_config_json").notNull(),
  modesJson: text("modes_json").notNull(),
  createdAt: text("created_at").notNull(),
  latestEventSeq: integer("latest_event_seq").notNull().default(0),
  latestProofEventHash: text("latest_proof_event_hash").notNull(),
});

export const apiRequests = sqliteTable(
  "api_requests",
  {
    requestId: text("request_id").primaryKey(),
    actionScope: text("action_scope").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    requestHash: text("request_hash").notNull(),
    responseJson: text("response_json").notNull(),
    status: text("status").notNull().default("completed"),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    scopeKey: uniqueIndex("api_requests_scope_key").on(table.actionScope, table.idempotencyKey),
  }),
);

export const jobs = sqliteTable(
  "jobs",
  {
    jobId: text("job_id").primaryKey(),
    sessionId: text("session_id"),
    kind: text("kind").notNull(),
    status: text("status").notNull(),
    dedupeKey: text("dedupe_key").notNull(),
    attempts: integer("attempts").notNull().default(0),
    nextAttemptAt: text("next_attempt_at"),
    lockedAt: text("locked_at"),
    payloadJson: text("payload_json").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    kindDedupe: uniqueIndex("jobs_kind_dedupe").on(table.kind, table.dedupeKey),
  }),
);

export const sources = sqliteTable(
  "sources",
  {
    sourceId: text("source_id").notNull(),
    sessionId: text("session_id").notNull(),
    sourceHash: text("source_hash").notNull(),
    manifestUrl: text("manifest_url").notNull(),
    manifestHash: text("manifest_hash").notNull(),
    issuer: text("issuer"),
    signature: text("signature"),
    capabilityVectorJson: text("capability_vector_json").notNull(),
    proofStatus: text("proof_status").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.sessionId, table.sourceHash] }),
  }),
);

export const sourceChallenges = sqliteTable("source_challenges", {
  challengeId: text("challenge_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  sourceHash: text("source_hash").notNull(),
  reasonHash: text("reason_hash").notNull(),
  evidenceRef: text("evidence_ref"),
  status: text("status").notNull(),
  createdAt: text("created_at").notNull(),
});

export const spends = sqliteTable(
  "spends",
  {
    spendId: text("spend_id").notNull(),
    sessionId: text("session_id").notNull(),
    pactId: text("pact_id").notNull(),
    toolId: text("tool_id").notNull(),
    payer: text("payer").notNull(),
    agentWallet: text("agent_wallet").notNull(),
    paymentToken: text("payment_token").notNull(),
    artifactHash: text("artifact_hash").notNull(),
    market: text("market").notNull(),
    sourceHashesJson: text("source_hashes_json").notNull(),
    sourceSetHash: text("source_set_hash").notNull(),
    sessionCommitment: text("session_commitment").notNull(),
    spendPreimageJson: text("spend_preimage_json").notNull(),
    maxPriceAtomic: text("max_price_atomic").notNull(),
    nonce: text("nonce").notNull(),
    status: text("status").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.sessionId, table.spendId] }),
  }),
);

export const cawReceiptOperations = sqliteTable("caw_receipt_operations", {
  operationId: text("operation_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  spendId: text("spend_id"),
  operationKind: text("operation_kind").notNull(),
  target: text("target"),
  selector: text("selector"),
  valueAtomic: text("value_atomic").notNull(),
  requestJson: text("request_json").notNull(),
  receiptBundleHash: text("receipt_bundle_hash"),
  status: text("status").notNull(),
  createdAt: text("created_at").notNull(),
});

export const evidenceEvents = sqliteTable(
  "evidence_events",
  {
    eventId: text("event_id").primaryKey(),
    sessionId: text("session_id").notNull(),
    eventSeq: integer("event_seq").notNull(),
    eventHash: text("event_hash").notNull(),
    prevProofEventHash: text("prev_proof_event_hash"),
    authority: text("authority").notNull(),
    kind: text("kind").notNull(),
    payloadHash: text("payload_hash").notNull(),
    payloadJson: text("payload_json").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    sessionSeq: uniqueIndex("evidence_events_session_seq").on(table.sessionId, table.eventSeq),
    sessionHash: uniqueIndex("evidence_events_session_hash").on(table.sessionId, table.eventHash),
  }),
);

export const cawRawReceiptBundles = sqliteTable(
  "caw_raw_receipt_bundles",
  {
    bundleId: text("bundle_id").primaryKey(),
    sessionId: text("session_id").notNull(),
    operationId: text("operation_id").notNull(),
    sourceLabel: text("source_label").notNull(),
    fetchedAt: text("fetched_at").notNull(),
    rawBundleHash: text("raw_bundle_hash").notNull(),
    rawBundleJson: text("raw_bundle_json").notNull(),
    receiptCount: integer("receipt_count").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    sessionOperationBundle: uniqueIndex("caw_raw_receipt_bundles_session_operation_bundle").on(
      table.sessionId,
      table.operationId,
      table.rawBundleHash,
    ),
  }),
);

export const cawCanonicalReceipts = sqliteTable(
  "caw_canonical_receipts",
  {
    rawReceiptHash: text("raw_receipt_hash").primaryKey(),
    canonicalReceiptHash: text("canonical_receipt_hash").notNull(),
    bundleId: text("bundle_id").notNull(),
    sessionId: text("session_id").notNull(),
    operationId: text("operation_id").notNull(),
    operationKind: text("operation_kind").notNull(),
    sourceLabel: text("source_label").notNull(),
    walletAddress: text("wallet_address").notNull(),
    target: text("target"),
    selector: text("selector"),
    requestId: text("request_id").notNull(),
    effect: text("effect").notNull(),
    status: text("status").notNull(),
    policyDigest: text("policy_digest").notNull(),
    paramsDigest: text("params_digest").notNull(),
    txHash: text("tx_hash"),
    txCount: text("tx_count").notNull(),
    expiry: text("expiry").notNull(),
    fetchedAt: text("fetched_at").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    sessionOperationCanonical: uniqueIndex("caw_canonical_receipts_session_operation_canonical").on(
      table.sessionId,
      table.operationId,
      table.canonicalReceiptHash,
    ),
  }),
);

export const cawLiveInteractions = sqliteTable("caw_live_interactions", {
  interactionId: text("interaction_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  kind: text("kind").notNull(),
  walletId: text("wallet_id"),
  pactId: text("pact_id"),
  cawRequestId: text("caw_request_id"),
  requestHash: text("request_hash").notNull(),
  requestJson: text("request_json").notNull(),
  responseHash: text("response_hash").notNull(),
  responseJson: text("response_json").notNull(),
  status: text("status").notNull(),
  authKeyHash: text("auth_key_hash"),
  createdAt: text("created_at").notNull(),
});

export const gateChainEvents = sqliteTable(
  "gate_chain_events",
  {
    gateEventId: text("gate_event_id").primaryKey(),
    sessionId: text("session_id").notNull(),
    spendId: text("spend_id").notNull(),
    eventKind: text("event_kind").notNull(),
    txHash: text("tx_hash").notNull(),
    logIndex: integer("log_index").notNull(),
    chainId: text("chain_id").notNull(),
    blockNumber: integer("block_number").notNull(),
    currentBlockNumber: integer("current_block_number").notNull(),
    finalityDepth: integer("finality_depth").notNull(),
    confirmations: integer("confirmations").notNull(),
    rawLogHash: text("raw_log_hash").notNull(),
    status: text("status").notNull(),
    observedEventId: text("observed_event_id"),
    finalizedEventId: text("finalized_event_id"),
    reorgEventId: text("reorg_event_id"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => ({
    sessionTxLogKind: uniqueIndex("gate_chain_events_session_tx_log_kind").on(
      table.sessionId,
      table.txHash,
      table.logIndex,
      table.eventKind,
    ),
  }),
);

export const artifactPreflights = sqliteTable("artifact_preflights", {
  preflightId: text("preflight_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  spendId: text("spend_id").notNull(),
  artifactHashPreview: text("artifact_hash_preview").notNull(),
  artifactCid: text("artifact_cid").notNull(),
  endpointUrl: text("endpoint_url").notNull(),
  priceDisclosureHash: text("price_disclosure_hash").notNull(),
  sourceStateSnapshotHash: text("source_state_snapshot_hash").notNull(),
  deliveryProofHash: text("delivery_proof_hash"),
  manifestFetchHash: text("manifest_fetch_hash"),
  endpointResponseHash: text("endpoint_response_hash"),
  leaseDryRunHash: text("lease_dry_run_hash"),
  verifiedAt: text("verified_at"),
  verifiedEventId: text("verified_event_id"),
  status: text("status").notNull(),
  createdAt: text("created_at").notNull(),
});

export const quotes = sqliteTable(
  "quotes",
  {
    quoteId: text("quote_id").primaryKey(),
    sessionId: text("session_id").notNull(),
    spendId: text("spend_id").notNull(),
    preflightId: text("preflight_id").notNull(),
    artifactCommitment: text("artifact_commitment").notNull(),
    artifactCid: text("artifact_cid").notNull(),
    priceDisclosureHash: text("price_disclosure_hash").notNull(),
    sourceStateSnapshotHash: text("source_state_snapshot_hash").notNull(),
    priceAtomic: text("price_atomic").notNull(),
    quoteNonce: text("quote_nonce").notNull(),
    validUntilBlock: text("valid_until_block").notNull(),
    quoteHash: text("quote_hash").notNull(),
    status: text("status").notNull(),
    chainId: text("chain_id"),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    sessionQuoteNonce: uniqueIndex("quotes_session_quote_nonce").on(table.sessionId, table.quoteNonce),
  }),
);

export const artifactAccessTokens = sqliteTable("artifact_access_tokens", {
  tokenId: text("token_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  spendId: text("spend_id").notNull(),
  payer: text("payer").notNull(),
  quoteId: text("quote_id").notNull(),
  preflightId: text("preflight_id").notNull(),
  artifactHash: text("artifact_hash").notNull(),
  artifactCid: text("artifact_cid").notNull(),
  artifactPayloadHash: text("artifact_payload_hash").notNull(),
  artifactPayloadJson: text("artifact_payload_json").notNull(),
  tokenHash: text("token_hash").notNull(),
  status: text("status").notNull(),
  leaseClaimJson: text("lease_claim_json"),
  leaseClaimedAt: text("lease_claimed_at"),
  issuedByVerifierRunId: text("issued_by_verifier_run_id"),
  settlementEventId: text("settlement_event_id"),
  createdAt: text("created_at").notNull(),
});

export const leaseRuns = sqliteTable("lease_runs", {
  leaseRunId: text("lease_run_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  spendId: text("spend_id").notNull(),
  payer: text("payer"),
  artifactHash: text("artifact_hash"),
  consumedArtifactPayloadHash: text("consumed_artifact_payload_hash"),
  targetRepo: text("target_repo").notNull(),
  targetCommit: text("target_commit").notNull(),
  status: text("status").notNull(),
  transcriptHash: text("transcript_hash"),
  toolsListHash: text("tools_list_hash"),
  toolsCallHash: text("tools_call_hash"),
  outputHash: text("output_hash"),
  leaseRunHash: text("lease_run_hash"),
  settlementEventId: text("settlement_event_id"),
  artifactTokenId: text("artifact_token_id"),
  completedAt: text("completed_at"),
  createdAt: text("created_at").notNull(),
});

export const chainIndexerCursors = sqliteTable("chain_indexer_cursors", {
  cursorId: text("cursor_id").primaryKey(),
  chainId: text("chain_id").notNull(),
  address: text("address"),
  topicsJson: text("topics_json").notNull(),
  lastIndexedBlock: integer("last_indexed_block"),
  latestHeadBlock: integer("latest_head_block").notNull(),
  finalizedHeadBlock: integer("finalized_head_block").notNull(),
  finalityDepth: integer("finality_depth").notNull(),
  lagBlocks: integer("lag_blocks").notNull(),
  status: text("status").notNull(),
  reason: text("reason").notNull(),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
});

export const chainIndexedLogs = sqliteTable(
  "chain_indexed_logs",
  {
    logId: text("log_id").primaryKey(),
    cursorId: text("cursor_id").notNull(),
    chainId: text("chain_id").notNull(),
    blockNumber: integer("block_number").notNull(),
    txHash: text("tx_hash").notNull(),
    logIndex: integer("log_index").notNull(),
    address: text("address"),
    topicsJson: text("topics_json").notNull(),
    data: text("data"),
    rawLogHash: text("raw_log_hash").notNull(),
    rawLogJson: text("raw_log_json").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    chainTxLog: uniqueIndex("chain_indexed_logs_chain_tx_log").on(table.chainId, table.txHash, table.logIndex),
  }),
);

export const mcpAdapterCalls = sqliteTable(
  "mcp_adapter_calls",
  {
    callId: text("call_id").primaryKey(),
    sessionId: text("session_id"),
    auditNonce: text("audit_nonce"),
    toolName: text("tool_name").notNull(),
    requestHash: text("request_hash").notNull(),
    responseHash: text("response_hash").notNull(),
    requestJson: text("request_json").notNull().default("{}"),
    responseJson: text("response_json").notNull().default("{}"),
    status: text("status").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    auditNonce: uniqueIndex("mcp_adapter_calls_audit_nonce").on(table.auditNonce),
  }),
);

export const operatorKeys = sqliteTable("operator_keys", {
  keyId: text("key_id").primaryKey(),
  role: text("role").notNull(),
  authority: text("authority").notNull(),
  authorizedMethodsHash: text("authorized_methods_hash").notNull(),
  authorizedMethodsJson: text("authorized_methods_json").notNull(),
  status: text("status").notNull(),
  useCount: integer("use_count").notNull().default(0),
  createdAt: text("created_at").notNull(),
  lastUsedAt: text("last_used_at"),
});

export const verifierRuns = sqliteTable("verifier_runs", {
  verifierRunId: text("verifier_run_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  inputHash: text("input_hash").notNull(),
  resultJson: text("result_json").notNull(),
  schemaOk: integer("schema_ok").notNull(),
  proofChipAllowed: integer("proof_chip_allowed").notNull(),
  winnerClaimAllowed: integer("winner_claim_allowed").notNull(),
  finalVerifierComplete: integer("final_verifier_complete").notNull(),
  createdAt: text("created_at").notNull(),
});

export const judgeCheckRows = sqliteTable(
  "judge_check_rows",
  {
    sessionId: text("session_id").notNull(),
    rowId: text("row_id").notNull(),
    label: text("label").notNull(),
    status: text("status").notNull(),
    authority: text("authority").notNull(),
    reason: text("reason").notNull(),
    evidenceEventId: text("evidence_event_id"),
    evidenceUrl: text("evidence_url"),
    createdAt: text("created_at").notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.sessionId, table.rowId] }),
  }),
);
