import { integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

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

export const artifactAccessTokens = sqliteTable("artifact_access_tokens", {
  tokenId: text("token_id").primaryKey(),
  sessionId: text("session_id").notNull(),
  spendId: text("spend_id").notNull(),
  payer: text("payer").notNull(),
  artifactHash: text("artifact_hash").notNull(),
  tokenHash: text("token_hash").notNull(),
  status: text("status").notNull(),
  issuedByVerifierRunId: text("issued_by_verifier_run_id"),
  settlementEventId: text("settlement_event_id"),
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
