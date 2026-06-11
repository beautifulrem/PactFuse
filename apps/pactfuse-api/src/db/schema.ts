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
