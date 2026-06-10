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
