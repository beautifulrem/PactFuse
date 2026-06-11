import { dirname } from "node:path";
import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { ZERO_HASH } from "../util.js";
import type { PactFuseDb } from "../types.js";
import * as schema from "./schema.js";

export function openPactFuseDb(path: string): PactFuseDb {
  if (path !== ":memory:") {
    mkdirSync(dirname(path), { recursive: true });
  }
  const sqlite = new DatabaseSync(path);
  sqlite.exec("PRAGMA journal_mode = WAL");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec("PRAGMA busy_timeout = 5000");
  migrate(sqlite);
  return { sqlite, drizzleSchema: schema };
}

export function migrate(sqlite: DatabaseSync): void {
  sqlite.exec(`
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  run_config_hash TEXT NOT NULL,
  run_config_json TEXT NOT NULL,
  modes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  latest_event_seq INTEGER NOT NULL DEFAULT 0,
  latest_proof_event_hash TEXT NOT NULL DEFAULT '${ZERO_HASH}'
);

CREATE TABLE IF NOT EXISTS api_requests (
  request_id TEXT PRIMARY KEY,
  action_scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed',
  created_at TEXT NOT NULL,
  UNIQUE(action_scope, idempotency_key)
);

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  session_id TEXT,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  locked_at TEXT,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(kind, dedupe_key)
);

CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  manifest_url TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  issuer TEXT,
  signature TEXT,
  capability_vector_json TEXT NOT NULL,
  proof_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(session_id, source_hash)
);

CREATE TABLE IF NOT EXISTS source_challenges (
  challenge_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  reason_hash TEXT NOT NULL,
  evidence_ref TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS spends (
  spend_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  pact_id TEXT NOT NULL,
  tool_id TEXT NOT NULL,
  payer TEXT NOT NULL,
  agent_wallet TEXT NOT NULL,
  source_hashes_json TEXT NOT NULL,
  source_set_hash TEXT NOT NULL DEFAULT '${ZERO_HASH}',
  session_commitment TEXT NOT NULL DEFAULT '${ZERO_HASH}',
  spend_preimage_json TEXT NOT NULL DEFAULT '{}',
  max_price_atomic TEXT NOT NULL,
  nonce TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(session_id, spend_id)
);

CREATE TABLE IF NOT EXISTS caw_receipt_operations (
  operation_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT,
  operation_kind TEXT NOT NULL,
  target TEXT,
  selector TEXT,
  value_atomic TEXT NOT NULL,
  request_json TEXT NOT NULL,
  receipt_bundle_hash TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_preflights (
  preflight_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT NOT NULL,
  artifact_hash_preview TEXT NOT NULL,
  endpoint_url TEXT NOT NULL,
  price_disclosure_hash TEXT NOT NULL,
  source_state_snapshot_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quotes (
  quote_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT NOT NULL,
  preflight_id TEXT NOT NULL,
  artifact_commitment TEXT NOT NULL,
  price_disclosure_hash TEXT NOT NULL,
  source_state_snapshot_hash TEXT NOT NULL,
  price_atomic TEXT NOT NULL,
  quote_nonce TEXT NOT NULL,
  valid_until_block TEXT NOT NULL,
  quote_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(session_id, quote_nonce)
);

CREATE TABLE IF NOT EXISTS artifact_access_tokens (
  token_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT NOT NULL,
  payer TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lease_runs (
  lease_run_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT NOT NULL,
  target_repo TEXT NOT NULL,
  target_commit TEXT NOT NULL,
  status TEXT NOT NULL,
  transcript_hash TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gate_chain_events (
  gate_event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  spend_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  tx_hash TEXT NOT NULL,
  log_index INTEGER NOT NULL,
  chain_id TEXT NOT NULL,
  block_number INTEGER NOT NULL,
  current_block_number INTEGER NOT NULL,
  finality_depth INTEGER NOT NULL,
  confirmations INTEGER NOT NULL,
  raw_log_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  observed_event_id TEXT,
  finalized_event_id TEXT,
  reorg_event_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(session_id, tx_hash, log_index, event_kind)
);

CREATE TABLE IF NOT EXISTS mcp_adapter_calls (
  call_id TEXT PRIMARY KEY,
  session_id TEXT,
  audit_nonce TEXT,
  tool_name TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_hash TEXT NOT NULL,
  request_json TEXT NOT NULL DEFAULT '{}',
  response_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(audit_nonce)
);

CREATE TABLE IF NOT EXISTS evidence_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  event_seq INTEGER NOT NULL,
  event_hash TEXT NOT NULL,
  prev_proof_event_hash TEXT,
  authority TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(session_id, event_seq),
  UNIQUE(session_id, event_hash)
);

CREATE TABLE IF NOT EXISTS verifier_runs (
  verifier_run_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  schema_ok INTEGER NOT NULL,
  proof_chip_allowed INTEGER NOT NULL,
  winner_claim_allowed INTEGER NOT NULL,
  final_verifier_complete INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS judge_check_rows (
  session_id TEXT NOT NULL,
  row_id TEXT NOT NULL,
  label TEXT NOT NULL,
  status TEXT NOT NULL,
  authority TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_event_id TEXT,
  evidence_url TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(session_id, row_id)
);
`);
  ensureColumn(sqlite, "api_requests", "status", "TEXT NOT NULL DEFAULT 'completed'");
  ensureColumn(sqlite, "mcp_adapter_calls", "audit_nonce", "TEXT");
  ensureColumn(sqlite, "mcp_adapter_calls", "request_json", "TEXT NOT NULL DEFAULT '{}'");
  ensureColumn(sqlite, "mcp_adapter_calls", "response_json", "TEXT NOT NULL DEFAULT '{}'");
  ensureColumn(sqlite, "spends", "source_set_hash", `TEXT NOT NULL DEFAULT '${ZERO_HASH}'`);
  ensureColumn(sqlite, "spends", "session_commitment", `TEXT NOT NULL DEFAULT '${ZERO_HASH}'`);
  ensureColumn(sqlite, "spends", "spend_preimage_json", "TEXT NOT NULL DEFAULT '{}'");
  ensureColumn(sqlite, "quotes", "preflight_id", "TEXT");
  ensureColumn(sqlite, "quotes", "price_disclosure_hash", `TEXT NOT NULL DEFAULT '${ZERO_HASH}'`);
  ensureColumn(sqlite, "quotes", "source_state_snapshot_hash", `TEXT NOT NULL DEFAULT '${ZERO_HASH}'`);
  sqlite.exec("CREATE UNIQUE INDEX IF NOT EXISTS mcp_adapter_calls_audit_nonce_idx ON mcp_adapter_calls(audit_nonce) WHERE audit_nonce IS NOT NULL");
}

function ensureColumn(sqlite: DatabaseSync, table: string, column: string, ddl: string): void {
  const rows = sqlite.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!rows.some((row) => row.name === column)) {
    sqlite.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
  }
}
