#!/usr/bin/env node

import { existsSync, lstatSync } from "node:fs";
import { resolve } from "node:path";

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const PLACEHOLDER_PATTERNS = [
  /^$/,
  /^replace[-_ ]?with/i,
  /^your[-_ ]/i,
  /^example/i,
  /\.example\.com$/i,
  /^0x0+$/i,
];

const allowMissing = process.argv.includes("--allow-missing");

const checks = [];
const liveActions = [
  "fund the CAW-controlled Base Sepolia wallet with gas and the selected payment token",
  "deploy SourceStateRegistry, ProcurementGate, PaidArtifactMarket, and the payment token or bind official Base Sepolia USDC",
  "submit and sync the active Cobo Pact policy, then capture deny_probe, approve, and activate_tool CAW receipts",
  "run the source challenge plus A/B trip and C settlement flow on chain",
  "host the artifact delivery endpoint and MCP lease JSON-RPC endpoint on public HTTPS origins",
  "execute /api/v1/evidence/public-claim and export live-smoke artifacts after every gate passes",
];

requireOne("api.base_url", ["PACTFUSE_API_BASE_URL"], {
  group: "live-smoke",
  description: "URL of the running pactfuse-api instance to test",
  validate: publicHttpUrl,
});
requireOne("live.session_id", ["PACTFUSE_LIVE_SMOKE_SESSION_ID"], {
  group: "live-smoke",
  description: "already-built live evidence session id",
  validate: (value) => HEX32.test(value) && value !== ZERO_HASH,
});
requireOne("live.artifact_output_dir", ["PACTFUSE_LIVE_SMOKE_OUTPUT_DIR"], {
  group: "live-smoke",
  description: "empty directory where live-smoke writes public proof artifacts",
  validate: nonPlaceholder,
  optional: true,
});
requireOne("api.operator_token", ["PACTFUSE_OPERATOR_TOKEN"], {
  group: "security",
  description: "operator bearer token for protected public-claim and proof-bundle gates",
  secret: true,
});
requireOne("api.challenge_submitter_token", ["PACTFUSE_CHALLENGE_SUBMITTER_TOKEN"], {
  group: "security",
  description: "challenge submitter bearer token; operator-token fallback is allowed but less isolated",
  secret: true,
  optional: true,
});
requireOne("api.artifact_signer_token", ["PACTFUSE_ARTIFACT_SIGNER_TOKEN"], {
  group: "security",
  description: "artifact signer bearer token; operator-token fallback is allowed but less isolated",
  secret: true,
  optional: true,
});
requireExactBoolean("PACTFUSE_ALLOW_INSECURE_MISSING_ROLE_TOKENS", false, {
  group: "security",
  description: "must be false or unset for public proof",
});
requireExactBoolean("PACTFUSE_ALLOW_INSECURE_PUBLIC_EVIDENCE_URLS", false, {
  group: "security",
  description: "must be false or unset so replay/proof URLs use public origins",
});
requireOne("security.mcp_audit_secret", ["PACTFUSE_MCP_AUDIT_TOKEN"], {
  group: "security",
  description: "HMAC secret for MCP audit ingest",
  secret: true,
});
requireOne("security.gate_ingest_secret", ["PACTFUSE_GATE_INGEST_TOKEN"], {
  group: "security",
  description: "HMAC secret for gate/indexer event ingest",
  secret: true,
});
requireOne("security.caw_ingest_token", ["PACTFUSE_CAW_INGEST_TOKEN"], {
  group: "security",
  description: "bearer token for raw CAW receipt ingest",
  secret: true,
});
requireOne("security.proof_signing_key", ["PACTFUSE_PROOF_SIGNING_PRIVATE_KEY_PEM", "PACTFUSE_PROOF_SIGNING_PRIVATE_KEY_PATH"], {
  group: "security",
  description: "Ed25519 private key used to sign public proof-bundle verifier attestations",
  secret: true,
  validate: keyOrExistingPath,
});
requireOne("security.trusted_proof_key_hashes", ["PACTFUSE_TRUSTED_PROOF_KEY_HASHES"], {
  group: "security",
  description: "comma-separated trusted proof signing public-key hashes including the active signer",
  validate: (value) => value.split(",").map((part) => part.trim()).filter(Boolean).every((part) => HEX32.test(part) && part !== ZERO_HASH),
});

requireOne("chain.rpc", ["PACTFUSE_CHAIN_RPC_URL"], {
  group: "chain",
  description: "live public testnet RPC URL used by viem-backed proof reads",
  validate: publicHttpUrl,
});
requireOne("chain.id", ["PACTFUSE_CHAIN_ID"], {
  group: "chain",
  description: "chain id expected from RPC, normally 84532 for Base Sepolia",
  validate: (value) => /^[0-9]+$/.test(value) && value !== "0",
});
requireOne("chain.deployment_registry", ["PACTFUSE_DEPLOYMENT_REGISTRY_PATH", "PACTFUSE_DEPLOYMENT_REGISTRY_JSON"], {
  group: "chain",
  description: "live deployment registry generated from RPC receipt/code/token metadata",
  validate: registrySourceValid,
});

requireOne("caw.live_api_url", ["PACTFUSE_CAW_LIVE_API_URL", "AGENT_WALLET_API_URL"], {
  group: "cobo",
  description: "Cobo Agentic Wallet live API base URL",
  validate: coboApiUrl,
});
requireOne("caw.live_api_key", ["PACTFUSE_CAW_LIVE_API_KEY", "AGENT_WALLET_API_KEY"], {
  group: "cobo",
  description: "Cobo Agentic Wallet API key for live Pact and contract-call operations",
  secret: true,
});
requireOne("caw.live_wallet_id", ["PACTFUSE_CAW_LIVE_WALLET_ID", "AGENT_WALLET_WALLET_ID"], {
  group: "cobo",
  description: "CAW wallet id used by the identity probe and operations",
});
requireOne("caw.export_url", ["PACTFUSE_CAW_EXPORT_URL"], {
  group: "cobo",
  description: "raw CAW receipt export or audit-log source",
  validate: coboApiUrl,
});
requireOne("caw.export_api_key", ["PACTFUSE_CAW_API_KEY", "AGENT_WALLET_API_KEY"], {
  group: "cobo",
  description: "API key used to re-fetch raw CAW receipts at claim-readiness time",
  secret: true,
});
requireOne("caw.export_wallet_id", ["PACTFUSE_CAW_WALLET_ID", "AGENT_WALLET_WALLET_ID"], {
  group: "cobo",
  description: "CAW wallet id used to filter receipt export rows",
});

requireOne("mcp.lease_url", ["PACTFUSE_LEASE_MCP_URL"], {
  group: "lease",
  description: "public HTTPS JSON-RPC endpoint for the live MCP lease runner",
  validate: publicHttpUrl,
});
requireOne("mcp.lease_tool_name", ["PACTFUSE_LEASE_MCP_TOOL_NAME"], {
  group: "lease",
  description: "tool name exposed by the lease MCP runner",
  optional: true,
});

requireOne("registry.rpc", ["PACTFUSE_REGISTRY_RPC_URL"], {
  group: "registry-generation",
  description: "RPC URL used by pnpm export-deployment-registry",
  validate: publicHttpUrl,
  optional: true,
});
requireOne("registry.payment_token", ["PACTFUSE_REGISTRY_PAYMENT_TOKEN_ADDRESS"], {
  group: "registry-generation",
  description: "payment token address to bind in the live registry",
  validate: (value) => ADDRESS.test(value) && value.toLowerCase() !== ZERO_ADDRESS,
  optional: true,
});
requireOne("registry.payment_token_deploy_tx", ["PACTFUSE_REGISTRY_PAYMENT_TOKEN_DEPLOY_TX"], {
  group: "registry-generation",
  description: "non-zero deployment tx for mock-test-token fallback",
  validate: (value) => HEX32.test(value) && value !== ZERO_HASH,
  optional: true,
});
requireOne("registry.payment_token_explorer_url", ["PACTFUSE_REGISTRY_PAYMENT_TOKEN_EXPLORER_URL"], {
  group: "registry-generation",
  description: "public explorer URL for the deployment tx",
  validate: publicHttpUrl,
  optional: true,
});
requireOne("registry.official_usdc_probe", ["PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS", "PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_REASON"], {
  group: "registry-generation",
  description: "official-USDC probe status and fallback reason when using mock-test-token",
  validate: () => hasNonPlaceholder("PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS") && hasNonPlaceholder("PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_REASON"),
  optional: true,
});

const required = checks.filter((check) => !check.optional);
const missingRequired = required.filter((check) => check.status !== "pass");
const optionalMissing = checks.filter((check) => check.optional && check.status !== "pass");
const groups = groupChecks(checks);
const report = {
  ok: missingRequired.length === 0,
  summary: {
    total: checks.length,
    required: required.length,
    passedRequired: required.length - missingRequired.length,
    missingRequired: missingRequired.length,
    optionalMissing: optionalMissing.length,
  },
  missingRequired: missingRequired.map(publicCheck),
  optionalMissing: optionalMissing.map(publicCheck),
  groups,
  requiredLiveActions: liveActions,
};

console.log(JSON.stringify(report, null, 2));
if (!allowMissing && !report.ok) {
  process.exit(1);
}

function requireOne(id, names, options) {
  const values = names
    .map((name) => ({ name, value: process.env[name] }))
    .filter((entry) => entry.value !== undefined && entry.value !== null);
  const selected = values.find((entry) => nonPlaceholder(String(entry.value)));
  let status = "pass";
  let reason = "configured";
  if (!selected) {
    status = "missing";
    reason = `set ${names.join(" or ")}`;
  } else if (options.validate && !options.validate(String(selected.value))) {
    status = "invalid";
    reason = `${selected.name} is present but invalid or placeholder`;
  }
  checks.push({
    id,
    group: options.group,
    names,
    configuredName: selected?.name ?? null,
    status,
    reason,
    description: options.description,
    secret: Boolean(options.secret),
    optional: Boolean(options.optional),
  });
}

function requireExactBoolean(name, expected, options) {
  const raw = process.env[name];
  let status = "pass";
  let reason = raw === undefined || raw === "" ? `${name} unset, treated as false` : `${name}=${raw.trim()}`;
  if (raw !== undefined && raw !== "") {
    const parsed = parseBoolean(raw);
    if (parsed === null) {
      status = "invalid";
      reason = `${name} must be true,false,1,0,yes,no,on,off`;
    } else if (parsed !== expected) {
      status = "invalid";
      reason = `${name} must be ${expected}`;
    }
  }
  checks.push({
    id: `boolean.${name}`,
    group: options.group,
    names: [name],
    configuredName: raw === undefined ? null : name,
    status,
    reason,
    description: options.description,
    secret: false,
    optional: false,
  });
}

function parseBoolean(value) {
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return null;
}

function groupChecks(items) {
  const output = {};
  for (const check of items) {
    output[check.group] ??= [];
    output[check.group].push(publicCheck(check));
  }
  return output;
}

function publicCheck(check) {
  return {
    id: check.id,
    names: check.names,
    configuredName: check.configuredName,
    status: check.status,
    optional: check.optional,
    secret: check.secret,
    reason: check.reason,
    description: check.description,
  };
}

function nonPlaceholder(value) {
  const trimmed = value.trim();
  return !PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function hasNonPlaceholder(name) {
  return typeof process.env[name] === "string" && nonPlaceholder(String(process.env[name]));
}

function publicHttpUrl(value) {
  if (!nonPlaceholder(value)) return false;
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") && Boolean(url.hostname);
  } catch {
    return false;
  }
}

function coboApiUrl(value) {
  if (!publicHttpUrl(value)) return false;
  try {
    const url = new URL(value);
    return url.hostname === "api.cobo.com" || url.hostname === "api.dev.cobo.com" || url.hostname.endsWith(".cobo.com");
  } catch {
    return false;
  }
}

function keyOrExistingPath(value) {
  if (!nonPlaceholder(value)) return false;
  if (value.includes("BEGIN PRIVATE KEY")) return true;
  const path = resolve(value);
  try {
    return existsSync(path) && lstatSync(path).isFile();
  } catch {
    return false;
  }
}

function registrySourceValid(value) {
  if (!nonPlaceholder(value)) return false;
  if (value.trim().startsWith("{")) return true;
  const path = resolve(value);
  try {
    return existsSync(path) && lstatSync(path).isFile();
  } catch {
    return false;
  }
}
