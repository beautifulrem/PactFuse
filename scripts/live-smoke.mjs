#!/usr/bin/env node

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { link, lstat, mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;
const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const PUBLIC_EXPLORER_HOST_PATTERNS = [
  /(^|\.)basescan\.org$/,
  /(^|\.)etherscan\.io$/,
  /(^|\.)etherscan\.org$/,
  /(^|\.)arbiscan\.io$/,
  /(^|\.)optimistic\.etherscan\.io$/,
  /(^|\.)polygonscan\.com$/,
  /(^|\.)blockscout\.com$/,
  /(^|\.)routescan\.io$/,
];

const baseUrl = stripTrailingSlash(process.env.PACTFUSE_API_BASE_URL ?? "http://127.0.0.1:8787");
const operatorToken = process.env.PACTFUSE_OPERATOR_TOKEN;
const sessionId = process.env.PACTFUSE_LIVE_SMOKE_SESSION_ID;
const requirePublicClaim = booleanEnv("PACTFUSE_LIVE_SMOKE_REQUIRE_PUBLIC_CLAIM", true);
const requiredProviders = listEnv("PACTFUSE_LIVE_SMOKE_REQUIRED_PROVIDERS", ["chain", "caw_live", "caw", "mcp_lease"]);
const trustedProofKeyHashes = new Set(listEnv("PACTFUSE_TRUSTED_PROOF_KEY_HASHES", []).map((value) => value.toLowerCase()));
const artifactOutputDir = process.env.PACTFUSE_LIVE_SMOKE_OUTPUT_DIR ? resolve(process.env.PACTFUSE_LIVE_SMOKE_OUTPUT_DIR) : null;

try {
  assert(operatorToken, "PACTFUSE_OPERATOR_TOKEN is required");
  assert(sessionId && HEX32.test(sessionId), "PACTFUSE_LIVE_SMOKE_SESSION_ID must be a 32-byte hex session id");

  const ready = await requestJson("/readyz");
  assert(ready.ok === true, "/readyz did not return ok=true", ready);
  assert(ready.proofProviderCheck?.checked === true, "/readyz did not run deep proof-provider checks", ready.proofProviderCheck);
  assert(ready.apiSecurity?.operatorTokenConfigured === true, "operator token is not configured", ready.apiSecurity);
  assert(ready.apiSecurity?.allowInsecureMissingRoleTokens === false, "insecure missing-role-token bypass is enabled", ready.apiSecurity);
  assert(ready.mcpAudit?.configured === true, "PACTFUSE_MCP_AUDIT_TOKEN is not configured", ready.mcpAudit);
  assert(ready.gateIngest?.configured === true, "PACTFUSE_GATE_INGEST_TOKEN is not configured", ready.gateIngest);
  assert(ready.proofBundleSigning?.configured === true, "proof bundle signing key is not configured", ready.proofBundleSigning);
  assert(
    trustedProofKeyHashes.has(String(ready.proofBundleSigning?.publicKeyHash ?? "").toLowerCase()),
    "readyz proof bundle signing publicKeyHash is not trusted",
    ready.proofBundleSigning,
  );

  const providers = new Map((ready.proofProviders ?? []).map((provider) => [provider.name, provider]));
  for (const providerName of requiredProviders) {
    const provider = providers.get(providerName);
    assert(provider?.ready === true, `proof provider ${providerName} is not ready`, provider ?? { name: providerName, ready: false });
  }

  const preflight = await requestJson(`/api/v1/evidence/live-preflight?sessionId=${encodeURIComponent(sessionId)}`);
  const preflightData = preflight.data;
  assert(preflight.ok === true && preflightData, "live-preflight did not return data", preflight);
  assert(preflightData.status === "ready", "live-preflight status is not ready", preflightData);
  assert(preflightData.readyForPublicClaim === true, "live-preflight is not ready for public claim", preflightData);
  assert(preflightData.winnerClaimAllowed === true, "live-preflight winnerClaimAllowed is not true", preflightData);
  assert((preflightData.blockingReasons ?? []).length === 0, "live-preflight still has blockers", preflightData.blockingReasons);
  assert((preflightData.requiredExternalInputs ?? []).length === 0, "live-preflight still requires external inputs", preflightData.requiredExternalInputs);
  for (const check of preflightData.checks ?? []) {
    assert(check.status === "pass", `live-preflight check ${check.checkId} did not pass`, check);
  }
  assert(preflightData.security?.cawIngestTokenConfigured === true, "PACTFUSE_CAW_INGEST_TOKEN is not configured", preflightData.security);

  let claimData = null;
  let proofBundleData = null;
  if (requirePublicClaim) {
    const claim = await requestJson(`/api/v1/evidence/public-claim?sessionId=${encodeURIComponent(sessionId)}`);
    claimData = claim.data;
    assert(claim.ok === true && claimData, "public-claim did not return data", claim);
    assert(claimData.claimStatus === "authorized_public_claim", "public-claim is not authorized", claimData);
    assert(claimData.proofChipAllowed === true, "public-claim proofChipAllowed is not true", claimData);
    assert(claimData.finalVerifierComplete === true, "public-claim finalVerifierComplete is not true", claimData);
    assert(claimData.winnerClaimAllowed === true, "public-claim winnerClaimAllowed is not true", claimData);
    assert(claimData.sessionId === sessionId, "public-claim sessionId does not match PACTFUSE_LIVE_SMOKE_SESSION_ID", {
      expected: sessionId,
      actual: claimData.sessionId,
    });
    assert(claimData.snapshotScope === "authorization_event", "public-claim snapshotScope is not authorization_event", claimData);
    assert(claimData.providerSnapshotOnly === true, "public-claim providerSnapshotOnly is not true", claimData);
    assert(typeof claimData.authorizedAt === "string" && claimData.authorizedAt.length > 0, "public-claim authorizedAt is missing", claimData);
    assert(
      Number.isInteger(claimData.authorizedEventSeq) && claimData.authorizedEventSeq > 1,
      "public-claim authorizedEventSeq is missing or invalid",
      claimData,
    );
    assert(
      Number.isInteger(claimData.asOfEventSeq) && claimData.asOfEventSeq === claimData.authorizedEventSeq - 1,
      "public-claim asOfEventSeq does not precede authorizedEventSeq",
      claimData,
    );
    assert(HEX32.test(claimData.providerStatusHash), "public-claim providerStatusHash is missing or invalid", claimData);
    assert(HEX32.test(claimData.serverHash), "public-claim serverHash is missing or invalid", claimData);
    assert(HEX32.test(claimData.publicClaimHash), "public-claim hash is missing or invalid", claimData);

    const proofBundle = await requestJson(`/api/v1/evidence/proof-bundle?sessionId=${encodeURIComponent(sessionId)}`);
    proofBundleData = proofBundle.data;
    assert(proofBundle.ok === true && proofBundleData, "proof-bundle did not return data", proofBundle);
    assert(proofBundleData.bundleType === "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1", "proof-bundle has the wrong bundle type", proofBundleData);
    assert(proofBundleData.winnerClaimAllowed === true, "proof-bundle winnerClaimAllowed is not true", proofBundleData);
    assert(proofBundleData.sessionId === sessionId, "proof-bundle sessionId does not match PACTFUSE_LIVE_SMOKE_SESSION_ID", {
      expected: sessionId,
      actual: proofBundleData.sessionId,
    });
    assert(proofBundleData.publicClaim?.sessionId === sessionId, "proof-bundle embedded publicClaim sessionId does not match", {
      expected: sessionId,
      actual: proofBundleData.publicClaim?.sessionId,
    });
    assert(proofBundleData.replayBundle?.sessionId === sessionId, "proof-bundle embedded replayBundle sessionId does not match", {
      expected: sessionId,
      actual: proofBundleData.replayBundle?.sessionId,
    });
    assert(proofBundleData.publicClaimHash === claimData.publicClaimHash, "proof-bundle public claim hash does not match public-claim", {
      proofBundlePublicClaimHash: proofBundleData.publicClaimHash,
      publicClaimHash: claimData.publicClaimHash,
    });
    assert(proofBundleData.claimInputReplayBundleHash === claimData.replayBundleHash, "proof-bundle claim input replay hash does not match public-claim", {
      claimInputReplayBundleHash: proofBundleData.claimInputReplayBundleHash,
      publicClaimReplayBundleHash: claimData.replayBundleHash,
    });
    assert(proofBundleData.replayBundleHash === claimData.replayBundleHash, "proof-bundle final replay hash does not match public-claim", {
      proofBundleReplayBundleHash: proofBundleData.replayBundleHash,
      publicClaimReplayBundleHash: claimData.replayBundleHash,
    });
    assert(HEX32.test(proofBundleData.proofBundleHash), "proof-bundle hash is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.publicClaimEventId), "proof-bundle public claim event id is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.publicClaimEventHash), "proof-bundle public claim event hash is missing or invalid", proofBundleData);
    assert(
      Number.isInteger(proofBundleData.publicClaimEventSeq) && proofBundleData.publicClaimEventSeq > 1,
      "proof-bundle public claim event seq is missing or invalid",
      proofBundleData,
    );
    assert(proofBundleData.snapshotScope === "authorization_event", "proof-bundle snapshotScope is not authorization_event", proofBundleData);
    assert(proofBundleData.providerSnapshotOnly === true, "proof-bundle providerSnapshotOnly is not true", proofBundleData);
    assert(proofBundleData.authorizedAt === claimData.authorizedAt, "proof-bundle authorizedAt does not match public-claim", {
      proofBundleAuthorizedAt: proofBundleData.authorizedAt,
      claimAuthorizedAt: claimData.authorizedAt,
    });
    assert(proofBundleData.asOfEventSeq === claimData.asOfEventSeq, "proof-bundle asOfEventSeq does not match public-claim", {
      proofBundleAsOfEventSeq: proofBundleData.asOfEventSeq,
      claimAsOfEventSeq: claimData.asOfEventSeq,
    });
    assert(
      proofBundleData.publicClaimEventSeq === claimData.authorizedEventSeq && proofBundleData.asOfEventSeq === proofBundleData.publicClaimEventSeq - 1,
      "proof-bundle public claim event seq is not bound to the authorization snapshot",
      proofBundleData,
    );
    assert(HEX32.test(proofBundleData.providerStatusHash), "proof-bundle provider status hash is missing or invalid", proofBundleData);
    assert(HEX32.test(proofBundleData.serverHash), "proof-bundle server hash is missing or invalid", proofBundleData);
    verifyProofBundleHashes(proofBundleData, claimData);
  }

  const artifactManifest = artifactOutputDir
    ? await exportLiveSmokeArtifacts({
        outputDir: artifactOutputDir,
        preflight: preflightData,
        publicClaim: claimData,
        proofBundle: proofBundleData,
      })
    : null;

  console.log(
    JSON.stringify(
      {
        ok: true,
        baseUrl,
        sessionId,
        requiredProviders,
        livePreflightStatus: preflightData.status,
        publicClaimHash: claimData?.publicClaimHash ?? null,
        proofBundleHash: proofBundleData?.proofBundleHash ?? null,
        artifactDir: artifactManifest?.artifactDir ?? null,
        artifactManifestHash: artifactManifest?.manifestHash ?? null,
      },
      null,
      2,
    ),
  );
} catch (error) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        baseUrl,
        sessionId: sessionId ?? null,
        error: error instanceof Error ? error.message : String(error),
        details: error && typeof error === "object" && "details" in error ? error.details : undefined,
      },
      null,
      2,
    ),
  );
  process.exit(1);
}

async function requestJson(path) {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: {
      authorization: `Bearer ${operatorToken}`,
      accept: "application/json",
    },
  });
  const text = await response.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw withDetails(new Error(`${path} returned non-JSON response`), { status: response.status, body: text.slice(0, 500) });
  }
  if (!response.ok) {
    throw withDetails(new Error(`${path} returned HTTP ${response.status}`), json);
  }
  return json;
}

async function exportLiveSmokeArtifacts(input) {
  await prepareArtifactOutputDir(input.outputDir);
  const artifacts = [];
  artifacts.push(await writeJsonArtifact(input.outputDir, "live-preflight.json", input.preflight));
  if (input.publicClaim) {
    artifacts.push(await writeJsonArtifact(input.outputDir, "public-claim.json", input.publicClaim));
  }
  if (input.proofBundle) {
    artifacts.push(await writeJsonArtifact(input.outputDir, "proof-bundle.json", input.proofBundle));
  }
  const manifestBase = {
    manifestType: "PACTFUSE_LIVE_SMOKE_ARTIFACTS_V1",
    generatedAt: new Date().toISOString(),
    sessionId,
    requiredProviders,
    livePreflightStatus: input.preflight.status,
    publicClaimHash: input.publicClaim?.publicClaimHash ?? null,
    proofBundleHash: input.proofBundle?.proofBundleHash ?? null,
    replayBundleHash: input.proofBundle?.replayBundleHash ?? input.publicClaim?.replayBundleHash ?? null,
    publicClaimEventHash: input.proofBundle?.publicClaimEventHash ?? null,
    providerStatusHash: input.proofBundle?.providerStatusHash ?? input.publicClaim?.providerStatusHash ?? null,
    deploymentRegistryHash: input.proofBundle?.deploymentRegistryHash ?? input.publicClaim?.deploymentRegistryHash ?? null,
    serverHash: input.proofBundle?.serverHash ?? input.publicClaim?.serverHash ?? null,
    artifacts,
  };
  const manifestHash = hashJson(manifestBase);
  const manifest = { ...manifestBase, manifestHash };
  await writeJsonArtifact(input.outputDir, "manifest.json", manifest);
  return { artifactDir: input.outputDir, manifestHash };
}

async function writeJsonArtifact(outputDir, name, value) {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  await writeNoOverwrite(join(outputDir, name), body);
  return {
    name,
    canonicalHash: hashJson(value),
    byteSha256: `0x${createHash("sha256").update(body).digest("hex")}`,
    bytes: Buffer.byteLength(body, "utf8"),
  };
}

async function prepareArtifactOutputDir(outputDir) {
  let stat = null;
  try {
    stat = await lstat(outputDir);
  } catch (error) {
    if (!isNodeErrorCode(error, "ENOENT")) {
      throw error;
    }
  }
  if (!stat) {
    await mkdir(outputDir, { recursive: true, mode: 0o755 });
    stat = await lstat(outputDir);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("PACTFUSE_LIVE_SMOKE_OUTPUT_DIR must be a real directory, not a symlink or file");
  }
  const existing = await readdir(outputDir);
  if (existing.length > 0) {
    throw new Error("PACTFUSE_LIVE_SMOKE_OUTPUT_DIR must be empty to avoid overwriting prior proof artifacts");
  }
}

async function writeNoOverwrite(path, body) {
  const tempPath = `${path}.tmp-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  try {
    await writeFile(tempPath, body, { encoding: "utf8", mode: 0o644, flag: "wx" });
    await link(tempPath, path);
  } finally {
    try {
      await unlink(tempPath);
    } catch (error) {
      if (!isNodeErrorCode(error, "ENOENT")) {
        throw error;
      }
    }
  }
}

function isNodeErrorCode(error, code) {
  return Boolean(error && typeof error === "object" && "code" in error && error.code === code);
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function booleanEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  return !["0", "false", "no", "off"].includes(raw.trim().toLowerCase());
}

function listEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const values = raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  return values.length > 0 ? values : fallback;
}

function verifyProofBundleHashes(proofBundle, claim) {
  assert(canonicalizeJson(proofBundle.publicClaim) === canonicalizeJson(claim), "proof-bundle publicClaim does not match public-claim response", {
    proofBundlePublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
    publicClaimHash: claim?.publicClaimHash,
  });
  assert(proofBundle.publicClaim?.publicClaimHash === proofBundle.publicClaimHash, "proof-bundle publicClaimHash does not match embedded publicClaim", {
    proofBundlePublicClaimHash: proofBundle.publicClaimHash,
    embeddedPublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
  });
  assert(
    hashJson(publicClaimHashInput(proofBundle.publicClaim)) === proofBundle.publicClaimHash,
    "proof-bundle publicClaimHash does not recompute from embedded publicClaim",
    {
      expected: proofBundle.publicClaimHash,
      actual: hashJson(publicClaimHashInput(proofBundle.publicClaim)),
    },
  );
  verifyPublicClaimVerifierRun(proofBundle);
  verifyPublicClaimModeAlignment(proofBundle);
  verifyPublicClaimSnapshotBinding(proofBundle);
  verifyReplayDeploymentRegistryBinding(proofBundle);
  verifyPublicClaimDeploymentRegistry(proofBundle);
  verifyPublicReplayUrls(proofBundle.replayBundle);
  verifyProofBundleAttestation(proofBundle);
  assert(hashJson(proofBundle.replayBundle) === proofBundle.replayBundleHash, "proof-bundle replayBundleHash does not recompute", {
    expected: proofBundle.replayBundleHash,
    actual: hashJson(proofBundle.replayBundle),
  });
  assert(hashJson(proofBundle.publicClaim.verifierRun) === proofBundle.verifierRunHash, "proof-bundle verifierRunHash does not recompute", {
    expected: proofBundle.verifierRunHash,
    actual: hashJson(proofBundle.publicClaim.verifierRun),
  });
  verifyProofBundleProviderStatuses(proofBundle);
  assert(hashJson(proofBundle.providerStatuses) === proofBundle.providerStatusHash, "proof-bundle providerStatusHash does not recompute", {
    expected: proofBundle.providerStatusHash,
    actual: hashJson(proofBundle.providerStatuses),
  });
  const deploymentRegistryHash = proofBundle.deploymentRegistry === null ? null : hashJson(proofBundle.deploymentRegistry);
  assert(deploymentRegistryHash === proofBundle.deploymentRegistryHash, "proof-bundle deploymentRegistryHash does not recompute", {
    expected: proofBundle.deploymentRegistryHash,
    actual: deploymentRegistryHash,
  });
  assert(hashJson(proofBundle.server) === proofBundle.serverHash, "proof-bundle serverHash does not recompute", {
    expected: proofBundle.serverHash,
    actual: hashJson(proofBundle.server),
  });
  const previousProofEventHash = verifyReplayBundleEvents(proofBundle.replayBundle, proofBundle.publicClaimEventSeq - 1);
  verifyPublicClaimEventHash(proofBundle, previousProofEventHash);
  const bundleBase = { ...proofBundle };
  delete bundleBase.proofBundleHash;
  assert(hashJson(bundleBase) === proofBundle.proofBundleHash, "proof-bundle hash does not recompute", {
    expected: proofBundle.proofBundleHash,
    actual: hashJson(bundleBase),
  });
}

function verifyProofBundleAttestation(proofBundle) {
  const attestation = proofBundle.verifierAttestation;
  assert(isObject(attestation), "proof-bundle verifierAttestation is missing", proofBundle);
  assert(attestation.scheme === "ed25519", "proof-bundle verifierAttestation scheme is not ed25519", attestation);
  assert(typeof attestation.publicKeyPem === "string" && attestation.publicKeyPem.length > 0, "proof-bundle verifierAttestation publicKeyPem is missing", attestation);
  assert(HEX32.test(attestation.publicKeyHash), "proof-bundle verifierAttestation publicKeyHash is missing or invalid", attestation);
  assert(HEX32.test(attestation.signedPayloadHash), "proof-bundle verifierAttestation signedPayloadHash is missing or invalid", attestation);
  assert(typeof attestation.signature === "string" && attestation.signature.length > 0, "proof-bundle verifierAttestation signature is missing", attestation);
  const publicKeyHash = hashText(attestation.publicKeyPem);
  assert(sameHex(publicKeyHash, attestation.publicKeyHash), "proof-bundle verifierAttestation publicKeyHash does not match publicKeyPem", {
    expected: attestation.publicKeyHash,
    actual: publicKeyHash,
  });
  assert(trustedProofKeyHashes.size > 0, "PACTFUSE_TRUSTED_PROOF_KEY_HASHES is required for public proof bundle verification");
  assert(
    trustedProofKeyHashes.has(String(attestation.publicKeyHash).toLowerCase()),
    "proof-bundle verifierAttestation publicKeyHash is not trusted",
    attestation,
  );
  const signedPayloadHash = hashJson(publicProofBundleVerifierAttestationInput(proofBundle, attestation));
  assert(sameHex(signedPayloadHash, attestation.signedPayloadHash), "proof-bundle verifierAttestation signedPayloadHash does not recompute", {
    expected: attestation.signedPayloadHash,
    actual: signedPayloadHash,
  });
  const signatureOk = cryptoVerify(
    null,
    Buffer.from(String(attestation.signedPayloadHash).slice(2), "hex"),
    createPublicKey(attestation.publicKeyPem),
    Buffer.from(attestation.signature, "base64"),
  );
  assert(signatureOk, "proof-bundle verifierAttestation signature is invalid", attestation);
}

function publicProofBundleVerifierAttestationInput(proofBundle, attestation) {
  return {
    attestationType: "PACTFUSE_PUBLIC_PROOF_VERIFIER_ATTESTATION_V1",
    scheme: attestation.scheme,
    keyId: attestation.keyId,
    publicKeyHash: attestation.publicKeyHash,
    bundleType: "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1",
    sessionId: proofBundle.sessionId,
    publicClaimHash: proofBundle.publicClaimHash,
    publicClaimEventSeq: proofBundle.publicClaimEventSeq,
    snapshotScope: "authorization_event",
    providerSnapshotOnly: true,
    authorizedAt: proofBundle.authorizedAt,
    asOfEventSeq: proofBundle.asOfEventSeq,
    claimInputReplayBundleHash: proofBundle.claimInputReplayBundleHash,
    replayBundleHash: proofBundle.replayBundleHash,
    verifierRunHash: proofBundle.verifierRunHash,
    providerStatusHash: proofBundle.providerStatusHash,
    deploymentRegistryHash: proofBundle.deploymentRegistryHash,
    serverHash: proofBundle.serverHash,
    winnerClaimAllowed: true,
  };
}

function verifyPublicClaimSnapshotBinding(proofBundle) {
  const claim = proofBundle.publicClaim;
  assert(isObject(claim), "proof-bundle publicClaim is missing", proofBundle.publicClaim);
  assert(claim.snapshotScope === "authorization_event", "proof-bundle publicClaim snapshotScope is not authorization_event", claim);
  assert(claim.providerSnapshotOnly === true, "proof-bundle publicClaim providerSnapshotOnly is not true", claim);
  assert(claim.authorizedEventSeq === proofBundle.publicClaimEventSeq, "publicClaim authorizedEventSeq does not match proof-bundle event seq", {
    authorizedEventSeq: claim.authorizedEventSeq,
    publicClaimEventSeq: proofBundle.publicClaimEventSeq,
  });
  assert(claim.asOfEventSeq === proofBundle.publicClaimEventSeq - 1, "publicClaim asOfEventSeq does not precede proof-bundle event seq", {
    asOfEventSeq: claim.asOfEventSeq,
    publicClaimEventSeq: proofBundle.publicClaimEventSeq,
  });
  assert(proofBundle.asOfEventSeq === claim.asOfEventSeq, "proof-bundle asOfEventSeq does not match publicClaim", {
    proofBundleAsOfEventSeq: proofBundle.asOfEventSeq,
    publicClaimAsOfEventSeq: claim.asOfEventSeq,
  });
  assert(proofBundle.authorizedAt === claim.authorizedAt, "proof-bundle authorizedAt does not match publicClaim", {
    proofBundleAuthorizedAt: proofBundle.authorizedAt,
    publicClaimAuthorizedAt: claim.authorizedAt,
  });
  assert(claim.providerStatusHash === proofBundle.providerStatusHash, "publicClaim providerStatusHash does not match proof-bundle snapshot", {
    publicClaimProviderStatusHash: claim.providerStatusHash,
    proofBundleProviderStatusHash: proofBundle.providerStatusHash,
  });
  assert(claim.deploymentRegistryHash === proofBundle.deploymentRegistryHash, "publicClaim deploymentRegistryHash does not match proof-bundle snapshot", {
    publicClaimDeploymentRegistryHash: claim.deploymentRegistryHash,
    proofBundleDeploymentRegistryHash: proofBundle.deploymentRegistryHash,
  });
  assert(claim.serverHash === proofBundle.serverHash, "publicClaim serverHash does not match proof-bundle snapshot", {
    publicClaimServerHash: claim.serverHash,
    proofBundleServerHash: proofBundle.serverHash,
  });
}

function verifyPublicClaimVerifierRun(proofBundle) {
  const verifierRun = proofBundle.publicClaim?.verifierRun;
  assert(isObject(verifierRun), "proof-bundle publicClaim.verifierRun is missing", proofBundle.publicClaim);
  assert(verifierRun.proofLevel === "final_replay_claim", "proof-bundle verifierRun proofLevel is not final_replay_claim", verifierRun);
  assert(verifierRun.schemaOk === true, "proof-bundle verifierRun schemaOk is not true", verifierRun);
  assert(verifierRun.proofChipAllowed === true, "proof-bundle verifierRun proofChipAllowed is not true", verifierRun);
  assert(verifierRun.finalVerifierComplete === true, "proof-bundle verifierRun finalVerifierComplete is not true", verifierRun);
  assert(verifierRun.winnerClaimAllowed === true, "proof-bundle verifierRun winnerClaimAllowed is not true", verifierRun);
  assert(verifierRun.requestedWinnerClaimAllowed === true, "proof-bundle verifierRun requestedWinnerClaimAllowed is not true", verifierRun);
  assert(Array.isArray(verifierRun.errors) && verifierRun.errors.length === 0, "proof-bundle verifierRun errors is not empty", verifierRun);
  assert(Array.isArray(verifierRun.warnings) && verifierRun.warnings.length === 0, "proof-bundle verifierRun warnings is not empty", verifierRun);
}

function verifyPublicClaimModeAlignment(proofBundle) {
  const claim = proofBundle.publicClaim;
  const verifierRun = claim?.verifierRun;
  assert(isObject(claim) && isObject(verifierRun), "proof-bundle publicClaim/verifierRun is missing", claim);
  for (const field of ["claimMode", "paymentMode", "tokenMode", "identityMode"]) {
    assert(claim[field] === verifierRun[field], `proof-bundle publicClaim.${field} does not match verifierRun.${field}`, {
      publicClaim: claim[field],
      verifierRun: verifierRun[field],
    });
  }
  const expectedTokenSettlementClaim = tokenSettlementClaimForTokenMode(claim.tokenMode);
  assert(
    expectedTokenSettlementClaim && claim.tokenSettlementClaim === expectedTokenSettlementClaim,
    "proof-bundle publicClaim.tokenSettlementClaim does not match tokenMode",
    {
      tokenMode: claim.tokenMode,
      tokenSettlementClaim: claim.tokenSettlementClaim,
      expectedTokenSettlementClaim,
    },
  );
  for (const field of ["proofChipAllowed", "finalVerifierComplete", "winnerClaimAllowed"]) {
    assert(claim[field] === verifierRun[field], `proof-bundle publicClaim.${field} does not match verifierRun.${field}`, {
      publicClaim: claim[field],
      verifierRun: verifierRun[field],
    });
  }
  assert(proofBundle.winnerClaimAllowed === claim.winnerClaimAllowed, "proof-bundle winnerClaimAllowed does not match publicClaim", {
    proofBundle: proofBundle.winnerClaimAllowed,
    publicClaim: claim.winnerClaimAllowed,
  });
}

function tokenSettlementClaimForTokenMode(tokenMode) {
  if (tokenMode === "official-testnet-usdc") {
    return "official-testnet-usdc";
  }
  if (tokenMode === "mock-test-token") {
    return "live-mock-erc20-fallback";
  }
  return null;
}

function verifyProofBundleProviderStatuses(proofBundle) {
  const providers = Array.isArray(proofBundle.providerStatuses) ? proofBundle.providerStatuses : [];
  assert(providers.length > 0, "proof-bundle providerStatuses is missing or empty", proofBundle.providerStatuses);
  const providersByName = new Map(providers.filter(isObject).map((provider) => [provider.name, provider]));
  for (const providerName of requiredProviders) {
    const provider = providersByName.get(providerName);
    assert(provider?.mode === "live" && provider.ready === true, `proof-bundle provider ${providerName} is not live and ready`, provider ?? null);
  }
}

function verifyReplayDeploymentRegistryBinding(proofBundle) {
  const replayBundle = proofBundle.replayBundle;
  assert(isObject(replayBundle), "proof-bundle replayBundle must be an object", replayBundle);
  assert(
    Object.prototype.hasOwnProperty.call(replayBundle, "deploymentRegistry"),
    "proof-bundle replayBundle.deploymentRegistry is missing",
    replayBundle,
  );
  assert(
    Object.prototype.hasOwnProperty.call(replayBundle, "deploymentRegistryHash"),
    "proof-bundle replayBundle.deploymentRegistryHash is missing",
    replayBundle,
  );
  const replayDeploymentRegistryHash = replayBundle.deploymentRegistry === null ? null : hashJson(replayBundle.deploymentRegistry);
  assert(
    replayDeploymentRegistryHash === replayBundle.deploymentRegistryHash,
    "proof-bundle replay deploymentRegistryHash does not recompute",
    {
      expected: replayBundle.deploymentRegistryHash,
      actual: replayDeploymentRegistryHash,
    },
  );
  assert(
    canonicalizeJson(replayBundle.deploymentRegistry) === canonicalizeJson(proofBundle.deploymentRegistry),
    "proof-bundle replay deploymentRegistry does not match authorization snapshot",
    {
      replayDeploymentRegistryHash,
      proofBundleDeploymentRegistryHash: proofBundle.deploymentRegistryHash,
    },
  );
  assert(
    replayBundle.deploymentRegistryHash === proofBundle.deploymentRegistryHash,
    "proof-bundle replay deploymentRegistryHash does not match authorization snapshot",
    {
      replayDeploymentRegistryHash: replayBundle.deploymentRegistryHash,
      proofBundleDeploymentRegistryHash: proofBundle.deploymentRegistryHash,
    },
  );
}

function verifyPublicClaimDeploymentRegistry(proofBundle) {
  const tokenMode = proofBundle.publicClaim?.tokenMode;
  if (tokenMode !== "mock-test-token" && tokenMode !== "official-testnet-usdc") {
    return;
  }
  const registry = proofBundle.deploymentRegistry;
  assert(isObject(registry) && registry.mode === "live", "public claim tokenMode requires live deployment registry", {
    tokenMode,
    deploymentRegistryHash: proofBundle.deploymentRegistryHash,
  });
  const quote = replayRowsForCollection(proofBundle.replayBundle, "quotes").find(
    (candidate) => candidate?.status === "chain_settleable_after_preflight",
  );
  assert(isObject(quote), "public claim tokenMode requires a chain-settleable quote in the replay bundle", proofBundle.replayBundle?.quotes);
  const spend = replayRowsForCollection(proofBundle.replayBundle, "spends").find((candidate) => candidate?.spendId === quote.spendId);
  assert(isObject(spend), "public claim tokenMode requires the chain-settleable quote spend in the replay bundle", {
    quoteId: quote.quoteId,
    spendId: quote.spendId,
  });
  assert(String(registry.chainId) === String(quote.chainId), "deployment registry chainId must match the chain-settleable quote", {
    registryChainId: registry.chainId,
    quoteChainId: quote.chainId,
  });
  const entry = (registry.entries ?? []).find(
    (candidate) =>
      candidate?.contractName === "PaymentToken" &&
      String(candidate.chainId) === String(quote.chainId) &&
      sameHex(candidate.address, spend.paymentToken) &&
      candidate.tokenMode === tokenMode,
  );
  assert(isObject(entry), "public claim tokenMode requires a matching PaymentToken deployment registry entry", {
    tokenMode,
    chainId: quote.chainId,
    paymentToken: spend.paymentToken,
  });
  assert(
    HEX32.test(entry.deploymentTxHash) &&
      entry.deploymentTxHash !== ZERO_HASH &&
      isPublicExplorerUrl(entry.explorerUrl) &&
      explorerUrlContainsTxHash(entry.explorerUrl, entry.deploymentTxHash) &&
      HEX32.test(entry.codeHash) &&
      entry.codeHash !== ZERO_HASH &&
      Number.isInteger(entry.decimals),
    "PaymentToken deployment registry entry is not live-proof complete",
    entry,
  );
  verifyLiveContractDeploymentRegistryEntries(proofBundle, registry, quote, spend);
  const probe = registry.officialUsdcProbe;
  if (tokenMode === "official-testnet-usdc") {
    assert(sameHex(spend.paymentToken, BASE_SEPOLIA_USDC) && String(quote.chainId) === "84532", "official USDC claim must use Base Sepolia USDC", {
      paymentToken: spend.paymentToken,
      chainId: quote.chainId,
    });
    assert(probe?.status === "passed", "official USDC claim requires a passed official-USDC probe", probe);
    return;
  }
  assert(
    probe?.status === "failed" && typeof probe.reason === "string" && probe.reason.length > 0,
    "mock token claim requires a failed official-USDC probe reason",
    probe,
  );
}

function verifyPublicReplayUrls(replayBundle) {
  for (const source of Array.isArray(replayBundle?.sources) ? replayBundle.sources : []) {
    if (source?.manifestUrl !== undefined) {
      assertPublicReplayUrl(`source ${source.sourceHash ?? "-"} manifestUrl`, source.manifestUrl);
    }
  }
  for (const preflight of Array.isArray(replayBundle?.artifactPreflights) ? replayBundle.artifactPreflights : []) {
    if (preflight?.endpointUrl !== undefined) {
      assertPublicReplayUrl(`artifact preflight ${preflight.preflightId ?? "-"} endpointUrl`, preflight.endpointUrl);
    }
  }
}

function assertPublicReplayUrl(label, value) {
  assert(typeof value === "string" && value.length > 0, `${label} must be a URL string`, value);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw withDetails(new Error(`${label} must be a valid URL`), value);
  }
  assert(url.protocol === "https:" || url.protocol === "http:", `${label} must use HTTP or HTTPS`, value);
  assert(!url.username && !url.password && !url.search && !url.hash, `${label} must not contain credentials, query strings, or fragments`, value);
  assert(isPublicReplayHostname(url.hostname), `${label} must use a public hostname`, value);
}

function verifyLiveContractDeploymentRegistryEntries(proofBundle, registry, quote, spend) {
  const requirements = new Map();
  const addRequirement = (contractName, address, chainId) => {
    if (!isEvmAddress(address) || String(chainId ?? "").length === 0) {
      return;
    }
    const key = `${contractName}:${String(chainId)}:${address.toLowerCase()}`;
    requirements.set(key, { contractName, address: address.toLowerCase(), chainId: String(chainId) });
  };

  const events = replayRowsForCollection(proofBundle.replayBundle, "events");
  for (const event of events) {
    const payload = isObject(event?.payload) ? event.payload : {};
    if ((event?.kind === "gate.spend_tripped" || event?.kind === "gate.spend_settled") && liveContractProofFinalized(payload)) {
      addRequirement("ProcurementGate", payload.contractAddress, payload.chainId);
    }
    if (event?.kind === "source.challenge.confirmed" && liveContractProofFinalized(payload)) {
      addRequirement("SourceStateRegistry", payload.sourceRegistryAddress, payload.chainId);
    }
  }
  if (quote.status === "chain_settleable_after_preflight") {
    addRequirement("PaidArtifactMarket", spend.market, quote.chainId);
  }

  for (const requirement of requirements.values()) {
    assert(String(registry.chainId) === requirement.chainId, `deployment registry chainId must match ${requirement.contractName} chain proof`, {
      registryChainId: registry.chainId,
      proofChainId: requirement.chainId,
    });
    const entry = (registry.entries ?? []).find(
      (candidate) =>
        candidate?.contractName === requirement.contractName &&
        String(candidate.chainId) === requirement.chainId &&
        sameHex(candidate.address, requirement.address),
    );
    assert(
      liveDeploymentRegistryEntryComplete(entry),
      `public claim requires a live ${requirement.contractName} deployment registry entry for ${requirement.address} on chain ${requirement.chainId}`,
      entry ?? requirement,
    );
  }
}

function liveContractProofFinalized(payload) {
  return payload?.finalityStatus === "finalized" && payload?.contractStateVerified === true;
}

function liveDeploymentRegistryEntryComplete(entry) {
  return (
    isObject(entry) &&
    HEX32.test(entry.deploymentTxHash) &&
    entry.deploymentTxHash !== ZERO_HASH &&
    isPublicExplorerUrl(entry.explorerUrl) &&
    explorerUrlContainsTxHash(entry.explorerUrl, entry.deploymentTxHash) &&
    HEX32.test(entry.codeHash) &&
    entry.codeHash !== ZERO_HASH
  );
}

function verifyReplayBundleEvents(replayBundle, expectedAsOfEventSeq) {
  const summaryEvents = replayBundle?.events;
  const events = replayRowsForCollection(replayBundle, "events");
  assert(Array.isArray(summaryEvents) && summaryEvents.length > 0, "proof-bundle replayBundle.events is missing or empty", replayBundle);
  assert(events.length > 0, "proof-bundle replay pages are missing events", replayBundle);
  assert(replayBundle.asOfEventSeq === expectedAsOfEventSeq, "proof-bundle replay asOfEventSeq does not precede public claim event", {
    expected: expectedAsOfEventSeq,
    actual: replayBundle.asOfEventSeq,
  });
  let previousEventSeq = 0;
  let previousProofEventHash = ZERO_HASH;
  for (const event of events) {
    assert(isObject(event), "proof-bundle replayBundle.events entries must be objects", event);
    for (const field of ["eventId", "sessionId", "eventSeq", "eventHash", "authority", "kind", "payloadHash", "payload"]) {
      assert(event[field] !== undefined, `proof-bundle replay event is missing ${field}`, event);
    }
    assert(event.sessionId === replayBundle.sessionId, "proof-bundle replay event sessionId does not match replay bundle", event);
    assert(Number.isInteger(event.eventSeq) && event.eventSeq > previousEventSeq, "proof-bundle replay eventSeq is not strictly increasing", event);
    previousEventSeq = event.eventSeq;
    const expectedPayloadHash = hashJson(event.payload);
    assert(sameHex(event.payloadHash, expectedPayloadHash), "proof-bundle replay event payloadHash does not recompute", {
      eventId: event.eventId,
      expected: event.payloadHash,
      actual: expectedPayloadHash,
    });
    const expectedPrevProofEventHash = event.authority === "proof" ? previousProofEventHash : null;
    assert(
      (event.prevProofEventHash ?? null) === expectedPrevProofEventHash,
      "proof-bundle replay event prevProofEventHash does not match proof chain",
      { eventId: event.eventId, expected: expectedPrevProofEventHash, actual: event.prevProofEventHash ?? null },
    );
    const expectedEventHash = hashJson({
      sessionId: event.sessionId,
      eventSeq: event.eventSeq,
      authority: event.authority,
      kind: event.kind,
      payloadHash: event.payloadHash,
      prevProofEventHash: event.prevProofEventHash ?? null,
    });
    assert(sameHex(event.eventHash, expectedEventHash), "proof-bundle replay eventHash does not recompute", {
      eventId: event.eventId,
      expected: event.eventHash,
      actual: expectedEventHash,
    });
    assert(sameHex(event.eventId, expectedEventHash), "proof-bundle replay eventId does not equal eventHash", {
      eventId: event.eventId,
      expected: expectedEventHash,
    });
    if (event.authority === "proof") {
      previousProofEventHash = event.eventHash.toLowerCase();
    }
  }
  assert(previousEventSeq === expectedAsOfEventSeq, "proof-bundle replay pages do not end at asOfEventSeq", {
    expected: expectedAsOfEventSeq,
    actual: previousEventSeq,
  });
  const expectedEventRoot = hashJson(summaryEvents.map((event) => event.eventHash));
  assert(sameHex(replayBundle.eventRoot, expectedEventRoot), "proof-bundle replay eventRoot does not recompute", {
    expected: replayBundle.eventRoot,
    actual: expectedEventRoot,
  });
  return previousProofEventHash;
}

function replayRowsForCollection(replayBundle, collection) {
  const pages = replayBundle?.replayPages?.[collection];
  if (Array.isArray(pages)) {
    return pages.flatMap((page) => (Array.isArray(page?.rows) ? page.rows : []));
  }
  const summaryRows = replayBundle?.[collection];
  return Array.isArray(summaryRows) ? summaryRows : [];
}

function verifyPublicClaimEventHash(proofBundle, previousProofEventHash) {
  const asOfEventSeq = proofBundle.publicClaimEventSeq - 1;
  const payload = {
    claim: proofBundle.publicClaim,
    publicClaimHash: proofBundle.publicClaimHash,
    replayBundle: proofBundle.replayBundle,
    replayBundleHash: proofBundle.claimInputReplayBundleHash,
    verifierRunHash: proofBundle.verifierRunHash,
    verifierAttestation: proofBundle.verifierAttestation,
    asOfEventSeq,
    providerStatuses: proofBundle.providerStatuses,
    providerStatusHash: proofBundle.providerStatusHash,
    deploymentRegistry: proofBundle.deploymentRegistry,
    deploymentRegistryHash: proofBundle.deploymentRegistryHash,
    server: proofBundle.server,
    serverHash: proofBundle.serverHash,
    proofAuthority: true,
    winnerClaimAllowed: true,
  };
  const payloadHash = hashJson(payload);
  const eventHash = hashJson({
    sessionId: proofBundle.sessionId,
    eventSeq: proofBundle.publicClaimEventSeq,
    authority: "proof",
    kind: "public.claim.authorized",
    payloadHash,
    prevProofEventHash: previousProofEventHash,
  });
  assert(sameHex(proofBundle.publicClaimEventHash, eventHash), "proof-bundle public claim event hash does not recompute", {
    expected: proofBundle.publicClaimEventHash,
    actual: eventHash,
  });
  assert(sameHex(proofBundle.publicClaimEventId, eventHash), "proof-bundle public claim event id does not equal event hash", {
    expected: proofBundle.publicClaimEventId,
    actual: eventHash,
  });
}

function publicClaimHashInput(claim) {
  return {
    sessionId: claim.sessionId,
    snapshotScope: claim.snapshotScope,
    providerSnapshotOnly: claim.providerSnapshotOnly,
    authorizedAt: claim.authorizedAt,
    authorizedEventSeq: claim.authorizedEventSeq,
    asOfEventSeq: claim.asOfEventSeq,
    claimMode: claim.claimMode,
    paymentMode: claim.paymentMode,
    tokenMode: claim.tokenMode,
    tokenSettlementClaim: claim.tokenSettlementClaim,
    identityMode: claim.identityMode,
    replayBundleHash: claim.replayBundleHash,
    providerStatusHash: claim.providerStatusHash,
    deploymentRegistryHash: claim.deploymentRegistryHash,
    serverHash: claim.serverHash,
    verifierRun: {
      claimMode: claim.verifierRun.claimMode,
      paymentMode: claim.verifierRun.paymentMode,
      tokenMode: claim.verifierRun.tokenMode,
      identityMode: claim.verifierRun.identityMode,
      proofLevel: claim.verifierRun.proofLevel,
      proofChipAllowed: claim.verifierRun.proofChipAllowed,
      finalVerifierComplete: claim.verifierRun.finalVerifierComplete,
      winnerClaimAllowed: claim.verifierRun.winnerClaimAllowed,
    },
  };
}

function hashJson(value) {
  return `0x${createHash("sha256").update(canonicalizeJson(value)).digest("hex")}`;
}

function hashText(value) {
  return `0x${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalizeJson(value) {
  return JSON.stringify(sortForJcs(value));
}

function sortForJcs(value) {
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
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      if (child !== undefined) {
        sorted[key] = sortForJcs(child);
      }
    }
    return sorted;
  }
  return value;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isEvmAddress(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isPublicReplayHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".test") ||
    host.endsWith(".local") ||
    host.endsWith(".lan") ||
    host.endsWith(".internal")
  ) {
    return false;
  }
  if (host.includes(":")) {
    return false;
  }
  if (isPrivateOrReservedIpv4(host)) {
    return false;
  }
  return host.includes(".");
}

function isPrivateOrReservedIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet, index) => !Number.isInteger(octet) || octet < 0 || octet > 255 || String(octet) !== parts[index])) {
    return false;
  }
  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;
  const c = octets[2] ?? -1;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function sameHex(left, right) {
  return typeof left === "string" && typeof right === "string" && left.toLowerCase() === right.toLowerCase();
}

function explorerUrlContainsTxHash(explorerUrl, txHash) {
  if (typeof explorerUrl !== "string" || typeof txHash !== "string") {
    return false;
  }
  try {
    const url = new URL(explorerUrl);
    const segments = url.pathname.toLowerCase().split("/").filter(Boolean);
    const txIndex = segments.indexOf("tx");
    return txIndex >= 0 && segments[txIndex + 1] === txHash.toLowerCase();
  } catch {
    return false;
  }
}

function isPublicExplorerUrl(value) {
  if (typeof value !== "string") {
    return false;
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") {
      return false;
    }
    const host = url.hostname.toLowerCase();
    return PUBLIC_EXPLORER_HOST_PATTERNS.some((pattern) => pattern.test(host));
  } catch {
    return false;
  }
}

function assert(condition, message, details) {
  if (!condition) {
    throw withDetails(new Error(message), details);
  }
}

function withDetails(error, details) {
  Object.defineProperty(error, "details", { value: details, enumerable: true });
  return error;
}
