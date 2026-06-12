#!/usr/bin/env node

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

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

const artifactDir = process.argv[2] ? resolve(process.argv[2]) : null;
const trustedProofKeyHashes = new Set(listEnv("PACTFUSE_TRUSTED_PROOF_KEY_HASHES", []).map((value) => value.toLowerCase()));

try {
  assert(artifactDir, "usage: node scripts/verify-live-artifacts.mjs <artifact-dir>");
  await verifyArtifactDir(artifactDir);
  const { manifest, artifactsByName } = await verifyManifestArtifacts(artifactDir);
  verifyArtifactSummary(manifest, artifactsByName);

  console.log(
    JSON.stringify(
      {
        ok: true,
        artifactDir,
        sessionId: manifest.sessionId,
        artifactManifestHash: manifest.manifestHash,
        publicClaimHash: manifest.publicClaimHash ?? null,
        proofBundleHash: manifest.proofBundleHash ?? null,
        artifactCount: manifest.artifacts.length,
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
        artifactDir,
        error: error instanceof Error ? error.message : String(error),
        details: error && typeof error === "object" && "details" in error ? error.details : undefined,
      },
      null,
      2,
    ),
  );
  process.exit(1);
}

async function verifyArtifactDir(dir) {
  const stat = await lstat(dir);
  assert(stat.isDirectory() && !stat.isSymbolicLink(), "artifact dir must be a real directory", { artifactDir: dir });
}

async function verifyManifestArtifacts(dir) {
  const manifest = await readJsonFile(join(dir, "manifest.json"));
  assert(manifest.manifestType === "PACTFUSE_LIVE_SMOKE_ARTIFACTS_V1", "manifest has the wrong manifestType", manifest);
  assert(HEX32.test(manifest.manifestHash), "manifestHash is missing or invalid", manifest);
  const manifestBase = { ...manifest };
  delete manifestBase.manifestHash;
  assert(hashJson(manifestBase) === manifest.manifestHash.toLowerCase(), "manifestHash does not recompute", {
    expected: manifest.manifestHash,
    actual: hashJson(manifestBase),
  });
  assert(Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0, "manifest.artifacts must be a non-empty array", manifest);

  const artifactsByName = new Map();
  for (const artifact of manifest.artifacts) {
    assert(isObject(artifact), "manifest artifact entries must be objects", artifact);
    const name = artifact.name;
    assert(isSafeArtifactName(name), "manifest artifact name must be a basename", { name });
    assert(!artifactsByName.has(name), "manifest artifact names must be unique", { name });
    assert(HEX32.test(artifact.canonicalHash), `artifact ${name} canonicalHash is missing or invalid`, artifact);
    assert(HEX32.test(artifact.byteSha256), `artifact ${name} byteSha256 is missing or invalid`, artifact);
    assert(Number.isInteger(artifact.bytes) && artifact.bytes > 0, `artifact ${name} bytes is missing or invalid`, artifact);

    const path = join(dir, name);
    const bytes = await readFile(path);
    assert(bytes.length === artifact.bytes, `artifact ${name} bytes does not match manifest`, {
      expected: artifact.bytes,
      actual: bytes.length,
    });
    const byteSha256 = `0x${createHash("sha256").update(bytes).digest("hex")}`;
    assert(byteSha256 === artifact.byteSha256.toLowerCase(), `artifact ${name} byteSha256 does not recompute`, {
      expected: artifact.byteSha256,
      actual: byteSha256,
    });
    const json = parseJson(bytes.toString("utf8"), name);
    const canonicalHash = hashJson(json);
    assert(canonicalHash === artifact.canonicalHash.toLowerCase(), `artifact ${name} canonicalHash does not recompute`, {
      expected: artifact.canonicalHash,
      actual: canonicalHash,
    });
    artifactsByName.set(name, json);
  }

  return { manifest, artifactsByName };
}

function verifyArtifactSummary(manifest, artifactsByName) {
  const preflight = artifactsByName.get("live-preflight.json");
  assert(isObject(preflight), "live-preflight.json artifact is required", [...artifactsByName.keys()]);
  assert(preflight.status === manifest.livePreflightStatus, "manifest livePreflightStatus does not match live-preflight artifact", {
    manifestStatus: manifest.livePreflightStatus,
    preflightStatus: preflight.status,
  });
  if (typeof preflight.sessionId === "string") {
    assert(preflight.sessionId === manifest.sessionId, "manifest sessionId does not match live-preflight artifact", {
      manifestSessionId: manifest.sessionId,
      preflightSessionId: preflight.sessionId,
    });
  }

  const publicClaim = artifactsByName.get("public-claim.json");
  if (manifest.publicClaimHash !== null) {
    assert(isObject(publicClaim), "manifest publicClaimHash requires public-claim.json", manifest);
    assert(publicClaim.publicClaimHash === manifest.publicClaimHash, "manifest publicClaimHash does not match public-claim artifact", {
      manifestPublicClaimHash: manifest.publicClaimHash,
      publicClaimHash: publicClaim.publicClaimHash,
    });
  }

  const proofBundle = artifactsByName.get("proof-bundle.json");
  if (manifest.proofBundleHash !== null) {
    assert(isObject(proofBundle), "manifest proofBundleHash requires proof-bundle.json", manifest);
    verifyProofBundle(proofBundle, publicClaim, manifest);
  }
}

function verifyProofBundle(proofBundle, publicClaim, manifest) {
  assert(proofBundle.bundleType === "PACTFUSE_PUBLIC_PROOF_BUNDLE_V1", "proof-bundle has the wrong bundleType", proofBundle);
  assert(proofBundle.winnerClaimAllowed === true, "proof-bundle winnerClaimAllowed is not true", proofBundle);
  assert(proofBundle.sessionId === manifest.sessionId, "proof-bundle sessionId does not match manifest", {
    manifestSessionId: manifest.sessionId,
    proofBundleSessionId: proofBundle.sessionId,
  });
  assert(proofBundle.proofBundleHash === manifest.proofBundleHash, "manifest proofBundleHash does not match proof-bundle artifact", {
    manifestProofBundleHash: manifest.proofBundleHash,
    proofBundleHash: proofBundle.proofBundleHash,
  });
  assert(canonicalizeJson(proofBundle.publicClaim) === canonicalizeJson(publicClaim), "proof-bundle publicClaim does not match public-claim artifact", {
    proofBundlePublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
    publicClaimHash: publicClaim?.publicClaimHash,
  });
  assert(proofBundle.publicClaimHash === proofBundle.publicClaim?.publicClaimHash, "proof-bundle publicClaimHash does not match embedded publicClaim", {
    proofBundlePublicClaimHash: proofBundle.publicClaimHash,
    embeddedPublicClaimHash: proofBundle.publicClaim?.publicClaimHash,
  });
  assert(proofBundle.publicClaimHash === manifest.publicClaimHash, "proof-bundle publicClaimHash does not match manifest", {
    proofBundlePublicClaimHash: proofBundle.publicClaimHash,
    manifestPublicClaimHash: manifest.publicClaimHash,
  });
  assert(hashJson(publicClaimHashInput(proofBundle.publicClaim)) === proofBundle.publicClaimHash, "proof-bundle publicClaimHash does not recompute", {
    expected: proofBundle.publicClaimHash,
    actual: hashJson(publicClaimHashInput(proofBundle.publicClaim)),
  });
  assert(hashJson(proofBundle.replayBundle) === proofBundle.replayBundleHash, "proof-bundle replayBundleHash does not recompute", {
    expected: proofBundle.replayBundleHash,
    actual: hashJson(proofBundle.replayBundle),
  });
  assert(hashJson(proofBundle.publicClaim.verifierRun) === proofBundle.verifierRunHash, "proof-bundle verifierRunHash does not recompute", {
    expected: proofBundle.verifierRunHash,
    actual: hashJson(proofBundle.publicClaim.verifierRun),
  });
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
  verifyProofBundleAttestation(proofBundle);
  assert(proofBundle.replayBundleHash === manifest.replayBundleHash, "proof-bundle replayBundleHash does not match manifest", {
    proofBundleReplayBundleHash: proofBundle.replayBundleHash,
    manifestReplayBundleHash: manifest.replayBundleHash,
  });
  assert(proofBundle.publicClaimEventHash === manifest.publicClaimEventHash, "proof-bundle publicClaimEventHash does not match manifest", {
    proofBundlePublicClaimEventHash: proofBundle.publicClaimEventHash,
    manifestPublicClaimEventHash: manifest.publicClaimEventHash,
  });
  assert(proofBundle.providerStatusHash === manifest.providerStatusHash, "proof-bundle providerStatusHash does not match manifest", {
    proofBundleProviderStatusHash: proofBundle.providerStatusHash,
    manifestProviderStatusHash: manifest.providerStatusHash,
  });
  assert(proofBundle.deploymentRegistryHash === manifest.deploymentRegistryHash, "proof-bundle deploymentRegistryHash does not match manifest", {
    proofBundleDeploymentRegistryHash: proofBundle.deploymentRegistryHash,
    manifestDeploymentRegistryHash: manifest.deploymentRegistryHash,
  });
  assert(proofBundle.serverHash === manifest.serverHash, "proof-bundle serverHash does not match manifest", {
    proofBundleServerHash: proofBundle.serverHash,
    manifestServerHash: manifest.serverHash,
  });

  verifyPublicClaimSnapshotBinding(proofBundle);
  verifyPublicClaimVerifierRun(proofBundle);
  verifyPublicClaimModeAlignment(proofBundle);
  verifyProofBundleProviderStatuses(proofBundle, manifest);
  verifyReplayDeploymentRegistryBinding(proofBundle);
  verifyPublicClaimDeploymentRegistry(proofBundle);
  verifyPublicReplayUrls(proofBundle.replayBundle);
  const previousProofEventHash = verifyReplayBundleEvents(proofBundle.replayBundle, proofBundle.publicClaimEventSeq - 1);
  verifyPublicClaimEventHash(proofBundle, previousProofEventHash);

  const bundleBase = { ...proofBundle };
  delete bundleBase.proofBundleHash;
  assert(hashJson(bundleBase) === proofBundle.proofBundleHash, "proof-bundle hash does not recompute", {
    expected: proofBundle.proofBundleHash,
    actual: hashJson(bundleBase),
  });
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
  for (const field of ["providerStatusHash", "deploymentRegistryHash", "serverHash"]) {
    assert(claim[field] === proofBundle[field], `publicClaim ${field} does not match proof-bundle`, {
      publicClaim: claim[field],
      proofBundle: proofBundle[field],
    });
  }
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

function verifyProofBundleProviderStatuses(proofBundle, manifest) {
  const providers = Array.isArray(proofBundle.providerStatuses) ? proofBundle.providerStatuses : [];
  const requiredProviders = Array.isArray(manifest.requiredProviders) ? manifest.requiredProviders : [];
  assert(providers.length > 0, "proof-bundle providerStatuses is missing or empty", proofBundle.providerStatuses);
  assert(requiredProviders.length > 0, "manifest requiredProviders is missing or empty", manifest.requiredProviders);
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
    assert((event.prevProofEventHash ?? null) === expectedPrevProofEventHash, "proof-bundle replay event prevProofEventHash does not match proof chain", {
      eventId: event.eventId,
      expected: expectedPrevProofEventHash,
      actual: event.prevProofEventHash ?? null,
    });
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
  const payload = {
    claim: proofBundle.publicClaim,
    publicClaimHash: proofBundle.publicClaimHash,
    replayBundle: proofBundle.replayBundle,
    replayBundleHash: proofBundle.claimInputReplayBundleHash,
    verifierRunHash: proofBundle.verifierRunHash,
    verifierAttestation: proofBundle.verifierAttestation,
    asOfEventSeq: proofBundle.publicClaim.asOfEventSeq,
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
  assert(isObject(claim?.verifierRun), "publicClaim.verifierRun is missing", claim);
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

async function readJsonFile(path) {
  return parseJson(await readFile(path, "utf8"), basename(path));
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function isSafeArtifactName(name) {
  return typeof name === "string" && name.length > 0 && basename(name) === name && name !== "." && name !== "..";
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

function assert(condition, message, details) {
  if (!condition) {
    const error = new Error(message);
    if (details !== undefined) {
      Object.defineProperty(error, "details", { value: details, enumerable: true });
    }
    throw error;
  }
}
