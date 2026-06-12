#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ZERO_HASH = `0x${"0".repeat(64)}`;

const artifactDir = process.argv[2] ? resolve(process.argv[2]) : null;

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
  for (const field of ["providerStatusHash", "deploymentRegistryHash", "serverHash"]) {
    assert(claim[field] === proofBundle[field], `publicClaim ${field} does not match proof-bundle`, {
      publicClaim: claim[field],
      proofBundle: proofBundle[field],
    });
  }
}

function verifyReplayBundleEvents(replayBundle, expectedAsOfEventSeq) {
  const events = replayBundle?.events;
  assert(Array.isArray(events) && events.length > 0, "proof-bundle replayBundle.events is missing or empty", replayBundle);
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
  const expectedEventRoot = hashJson(events.map((event) => event.eventHash));
  assert(sameHex(replayBundle.eventRoot, expectedEventRoot), "proof-bundle replay eventRoot does not recompute", {
    expected: replayBundle.eventRoot,
    actual: expectedEventRoot,
  });
  return previousProofEventHash;
}

function verifyPublicClaimEventHash(proofBundle, previousProofEventHash) {
  const payload = {
    claim: proofBundle.publicClaim,
    publicClaimHash: proofBundle.publicClaimHash,
    replayBundleHash: proofBundle.claimInputReplayBundleHash,
    verifierRunHash: proofBundle.verifierRunHash,
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
    identityMode: claim.identityMode,
    replayBundleHash: claim.replayBundleHash,
    providerStatusHash: claim.providerStatusHash,
    deploymentRegistryHash: claim.deploymentRegistryHash,
    serverHash: claim.serverHash,
    verifierRun: {
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

function sameHex(left, right) {
  return typeof left === "string" && typeof right === "string" && left.toLowerCase() === right.toLowerCase();
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
