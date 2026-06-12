import { describe, expect, it } from "vitest";
import {
  ArtifactAccessIssuePayloadSchema,
  ArtifactCidSchema,
  ArtifactPreflightPayloadSchema,
  ArtifactPreflightVerifyPayloadSchema,
  ProofBundleVerifierAttestationSchema,
  PublicClaimViewSchema,
} from "./index.js";

const HEX_A = `0x${"a".repeat(64)}`;
const HEX_B = `0x${"B".repeat(64)}`;

describe("artifact evidence schemas", () => {
  it("accepts sha256 artifact CIDs with hex32 digests", () => {
    expect(ArtifactCidSchema.parse(`sha256:${HEX_A}`)).toBe(`sha256:${HEX_A}`);
    expect(ArtifactCidSchema.parse(`sha256:${HEX_B}`)).toBe(`sha256:${HEX_B}`);
  });

  it("rejects non sha256 artifact CIDs", () => {
    expect(() => ArtifactCidSchema.parse(HEX_A)).toThrow();
    expect(() => ArtifactCidSchema.parse(`ipfs:${HEX_A}`)).toThrow();
  });

  it("requires artifactCid on artifact preflight payloads", () => {
    const payload = {
      spendId: HEX_A,
      artifactHashPreview: HEX_A,
      artifactCid: `sha256:${HEX_A}`,
      endpointUrl: "https://example.com/artifact.json",
      priceDisclosureHash: HEX_A,
      sourceStateSnapshotHash: HEX_A,
    };

    expect(ArtifactPreflightPayloadSchema.parse(payload)).toEqual(payload);
    expect(() => ArtifactPreflightPayloadSchema.parse({ ...payload, artifactCid: undefined })).toThrow();
  });

  it("requires delivery proof hashes on artifact preflight verify payloads", () => {
    const payload = {
      preflightId: HEX_A,
      artifactPayloadHash: HEX_A,
      artifactCid: `sha256:${HEX_A}`,
      manifestFetchHash: HEX_A,
      endpointResponseHash: HEX_A,
      leaseDryRunHash: HEX_A,
    };

    expect(ArtifactPreflightVerifyPayloadSchema.parse(payload)).toEqual({
      ...payload,
      verificationMode: "caller_hash_attestation",
    });
    expect(() => ArtifactPreflightVerifyPayloadSchema.parse({ ...payload, manifestFetchHash: undefined })).toThrow();
    expect(ArtifactPreflightVerifyPayloadSchema.parse({ preflightId: HEX_A, verificationMode: "server_live_fetch" })).toEqual({
      preflightId: HEX_A,
      verificationMode: "server_live_fetch",
    });
  });

  it("requires quote binding and payload bytes for artifact access issuance", () => {
    const payload = {
      spendId: HEX_A,
      payer: "0x1234",
      quoteId: HEX_B,
      artifactHash: HEX_A,
      artifactPayload: { content: "scan-result" },
    };

    expect(ArtifactAccessIssuePayloadSchema.parse(payload)).toEqual(payload);
    expect(() => ArtifactAccessIssuePayloadSchema.parse({ ...payload, quoteId: undefined })).toThrow();
    expect(() => ArtifactAccessIssuePayloadSchema.parse({ ...payload, artifactPayload: undefined })).toThrow();
  });

  it("requires a verifier attestation signature shape on public proof bundles", () => {
    const attestation = {
      scheme: "ed25519",
      keyId: "test-key",
      publicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n",
      publicKeyHash: HEX_A,
      signedPayloadHash: HEX_B,
      signature: "x".repeat(88),
    };

    expect(ProofBundleVerifierAttestationSchema.parse(attestation)).toEqual(attestation);
    expect(() => ProofBundleVerifierAttestationSchema.parse({ ...attestation, signature: undefined })).toThrow();
  });

  it("binds public token settlement claims to the token mode", () => {
    const verifierRun = {
      sessionId: HEX_A,
      proofLevel: "final_replay_claim",
      claimMode: "caw-target-real",
      paymentMode: "gate-paid-artifact-real",
      tokenMode: "mock-test-token",
      identityMode: "p0-floor-one-wallet",
      schemaOk: true,
      proofChipAllowed: true,
      winnerClaimAllowed: true,
      requestedWinnerClaimAllowed: true,
      finalVerifierComplete: true,
      errors: [],
      warnings: [],
    };
    const claim = {
      sessionId: HEX_A,
      claimStatus: "authorized_public_claim",
      snapshotScope: "authorization_event",
      providerSnapshotOnly: true,
      authorizedAt: "2026-06-11T00:00:00.000Z",
      authorizedEventSeq: 2,
      asOfEventSeq: 1,
      claimMode: "caw-target-real",
      paymentMode: "gate-paid-artifact-real",
      tokenMode: "mock-test-token",
      tokenSettlementClaim: "live-mock-erc20-fallback",
      identityMode: "p0-floor-one-wallet",
      replayBundleHash: HEX_A,
      providerStatusHash: HEX_A,
      deploymentRegistryHash: HEX_B,
      serverHash: HEX_A,
      verifierRun,
      proofChipAllowed: true,
      finalVerifierComplete: true,
      winnerClaimAllowed: true,
      publicClaimHash: HEX_B,
    };

    expect(PublicClaimViewSchema.parse(claim)).toEqual(claim);
    expect(() => PublicClaimViewSchema.parse({ ...claim, tokenSettlementClaim: "official-testnet-usdc" })).toThrow();
    expect(() =>
      PublicClaimViewSchema.parse({
        ...claim,
        verifierRun: { ...verifierRun, tokenMode: "local-mocked" },
      }),
    ).toThrow();
    expect(() =>
      PublicClaimViewSchema.parse({
        ...claim,
        verifierRun: { ...verifierRun, winnerClaimAllowed: false },
      }),
    ).toThrow();
    expect(
      PublicClaimViewSchema.parse({
        ...claim,
        tokenMode: "official-testnet-usdc",
        tokenSettlementClaim: "official-testnet-usdc",
        verifierRun: { ...verifierRun, tokenMode: "official-testnet-usdc" },
      }).tokenSettlementClaim,
    ).toBe("official-testnet-usdc");
  });
});
