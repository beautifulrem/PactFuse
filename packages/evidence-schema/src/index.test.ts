import { describe, expect, it } from "vitest";
import {
  ArtifactAccessIssuePayloadSchema,
  ArtifactCidSchema,
  ArtifactPreflightPayloadSchema,
  ArtifactPreflightVerifyPayloadSchema,
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

    expect(ArtifactPreflightVerifyPayloadSchema.parse(payload)).toEqual(payload);
    expect(() => ArtifactPreflightVerifyPayloadSchema.parse({ ...payload, manifestFetchHash: undefined })).toThrow();
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
});
