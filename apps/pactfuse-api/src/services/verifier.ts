import type { EvidenceVerifier } from "../types.js";

export function createVerifierAdapter(): EvidenceVerifier {
  return {
    async verify(receipt: unknown, options: Record<string, unknown> = {}) {
      const verifierUrl = new URL("../../../../packages/verifier/pactfuse-verify-receipt.mjs", import.meta.url).href;
      const mod = (await import(verifierUrl)) as {
        verifyEvidence?: (receipt: unknown, options?: Record<string, unknown>) => Record<string, unknown>;
      };
      if (!mod.verifyEvidence) {
        return {
          schemaOk: false,
          proofChipAllowed: false,
          winnerClaimAllowed: false,
          requestedWinnerClaimAllowed: false,
          finalVerifierComplete: false,
          warnings: [],
          errors: ["verifier module did not export verifyEvidence"],
        };
      }
      return mod.verifyEvidence(receipt, options);
    },
  };
}
