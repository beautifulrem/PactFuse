import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyEvidence } from "./pactfuse-verify-receipt.mjs";

const pendingReceiptPath = new URL("../../docs/evidence/receipt-pack.pending.example.json", import.meta.url);
const verifierPath = new URL("./pactfuse-verify-receipt.mjs", import.meta.url);
const pendingReceiptFile = fileURLToPath(pendingReceiptPath);
const verifierFile = fileURLToPath(verifierPath);

describe("pactfuse receipt verifier contract", () => {
  it("keeps schema-only separate from proof-chip authority", () => {
    const receipt = pendingReceipt();
    const result = verifyEvidence(receipt, { cliMode: "schema-only" });

    expect(result.schemaOk).toBe(true);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.winnerClaimAllowed).toBe(false);

    const schemaOnlyCli = spawnSync(process.execPath, [verifierFile, "--schema-only", pendingReceiptFile], {
      encoding: "utf8",
    });
    const proofCli = spawnSync(process.execPath, [verifierFile, pendingReceiptFile], { encoding: "utf8" });
    const schemaOnlyJson = JSON.parse(schemaOnlyCli.stdout);

    expect(schemaOnlyCli.status).toBe(0);
    expect(schemaOnlyJson.schemaOk).toBe(true);
    expect(schemaOnlyJson.proofChipAllowed).toBe(false);
    expect(schemaOnlyJson.finalVerifierComplete).toBe(false);
    expect(proofCli.status).toBe(1);
  });

  it.each([
    ["root winner flag", (receipt) => void (receipt.winnerClaimAllowed = true)],
    ["status field winner flag", (receipt) => void (receipt.statusFields.winnerClaimAllowed = true)],
    [
      "claim winner flag with real-evidence marker",
      (receipt) => {
        receipt.statusFields.isRealEvidence = true;
        receipt.claim = { winnerClaimAllowed: true };
      },
    ],
  ])("rejects %s", (_label, mutate) => {
    const receipt = pendingReceipt();
    mutate(receipt);
    const result = verifyEvidence(receipt, { cliMode: "proof-chip" });

    expect(result.requestedWinnerClaimAllowed).toBe(true);
    expect(result.winnerClaimAllowed).toBe(false);
    expect(result.proofChipAllowed).toBe(false);
    expect(result.finalVerifierComplete).toBe(false);
    expect(result.errors).toContain(
      "this scaffold is structural-only and refuses winnerClaimAllowed: true; run the full chain/signature/hash verifier before winner claims",
    );
  });
});

function pendingReceipt() {
  return JSON.parse(readFileSync(pendingReceiptPath, "utf8"));
}
