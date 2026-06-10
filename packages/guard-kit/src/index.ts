export const PACTFUSE_GUARD_KIT_P0 = {
  packageStatus: "scaffold",
  sourceFreshGuard: "planned",
  procurementGate: "planned",
  freshSourceEscrow: "planned",
  winnerClaimAllowed: false,
} as const;

export type SourceFreshGuardAdoption = {
  registry: `0x${string}`;
  sourceSetHash: `0x${string}`;
  spendId: `0x${string}`;
};

export function assertP0GuardKitMode(): typeof PACTFUSE_GUARD_KIT_P0 {
  return PACTFUSE_GUARD_KIT_P0;
}
