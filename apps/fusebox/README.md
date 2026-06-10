# Fusebox Preview

This folder is not the live Fusebox application yet.

It contains fixture design previews for the Fusebox frontend locks. These files exist only to prove visual direction, first-viewport dominance, and physical fuse-cartridge primitives. They are not live evidence and are not wired to `apps/pactfuse-api`.

Current status:

- live app: pending
- `pactfuse-api`: pending
- proof states: fixture / pending only
- winner claim: forbidden

Preview files:

- `preview/fusebox/index.html`: legacy W8 static fixture.
- `preview/fusebox-v2/index.html`: W9 visual/motion prototype, matching the dark machined-instrument direction.

The v2 prototype may use semantic trip/clean colors to show the intended choreography, but its global prototype/fixture stamp is authoritative: it is a motion preview, not proof authority. Production Fusebox must derive all pass/trip/settle states from `/api/v1/evidence/stream` or its polling fallback.
