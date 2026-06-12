/* ReactiveFlowMap — abstract system topology. One SVG, flat geometry:
 * agent wallet → pact policy checkpoint → procurement gate (breaker) →
 * artifact market, with the source registry feeding the gate's trip signal.
 * Every visual change is driven by machine state via apply(); pulses and
 * path draws are CSS-class driven so reduced-motion collapses to final
 * states without JS branches. */

import { short, fmt } from "../data.mjs";

const VB = { w: 720, h: 312 };

export function mountFlowMap(host, facts = {}) {
  host.innerHTML = `
  <svg class="fm" viewBox="0 0 ${VB.w} ${VB.h}" role="img" aria-label="System map: idle">
    <g class="fm-paths" aria-hidden="true">
      <path id="fm-p-ap"  class="fm-path" d="M106 192 H 196"/>
      <path id="fm-p-pg"  class="fm-path" d="M244 192 H 356"/>
      <path id="fm-p-gm"  class="fm-path" d="M444 192 H 574"/>
      <path id="fm-p-sig" class="fm-path" d="M400 94 V 148"/>
      <path id="fm-d-ap"  class="fm-draw" pathLength="100" d="M106 192 H 196"/>
      <path id="fm-d-pg"  class="fm-draw" pathLength="100" d="M244 192 H 356"/>
      <path id="fm-d-gm"  class="fm-draw" pathLength="100" d="M444 192 H 574"/>
      <path id="fm-d-sig" class="fm-draw" pathLength="100" d="M400 94 V 148"/>
    </g>

    <g class="fm-node fm-agent" transform="translate(70,192)" aria-hidden="true">
      <circle r="26" class="fm-shape"/>
      <path class="fm-glyph" d="M-9 4c2-7 16-7 18 0M0-9a5 5 0 1 0 .01 0Z" transform="translate(0,-1)"/>
      <text class="fm-name" y="44">agent wallet</text>
      <text class="fm-sub" y="58">cobo caw</text>
    </g>

    <g class="fm-node fm-policy" transform="translate(220,192)" aria-hidden="true">
      <rect x="-14" y="-30" width="9" height="60" rx="2.5" class="fm-shape"/>
      <rect x="5" y="-30" width="9" height="60" rx="2.5" class="fm-shape"/>
      <circle class="fm-deny-ring" r="34" />
      <text class="fm-name" y="48">pact policy</text>
      <text class="fm-sub" y="62">allowlist · limits</text>
    </g>

    <g class="fm-node fm-gate" transform="translate(400,192)" aria-hidden="true">
      <circle r="34" class="fm-shape"/>
      <path d="M-22 0h10" class="fm-glyph"/>
      <path d="M12 0h10" class="fm-glyph"/>
      <circle cx="-12" cy="0" r="3" class="fm-dot"/>
      <circle cx="12" cy="0" r="3" class="fm-dot"/>
      <path class="fm-arm" d="M-12 0 L 12 0"/>
      <text class="fm-name" y="52">procurement gate</text>
      <text class="fm-sub" y="66">source-bound breaker</text>
    </g>

    <g class="fm-node fm-registry" transform="translate(400,62)" aria-hidden="true">
      <rect x="-26" y="-22" width="52" height="44" rx="8" class="fm-shape"/>
      <path class="fm-glyph" d="M-10-6h20M-10 0h20M-10 6h12"/>
      <g class="fm-beacon">
        <path class="fm-beacon-core" d="M0-34 6-28 0-22-6-28Z"/>
        <circle class="fm-beacon-ring" r="10" cy="-28"/>
      </g>
      <text class="fm-name" x="-38" y="4" style="text-anchor:end">source registry</text>
    </g>

    <g class="fm-node fm-market" transform="translate(610,192)" aria-hidden="true">
      <rect x="-26" y="-26" width="52" height="52" rx="9" class="fm-shape"/>
      <path class="fm-glyph fm-market-doc" d="M-7-10h9l5 5v15h-14v-20Z"/>
      <path class="fm-glyph fm-market-check" pathLength="100" d="m-5 1 4 4 7-8"/>
      <text class="fm-name" y="44">artifact market</text>
      <text class="fm-sub" y="58">paid delivery</text>
    </g>

    <g class="fm-tags" aria-hidden="true">
      <text id="fm-tag-sig" class="fm-tag" x="412" y="126" text-anchor="start"></text>
      <text id="fm-tag-pg" class="fm-tag" x="252" y="176" text-anchor="start"></text>
      <text id="fm-tag-gm" class="fm-tag" x="452" y="176" text-anchor="start"></text>
      <text id="fm-tag-out" class="fm-tag fm-tag-out" x="400" y="296"></text>
    </g>
  </svg>`;

  const svg = host.querySelector("svg");
  const tag = (id) => host.querySelector(`#fm-tag-${id}`);

  function setTags({ sig = "", pg = "", gm = "", out = "" }) {
    tag("sig").textContent = sig;
    tag("pg").textContent = pg;
    tag("gm").textContent = gm;
    tag("out").textContent = out;
  }

  function apply(ms) {
    const flow =
      ms.stage === "failed"
        ? (ms.stepIndex >= 0 ? ms.scenario.steps[ms.stepIndex].flow : "armed")
        : ms.stage === "success"
          ? `${ms.scenario?.flow}-done`
          : (ms.activeStep?.flow ?? (ms.scenario ? "armed" : "idle"));
    svg.dataset.flow = flow;
    svg.dataset.stage = ms.stage;
    const f = facts ?? {};
    const sc = ms.scenario?.id;
    if (sc === "trip") {
      const t = {
        "trip-challenge": { sig: "challenge submitted" },
        "trip-detect": { sig: `finalized · block ${f.challenge?.blockNumber ?? "—"}` },
        "trip-cut": { sig: `block ${f.challenge?.blockNumber ?? "—"}`, gm: "0 moved", out: "payment path open · spends tripped before settlement" },
        "trip-done": { gm: "0 moved", out: `protected · trips finalized at blocks ${f.blocks?.slice(-2).join(", ") ?? "—"}` },
      }[flow];
      setTags(t ?? {});
    } else if (sc === "settle") {
      const t = {
        "settle-approve": { pg: "approve in policy" },
        "settle-allow": { pg: `allow 0 → ${fmt(f.allowance?.allowanceAfter)}` },
        "settle-pay": { pg: `allow ${fmt(f.allowance?.allowanceAfter)}`, gm: `${fmt((f.delta?.marketAfter ?? 0) - (f.delta?.marketBefore ?? 0))} atomic`, out: `SpendSettled · block ${f.settled?.blockNumber ?? "—"}` },
        "settle-deliver": { gm: `${fmt((f.delta?.marketAfter ?? 0) - (f.delta?.marketBefore ?? 0))} atomic`, out: `artifact ${short(f.lease?.artifactHash ?? "", 8, 4)} · lease run live` },
        "settle-done": { gm: "delivered", out: "settled · artifact consumed through bounded MCP lease" },
      }[flow];
      setTags(t ?? {});
    } else if (sc === "deny") {
      const t = {
        "deny-call": { pg: "wrong target" },
        "deny-check": { pg: "target ∉ allowlist" },
        "deny-block": { pg: "live_denied", out: "request stopped at the policy wall · no transaction exists" },
        "deny-done": { pg: "live_denied", out: "denied · structured CAW audit evidence recorded" },
      }[flow];
      setTags(t ?? {});
    } else {
      setTags({});
    }
    const labels = {
      idle: "System map: idle",
      armed: `System map: scenario armed — ${ms.scenario?.title ?? ""}`,
      failed: "System map: protective action failed — retry available",
    };
    svg.setAttribute("aria-label", labels[flow] ?? `System map: ${ms.activeStep?.title ?? ms.stage}`);
  }

  return { apply };
}
