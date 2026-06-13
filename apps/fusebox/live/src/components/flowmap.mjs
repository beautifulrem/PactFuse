/* ReactiveFlowMap — the PactFuse spend line.
 *
 * A single left→right pipeline: agent wallet → pact policy → procurement gate
 * (a real circuit breaker) → artifact market, with the source registry watching
 * from above, able to trip the breaker. One token — the "spend" — travels the
 * line, and WHERE IT COMES TO REST encodes the outcome:
 *   • delivered at the market   (settle  — clean source)
 *   • halted at the open breaker (trip    — unsafe source, cut before payment)
 *   • stopped at the policy wall (deny    — wrong target, never reaches the gate)
 *
 * Three spatially distinct end states = a 10-second read of the whole product.
 *
 * Every visual is derived from machine state via apply(). All motion is CSS-class
 * driven off data-flow / data-* attributes, so reduced-motion collapses to the
 * correct STATIC end state (packet at its resting node, breaker open/closed,
 * downstream severed) with no JS branches. Geometry lives in one place (GEO) and
 * is published to CSS as custom properties, so the packet never drifts from the
 * nodes it travels between. */

import { short, fmt } from "../data.mjs";

// ── geometry (viewBox units) — single source of truth ──────────────────────
const VB = { w: 920, h: 300 };
const LINE_Y = 196; // the spend line
const X = { wallet: 132, policy: 340, gate: 548, market: 770 };
const REG = { x: 548, y: 66 }; // source registry, above the gate
const HALF = 32; // standard node tile half-extent
const GHALF = 46; // breaker housing half-extent

// wire endpoints sit on the tile edges so the line reads as continuous
const seg = (ax, bx, hb = HALF, ha = HALF) => `M${X[ax] + ha} ${LINE_Y} H ${X[bx] - hb}`;

// which node the spend rests on for each flow state (its journey frontier)
const PACKET_AT = {
  "settle-approve": "wallet", "settle-allow": "policy", "settle-pay": "gate",
  "settle-deliver": "market", "settle-done": "market",
  "trip-challenge": "wallet", "trip-detect": "policy", "trip-cut": "gate", "trip-done": "gate",
  "deny-call": "wallet", "deny-check": "policy", "deny-block": "policy", "deny-done": "policy",
};
// where the spend is stopped by a protective barrier (drives the halt ring)
const HALT_AT = { "trip-cut": "gate", "trip-done": "gate", "deny-block": "policy", "deny-done": "policy" };
// compact, punchy status word shown under the breaker
const OUTCOME = {
  "settle-deliver": "delivered", "settle-done": "delivered",
  "trip-cut": "spend halted", "trip-done": "spend halted",
  "deny-block": "denied", "deny-done": "denied",
};

const node = (key, glyph, name, sub) => `
  <g class="fm-node" data-node="${key}" transform="translate(${X[key]},${LINE_Y})">
    <rect class="fm-tile" x="${-HALF}" y="${-HALF}" width="${HALF * 2}" height="${HALF * 2}" rx="14"/>
    <use class="fm-ic" href="#sym-${glyph}" x="-15" y="-15" width="30" height="30"/>
    <text class="fm-name" y="${HALF + 20}">${name}</text>
    ${sub ? `<text class="fm-sub" y="${HALF + 34}">${sub}</text>` : ""}
  </g>`;

export function mountFlowMap(host, facts = {}) {
  host.innerHTML = `
  <svg class="fm" viewBox="0 0 ${VB.w} ${VB.h}" role="img" aria-label="System map: idle"
       style="--x-wallet:${X.wallet}px;--x-policy:${X.policy}px;--x-gate:${X.gate}px;--x-market:${X.market}px;--y-line:${LINE_Y}px;--pk-x:${X.wallet}px">
    <defs>
      <pattern id="fm-grid" width="26" height="26" patternUnits="userSpaceOnUse">
        <circle cx="1" cy="1" r="1" class="fm-grid-dot"/>
      </pattern>
    </defs>
    <rect class="fm-backdrop" x="0" y="0" width="${VB.w}" height="${VB.h}" fill="url(#fm-grid)" aria-hidden="true"/>

    <g class="fm-wires" aria-hidden="true">
      <path class="fm-wire" data-seg="w1" d="${seg("wallet", "policy")}"/>
      <path class="fm-wire" data-seg="w2" d="${seg("policy", "gate", GHALF)}"/>
      <path class="fm-wire" data-seg="w3" d="${seg("gate", "market", HALF, GHALF)}"/>
      <path class="fm-wire fm-wire-sig" data-seg="sig" d="M${REG.x} ${REG.y + HALF} V ${LINE_Y - GHALF}"/>
      <path class="fm-cut" d="M${(X.gate + GHALF + X.market - HALF) / 2 - 9} ${LINE_Y - 9} l18 18 M${(X.gate + GHALF + X.market - HALF) / 2 + 9} ${LINE_Y - 9} l-18 18"/>
    </g>

    <!-- source registry (watchtower) -->
    <g class="fm-node fm-registry" data-node="registry" transform="translate(${REG.x},${REG.y})">
      <g class="fm-beacon"><circle class="fm-beacon-ring" r="${HALF + 8}"/></g>
      <rect class="fm-tile" x="${-HALF}" y="${-HALF}" width="${HALF * 2}" height="${HALF * 2}" rx="14"/>
      <use class="fm-ic" href="#sym-registry" x="-15" y="-15" width="30" height="30"/>
      <text class="fm-name" y="${-HALF - 12}">source registry</text>
    </g>

    ${node("wallet", "wallet", "agent wallet", "cobo caw")}
    ${node("policy", "shield", "pact policy", "allowlist · limits")}
    ${node("market", "package", "artifact market", "paid delivery")}

    <!-- policy deny ring -->
    <circle class="fm-deny-ring" cx="${X.policy}" cy="${LINE_Y}" r="${HALF + 8}" aria-hidden="true"/>

    <!-- procurement gate — the breaker (hero) -->
    <g class="fm-node fm-gate" data-node="gate" transform="translate(${X.gate},${LINE_Y})">
      <rect class="fm-gate-ring" x="${-GHALF - 8}" y="${-GHALF - 8}" width="${(GHALF + 8) * 2}" height="${(GHALF + 8) * 2}" rx="20"/>
      <rect class="fm-tile fm-gate-tile" x="${-GHALF}" y="${-GHALF}" width="${GHALF * 2}" height="${GHALF * 2}" rx="16"/>
      <path class="fm-stub" d="M${-GHALF} 0 H -22"/>
      <path class="fm-stub fm-stub-out" d="M22 0 H ${GHALF}"/>
      <circle class="fm-contact" cx="-22" cy="0" r="4.5"/>
      <circle class="fm-contact fm-contact-out" cx="22" cy="0" r="4.5"/>
      <path class="fm-arm" d="M-22 0 H 22"/>
      <text class="fm-name" y="${GHALF + 20}">procurement gate</text>
      <text class="fm-out" id="fm-out" y="${GHALF + 36}"></text>
    </g>

    <!-- evidence tags, anchored to segments (computed, not magic) -->
    <g class="fm-tags" aria-hidden="true">
      <text id="fm-tag-sig" class="fm-tag" x="${REG.x + 18}" y="${(REG.y + HALF + LINE_Y - GHALF) / 2 + 4}" text-anchor="start"></text>
      <text id="fm-tag-pg"  class="fm-tag" x="${(X.policy + X.gate) / 2}" y="${LINE_Y - 18}" text-anchor="middle"></text>
      <text id="fm-tag-gm"  class="fm-tag" x="${(X.gate + X.market) / 2}" y="${LINE_Y - 18}" text-anchor="middle"></text>
    </g>

    <!-- outcome badges: market delivered ✓ / policy denied ⊘ -->
    <use class="fm-check" href="#sym-check" x="${X.market + HALF - 16}" y="${LINE_Y - HALF - 4}" width="22" height="22" aria-hidden="true"/>
    <use class="fm-deny-badge" href="#sym-deny" x="${X.policy + HALF - 16}" y="${LINE_Y - HALF - 4}" width="22" height="22" aria-hidden="true"/>

    <!-- top layer: the travelling spend + the trip signal -->
    <g class="fm-packet" aria-hidden="true">
      <circle class="fm-packet-halo" r="12"/>
      <circle class="fm-packet-core" r="5.5"/>
    </g>
    <circle class="fm-sig-pulse" cx="${REG.x}" cy="${REG.y + HALF}" r="3.5" aria-hidden="true"/>
  </svg>`;

  const svg = host.querySelector("svg");
  const out = host.querySelector("#fm-out");
  const tag = (id) => host.querySelector(`#fm-tag-${id}`);

  function setTags({ sig = "", pg = "", gm = "" }) {
    tag("sig").textContent = sig;
    tag("pg").textContent = pg;
    tag("gm").textContent = gm;
  }

  function apply(ms) {
    // failure (e.g. ?fail=1) resolves on its own: the spend is stranded at the
    // step that could not execute, the breaker is NOT shown as a clean open, and
    // tone is danger — a broken action never inherits a success/in-progress look.
    if (ms.stage === "failed") {
      const at = PACKET_AT[ms.activeStep?.flow] ?? "gate";
      svg.dataset.flow = "failed";
      svg.dataset.stage = "failed";
      svg.dataset.packet = "on";
      svg.style.setProperty("--pk-x", `${X[at]}px`);
      svg.dataset.halt = at;
      svg.dataset.tone = "danger";
      svg.dataset.failnode = at;
      out.textContent = "failed";
      setTags({});
      svg.setAttribute("aria-label", `System map: protective action failed at the ${at} — retry available`);
      return;
    }
    delete svg.dataset.failnode;

    const flow =
      ms.stage === "success"
        ? `${ms.scenario?.flow}-done`
        : (ms.activeStep?.flow ?? (ms.scenario ? "armed" : "idle"));

    svg.dataset.flow = flow;
    svg.dataset.stage = ms.stage;

    // the travelling spend: position, visibility, halt barrier, tone. data-halt
    // is set ONLY at a real barrier (present-attribute selectors must not match
    // an empty string), so it is removed otherwise.
    const at = PACKET_AT[flow];
    svg.dataset.packet = at ? "on" : "off";
    if (at) svg.style.setProperty("--pk-x", `${X[at]}px`);
    if (HALT_AT[flow]) svg.dataset.halt = HALT_AT[flow];
    else delete svg.dataset.halt;
    svg.dataset.tone =
      flow.startsWith("settle") ? (["settle-pay", "settle-deliver", "settle-done"].includes(flow) ? "success" : "accent")
        : flow.startsWith("trip") ? (["trip-cut", "trip-done"].includes(flow) ? "danger" : "warning")
          : flow.startsWith("deny") ? "warning"
            : "accent";

    out.textContent = OUTCOME[flow] ?? "";

    // evidence tags — identical bindings to the prior map, repositioned
    const f = facts ?? {};
    const sc = ms.scenario?.id;
    if (sc === "trip") {
      setTags({
        "trip-challenge": { sig: "challenge submitted" },
        "trip-detect": { sig: `finalized · block ${f.challenge?.blockNumber ?? "—"}` },
        "trip-cut": { sig: `block ${f.challenge?.blockNumber ?? "—"}`, gm: "0 moved" },
        "trip-done": { sig: `blocks ${f.blocks?.slice(-2).join(", ") ?? "—"}`, gm: "0 moved" },
      }[flow] ?? {});
    } else if (sc === "settle") {
      const moved = fmt((f.delta?.marketAfter ?? 0) - (f.delta?.marketBefore ?? 0));
      setTags({
        "settle-approve": { pg: "approve in policy" },
        "settle-allow": { pg: `allow 0 → ${fmt(f.allowance?.allowanceAfter)}` },
        "settle-pay": { pg: `allow ${fmt(f.allowance?.allowanceAfter)}`, gm: `${moved} atomic` },
        "settle-deliver": { pg: `allow ${fmt(f.allowance?.allowanceAfter)}`, gm: `artifact ${short(f.lease?.artifactHash ?? "", 6, 4)}` },
        "settle-done": { gm: "delivered" },
      }[flow] ?? {});
    } else if (sc === "deny") {
      setTags({
        "deny-call": { pg: "wrong target" },
        "deny-check": { pg: "target ∉ allowlist" },
        "deny-block": { pg: "live_denied" },
        "deny-done": { pg: "live_denied" },
      }[flow] ?? {});
    } else {
      setTags({});
    }

    const labels = {
      idle: "System map: idle — select a scenario",
      armed: `System map: armed — ${ms.scenario?.title ?? ""}`,
    };
    svg.setAttribute(
      "aria-label",
      labels[flow] ?? `System map: ${ms.activeStep?.title ?? ms.stage} — spend at ${at ?? "origin"}`,
    );
  }

  return { apply };
}
