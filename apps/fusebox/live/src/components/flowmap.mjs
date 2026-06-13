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

import { short, fmt, blockUrl } from "../data.mjs";
import { STAGE } from "../machine.mjs";
import { icon } from "../symbols.mjs";
import { t } from "../i18n.mjs";

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
  "armed": "wallet",
  "settle-approve": "wallet", "settle-allow": "policy", "settle-pay": "gate",
  "settle-deliver": "market", "settle-done": "market",
  "trip-challenge": "wallet", "trip-detect": "policy", "trip-cut": "gate", "trip-done": "gate",
  "deny-call": "wallet", "deny-check": "policy", "deny-block": "policy", "deny-done": "policy",
};
// where the spend is stopped by a protective barrier (drives the halt ring)
const HALT_AT = { "trip-cut": "gate", "trip-done": "gate", "deny-block": "policy", "deny-done": "policy" };
// Resting x (px) for the travelling spend. It ALWAYS rests on a wire, never on a
// node's glyph, so the wallet / shield / breaker / package icons are never
// covered. The origin wallet has no inbound wire, so it rests on its outgoing
// (right) edge — "loaded, departing"; every other node rests just before its
// tile on the incoming wire. A halted/stranded spend sits a touch further out so
// its pulse-ring also clears the barrier it was stopped by. "Passing through" is
// read from the glide between two doorsteps (e.g. across the closing breaker),
// not from parking the dot on top of the mechanism.
const PACKET_GAP = 14; // resting clearance from a node edge
const PACKET_HALT_GAP = 18; // extra room so the halt pulse-ring clears the barrier
const packetX = (node, halted) => {
  const half = node === "gate" ? GHALF : HALF;
  if (node === "wallet") return X.wallet + half + PACKET_GAP;
  return X[node] - half - (halted ? PACKET_HALT_GAP : PACKET_GAP);
};
// compact, punchy status word shown under the breaker
const OUTCOME = {
  "armed": t("verdict.armed"),
  "settle-deliver": t("verdict.delivered"), "settle-done": t("verdict.delivered"),
  "trip-cut": t("verdict.spendHalted"), "trip-done": t("verdict.spendHalted"),
  "deny-block": t("verdict.denied"), "deny-done": t("verdict.denied"),
};

// Mobile (<560px) vertical re-stack of the same pipeline. Driven by the SAME
// machine state, but index-based (reached/halt/tone) so it needs no per-flow CSS.
const NODE_ORDER = ["wallet", "policy", "gate", "market"];
const VNODES = [
  { key: "wallet", glyph: "wallet", name: t("node.wallet"), sub: t("node.walletSub") },
  { key: "policy", glyph: "shield", name: t("node.policy"), sub: t("node.policySub") },
  { key: "gate", glyph: "breaker", name: t("node.gate"), sub: t("node.gateSub") },
  { key: "market", glyph: "package", name: t("node.market"), sub: t("node.marketSub") },
];

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
      <text class="fm-name" y="${-HALF - 12}">${t("node.registry")}</text>
    </g>

    ${node("wallet", "wallet", t("node.wallet"), t("node.walletSub"))}
    ${node("policy", "shield", t("node.policy"), t("node.policySub"))}
    ${node("market", "package", t("node.market"), t("node.marketSub"))}


    <!-- procurement gate — the breaker (hero) -->
    <g class="fm-node fm-gate" data-node="gate" transform="translate(${X.gate},${LINE_Y})">
      <rect class="fm-gate-ring" x="${-GHALF - 8}" y="${-GHALF - 8}" width="${(GHALF + 8) * 2}" height="${(GHALF + 8) * 2}" rx="20"/>
      <rect class="fm-tile fm-gate-tile" x="${-GHALF}" y="${-GHALF}" width="${GHALF * 2}" height="${GHALF * 2}" rx="16"/>
      <path class="fm-stub" d="M${-GHALF} 0 H -22"/>
      <path class="fm-stub fm-stub-out" d="M22 0 H ${GHALF}"/>
      <circle class="fm-contact" cx="-22" cy="0" r="4.5"/>
      <circle class="fm-contact fm-contact-out" cx="22" cy="0" r="4.5"/>
      <path class="fm-arm" d="M-22 0 H 22"/>
      <text class="fm-name" y="${GHALF + 20}">${t("node.gate")}</text>
      <text class="fm-out" id="fm-out" y="${GHALF + 36}"></text>
    </g>

    <!-- evidence tags, anchored to segments (computed, not magic) -->
    <g class="fm-tags" aria-hidden="true">
      <a id="fm-tag-sig-link" target="_blank" rel="noopener" tabindex="-1"><text id="fm-tag-sig" class="fm-tag" x="${REG.x + 18}" y="${(REG.y + HALF + LINE_Y - GHALF) / 2 + 4}" text-anchor="start"></text></a>
      <text id="fm-tag-pg"  class="fm-tag" x="${(X.policy + X.gate) / 2}" y="${LINE_Y - 18}" text-anchor="middle"></text>
      <text id="fm-tag-gm"  class="fm-tag" x="${(X.gate + X.market) / 2}" y="${LINE_Y - 18}" text-anchor="middle"></text>
    </g>

    <!-- outcome pips: market delivered ✓ / policy denied ✕ — opaque corner chips
         that cleanly cover the node outline beneath them (no tangled overlap) -->
    <g class="fm-check" aria-hidden="true">
      <circle class="fm-badge-bg" cx="${X.market + HALF}" cy="${LINE_Y - HALF}" r="12"/>
      <use class="fm-check-tick" href="#sym-check" x="${X.market + HALF - 9}" y="${LINE_Y - HALF - 9}" width="18" height="18"/>
    </g>
    <g class="fm-deny-badge" aria-hidden="true">
      <circle class="fm-badge-bg" cx="${X.policy + HALF}" cy="${LINE_Y - HALF}" r="12"/>
      <use class="fm-deny-x" href="#sym-close" x="${X.policy + HALF - 9}" y="${LINE_Y - HALF - 9}" width="18" height="18"/>
    </g>

    <!-- top layer: the travelling spend + the trip signal -->
    <g class="fm-packet" aria-hidden="true">
      <circle class="fm-packet-halo" r="12"/>
      <circle class="fm-packet-core" r="5.5"/>
    </g>
    <circle class="fm-sig-pulse" cx="${REG.x}" cy="${REG.y + HALF}" r="3.5" aria-hidden="true"/>
  </svg>
  <ol class="fm-vlist" aria-hidden="true">
    ${VNODES.map((n) => `
    <li class="fm-vnode" data-node="${n.key}">
      <span class="fm-vicon">${icon(n.glyph)}</span>
      <span class="fm-vmain"><span class="fm-vname">${n.name}</span><span class="fm-vsub">${n.sub}</span></span>
      <span class="fm-vstate"></span>
    </li>`).join("")}
  </ol>`;

  const svg = host.querySelector("svg");
  const out = host.querySelector("#fm-out");
  const tag = (id) => host.querySelector(`#fm-tag-${id}`);
  const vnodes = [...host.querySelectorAll(".fm-vnode")];

  // one-shot "power-up": draw the conduits in once on mount — never on state
  // changes, so it can't compound with the travelling spend. Uses real path
  // lengths and clears its own inline styles afterwards, so the per-state wire
  // colour/dash rules are completely unaffected. Reduced-motion skips it.
  if (document.body.dataset.motion === "full") {
    // defer one frame: getTotalLength() can return 0 if measured synchronously
    // right after innerHTML (before the SVG is laid out).
    requestAnimationFrame(() => {
      const wires = [...svg.querySelectorAll(".fm-wire")];
      const lens = wires.map((w) => { try { return w.getTotalLength(); } catch { return 0; } });
      if (!lens.some((l) => l > 0)) return; // hidden (e.g. mobile re-stack) — skip
      wires.forEach((w, i) => { if (lens[i]) { w.style.strokeDasharray = `${lens[i]}`; w.style.strokeDashoffset = `${lens[i]}`; } });
      requestAnimationFrame(() => {
        wires.forEach((w, i) => {
          if (!lens[i]) return;
          w.style.transition = `stroke-dashoffset 0.62s cubic-bezier(0.16,1,0.3,1) ${0.18 + i * 0.1}s`;
          w.style.strokeDashoffset = "0";
        });
      });
      setTimeout(() => {
        for (const w of wires) { w.style.strokeDasharray = ""; w.style.strokeDashoffset = ""; w.style.transition = ""; }
      }, 1400);
    });
  }

  // Mobile vertical list: each node's state derives from how far the spend
  // reached, where it halted, and the tone — no per-flow rules.
  function applyVList(reached, tone, haltNode, outcomeWord) {
    vnodes.forEach((li) => {
      const idx = NODE_ORDER.indexOf(li.dataset.node);
      let state;
      if (idx < reached) state = "done";
      else if (idx === reached) state = li.dataset.node === haltNode ? "halt" : "active";
      else state = haltNode ? "severed" : "idle";
      li.dataset.state = state;
      li.dataset.tone = state === "idle" || state === "severed" ? "" : tone;
      li.querySelector(".fm-vstate").textContent = idx === reached ? (outcomeWord || "") : "";
    });
  }

  // On narrow viewports the map scrolls horizontally (min-width keeps labels
  // legible), so pan it to keep the active/resting node on-screen — otherwise the
  // hero breaker and one of the three outcomes clip off the edge. No-op on desktop.
  let lastCenter = null;
  function centerOn(nodeKey) {
    if (!nodeKey || nodeKey === lastCenter) return; // skip repeats (e.g. per-log-line emits)
    const max = host.scrollWidth - host.clientWidth;
    if (max <= 1) return; // desktop: not scrollable — don't cache, so a resize still pans
    lastCenter = nodeKey;
    const rendered = svg.getBoundingClientRect().width || host.scrollWidth;
    const px = (X[nodeKey] / VB.w) * rendered;
    const left = Math.max(0, Math.min(max, px - host.clientWidth / 2));
    host.scrollTo({ left, behavior: document.body.dataset.motion === "off" ? "auto" : "smooth" });
  }

  function setTags({ sig = "", pg = "", gm = "", sigBlock = null }) {
    tag("sig").textContent = sig;
    tag("pg").textContent = pg;
    tag("gm").textContent = gm;
    // the registry→gate caption deep-links to its block when it names one
    const sigLink = host.querySelector("#fm-tag-sig-link");
    if (sigLink) {
      if (sigBlock != null && String(sigBlock) !== "—" && String(sigBlock) !== "") {
        sigLink.setAttribute("href", blockUrl(sigBlock));
      } else {
        sigLink.removeAttribute("href");
      }
    }
  }

  function apply(ms) {
    // failure (e.g. ?fail=1) resolves on its own: the spend is stranded at the
    // step that could not execute, the breaker is NOT shown as a clean open, and
    // tone is danger — a broken action never inherits a success/in-progress look.
    if (ms.stage === STAGE.failed) {
      const at = PACKET_AT[ms.activeStep?.flow] ?? "gate";
      svg.dataset.flow = "failed";
      svg.dataset.stage = STAGE.failed;
      svg.dataset.packet = "on";
      svg.style.setProperty("--pk-x", `${packetX(at, true)}px`); // stranded: keep it off the failed node's glyph
      svg.dataset.halt = at;
      svg.dataset.tone = "danger";
      svg.dataset.failnode = at;
      out.textContent = t("verdict.failed");
      setTags({});
      svg.setAttribute("aria-label", `System map: protective action failed at the ${at} — retry available`);
      centerOn(at);
      applyVList(NODE_ORDER.indexOf(at), "danger", at, t("verdict.failed"));
      return;
    }
    delete svg.dataset.failnode;

    const flow =
      ms.stage === STAGE.success
        ? `${ms.scenario?.flow}-done`
        : (ms.activeStep?.flow ?? (ms.scenario ? "armed" : "idle"));
    if (flow !== "idle" && flow !== "armed" && !(flow in PACKET_AT)) {
      console.warn(`[flowmap] no PACKET_AT entry for flow "${flow}" — packet/outcome will be blank`);
    }

    svg.dataset.flow = flow;
    svg.dataset.stage = ms.stage;

    // the travelling spend: position, visibility, halt barrier, tone. data-halt
    // is set ONLY at a real barrier (present-attribute selectors must not match
    // an empty string), so it is removed otherwise.
    const at = PACKET_AT[flow];
    const halt = HALT_AT[flow];
    svg.dataset.packet = at ? "on" : "off";
    if (at) svg.style.setProperty("--pk-x", `${packetX(at, Boolean(halt))}px`);
    if (halt) svg.dataset.halt = halt;
    else delete svg.dataset.halt;
    svg.dataset.tone =
      flow === "armed" ? (ms.scenario?.tone ?? "accent")
        : flow.startsWith("settle") ? (["settle-pay", "settle-deliver", "settle-done"].includes(flow) ? "success" : "accent")
        : flow.startsWith("trip") ? (["trip-cut", "trip-done"].includes(flow) ? "danger" : "warning")
          : flow.startsWith("deny") ? "warning"
            : "accent";

    out.textContent = OUTCOME[flow] ?? "";

    // evidence tags — identical bindings to the prior map, repositioned
    const f = facts ?? {};
    const sc = ms.scenario?.id;
    if (sc === "trip") {
      const b = f.challenge?.blockNumber;
      const tail = f.blocks?.slice(-2);
      setTags({
        "trip-challenge": { sig: "challenge submitted" },
        "trip-detect": { sig: `finalized · block ${b ?? "—"}`, sigBlock: b },
        "trip-cut": { sig: `block ${b ?? "—"}`, gm: "0 moved", sigBlock: b },
        "trip-done": { sig: `blocks ${tail?.join(", ") ?? "—"}`, gm: "0 moved", sigBlock: tail?.at(-1) },
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
    centerOn(at || "gate"); // idle/armed: keep the hero breaker centred, not clipped
    const vtone = flow === "trip-done" ? "success" : svg.dataset.tone; // resolved trip = protected (green), matching desktop
    applyVList(NODE_ORDER.indexOf(at ?? ""), vtone, HALT_AT[flow] ?? null, OUTCOME[flow] ?? "");
  }

  return { apply };
}
