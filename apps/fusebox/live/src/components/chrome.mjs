/* App chrome: header (value prop + provenance), metric strip, judge-check
 * and hash drawers, footer provenance line, toast. */

import { icon } from "../symbols.mjs";
import { short, fmt } from "../data.mjs";

export function mountHeader(host, model) {
  const claim = model.claim;
  const passed = model.judgeRows.filter((r) => r.status === "pass").length;
  const total = model.judgeRows.length;
  host.innerHTML = `
    <div class="head-brand">
      <p class="head-kicker mono">Fusebox proof cockpit · Cobo Agentic Wallet track</p>
      <h1 class="head-title"><em>PactFuse</em> · source-fresh procurement for agent spending</h1>
      <p class="head-lede">PactFuse watches the chain while an agent buys tool leases with its Cobo Agentic Wallet.
      If a pinned source turns unsafe, the on-chain gate interrupts the spend <em>before payment</em>; clean leases settle and deliver — every claim below replays signed evidence.</p>
      <div class="head-proofline" role="list" aria-label="Proof path">
        <span class="proof-step" role="listitem" data-tone="accent">${icon("wallet")}<span><b>CAW authorizes</b><small>owner-bound spend rail</small></span></span>
        <span class="proof-step" role="listitem" data-tone="danger">${icon("breaker")}<span><b>Gate interrupts</b><small>unsafe source before payment</small></span></span>
        <span class="proof-step" role="listitem" data-tone="success">${icon("check")}<span><b>Receipt proves</b><small>${total ? `${passed}/${total} judge checks` : "fixture mode only"}</small></span></span>
      </div>
    </div>
    <div class="head-side">
      <div class="head-chips">
        <button class="chip chip-copy" id="sessionChip" type="button" title="Copy session id">
          ${icon("doc")} <span class="mono">${short(model.sessionId, 8, 6)}</span>
        </button>
        <span class="chip" data-tone="${model.source === "verified" ? "success" : "warning"}">
          ${model.source === "verified" ? "verified evidence" : "fixture fallback"}
        </span>
        ${claim ? `<span class="chip" data-tone="provenance" title="${claim.claimMode} · ${claim.tokenSettlementClaim} · authorized ${claim.authorizedAt}">live claim · mock-ERC20 settlement (testnet)</span>` : ""}
      </div>
      <div class="head-links">
        <button class="btn btn-ghost" id="openJudge" type="button">${icon("check")} ${model.judgeRows.length ? `judge check ${passed}/${total}` : "judge check —"}</button>
        <button class="btn btn-ghost" id="openHashes" type="button">${icon("pulse")} proof hashes</button>
      </div>
      ${
        model.source === "fixture"
          ? `<p class="evidence-alert" role="status">Proof artifacts did not load from this origin. UI is in fixture fallback and cannot claim verified pass.</p>`
          : ""
      }
    </div>
  `;
}

export function mountMetrics(host, model) {
  host.innerHTML = model.metrics
    .map(
      (m) => `
    <div class="metric" data-tone="${m.tone ?? ""}">
      <span class="metric-value mono" data-target="${m.value}">0</span><span class="metric-suffix mono">${m.suffix ?? ""}</span>
      <span class="metric-label">${m.label}</span>
    </div>`,
    )
    .join("");

  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  host.querySelectorAll(".metric-value").forEach((n) => {
    const target = Number(n.dataset.target) || 0;
    if (reduce || target === 0) {
      n.textContent = fmt(target);
      return;
    }
    const t0 = performance.now();
    const dur = 900;
    const tick = (t) => {
      const p = Math.min(1, (t - t0) / dur);
      n.textContent = fmt(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

function claimStatementItem(model) {
  const c = model.claim;
  if (!c) return "";
  return `<div class="hx-item"><p class="hx-k mono">authorized public claim</p><div class="hx-v"><code class="mono">${c.claimStatus} @ ${c.authorizedAt} · claimMode=${c.claimMode} · tokenSettlementClaim=${c.tokenSettlementClaim} · winnerClaimAllowed=${c.winnerClaimAllowed} (session-scoped)</code></div></div>`;
}

export function mountDrawers(root, model, toast) {
  root.innerHTML = `
    <div class="drawer" id="drawerJudge" role="dialog" aria-modal="true" aria-label="Judge check" hidden>
      <header><h3>Judge check</h3><span class="mono drawer-sub">${short(model.sessionId, 8, 6)}</span>
        <button class="btn btn-ghost drawer-x" type="button" data-close aria-label="Close">${icon("close")}</button></header>
      <div class="drawer-body">
        ${
          model.judgeRows.length
            ? model.judgeRows
                .map(
                  (r) => `
          <div class="jc-row" data-status="${r.status}">
            <i class="jc-dot" aria-hidden="true"></i>
            <div>
              <p class="jc-label">${r.label} <span class="mono">${r.status} · ${r.authority}</span></p>
              <p class="jc-reason">${r.reason ?? ""}</p>
              <p class="jc-ev mono">evidence ${short(r.evidenceEventId ?? "", 12, 6)}</p>
            </div>
          </div>`,
                )
                .join("")
            : `<p class="jc-reason">fixture mode — judge rows unavailable</p>`
        }
      </div>
    </div>
    <div class="drawer" id="drawerHashes" role="dialog" aria-modal="true" aria-label="Proof hashes" hidden>
      <header><h3>Proof hashes</h3><span class="mono drawer-sub">recompute offline · verify-live-artifacts</span>
        <button class="btn btn-ghost drawer-x" type="button" data-close aria-label="Close">${icon("close")}</button></header>
      <div class="drawer-body">
        ${claimStatementItem(model)}
        ${Object.entries(model.hashes)
          .map(
            ([k, v]) => `
          <div class="hx-item">
            <p class="hx-k mono">${k}</p>
            <div class="hx-v"><code class="mono">${v ?? "—"}</code>
            ${v && String(v).startsWith("0x") ? `<button class="btn btn-ghost" type="button" data-copy="${v}" aria-label="Copy ${k} hash">${icon("copy")}</button>` : ""}</div>
          </div>`,
          )
          .join("")}
        ${model.attestation ? `<div class="hx-item"><p class="hx-k mono">ed25519 attestation</p><div class="hx-v"><code class="mono">sig ${short(model.attestation.signature, 16, 10)}</code></div></div>` : ""}
      </div>
    </div>
    <div class="scrim" id="scrim" hidden></div>
  `;

  const scrim = root.querySelector("#scrim");
  // mirror the drawer transition so it can't desync from the token
  const DUR_MED = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--dur-med")) || 260;
  let lastFocus = null;
  const open = (id) => {
    lastFocus = document.activeElement;
    const d = root.querySelector(id);
    d.hidden = false;
    scrim.hidden = false;
    requestAnimationFrame(() => d.classList.add("is-open"));
    d.querySelector("[data-close]").focus();
  };
  const closeAll = () => {
    root.querySelectorAll(".drawer.is-open").forEach((d) => {
      d.classList.remove("is-open");
      setTimeout(() => (d.hidden = true), DUR_MED);
    });
    scrim.hidden = true;
    lastFocus?.focus?.();
  };
  root.addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) closeAll();
    const c = e.target.closest("[data-copy]");
    if (c) navigator.clipboard.writeText(c.dataset.copy).then(() => toast("hash copied"), () => toast("copy failed"));
  });
  scrim.addEventListener("click", closeAll);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeAll();
    if (e.key === "Tab") {
      const openDrawer = root.querySelector(".drawer.is-open");
      if (!openDrawer) return;
      const focusables = [...openDrawer.querySelectorAll("button, a[href]")];
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      } else if (!openDrawer.contains(document.activeElement)) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  return { openJudge: () => open("#drawerJudge"), openHashes: () => open("#drawerHashes") };
}

export function mountFooter(host, model) {
  host.textContent =
    model.source === "verified"
      ? `verified replay · public claim authorized ${(model.claim?.authorizedAt ?? "").slice(0, 10)} · the console renders evidence — it never creates proof authority`
      : `fixture fallback — proof artifacts unreachable from this origin; fixture states render no proof pass. serve the repo root to load the verified session`;
}

export function makeToast(host) {
  let timer;
  return (msg) => {
    host.textContent = msg;
    host.hidden = false;
    clearTimeout(timer);
    timer = setTimeout(() => (host.hidden = true), 2200);
  };
}
