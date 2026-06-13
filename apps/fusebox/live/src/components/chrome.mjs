/* App chrome: header (value prop + provenance), metric strip, judge-check
 * and hash drawers, footer provenance line, toast. */

import { icon } from "../symbols.mjs";
import { short, fmt } from "../data.mjs";
import { t, getLang } from "../i18n.mjs";

export function mountHeader(host, model) {
  const claim = model.claim;
  const passed = model.judgeRows.filter((r) => r.status === "pass").length;
  const total = model.judgeRows.length;
  host.innerHTML = `
    <div class="head-brand">
      <p class="head-kicker mono">${t("head.kicker")}</p>
      <h1 class="head-title">${t("head.titleHtml")}</h1>
      <p class="head-lede">${t("head.ledeHtml")}</p>
      <div class="head-proofline" role="list" aria-label="${t("head.proof1b")}">
        <span class="proof-step" role="listitem" data-tone="accent">${icon("wallet")}<span><b>${t("head.proof1b")}</b><small>${t("head.proof1s")}</small></span></span>
        <span class="proof-step" role="listitem" data-tone="danger">${icon("breaker")}<span><b>${t("head.proof2b")}</b><small>${t("head.proof2s")}</small></span></span>
        <span class="proof-step" role="listitem" data-tone="success">${icon("check")}<span><b>${t("head.proof3b")}</b><small>${total ? t("head.proof3s", { n: `${passed}/${total}` }) : t("head.proof3sFixture")}</small></span></span>
      </div>
    </div>
    <div class="head-side">
      <div class="lang-toggle" role="group" aria-label="Language / 语言">
        <button type="button" data-lang="en" class="${getLang() === "en" ? "is-active" : ""}" aria-pressed="${getLang() === "en"}">EN</button>
        <button type="button" data-lang="zh" class="${getLang() === "zh" ? "is-active" : ""}" aria-pressed="${getLang() === "zh"}">中文</button>
      </div>
      <div class="head-chips">
        <button class="chip chip-copy" id="sessionChip" type="button" title="Copy session id">
          ${icon("doc")} <span class="mono">${short(model.sessionId, 8, 6)}</span>
        </button>
        <span class="chip" data-tone="${model.source === "verified" ? "success" : "warning"}">
          ${model.source === "verified" ? t("chip.verified") : t("chip.fixture")}
        </span>
        ${claim ? `<span class="chip" data-tone="provenance" title="${claim.claimMode} · ${claim.tokenSettlementClaim} · authorized ${claim.authorizedAt}">${t("chip.liveClaim")}</span>` : ""}
      </div>
      <div class="head-links">
        <button class="btn btn-ghost" id="openJudge" type="button">${icon("check")} ${model.judgeRows.length ? t("link.judge", { p: passed, t: total }) : t("link.judgeEmpty")}</button>
        <button class="btn btn-ghost" id="openHashes" type="button">${icon("pulse")} ${t("link.hashes")}</button>
        <button class="btn btn-ghost" id="openSelfTest" type="button">${icon("shield")} ${t("link.selftest")}</button>
      </div>
      ${
        model.source === "fixture"
          ? `<p class="evidence-alert" role="status">${t("alert.fixture")}</p>`
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
    <div class="drawer" id="drawerJudge" role="dialog" aria-modal="true" aria-label="${t("drawer.judge")}" hidden>
      <header><h3>${t("drawer.judge")}</h3><span class="mono drawer-sub">${short(model.sessionId, 8, 6)}</span>
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
            : `<p class="jc-reason">${t("judge.fixture")}</p>`
        }
      </div>
    </div>
    <div class="drawer" id="drawerHashes" role="dialog" aria-modal="true" aria-label="${t("drawer.hashes")}" hidden>
      <header><h3>${t("drawer.hashes")}</h3><span class="mono drawer-sub">${t("drawer.hashesSub")}</span>
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
    <div class="drawer" id="drawerSelfTest" role="dialog" aria-modal="true" aria-label="${t("drawer.selftest")}" hidden>
      <header><h3>${t("drawer.selftest")}</h3><span class="mono drawer-sub">${t("drawer.selftestSub")}</span>
        <button class="btn btn-ghost drawer-x" type="button" data-close aria-label="Close">${icon("close")}</button></header>
      <div class="drawer-body">
        <ol class="st-list" id="stList"></ol>
        <p class="st-summary mono" id="stSummary"></p>
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
    if (c) navigator.clipboard.writeText(c.dataset.copy).then(() => toast(t("toast.hash")), () => toast(t("toast.copyFail")));
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

  // Self-test: a one-click, client-side integrity check of the loaded evidence.
  // Honest — it asserts what the bundle actually carries (verified vs fixture),
  // and reveals each check in sequence for a 10-second confidence read.
  function runSelfTest() {
    const passed = model.judgeRows.filter((r) => r.status === "pass").length;
    const total = model.judgeRows.length;
    const hashCount = Object.values(model.hashes ?? {}).filter((v) => String(v).startsWith("0x")).length;
    const checks = [
      { label: t("st.loaded"), pass: Boolean(model.sessionId) },
      { label: model.source === "verified" ? t("st.verified") : t("st.fixture"), pass: model.source === "verified" },
      { label: t("st.judge", { p: passed, t: total || "—" }), pass: total > 0 && passed === total },
      { label: t("st.claim"), pass: Boolean(model.claim) },
      { label: t("st.hashes", { n: hashCount }), pass: hashCount > 0 },
      { label: t("st.attest"), pass: Boolean(model.attestation) },
    ];
    const stList = root.querySelector("#stList");
    const stSummary = root.querySelector("#stSummary");
    stList.innerHTML = checks
      .map((c) => `<li class="st-row" data-state="pending"><i class="st-dot" aria-hidden="true"></i><span class="st-label">${c.label}</span><span class="st-mark" aria-hidden="true"></span></li>`)
      .join("");
    stSummary.textContent = "";
    stSummary.removeAttribute("data-tone");
    const rows = [...stList.querySelectorAll(".st-row")];
    const instant = document.body.dataset.motion === "off";
    const reveal = (i) => {
      if (i >= checks.length) {
        const ok = checks.every((c) => c.pass);
        stSummary.dataset.tone = ok ? "success" : "warning";
        stSummary.textContent = ok
          ? t("st.ok", { n: checks.length })
          : t("st.bad", { p: checks.filter((c) => c.pass).length, n: checks.length });
        return;
      }
      rows[i].dataset.state = checks[i].pass ? "pass" : "fail";
      rows[i].querySelector(".st-mark").textContent = checks[i].pass ? "✓" : "✕";
      setTimeout(() => reveal(i + 1), instant ? 0 : 230);
    };
    reveal(0);
  }

  return {
    openJudge: () => open("#drawerJudge"),
    openHashes: () => open("#drawerHashes"),
    openSelfTest: () => { open("#drawerSelfTest"); runSelfTest(); },
  };
}

export function mountFooter(host, model) {
  host.textContent =
    model.source === "verified"
      ? t("footer.verified", { date: (model.claim?.authorizedAt ?? "").slice(0, 10) })
      : t("footer.fixture");
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
