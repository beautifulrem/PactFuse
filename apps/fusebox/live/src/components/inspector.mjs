/* Inspector + live log. The inspector shows the active step's evidence
 * payload (kind, seq, tx, block, risk); the log appends machine entries so
 * the process is visible, not just the result. */

import { short, txUrl, addrUrl, blockUrl } from "../data.mjs";
import { STAGE } from "../machine.mjs";
import { t } from "../i18n.mjs";

// dimmed schematic of what a run WILL bind — fills the idle inspector well
const SCAFFOLD = ["event", "tx", "block", "risk"]
  .map((k) => `<div class="is-ph"><dt>${k}</dt><dd>—</dd></div>`)
  .join("");

const RISK = {
  danger: { key: "risk.danger", tone: "danger" },
  warning: { key: "risk.warning", tone: "warning" },
  success: { key: "risk.success", tone: "success" },
  info: { key: "risk.info", tone: "info" },
};

// Which evidence values are on-chain entities that deep-link to the explorer:
// tx → /tx, these address fields → /address, numeric block → /block. Internal
// ids (spendId, policyDigest, artifactHash, leaseRunId, operationId, sourceHash)
// are NOT explorer entities, so they stay plain text (a link would 404).
const ADDR_KEYS = new Set(["gate", "owner", "spender", "wallet"]);
const exLink = (href, text) => `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
const kvRow = (k, inner) => `<div><dt>${k}</dt><dd>${inner}</dd></div>`;

// the on-chain reference a log row can expand to (full untruncated value + copy)
const REF_RE = /\/(tx|address|block)\/(.+)$/;
const refFromLog = (item) => {
  if (item.link) return { k: "tx", v: item.link };
  const m = item.href && item.href.match(REF_RE);
  return m ? { k: m[1], v: m[2] } : null;
};

export function mountInspector(host) {
  host.innerHTML = `
    <h2 class="panel-title">${t("insp.title")}</h2>
    <div class="inspector-state" id="insState">
      <span class="risk-pill" id="insRisk" data-tone="muted">${t("insp.idle")}</span>
      <span class="inspector-title" id="insTitle">${t("insp.noEvent")}</span>
    </div>
    <p class="inspector-detail" id="insDetail">${t("insp.scaffold")}</p>
    <dl class="inspector-kv mono" id="insKv"></dl>
  `;
  const risk = host.querySelector("#insRisk");
  const title = host.querySelector("#insTitle");
  const detail = host.querySelector("#insDetail");
  const kv = host.querySelector("#insKv");

  function apply(ms) {
    const step = ms.activeStep;
    if (!step) {
      risk.dataset.tone = "muted";
      risk.textContent = t("insp.idle");
      title.textContent = ms.scenario ? `${ms.scenario.title}${t("insp.armedSuffix")}` : t("insp.noEvent");
      detail.textContent = ms.scenario?.lede ?? t("insp.scaffold");
      kv.innerHTML = SCAFFOLD;
      return;
    }
    const base = RISK[step.tone ?? "info"];
    const r = ms.stage === STAGE.failed ? { label: t("risk.failed"), tone: "danger" } : { label: t(base.key), tone: base.tone };
    risk.dataset.tone = r.tone;
    risk.textContent = ms.stage === STAGE.failed ? r.label : (step.risk ?? r.label);
    title.textContent = step.title;
    detail.textContent = ms.stage === STAGE.failed ? (ms.error ?? "failed") : step.detail;
    if (ms.stage === STAGE.failed) {
      // don't show tx/block evidence under "execution failed" — the action never ran
      kv.innerHTML = `<div><dt>evidence</dt><dd>${t("insp.notReached")}</dd></div>`;
      return;
    }
    const rows = Object.entries(step.evidence ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== "");
    kv.innerHTML = rows
      .map(([k, v]) => {
        if (k === "tx" && typeof v === "string") {
          return kvRow("tx", exLink(txUrl(v), short(v, 12, 6)));
        }
        if (k === "block" && /^\d+$/.test(String(v))) {
          return kvRow("block", exLink(blockUrl(v), v));
        }
        if (ADDR_KEYS.has(k) && typeof v === "string" && v.startsWith("0x")) {
          return kvRow(k, exLink(addrUrl(v), short(v, 8, 4)));
        }
        if (k === "event" && typeof v === "object") {
          return kvRow("event", `#${v.seq ?? "—"} · ${v.kind ?? ""}`);
        }
        return kvRow(k, typeof v === "object" ? JSON.stringify(v) : v);
      })
      .join("");
  }
  return { apply };
}

export function mountLog(host, { machine }) {
  host.innerHTML = `
    <h2 class="panel-title">${t("log.title")} <button class="btn btn-ghost panel-clear" id="logClear" type="button" aria-label="${t("log.clear")}">${t("log.clear")}</button></h2>
    <ol class="log" id="logList" aria-label="${t("log.title")}"></ol>
    <p class="log-empty" id="logEmpty">${t("log.empty")}</p>
  `;
  const list = host.querySelector("#logList");
  const empty = host.querySelector("#logEmpty");
  // route through the store so view + counter never desync (stageNote is the
  // single spoken progress channel, so the log is a silent scrollable record)
  host.querySelector("#logClear").addEventListener("click", () => machine.clearLog());

  // expand a row to reveal its full on-chain value + copy (delegated, once)
  list.addEventListener("click", (e) => {
    const exp = e.target.closest(".log-expand");
    if (exp) {
      const open = exp.getAttribute("aria-expanded") === "true";
      exp.setAttribute("aria-expanded", String(!open));
      exp.closest(".log-row").querySelector(".log-detail").hidden = open;
      return;
    }
    const cp = e.target.closest(".ld-copy");
    if (cp) {
      navigator.clipboard?.writeText(cp.dataset.copy);
      cp.dataset.label = cp.dataset.label || cp.textContent;
      cp.textContent = "copied"; cp.classList.add("is-copied");
      setTimeout(() => { cp.textContent = cp.dataset.label; cp.classList.remove("is-copied"); }, 1200);
    }
  });

  let rendered = 0;
  function apply(ms, type) {
    if (type === "reset" || type === "run-start" || type === "select" || type === "log-clear") {
      list.innerHTML = "";
      rendered = 0;
    }
    // Only auto-follow new lines if the reader is already pinned to the bottom.
    // Otherwise a run that appends a line every ~1.5s would keep yanking them
    // back down — so they could never scroll up to read an earlier evidence row.
    const pinnedToBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 24;
    while (rendered < ms.log.length) {
      const item = ms.log[rendered++];
      const li = document.createElement("li");
      li.className = "log-row";
      li.dataset.tone = item.tone;
      const time = new Date(item.at).toLocaleTimeString("en-GB", { hour12: false });
      // item.href is an explicit explorer URL (e.g. an /address line); item.link
      // is a bare tx hash kept for back-compat and resolved to /tx here.
      const href = item.href ?? (item.link ? txUrl(item.link) : null);
      const ref = refFromLog(item);
      li.innerHTML = `<span class="log-time">${time}</span><span class="log-meta">${item.meta ?? ""}</span><span class="log-text">${
        href ? `<a href="${href}" target="_blank" rel="noopener">${item.text}</a>` : item.text
      }</span>${
        ref ? `<button class="log-expand" type="button" aria-expanded="false" aria-label="Show full ${ref.k}">›</button>` : ""
      }${
        ref ? `<div class="log-detail mono" hidden><span class="ld-k">${ref.k}</span><code class="ld-v">${ref.v}</code><button class="ld-copy" type="button" data-copy="${ref.v}" aria-label="Copy ${ref.k}">copy</button></div>` : ""
      }`;
      list.append(li);
    }
    if (pinnedToBottom) list.scrollTop = list.scrollHeight;
    empty.hidden = ms.log.length > 0;
  }
  return { apply };
}
