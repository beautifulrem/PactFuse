/* Inspector + live log. The inspector shows the active step's evidence
 * payload (kind, seq, tx, block, risk); the log appends machine entries so
 * the process is visible, not just the result. */

import { short, txUrl, addrUrl, blockUrl } from "../data.mjs";
import { STAGE } from "../machine.mjs";

// dimmed schematic of what a run WILL bind — fills the idle inspector well
const SCAFFOLD = ["event", "tx", "block", "risk"]
  .map((k) => `<div class="is-ph"><dt>${k}</dt><dd>—</dd></div>`)
  .join("");

const RISK = {
  danger: { label: "high risk", tone: "danger" },
  warning: { label: "policy violation", tone: "warning" },
  success: { label: "clean path", tone: "success" },
  info: { label: "monitored", tone: "info" },
};

// Which evidence values are on-chain entities that deep-link to the explorer:
// tx → /tx, these address fields → /address, numeric block → /block. Internal
// ids (spendId, policyDigest, artifactHash, leaseRunId, operationId, sourceHash)
// are NOT explorer entities, so they stay plain text (a link would 404).
const ADDR_KEYS = new Set(["gate", "owner", "spender", "wallet"]);
const exLink = (href, text) => `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
const kvRow = (k, inner) => `<div><dt>${k}</dt><dd>${inner}</dd></div>`;

export function mountInspector(host) {
  host.innerHTML = `
    <h2 class="panel-title">Inspector</h2>
    <div class="inspector-state" id="insState">
      <span class="risk-pill" id="insRisk" data-tone="muted">idle</span>
      <span class="inspector-title" id="insTitle">no active event</span>
    </div>
    <p class="inspector-detail" id="insDetail">Select and run a scenario; each step binds to a verified evidence row.</p>
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
      risk.textContent = "idle";
      title.textContent = ms.scenario ? `${ms.scenario.title} — armed` : "no active event";
      detail.textContent = ms.scenario?.lede ?? "Select and run a scenario; each step binds to a verified evidence row.";
      kv.innerHTML = SCAFFOLD;
      return;
    }
    const r = ms.stage === STAGE.failed ? { label: "execution failed", tone: "danger" } : RISK[step.tone ?? "info"];
    risk.dataset.tone = r.tone;
    risk.textContent = ms.stage === STAGE.failed ? r.label : (step.risk ?? r.label);
    title.textContent = step.title;
    detail.textContent = ms.stage === STAGE.failed ? (ms.error ?? "failed") : step.detail;
    if (ms.stage === STAGE.failed) {
      // don't show tx/block evidence under "execution failed" — the action never ran
      kv.innerHTML = `<div><dt>evidence</dt><dd>not reached · step did not execute</dd></div>`;
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
    <h2 class="panel-title">Evidence log <button class="btn btn-ghost panel-clear" id="logClear" type="button" aria-label="Clear evidence log">clear</button></h2>
    <ol class="log" id="logList" aria-label="Evidence log"></ol>
    <p class="log-empty" id="logEmpty">log is empty — run a scenario</p>
  `;
  const list = host.querySelector("#logList");
  const empty = host.querySelector("#logEmpty");
  // route through the store so view + counter never desync (stageNote is the
  // single spoken progress channel, so the log is a silent scrollable record)
  host.querySelector("#logClear").addEventListener("click", () => machine.clearLog());

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
      li.innerHTML = `<span class="log-time">${time}</span><span class="log-meta">${item.meta ?? ""}</span><span class="log-text">${
        href ? `<a href="${href}" target="_blank" rel="noopener">${item.text}</a>` : item.text
      }</span>`;
      list.append(li);
    }
    if (pinnedToBottom) list.scrollTop = list.scrollHeight;
    empty.hidden = ms.log.length > 0;
  }
  return { apply };
}
