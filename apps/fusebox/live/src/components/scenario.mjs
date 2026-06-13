/* EventTriggerPanel + stage rail. The operator side of the console: pick a
 * real evidence scenario, run it, watch the stage machine, retry on failure,
 * reset to idle. */

import { icon } from "../symbols.mjs";
import { STAGE } from "../machine.mjs";

const RAIL = [
  { id: STAGE.pending, label: "event" },
  { id: STAGE.detected, label: "detect" },
  { id: STAGE.executing, label: "respond" },
  { id: STAGE.success, label: "done" },
];

export function mountScenarioPanel(host, { machine, scenarios }) {
  host.innerHTML = `
    <h2 class="panel-title">Risk scenarios <span class="panel-hint">replayed from verified evidence</span></h2>
    <div class="scenario-list" role="radiogroup" aria-label="Choose a risk scenario"></div>
    <div class="scenario-actions">
      <button class="btn btn-primary" id="runBtn" type="button" disabled>${icon("play")} Run scenario</button>
      <button class="btn" id="resetBtn" type="button">${icon("reset")} Reset</button>
    </div>
    <button class="fail-toggle" id="failToggle" type="button" role="switch" aria-checked="false">
      <span class="fail-track" aria-hidden="true"><span class="fail-knob"></span></span>
      <span>simulate transport drop</span>
    </button>
    <ol class="stage-rail" aria-label="Demo stage">
      ${RAIL.map((r) => `<li class="stage-pill" data-stage-id="${r.id}"><i class="stage-dot" aria-hidden="true"></i>${r.label}</li>`).join("")}
    </ol>
    <div class="stage-note" id="stageNote" role="status" aria-live="polite"></div>
  `;

  const list = host.querySelector(".scenario-list");
  list.innerHTML = scenarios
    .map(
      (s) => `
    <button class="scenario" type="button" role="radio" aria-checked="false" tabindex="-1" data-id="${s.id}" data-tone="${s.tone}">
      <span class="scenario-mark" aria-hidden="true">${icon(s.id === "trip" ? "breaker" : s.id === "settle" ? "shield" : "deny")}</span>
      <span class="scenario-body">
        <span class="scenario-title">${s.title}</span>
        <span class="scenario-lede">${s.lede}</span>
      </span>
    </button>`,
    )
    .join("");

  const runBtn = host.querySelector("#runBtn");
  const resetBtn = host.querySelector("#resetBtn");
  const note = host.querySelector("#stageNote");

  const isRunning = () => [STAGE.pending, STAGE.detected, STAGE.executing].includes(machine.state.stage);
  const pick = (id) => machine.select(scenarios.find((s) => s.id === id));

  list.querySelectorAll(".scenario").forEach((btn) =>
    btn.addEventListener("click", () => pick(btn.dataset.id)),
  );

  // APG radiogroup keyboard model: arrows/Home/End move selection + focus (roving
  // tabindex is maintained in apply()); selection is locked while a run is in flight.
  list.addEventListener("keydown", (e) => {
    const items = [...list.querySelectorAll(".scenario")];
    const i = items.indexOf(document.activeElement);
    if (i < 0 || isRunning()) return;
    let j = i;
    if (e.key === "ArrowDown" || e.key === "ArrowRight") j = (i + 1) % items.length;
    else if (e.key === "ArrowUp" || e.key === "ArrowLeft") j = (i - 1 + items.length) % items.length;
    else if (e.key === "Home") j = 0;
    else if (e.key === "End") j = items.length - 1;
    else return;
    e.preventDefault();
    pick(items[j].dataset.id); // apply() runs synchronously and sets tabindex…
    items[j].focus(); // …so the freshly-selected radio is focusable here
  });

  runBtn.addEventListener("click", () => {
    if (machine.state.stage === STAGE.failed) machine.retry();
    else machine.run();
  });
  resetBtn.addEventListener("click", () => machine.reset());

  const failToggle = host.querySelector("#failToggle");
  failToggle.setAttribute("aria-checked", String(machine.state.failArmed)); // sync with ?fail=1
  failToggle.addEventListener("click", () => {
    const on = failToggle.getAttribute("aria-checked") !== "true";
    failToggle.setAttribute("aria-checked", String(on));
    machine.armFailure(on);
  });

  function apply(ms) {
    let anyChecked = false;
    list.querySelectorAll(".scenario").forEach((b) => {
      const sel = b.dataset.id === ms.scenarioId;
      b.setAttribute("aria-checked", String(sel));
      b.classList.toggle("is-selected", sel);
      b.tabIndex = sel ? 0 : -1; // roving tabindex follows the checked radio
      if (sel) anyChecked = true;
    });
    if (!anyChecked) { const first = list.querySelector(".scenario"); if (first) first.tabIndex = 0; }
    const running = [STAGE.pending, STAGE.detected, STAGE.executing].includes(ms.stage);
    runBtn.disabled = !ms.scenario || running;
    runBtn.innerHTML =
      ms.stage === STAGE.failed
        ? `${icon("retry")} Retry`
        : ms.stage === STAGE.success
          ? `${icon("play")} Run again`
          : `${icon("play")} Run scenario`;
    host.dataset.stage = ms.stage;

    const reached = { [STAGE.pending]: 1, [STAGE.detected]: 2, [STAGE.executing]: 3, [STAGE.success]: 4, [STAGE.failed]: 3 }[ms.stage] ?? 0;
    host.querySelectorAll(".stage-pill").forEach((p, i) => {
      p.dataset.state = i < reached ? (i === reached - 1 && ms.stage === STAGE.failed ? "failed" : i === reached - 1 ? "active" : "done") : "wait";
      if (ms.stage === STAGE.success) p.dataset.state = "done";
    });

    if (ms.stage === STAGE.failed) {
      note.textContent = `failed — ${ms.error}`;
      note.dataset.tone = "danger";
    } else if (ms.stage === STAGE.success) {
      note.textContent = ms.outcome?.label ?? "complete";
      note.dataset.tone = ms.outcome?.tone ?? "success";
    } else if (ms.activeStep) {
      note.textContent = ms.activeStep.title;
      note.dataset.tone = ms.activeStep.tone ?? "info";
    } else if (ms.scenario) {
      note.textContent = "armed — run to replay the evidence";
      note.dataset.tone = "info";
    } else {
      note.textContent = "select a scenario to begin";
      note.dataset.tone = "muted";
    }
  }

  return { apply };
}
