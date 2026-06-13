/* AppShell boot: load evidence (with explicit loading and error states),
 * build the machine, mount components, and wire subscriptions. */

import { mountSymbolSprite } from "./symbols.mjs";
import { createMachine } from "./machine.mjs";
import { loadEvidence, fixtureModel, DEFAULT_SESSION } from "./data.mjs";
import { mountScenarioPanel, mountStageRail } from "./components/scenario.mjs";
import { mountFlowMap } from "./components/flowmap.mjs";
import { mountInspector, mountLog } from "./components/inspector.mjs";
import { mountHeader, mountMetrics, mountDrawers, mountFooter, makeToast } from "./components/chrome.mjs";

const qs = new URLSearchParams(location.search);
const $ = (id) => document.getElementById(id);

async function boot() {
  mountSymbolSprite();
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.body.dataset.motion = reduce ? "off" : "full";

  const loadingEl = $("appLoading");
  let model;
  try {
    model = await loadEvidence({
      session: qs.get("session") ?? DEFAULT_SESSION,
      artifactsBase: qs.get("artifacts") ?? undefined,
    });
  } catch (err) {
    console.warn("[console] artifacts unreachable, fixture fallback:", err);
    model = fixtureModel();
  }
  loadingEl.remove();

  const machine = createMachine();
  machine.setInstant(reduce);
  const failParam = qs.get("fail"); // ?fail=1 arms a transport drop; the in-UI toggle drives the same flag
  machine.armFailure(failParam !== null && failParam !== "0" && failParam !== "false");

  // keep motion preference live: OS toggles mid-session update both the CSS
  // gate (data-motion) and the machine's instant stepping.
  matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (e) => {
    document.body.dataset.motion = e.matches ? "off" : "full";
    machine.setInstant(e.matches);
  });

  const toast = makeToast($("toast"));
  mountHeader($("appHeader"), model);
  mountMetrics($("metricStrip"), model);
  const drawers = mountDrawers($("drawerRoot"), model, toast);
  mountFooter($("appFooter"), model);

  const scenarioPanel = mountScenarioPanel($("scenarioPanel"), { machine, scenarios: model.scenarios });
  const stageRail = mountStageRail($("stageRail"));
  const flowMap = mountFlowMap($("flowMap"), model.facts);
  const inspector = mountInspector($("inspectorPanel"));
  const log = mountLog($("logPanel"), { machine });

  const applyAll = (ms, type) => {
    scenarioPanel.apply(ms);
    stageRail.apply(ms);
    flowMap.apply(ms);
    inspector.apply(ms);
    log.apply(ms, type);
  };
  machine.subscribe(applyAll);

  $("appHeader").addEventListener("click", (e) => {
    if (e.target.closest("#sessionChip")) {
      navigator.clipboard.writeText(model.sessionId).then(() => toast("session id copied"), () => toast(model.sessionId));
    }
    if (e.target.closest("#openJudge")) drawers.openJudge();
    if (e.target.closest("#openHashes")) drawers.openHashes();
  });

  machine.select(model.scenarios[0]);
  applyAll(machine.state, "init");

  if (qs.has("autorun")) machine.run();
}

boot();
