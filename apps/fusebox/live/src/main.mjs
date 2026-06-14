/* AppShell boot: load evidence (with explicit loading and error states),
 * build the machine, mount components, and wire subscriptions. */

import { mountSymbolSprite } from "./symbols.mjs";
import { createMachine, STAGE } from "./machine.mjs";
import { loadEvidence, fixtureModel, DEFAULT_SESSION } from "./data.mjs";
import { mountScenarioPanel, mountStageRail } from "./components/scenario.mjs";
import { mountFlowMap } from "./components/flowmap.mjs";
import { mountInspector, mountLog } from "./components/inspector.mjs";
import { mountHeader, mountMetrics, mountDrawers, mountFooter, makeToast } from "./components/chrome.mjs";
import { t, setLang, applyStaticI18n } from "./i18n.mjs";

const qs = new URLSearchParams(location.search);
const $ = (id) => document.getElementById(id);

async function boot() {
  mountSymbolSprite();
  applyStaticI18n(); // translate static markup (loading text, help overlay) to the saved language
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.body.dataset.motion = reduce ? "off" : "full";

  const splash = $("splashScreen");
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
  document.body.dataset.evidence = model.source;
  // dismiss splash with a fade after a minimum visible time (let the bar animation finish)
  const minSplash = new Promise((r) => setTimeout(r, 2200));
  await minSplash;
  splash.hidden = true;
  setTimeout(() => splash.remove(), 700);

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

  // pointer parallax for the ambient aurora: one rAF-throttled CSS var write.
  // The transform that consumes --mx/--my is gated to data-motion=full in CSS,
  // so reduced-motion / the JS toggle ignore it for free.
  let parallaxRaf = 0;
  addEventListener("pointermove", (e) => {
    if (parallaxRaf) return;
    parallaxRaf = requestAnimationFrame(() => {
      parallaxRaf = 0;
      document.body.style.setProperty("--mx", (e.clientX / innerWidth - 0.5).toFixed(3));
      document.body.style.setProperty("--my", (e.clientY / innerHeight - 0.5).toFixed(3));
    });
  }, { passive: true });

  const toast = makeToast($("toast"));
  mountHeader($("appHeader"), model);
  mountMetrics($("metricStrip"), model);
  const drawers = mountDrawers($("drawerRoot"), model, toast);
  mountFooter($("appFooter"), model);

  const scenarioPanel = mountScenarioPanel($("scenarioPanel"), { machine, scenarios: model.scenarios, onchain: model.onchain });
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
    const langBtn = e.target.closest(".lang-toggle [data-lang]");
    if (langBtn) { setLang(langBtn.dataset.lang); return; } // persists + reloads in the chosen language
    if (e.target.closest("#sessionChip")) {
      navigator.clipboard.writeText(model.sessionId).then(() => toast(t("toast.session")), () => toast(model.sessionId));
    }
    if (e.target.closest("#openJudge")) drawers.openJudge();
    if (e.target.closest("#openHashes")) drawers.openHashes();
    if (e.target.closest("#openSelfTest")) drawers.openSelfTest?.();
    if (e.target.closest("#openChainState")) drawers.openChainState?.();
  });

  // ── judge-friendly keyboard shortcuts + help overlay ──────────────────────
  const helpEl = $("shortcutHelp");
  const setHelp = (open) => { helpEl.hidden = !open; if (open) helpEl.querySelector("#helpClose")?.focus(); };
  helpEl.addEventListener("click", (e) => { if (e.target === helpEl || e.target.closest("#helpClose")) setHelp(false); });
  $("helpHint").addEventListener("click", () => setHelp(true));
  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || e.target.isContentEditable) return;
    if (e.key === "?") { e.preventDefault(); setHelp(helpEl.hidden); return; }
    if (!helpEl.hidden) { if (e.key === "Escape") setHelp(false); return; }
    if (document.querySelector(".drawer.is-open")) return; // open drawers own their keys (Esc/Tab)
    const k = e.key.toLowerCase();
    if (k >= "1" && k <= "3") { const s = model.scenarios[+k - 1]; if (s) machine.select(s); e.preventDefault(); }
    else if (k === "r") { machine.state.stage === STAGE.failed ? machine.retry() : machine.run(); e.preventDefault(); }
    else if (k === "c") { machine.clearLog(); e.preventDefault(); }
    else if (k === "0") { machine.reset(); e.preventDefault(); }
    else if (k === "j") { drawers.openJudge(); e.preventDefault(); }
    else if (k === "h") { drawers.openHashes(); e.preventDefault(); }
    else if (k === "t") { drawers.openSelfTest?.(); e.preventDefault(); }
    else if (k === "g") { drawers.openChainState?.(); e.preventDefault(); }
  });

  machine.select(model.scenarios[0]);
  applyAll(machine.state, "init");

  if (qs.has("autorun")) machine.run();
}

boot();
