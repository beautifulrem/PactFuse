/* Demo state machine. UI, flow map, log, and controls all derive from this
 * single store; nothing animates outside a stage transition. The step driver
 * is pluggable: the default driver paces evidence-backed steps on a timer, a
 * future live driver can push the same step events from SSE. */

export const STAGE = {
  idle: "idle",
  pending: "pending",
  detected: "detected",
  executing: "executing",
  success: "success",
  failed: "failed",
};

const STEP_MS = 1450;

export function createMachine() {
  const listeners = new Set();
  const state = {
    stage: STAGE.idle,
    scenarioId: null,
    scenario: null,
    stepIndex: -1,
    activeStep: null,
    outcome: null,
    error: null,
    runId: 0,
    instant: false,
    failArmed: false, // operator toggle / ?fail=1: arm a one-shot transport drop
    failPending: false, // resolved per-run from failArmed; a retry clears it
    log: [],
  };

  const emit = (type) => listeners.forEach((fn) => fn(state, type));
  const delay = (ms) =>
    new Promise((res) => setTimeout(res, state.instant ? 0 : ms));

  function pushLog(line, tone = "info") {
    state.log.push({ ...line, tone, at: Date.now() });
    emit("log");
  }

  function select(scenario) {
    if (state.stage !== STAGE.idle && state.stage !== STAGE.success && state.stage !== STAGE.failed) return;
    state.scenarioId = scenario?.id ?? null;
    state.scenario = scenario ?? null;
    state.stage = STAGE.idle;
    state.stepIndex = -1;
    state.activeStep = null;
    state.outcome = null;
    state.error = null;
    state.log = [];
    emit("select");
  }

  async function run(recover = false) {
    if (!state.scenario || state.stage === STAGE.pending || state.stage === STAGE.detected || state.stage === STAGE.executing) return;
    const runId = ++state.runId;
    // one-shot failure injection: a normal run honours the armed flag; a retry
    // (recover) always clears it, so the same scenario recovers and then re-arms
    // on the next fresh run if the toggle is still on.
    state.failPending = recover ? false : state.failArmed;
    state.outcome = null;
    state.error = null;
    state.stepIndex = -1;
    state.activeStep = null; // clear the prior terminal frame before announcing
    state.stage = STAGE.pending;
    state.log = [];
    emit("run-start");
    pushLog({ text: `scenario armed · ${state.scenario.title}`, meta: "operator" }, "info");

    for (let i = 0; i < state.scenario.steps.length; i++) {
      if (runId !== state.runId) return;
      const step = state.scenario.steps[i];
      if (step.fragile && state.failPending) {
        state.stage = STAGE.failed;
        state.error = step.failReason ?? "simulated transport drop, retry clears it";
        state.activeStep = step;
        pushLog({ text: `step failed · ${state.error}`, meta: "driver" }, "danger");
        emit("stage");
        return;
      }
      state.stage = step.stage;
      state.stepIndex = i;
      state.activeStep = step;
      emit("stage");
      for (const line of step.log ?? []) pushLog(line, step.tone ?? "info");
      await delay(step.holdMs ?? STEP_MS);
    }

    if (runId !== state.runId) return;
    state.stage = STAGE.success;
    state.outcome = state.scenario.outcome;
    emit("stage");
    pushLog({ text: `outcome · ${state.scenario.outcome.label}`, meta: "verifier" }, state.scenario.outcome.tone);
  }

  function reset() {
    state.runId++;
    state.stage = STAGE.idle;
    state.stepIndex = -1;
    state.activeStep = null;
    state.outcome = null;
    state.error = null;
    state.log = [];
    emit("reset");
  }

  function retry() {
    if (state.stage !== STAGE.failed) return;
    run(true);
  }

  function armFailure(v) {
    state.failArmed = Boolean(v);
  }

  function clearLog() {
    state.log = [];
    emit("log-clear");
  }

  return {
    state,
    subscribe: (fn) => (listeners.add(fn), () => listeners.delete(fn)),
    select,
    run,
    reset,
    retry,
    armFailure,
    clearLog,
    setInstant: (v) => (state.instant = Boolean(v)),
  };
}
