/* Tiny i18n for the console. The readable UI (chrome, scenario narrative, labels)
 * translates; protocol/evidence text (tx hashes, event names, log records, claim
 * modes) stays in its canonical form. Language is persisted in localStorage and
 * applied at boot — setLang() reloads so every string (incl. the evidence-derived
 * model) is rebuilt in one language with no partial-render edge cases. */

const STR = {
  en: {
    "loading": "loading signed proof artifacts…",

    "head.kicker": "Fusebox proof cockpit · Cobo Agentic Wallet track",
    "head.titleHtml": "<em>PactFuse</em> · source-fresh procurement for agent spending",
    "head.ledeHtml": "PactFuse watches the chain while an agent buys tool leases with its Cobo Agentic Wallet. If a pinned source turns unsafe, the on-chain gate interrupts the spend <em>before payment</em>; clean leases settle and deliver. Every claim below replays signed evidence.",
    "head.proofEyebrow": "How it works · one spend, three checkpoints",
    "head.proof1b": "Wallet authorizes", "head.proof1s": "the agent spends from its Cobo Agentic Wallet, bound to the owner's policy",
    "head.proof2b": "Gate interrupts", "head.proof2s": "if the pinned source turns unsafe, the on-chain gate cuts the spend before payment",
    "head.proof3b": "Receipt proves", "head.proof3s": "every claim here replays signed on-chain evidence ({n} judge checks pass)", "head.proof3sFixture": "fixture mode · evidence unavailable, no verified pass",
    "chip.verified": "verified evidence", "chip.fixture": "fixture fallback",
    "chip.liveClaim": "live claim · mock-ERC20 settlement (testnet)",
    "link.judge": "judge check {p}/{t}", "link.judgeEmpty": "judge check",
    "link.hashes": "proof hashes", "link.selftest": "self-test",
    "alert.fixture": "Proof artifacts did not load from this origin. UI is in fixture fallback and cannot claim verified pass.",

    "metric.settled": "settled & delivered", "metric.blocked": "blocked before payment",
    "metric.ledgerSeq": "ledger seq", "metric.cawAudit": "caw audit rows",

    "panel.scenarios": "Risk scenarios", "panel.scenariosHint": "replayed from verified evidence",
    "btn.run": "Run scenario", "btn.running": "Running evidence", "btn.retry": "Retry",
    "btn.runAgain": "Run again", "btn.reset": "Reset", "toggle.fail": "simulate transport drop",

    "sc.trip.title": "Unsafe source → auto-interrupt",
    "sc.trip.lede": "A pinned source turns unsafe after quote. The gate must cut payment before funds move.",
    "sc.trip.outcome": "protected · 0 moved on the challenged source",
    "sc.trip.s1": "Issuer submits a source challenge",
    "sc.trip.s2": "SourceChallenged finalized on Base Sepolia",
    "sc.trip.s3": "ProcurementGate interrupts the bound spends",
    "sc.settle.title": "Fresh source → settle & deliver",
    "sc.settle.lede": "The source stays clean, so the same gate settles the lease and releases the artifact.",
    "sc.settle.outcome": "settled · {n} {sym}-atomic moved",
    "sc.settle.s1": "Agent approves the gate through CAW",
    "sc.settle.s2": "Allowance verified on-chain",
    "sc.settle.s3": "activate_tool settles the clean spend",
    "sc.settle.s4": "Artifact released, lease executed",
    "sc.deny.title": "Wrong target → policy denial",
    "sc.deny.lede": "The agent is pointed at a contract outside its Pact. CAW must refuse before anything reaches the chain.",
    "sc.deny.outcome": "denied · request never reached the chain",
    "sc.deny.s1": "Agent submits a wrong-target contract call",
    "sc.deny.s2": "Pact policy mismatch detected",
    "sc.deny.s3": "CAW rejects the operation",

    "stage.event": "event", "stage.detect": "detect", "stage.respond": "respond", "stage.done": "done",
    "note.idle": "select a scenario to begin", "note.armed": "armed · evidence replay ready",
    "note.failedPrefix": "failed: ",

    "node.wallet": "agent wallet", "node.walletSub": "cobo caw",
    "node.policy": "pact policy", "node.policySub": "allowlist · limits",
    "node.gate": "procurement gate", "node.gateSub": "source-bound breaker",
    "node.market": "artifact market", "node.marketSub": "paid delivery",
    "node.registry": "source registry",
    "tip.wallet": "The agent's Cobo Agentic Wallet. It can spend only within the owner's Pact policy.",
    "tip.policy": "The Pact policy: the allowlist and spend limits the agent must stay inside.",
    "tip.gate": "The on-chain circuit breaker. If the pinned source turns unsafe, it cuts the payment before any funds move.",
    "tip.market": "Where the tool lease is delivered once a clean spend settles.",
    "tip.registry": "Watches source freshness on-chain. A challenge raised here is what trips the gate.",
    "verdict.armed": "armed", "verdict.delivered": "delivered",
    "verdict.spendHalted": "spend halted", "verdict.denied": "denied", "verdict.failed": "failed",

    "insp.title": "Inspector", "insp.idle": "idle", "insp.noEvent": "no active event",
    "insp.armedSuffix": " · armed",
    "insp.scaffold": "Select and run a scenario; each step binds to a verified evidence row.",
    "risk.danger": "high risk", "risk.warning": "policy violation", "risk.success": "clean path",
    "risk.info": "monitored", "risk.failed": "execution failed",
    "insp.notReached": "not reached · step did not execute",

    "log.title": "Evidence log", "log.clear": "clear", "log.empty": "log is empty · run a scenario",

    "drawer.judge": "Judge check", "drawer.hashes": "Proof hashes",
    "drawer.hashesSub": "recompute offline · verify-live-artifacts",
    "drawer.selftest": "Self-test", "drawer.selftestSub": "client-side integrity check",
    "judge.fixture": "fixture mode · judge rows unavailable",
    "jr.caw_boundary": "CAW boundary", "jr.caw_boundary.reason": "CAW approve tx, ERC20 Approval log, and allowance state verified",
    "jr.source_challenge": "Source challenge", "jr.source_challenge.reason": "indexed and finalized the public-chain SourceChallenged log",
    "jr.ab_trip": "A/B trip", "jr.ab_trip.reason": "indexed and finalized the public-chain SpendTripped log (A/B)",
    "jr.c_settlement": "C settlement", "jr.c_settlement.reason": "finalized SpendSettled log plus ERC20 balance delta verified",
    "jr.artifact_access": "Artifact access", "jr.artifact_access.reason": "bearer token issued after finalized settlement, with balance-delta proof, quote binding, and a replay-clean verifier run",
    "jr.lease_execution": "Lease execution", "jr.lease_execution.reason": "MCP tools/list and tools/call transcript recorded for the bearer-bound clean lease",
    "auth.proof": "proof", "auth.delivery": "delivery", "jc.pass": "pass", "jc.evidence": "evidence", "jc.viewTx": "view tx",
    "hash.claim": "authorized public claim", "hash.attest": "ed25519 attestation",
    "hash.publicClaim": "public claim", "hash.proofBundle": "proof bundle", "hash.replayBundle": "replay bundle",
    "hash.verifierRun": "verifier run", "hash.deployRegistry": "deployment registry", "hash.serverMeta": "server metadata",
    "hash.attestKey": "attestation key", "hash.note": "note",
    "st.loaded": "Evidence bundle loaded", "st.verified": "Source: verified replay",
    "st.fixture": "Source: fixture fallback", "st.judge": "Judge check {p}/{t}",
    "st.claim": "Public claim authorized", "st.hashes": "Proof hashes present ({n})",
    "st.attest": "Ed25519 verifier attestation",
    "st.ok": "✓ all {n} checks passed · verified replay",
    "st.bad": "{p}/{n} checks passed · fixture / incomplete",
    "st.live": "Live on-chain re-verification", "st.liveSub": "Base Sepolia · live read",
    "st.liveChecking": "querying Base Sepolia…", "st.head": "chain head {n} · re-checked just now",
    "st.confs": "{c} confirmations", "st.notFound": "not found on-chain",
    "st.rpcError": "could not reach Base Sepolia RPC from this origin",

    "help.title": "Keyboard shortcuts",
    "help.r1": "Select risk scenario", "help.r2": "Run / retry the scenario",
    "help.r3": "Clear evidence log", "help.r4": "Reset to idle",
    "help.r5": "Judge check · Proof hashes · Self-test", "help.r6": "Toggle this help", "help.r7": "Close",
    "help.close": "close", "help.hint": "? shortcuts",

    "footer.verified": "verified replay · public claim authorized {date} · the console renders evidence · it never creates proof authority",
    "footer.fixture": "fixture fallback · proof artifacts unreachable from this origin; fixture states render no proof pass. serve the repo root to load the verified session",

    "toast.session": "session id copied", "toast.hash": "hash copied", "toast.copyFail": "copy failed",
  },
  zh: {
    "loading": "正在加载签名证明产物…",

    "head.kicker": "Fusebox 证据驾驶舱 · Cobo Agentic Wallet 赛道",
    "head.titleHtml": "<em>PactFuse</em> · 面向 Agent 支付的来源新鲜采购",
    "head.ledeHtml": "PactFuse 在 Agent 用其 Cobo Agentic Wallet 购买工具租约时持续盯链。若钉住的来源变得不安全,链上闸门会在<em>付款之前</em>熔断这笔支付;干净的租约则结算并交付。下方每条声明都重放签名证据。",
    "head.proofEyebrow": "工作原理 · 一次支付的三道关卡",
    "head.proof1b": "钱包授权", "head.proof1s": "Agent 从其 Cobo Agentic Wallet 支付,且全程受 owner 策略约束",
    "head.proof2b": "闸门熔断", "head.proof2s": "钉住的来源一旦不安全,链上闸门在付款前切断这笔支付",
    "head.proof3b": "回执自证", "head.proof3s": "页面每条声明都重放链上签名证据,{n} 项 judge 校验通过", "head.proof3sFixture": "fixture 模式:证据不可用,无已验证通过",
    "chip.verified": "已验证证据", "chip.fixture": "fixture 回退",
    "chip.liveClaim": "live claim · mock-ERC20 结算(测试网)",
    "link.judge": "judge 校验 {p}/{t}", "link.judgeEmpty": "judge 校验",
    "link.hashes": "证明哈希", "link.selftest": "自检",
    "alert.fixture": "证明产物未能从此来源加载。界面处于 fixture 回退,无法声明已验证通过。",

    "metric.settled": "已结算交付", "metric.blocked": "付款前拦截",
    "metric.ledgerSeq": "ledger 序号", "metric.cawAudit": "CAW 审计行",

    "panel.scenarios": "风险场景", "panel.scenariosHint": "重放自已验证证据",
    "btn.run": "运行场景", "btn.running": "运行证据中", "btn.retry": "重试",
    "btn.runAgain": "再次运行", "btn.reset": "复位", "toggle.fail": "模拟传输中断",

    "sc.trip.title": "不安全来源 → 自动熔断",
    "sc.trip.lede": "钉住的来源在报价后变得不安全。闸门必须在资金转移前切断付款。",
    "sc.trip.outcome": "已保护 · 受挑战来源上 0 移动",
    "sc.trip.s1": "发行方提交来源挑战",
    "sc.trip.s2": "SourceChallenged 在 Base Sepolia 最终确认",
    "sc.trip.s3": "ProcurementGate 熔断绑定的支付",
    "sc.settle.title": "新鲜来源 → 结算并交付",
    "sc.settle.lede": "来源保持干净,因此同一闸门结算租约并释放 artifact。",
    "sc.settle.outcome": "已结算 · 移动 {n} {sym}-atomic",
    "sc.settle.s1": "Agent 通过 CAW 授权闸门",
    "sc.settle.s2": "额度已在链上验证",
    "sc.settle.s3": "activate_tool 结算干净支付",
    "sc.settle.s4": "Artifact 已释放,租约已执行",
    "sc.deny.title": "错误目标 → 策略拒绝",
    "sc.deny.lede": "Agent 指向其 Pact 之外的合约。CAW 必须在任何东西上链前拒绝。",
    "sc.deny.outcome": "已拒绝 · 请求从未上链",
    "sc.deny.s1": "Agent 提交错误目标的合约调用",
    "sc.deny.s2": "检测到 Pact 策略不匹配",
    "sc.deny.s3": "CAW 拒绝该操作",

    "stage.event": "事件", "stage.detect": "检测", "stage.respond": "响应", "stage.done": "完成",
    "note.idle": "选择一个场景开始", "note.armed": "已就绪 · 证据重放就绪",
    "note.failedPrefix": "失败:",

    "node.wallet": "Agent 钱包", "node.walletSub": "cobo caw",
    "node.policy": "Pact 策略", "node.policySub": "白名单 · 限额",
    "node.gate": "采购闸门", "node.gateSub": "来源绑定断路器",
    "node.market": "Artifact 市场", "node.marketSub": "付费交付",
    "node.registry": "来源登记表",
    "tip.wallet": "Agent 的 Cobo Agentic Wallet,只能在 owner 的 Pact 策略范围内支付。",
    "tip.policy": "Pact 策略:规定 Agent 必须遵守的白名单与支付限额。",
    "tip.gate": "链上断路器。钉住的来源一旦不安全,它会在资金转移前切断付款。",
    "tip.market": "干净的支付结算后,工具租约在这里交付。",
    "tip.registry": "在链上盯住来源新鲜度;这里发起的挑战会触发闸门熔断。",
    "verdict.armed": "已就绪", "verdict.delivered": "已交付",
    "verdict.spendHalted": "支付已熔断", "verdict.denied": "已拒绝", "verdict.failed": "失败",

    "insp.title": "检查器", "insp.idle": "空闲", "insp.noEvent": "无活动事件",
    "insp.armedSuffix": " · 已就绪",
    "insp.scaffold": "选择并运行一个场景;每一步都绑定到一条已验证的证据。",
    "risk.danger": "高风险", "risk.warning": "策略违规", "risk.success": "干净路径",
    "risk.info": "受监控", "risk.failed": "执行失败",
    "insp.notReached": "未到达 · 该步未执行",

    "log.title": "证据日志", "log.clear": "清空", "log.empty": "日志为空 · 运行一个场景",

    "drawer.judge": "Judge 校验", "drawer.hashes": "证明哈希",
    "drawer.hashesSub": "离线重算 · verify-live-artifacts",
    "drawer.selftest": "自检", "drawer.selftestSub": "客户端完整性检查",
    "judge.fixture": "fixture 模式 · 无 judge 行",
    "jr.caw_boundary": "CAW 边界", "jr.caw_boundary.reason": "已验证 CAW approve 交易、ERC20 Approval 日志与额度状态",
    "jr.source_challenge": "来源挑战", "jr.source_challenge.reason": "已索引并最终确认公链上的 SourceChallenged 日志",
    "jr.ab_trip": "A/B 熔断", "jr.ab_trip.reason": "已索引并最终确认公链上的 SpendTripped 日志(A/B)",
    "jr.c_settlement": "C 结算", "jr.c_settlement.reason": "已最终确认 SpendSettled 日志,并核对 ERC20 余额变动",
    "jr.artifact_access": "Artifact 访问", "jr.artifact_access.reason": "结算最终确认后签发 bearer 令牌,含余额变动证明、报价绑定与重放洁净的验证器运行",
    "jr.lease_execution": "租约执行", "jr.lease_execution.reason": "为 bearer 绑定的洁净租约记录了 MCP tools/list 与 tools/call 全过程",
    "auth.proof": "证明", "auth.delivery": "交付", "jc.pass": "通过", "jc.evidence": "证据", "jc.viewTx": "查看交易",
    "hash.claim": "已授权公开声明", "hash.attest": "ed25519 签名",
    "hash.publicClaim": "公开声明", "hash.proofBundle": "证明包", "hash.replayBundle": "重放包",
    "hash.verifierRun": "验证器运行", "hash.deployRegistry": "部署登记表", "hash.serverMeta": "服务端元数据",
    "hash.attestKey": "签名公钥", "hash.note": "说明",
    "st.loaded": "证据包已加载", "st.verified": "来源:已验证重放",
    "st.fixture": "来源:fixture 回退", "st.judge": "Judge 校验 {p}/{t}",
    "st.claim": "公开声明已授权", "st.hashes": "证明哈希已存在({n})",
    "st.attest": "Ed25519 验证器签名",
    "st.ok": "✓ 全部 {n} 项检查通过 · 已验证重放",
    "st.bad": "{p}/{n} 项检查通过 · fixture / 不完整",
    "st.live": "链上实时复核", "st.liveSub": "Base Sepolia · 实时读取",
    "st.liveChecking": "正在查询 Base Sepolia…", "st.head": "链头 {n} · 刚刚复核",
    "st.confs": "{c} 个确认", "st.notFound": "链上未找到",
    "st.rpcError": "无法从此来源访问 Base Sepolia RPC",

    "help.title": "键盘快捷键",
    "help.r1": "选择风险场景", "help.r2": "运行 / 重试场景",
    "help.r3": "清空证据日志", "help.r4": "复位到空闲",
    "help.r5": "Judge 校验 · 证明哈希 · 自检", "help.r6": "切换本帮助", "help.r7": "关闭",
    "help.close": "关闭", "help.hint": "? 快捷键",

    "footer.verified": "已验证重放 · 公开声明授权于 {date} · 控制台只渲染证据 · 从不创造证明权威",
    "footer.fixture": "fixture 回退 · 证明产物无法从此来源加载;fixture 状态不渲染证明通过。请以仓库根目录提供服务以加载已验证 session",

    "toast.session": "已复制 session id", "toast.hash": "已复制哈希", "toast.copyFail": "复制失败",
  },
};

const LANGS = ["en", "zh"];

// First visit follows the browser's language (zh* → Chinese, else English);
// an explicit choice persisted by setLang() always wins thereafter.
function detectLang() {
  try {
    const cands = navigator.languages?.length ? navigator.languages : [navigator.language];
    for (const c of cands) {
      const v = (c || "").toLowerCase();
      if (v.startsWith("zh")) return "zh";
      if (v.startsWith("en")) return "en";
    }
  } catch { /* navigator unavailable */ }
  return "en";
}

let lang = detectLang();
try {
  const saved = localStorage.getItem("pactfuse-lang");
  if (LANGS.includes(saved)) lang = saved;
} catch { /* localStorage may be blocked */ }

export const getLang = () => lang;

export function t(key, vars) {
  let s = (STR[lang] && STR[lang][key]) ?? STR.en[key] ?? key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? `{${k}}`));
  return s;
}

export function setLang(next) {
  if (!LANGS.includes(next) || next === lang) return;
  try { localStorage.setItem("pactfuse-lang", next); } catch { /* ignore */ }
  location.reload();
}

// apply [data-i18n] / [data-i18n-html] text on static markup at boot
export function applyStaticI18n(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  root.querySelectorAll("[data-i18n-html]").forEach((el) => { el.innerHTML = t(el.dataset.i18nHtml); });
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
}
