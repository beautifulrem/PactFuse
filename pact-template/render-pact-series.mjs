#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const BASE_TEMPLATE_PATH = new URL("./gate-paid-artifact-real.json", import.meta.url);

function usage() {
  console.error("Usage: node pact-template/render-pact-series.mjs pact-template/pact-series.config.json");
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function replaceString(value, replacements) {
  let next = value;
  for (const [from, to] of Object.entries(replacements)) {
    next = next.split(from).join(to);
  }
  return next;
}

function deepReplace(value, replacements) {
  if (typeof value === "string") {
    return replaceString(value, replacements);
  }
  if (Array.isArray(value)) {
    return value.map((item) => deepReplace(item, replacements));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, deepReplace(item, replacements)]));
  }
  return value;
}

function assertHex32(name, value) {
  if (!/^0x[a-fA-F0-9]{64}$/.test(value)) {
    throw new Error(`${name} must be bytes32 hex`);
  }
}

function assertAddress(name, value) {
  if (!/^0x[a-fA-F0-9]{40}$/.test(value)) {
    throw new Error(`${name} must be an EVM address`);
  }
  if (/^0x0{40}$/.test(value)) {
    throw new Error(`${name} must not be the zero address`);
  }
}

function assertSelector(name, value) {
  if (!/^0x[a-fA-F0-9]{8}$/.test(value)) {
    throw new Error(`${name} must be a 4-byte selector`);
  }
  if (value === "0x00000000") {
    throw new Error(`${name} must not be the zero selector`);
  }
}

function validateConfig(config) {
  assertAddress("publicTestMockErc20", config.publicTestMockErc20);
  assertAddress("procurementGate", config.procurementGate);
  assertSelector("erc20ApproveSelector", config.erc20ApproveSelector);
  assertSelector("activateToolSelector", config.activateToolSelector);
  assertHex32("toolId", config.toolId);

  if (!Array.isArray(config.pacts) || config.pacts.length !== 3) {
    throw new Error("config.pacts must contain exactly Pact A, Pact B, and Pact C");
  }

  const labels = config.pacts.map((pact) => pact.label).join("");
  if (labels !== "ABC") {
    throw new Error("config.pacts labels must be A, B, C in order");
  }

  const ids = new Set();
  for (const pact of config.pacts) {
    assertHex32(`pact ${pact.label} pactId`, pact.pactId);
    assertHex32(`pact ${pact.label} spendId`, pact.spendId);
    if (!/^[0-9]+$/.test(String(pact.quoteNonce))) {
      throw new Error(`pact ${pact.label} quoteNonce must be decimal`);
    }
    if (!["challenged", "clean"].includes(pact.sourceBinding)) {
      throw new Error(`pact ${pact.label} sourceBinding must be challenged or clean`);
    }
    for (const id of [pact.pactId, pact.spendId, pact.quoteNonce]) {
      if (ids.has(id)) {
        throw new Error(`duplicate pact series id or nonce: ${id}`);
      }
      ids.add(id);
    }
  }
}

export function renderPactSeries(config, baseTemplate) {
  validateConfig(config);

  return {
    series: "PACTFUSE_AB_C_GATE_PAID_V1",
    mode: "gate-paid-artifact-real",
    generatedAt: new Date(0).toISOString(),
    pacts: config.pacts.map((pact) => {
      const renderedPact = deepReplace(baseTemplate, {
        TBASE_SETH: config.chainId,
        "<PUBLIC_TESTNET_MOCK_ERC20>": config.publicTestMockErc20,
        "<ProcurementGate>": config.procurementGate,
        "<erc20-approve-selector>": config.erc20ApproveSelector,
        "<activateTool-selector>": config.activateToolSelector,
        "<pactId>": pact.pactId,
        "<spendId>": pact.spendId,
        "<toolId>": config.toolId,
        "200000": String(config.maxPrice),
      });

      return {
        label: pact.label,
        pactId: pact.pactId,
        spendId: pact.spendId,
        quoteNonce: String(pact.quoteNonce),
        sourceBinding: pact.sourceBinding,
        gateBinding: "spendId is registered in Gate storage, not pinned in pre-approved CAW params_match",
        expectedReceiptSlots: {
          denyRequestId: null,
          approveTxHash: null,
          activateRequestId: null,
          activateTxHash: null,
          spendTrippedTxHash: pact.sourceBinding === "challenged" ? null : "not-applicable",
          spendSettledTxHash: pact.sourceBinding === "clean" ? null : "not-applicable",
          balanceDelta: pact.sourceBinding === "clean" ? null : "not-applicable"
        },
        pact: renderedPact
      };
    })
  };
}

function main() {
  const [configPath] = process.argv.slice(2);
  if (!configPath || configPath === "-h" || configPath === "--help") {
    usage();
    process.exit(configPath ? 0 : 1);
  }

  const config = readJson(configPath);
  const baseTemplate = readJson(BASE_TEMPLATE_PATH);
  console.log(JSON.stringify(renderPactSeries(config, baseTemplate), null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
