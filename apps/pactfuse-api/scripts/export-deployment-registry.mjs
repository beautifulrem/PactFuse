#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createPublicClient, http, keccak256 } from "viem";
import { DeploymentRegistrySchema } from "@pactfuse/evidence-schema";

const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const PUBLIC_EXPLORER_HOST_PATTERNS = [
  /(^|\.)basescan\.org$/,
  /(^|\.)etherscan\.io$/,
  /(^|\.)etherscan\.org$/,
  /(^|\.)arbiscan\.io$/,
  /(^|\.)optimistic\.etherscan\.io$/,
  /(^|\.)polygonscan\.com$/,
  /(^|\.)blockscout\.com$/,
  /(^|\.)routescan\.io$/,
];
const ERC20_SYMBOL_ABI = [
  {
    type: "function",
    name: "symbol",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "string" }],
  },
];
const ERC20_DECIMALS_ABI = [
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint8" }],
  },
];

try {
  const input = readInput();
  const client = createPublicClient({ transport: http(input.rpcUrl) });
  const actualChainId = String(await client.getChainId());
  assert(actualChainId === input.chainId, `RPC chainId ${actualChainId} does not match requested chainId ${input.chainId}`);

  const receipt = await client.getTransactionReceipt({ hash: input.deploymentTxHash });
  const receiptHash = String(receipt.transactionHash ?? "").toLowerCase();
  assert(receiptHash === input.deploymentTxHash.toLowerCase(), "deployment receipt transactionHash does not match");
  assert(isSuccessfulReceiptStatus(receipt.status), "deployment receipt status is not explicitly successful");
  assert(
    typeof receipt.contractAddress === "string" && receipt.contractAddress.toLowerCase() === input.paymentTokenAddress.toLowerCase(),
    "deployment receipt contractAddress does not match payment token address",
  );

  const [code, symbol, decimals] = await Promise.all([
    client.getCode({ address: input.paymentTokenAddress }),
    client.readContract({ address: input.paymentTokenAddress, abi: ERC20_SYMBOL_ABI, functionName: "symbol" }),
    client.readContract({ address: input.paymentTokenAddress, abi: ERC20_DECIMALS_ABI, functionName: "decimals" }),
  ]);
  assert(code && code !== "0x", "payment token address has no bytecode");

  const registry = DeploymentRegistrySchema.parse({
    mode: "live",
    chainId: input.chainId,
    officialUsdcProbe: {
      status: input.officialUsdcProbeStatus,
      reason: input.officialUsdcProbeReason,
    },
    entries: [
      {
        contractName: "PaymentToken",
        chainId: input.chainId,
        address: input.paymentTokenAddress,
        deploymentTxHash: input.deploymentTxHash,
        explorerUrl: input.explorerUrl,
        codeHash: keccak256(code),
        tokenMode: input.tokenMode,
        symbol: String(symbol),
        decimals: Number(decimals),
      },
    ],
  });
  const body = `${JSON.stringify(registry, null, 2)}\n`;
  if (input.outputPath) {
    await mkdir(dirname(input.outputPath), { recursive: true });
    await writeFile(input.outputPath, body, { encoding: "utf8", mode: 0o644, flag: input.force ? "w" : "wx" });
  } else {
    process.stdout.write(body);
  }
} catch (error) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      },
      null,
      2,
    ),
  );
  process.exit(1);
}

function readInput() {
  const chainId = requiredEnv("PACTFUSE_REGISTRY_CHAIN_ID", process.env.PACTFUSE_CHAIN_ID);
  const paymentTokenAddress = normalizeAddress(requiredEnv("PACTFUSE_REGISTRY_PAYMENT_TOKEN_ADDRESS"));
  const deploymentTxHash = normalizeHex32(requiredEnv("PACTFUSE_REGISTRY_PAYMENT_TOKEN_DEPLOY_TX"));
  const explorerUrl = requiredEnv("PACTFUSE_REGISTRY_PAYMENT_TOKEN_EXPLORER_URL");
  assertPublicExplorerUrl(explorerUrl, deploymentTxHash);
  const tokenMode = process.env.PACTFUSE_REGISTRY_TOKEN_MODE ?? tokenModeForPaymentToken(paymentTokenAddress, chainId);
  assert(tokenMode === "mock-test-token" || tokenMode === "official-testnet-usdc", "PACTFUSE_REGISTRY_TOKEN_MODE must be mock-test-token or official-testnet-usdc");
  assertTokenModeMatchesPaymentToken(tokenMode, paymentTokenAddress, chainId);
  const officialUsdcProbeStatus = process.env.PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS ?? (tokenMode === "official-testnet-usdc" ? "passed" : "failed");
  assert(
    officialUsdcProbeStatus === "failed" || officialUsdcProbeStatus === "passed",
    "PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS must be failed or passed for a live registry",
  );
  assert(
    tokenMode !== "official-testnet-usdc" || officialUsdcProbeStatus === "passed",
    "official-testnet-usdc requires PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS=passed",
  );
  assert(
    tokenMode !== "mock-test-token" || officialUsdcProbeStatus === "failed",
    "mock-test-token requires PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_STATUS=failed",
  );
  const officialUsdcProbeReason =
    process.env.PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_REASON ??
    (tokenMode === "official-testnet-usdc"
      ? "official Base Sepolia USDC address selected and verified on chain"
      : "");
  assert(officialUsdcProbeReason.trim().length > 0, "PACTFUSE_REGISTRY_OFFICIAL_USDC_PROBE_REASON is required for mock-test-token fallback");
  return {
    rpcUrl: requiredEnv("PACTFUSE_REGISTRY_RPC_URL", process.env.PACTFUSE_CHAIN_RPC_URL),
    chainId,
    paymentTokenAddress,
    deploymentTxHash,
    explorerUrl,
    tokenMode,
    officialUsdcProbeStatus,
    officialUsdcProbeReason,
    outputPath: process.env.PACTFUSE_REGISTRY_OUTPUT_PATH,
    force: booleanEnv("PACTFUSE_REGISTRY_OUTPUT_FORCE", false),
  };
}

function requiredEnv(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function normalizeAddress(value) {
  assert(/^0x[0-9a-fA-F]{40}$/.test(value), "payment token address must be a 20-byte hex address");
  return value.toLowerCase();
}

function normalizeHex32(value) {
  assert(/^0x[0-9a-fA-F]{64}$/.test(value), "deployment tx hash must be a 32-byte hex hash");
  return value.toLowerCase();
}

function tokenModeForPaymentToken(address, chainId) {
  return chainId === "84532" && address.toLowerCase() === BASE_SEPOLIA_USDC ? "official-testnet-usdc" : "mock-test-token";
}

function assertTokenModeMatchesPaymentToken(tokenMode, address, chainId) {
  const officialBaseSepoliaUsdc = address.toLowerCase() === BASE_SEPOLIA_USDC;
  assert(
    tokenMode !== "official-testnet-usdc" || (chainId === "84532" && officialBaseSepoliaUsdc),
    "official-testnet-usdc requires Base Sepolia chainId 84532 and the official Base Sepolia USDC address",
  );
  assert(
    tokenMode !== "mock-test-token" || !officialBaseSepoliaUsdc,
    "mock-test-token cannot be used with the official Base Sepolia USDC address",
  );
}

function isSuccessfulReceiptStatus(status) {
  return status === "success" || status === "0x1" || status === 1 || status === true;
}

function assertPublicExplorerUrl(explorerUrl, txHash) {
  let url;
  try {
    url = new URL(explorerUrl);
  } catch {
    throw new Error("PACTFUSE_REGISTRY_PAYMENT_TOKEN_EXPLORER_URL must be a valid URL");
  }
  const host = url.hostname.toLowerCase();
  assert(url.protocol === "https:", "PACTFUSE_REGISTRY_PAYMENT_TOKEN_EXPLORER_URL must use HTTPS");
  assert(host !== "localhost" && !host.endsWith(".localhost") && host !== "example.com" && !host.endsWith(".example.com"), "explorer URL must be public");
  assert(
    PUBLIC_EXPLORER_HOST_PATTERNS.some((pattern) => pattern.test(host)),
    "explorer URL host must be a known public block explorer",
  );
  assert(explorerUrlPointsToTransaction(url, txHash), "explorer URL must point to the deployment transaction");
}

function explorerUrlPointsToTransaction(url, txHash) {
  const segments = url.pathname.toLowerCase().split("/").filter(Boolean);
  const txIndex = segments.indexOf("tx");
  return txIndex >= 0 && segments[txIndex + 1] === txHash.toLowerCase();
}

function booleanEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  return !["0", "false", "no", "off"].includes(raw.trim().toLowerCase());
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
