import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { AuditApi, Configuration, PactsApi, TransactionsApi, WalletsApi } from "@cobo/agentic-wallet";
import { createPublicClient, decodeEventLog, http } from "viem";
import type {
  ContractCallCreate,
  TransferCreate,
} from "@cobo/agentic-wallet";
import type {
  ArtifactDeliveryVerifier,
  ArtifactDeliveryVerificationInput,
  CawLiveAuditInput,
  CawLiveClient,
  CawLiveContractCallInput,
  CawLivePactSubmitInput,
  CawLiveTransferInput,
  CawReceiptSource,
  ChainClient,
  McpLeaseClient,
  McpLeaseExecutionInput,
  McpLeaseExecutionResult,
  PactTemplateBinding,
  PactTemplateRegistry,
  ProofProviderStatus,
} from "../types.js";
import { hashJson, sha256Hex } from "../util.js";

const DEFAULT_TEMPLATES: Array<{ mode: PactTemplateBinding["mode"]; path: string }> = [
  { mode: "gate-paid-artifact-real", path: "../../../../pact-template/gate-paid-artifact-real.json" },
  { mode: "permit-payment-real", path: "../../../../pact-template/permit-payment-real.appendix.json" },
];
const MAX_ARTIFACT_DELIVERY_RESPONSE_BYTES = 512 * 1024;
export const PACTFUSE_CHAIN_EVENT_ABI = [
  {
    type: "event",
    name: "SpendTripped",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "spendId", type: "bytes32", indexed: true },
    ],
  },
  {
    type: "event",
    name: "SpendSettled",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "spendId", type: "bytes32", indexed: true },
    ],
  },
  {
    type: "event",
    name: "SourceChallenged",
    inputs: [
      { name: "sessionId", type: "bytes32", indexed: true },
      { name: "sourceHash", type: "bytes32", indexed: true },
      { name: "reasonHash", type: "bytes32", indexed: true },
    ],
  },
] as const;
const MAX_MCP_RESPONSE_BYTES = 512 * 1024;
const OFFICIAL_COBO_API_HOSTS = ["api.cobo.com", "api.dev.cobo.com", "api.agenticwallet.cobo.com"] as const;
const REQUIRED_LEASE_TOOL_ARGUMENTS = [
  "sessionId",
  "leaseRunId",
  "spendId",
  "payer",
  "artifactHash",
  "artifactPayloadHash",
  "artifactPayload",
  "targetRepo",
  "targetCommit",
] as const;
const DANGEROUS_TOOL_NAME_PATTERN =
  /(write|edit|delete|remove|shell|exec|terminal|command|commit|push|deploy|transfer|send|apply|patch|modify|create|move|copy|rename|upload|download|file|fs|process|subprocess)/;

export function createUnconfiguredChainClient(): ChainClient {
  return {
    async status() {
      return unconfiguredStatus("chain", "chain RPC endpoint is not configured");
    },
    async getBlockNumber() {
      throw new Error("chain provider is unconfigured; cannot read current block number");
    },
    async getTransactionReceipt() {
      throw new Error("chain provider is unconfigured; cannot verify transaction receipt");
    },
    async getCode() {
      throw new Error("chain provider is unconfigured; cannot verify contract bytecode");
    },
    async getLogs() {
      throw new Error("chain provider is unconfigured; cannot verify event logs");
    },
    async readContract() {
      throw new Error("chain provider is unconfigured; cannot verify contract state");
    },
  };
}

export function createViemChainClient(input: { rpcUrl: string; chainId?: string | number }): ChainClient {
  const client = createPublicClient({ transport: http(input.rpcUrl) });
  const configuredChainId = input.chainId === undefined || input.chainId === "" ? undefined : String(input.chainId);
  return {
    async status() {
      try {
        const [, chainId] = await Promise.all([client.getBlockNumber(), client.getChainId()]);
        const actualChainId = String(chainId);
        if (configuredChainId !== undefined && actualChainId !== configuredChainId) {
          return {
            name: "chain",
            mode: "live",
            ready: false,
            reason: `configured chainId ${configuredChainId} does not match RPC chainId ${actualChainId}`,
            endpoint: input.rpcUrl,
            chainId: actualChainId,
          };
        }
        return {
          name: "chain",
          mode: "live",
          ready: true,
          reason: "chain RPC endpoint is configured",
          endpoint: input.rpcUrl,
          chainId: actualChainId,
        };
      } catch (error) {
        const failedStatus: ProofProviderStatus = {
          name: "chain",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "chain RPC endpoint failed readiness check",
          endpoint: input.rpcUrl,
        };
        if (configuredChainId !== undefined) {
          failedStatus.chainId = configuredChainId;
        }
        return failedStatus;
      }
    },
    async getBlockNumber() {
      return Number(await client.getBlockNumber());
    },
    async getTransactionReceipt(txHash: string) {
      const receipt = await client.getTransactionReceipt({ hash: txHash as `0x${string}` });
      return normalizeChainValue(receipt) as Record<string, unknown>;
    },
    async getCode(address: string) {
      return String(await client.getCode({ address: address as `0x${string}` }));
    },
    async getLogs(query: Record<string, unknown>) {
      if (configuredChainId !== undefined && typeof query.chainId === "string" && !sameChainId(query.chainId, configuredChainId)) {
        throw new Error(`requested chainId ${query.chainId} does not match configured chainId ${configuredChainId}`);
      }
      const fromBlock = toBigIntBlock(query.fromBlock ?? query.blockNumber);
      const toBlock = toBigIntBlock(query.toBlock ?? query.blockNumber ?? query.fromBlock);
      const filter: Record<string, unknown> = {
        fromBlock: toRpcBlock(fromBlock),
        toBlock: toRpcBlock(toBlock),
      };
      const address = optionalHex(query.address);
      if (address) {
        filter.address = address;
      }
      const topics = Array.isArray(query.topics)
        ? query.topics.map((topic) => (typeof topic === "string" && topic.length > 0 ? (topic as `0x${string}`) : null))
        : undefined;
      if (topics) {
        filter.topics = topics;
      }
      const requestLogs = client.request as (args: { method: "eth_getLogs"; params: [Record<string, unknown>] }) => Promise<unknown[]>;
      const logs = await requestLogs({
        method: "eth_getLogs",
        params: [filter],
      });
      return logs.map((log: unknown) => normalizePactFuseChainLog(normalizeChainValue(log) as Record<string, unknown>));
    },
    async readContract(query: {
      address: string;
      abi: readonly unknown[];
      functionName: string;
      args?: readonly unknown[];
      blockNumber?: number;
    }) {
      const readContract = client.readContract as (input: {
        address: `0x${string}`;
        abi: readonly unknown[];
        functionName: string;
        args?: readonly unknown[];
        blockNumber?: bigint;
      }) => Promise<unknown>;
      const request: {
        address: `0x${string}`;
        abi: readonly unknown[];
        functionName: string;
        args?: readonly unknown[];
        blockNumber?: bigint;
      } = {
        address: query.address as `0x${string}`,
        abi: query.abi,
        functionName: query.functionName,
      };
      if (query.args !== undefined) {
        request.args = query.args;
      }
      if (query.blockNumber !== undefined) {
        request.blockNumber = toBigIntBlock(query.blockNumber);
      }
      const result = await readContract(request);
      return normalizeChainValue(result);
    },
  };
}

export function normalizePactFuseChainLog(log: Record<string, unknown>): Record<string, unknown> {
  const rawRpcLogHash = hashChainJson(log);
  const topics = Array.isArray(log.topics) ? log.topics.filter((topic): topic is `0x${string}` => typeof topic === "string") : [];
  const data = typeof log.data === "string" && log.data.startsWith("0x") ? (log.data as `0x${string}`) : "0x";
  if (topics.length === 0) {
    return { ...log, rawRpcLogHash };
  }
  try {
    const eventTopics = topics as [signature: `0x${string}`, ...args: `0x${string}`[]];
    const decoded = decodeEventLog({
      abi: PACTFUSE_CHAIN_EVENT_ABI,
      data,
      topics: eventTopics,
    });
    return {
      ...log,
      rawRpcLogHash,
      eventName: decoded.eventName,
      event: decoded.eventName,
      name: decoded.eventName,
      args: normalizeChainValue(decoded.args),
    };
  } catch {
    return { ...log, rawRpcLogHash };
  }
}

function hashChainJson(value: unknown): `0x${string}` {
  return hashJson(normalizeChainValue(value));
}

export function createUnconfiguredCawReceiptSource(): CawReceiptSource {
  return {
    async status() {
      return unconfiguredStatus("caw", "CAW receipt source is not configured");
    },
    async fetchReceiptBundle() {
      throw new Error("CAW receipt source is unconfigured; cannot fetch raw receipt bundle");
    },
  };
}

export function createHttpsCawReceiptSource(input: {
  exportUrl: string;
  apiKey?: string;
  walletId?: string;
  limit?: number;
  trustedHosts?: readonly string[];
  allowInsecureTestEndpoint?: boolean;
}): CawReceiptSource {
  const limit = input.limit ?? 50;
  return {
    async status() {
      try {
        const trust = cawEndpointTrust({
          endpoint: input.exportUrl,
          trustedHosts: input.trustedHosts,
          allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
          label: "CAW export endpoint",
        });
        if (!trust.ok) {
          return {
            name: "caw",
            mode: "live",
            ready: false,
            reason: trust.reason,
            endpoint: input.exportUrl,
          } satisfies ProofProviderStatus;
        }
        if (!input.apiKey) {
          return {
            name: "caw",
            mode: "live",
            ready: false,
            reason: "CAW export API key is missing",
            endpoint: input.exportUrl,
          } satisfies ProofProviderStatus;
        }
        const url = cawExportUrl(input.exportUrl, input.walletId, { limit: 1 });
        const response = await fetch(url, {
          method: "GET",
          headers: cawHeaders(input.apiKey),
        });
        if (!response.ok) {
          return {
            name: "caw",
            mode: "live",
            ready: false,
            reason: `CAW export endpoint returned HTTP ${response.status}`,
            endpoint: input.exportUrl,
          } satisfies ProofProviderStatus;
        }
        return {
          name: "caw",
          mode: "live",
          ready: true,
          reason: "CAW raw audit/export endpoint is configured",
          endpoint: input.exportUrl,
        };
      } catch (error) {
        return {
          name: "caw",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "CAW export endpoint failed readiness check",
          endpoint: input.exportUrl,
        };
      }
    },
    async fetchReceiptBundle(request: Record<string, unknown>) {
      assertTrustedCawEndpoint({
        endpoint: input.exportUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW export endpoint",
      });
      if (!input.apiKey) {
        throw new Error("CAW export API key is missing");
      }
      const auditFilter = cawAuditFilterForOperationKind(optionalString(request.operationKind) ?? null);
      const url = cawExportUrl(input.exportUrl, input.walletId, {
        limit,
        session_id: optionalString(request.sessionId),
        operation_id: optionalString(request.operationId),
        source_label: optionalString(request.sourceLabel),
        operation_kind: optionalString(request.operationKind),
        action: auditFilter.action,
        result: auditFilter.result,
      });
      const response = await fetch(url, {
        method: "GET",
        headers: cawHeaders(input.apiKey),
      });
      const body = await parseCawResponse(response);
      const receipts = extractCawReceiptItems(body);
      return {
        source: "caw-api",
        sourceLabel: optionalString(request.sourceLabel) ?? "caw-api",
        sessionId: request.sessionId,
        operationId: request.operationId,
        operationKind: request.operationKind,
        walletId: input.walletId ?? null,
        fetchedAt: new Date().toISOString(),
        exportUrl: input.exportUrl,
        receipts,
        raw: body,
      };
    },
  };
}

export function createUnconfiguredCawLiveClient(): CawLiveClient {
  return {
    async status() {
      return unconfiguredStatus("caw_live", "CAW live API is not configured");
    },
    async getWallet() {
      throw new Error("CAW live API is unconfigured; cannot read wallet");
    },
    async listWalletAddresses() {
      throw new Error("CAW live API is unconfigured; cannot list wallet addresses");
    },
    async submitPact() {
      throw new Error("CAW live API is unconfigured; cannot submit pact");
    },
    async getPact() {
      throw new Error("CAW live API is unconfigured; cannot sync pact");
    },
    async transferToken() {
      throw new Error("CAW live API is unconfigured; cannot transfer token");
    },
    async contractCall() {
      throw new Error("CAW live API is unconfigured; cannot submit contract call");
    },
    async listAuditLogs() {
      throw new Error("CAW live API is unconfigured; cannot list audit logs");
    },
  };
}

export function createCoboAgenticWalletClient(input: {
  baseUrl: string;
  apiKey: string;
  walletId?: string;
  timeoutMs?: number;
  trustedHosts?: readonly string[];
  allowInsecureTestEndpoint?: boolean;
}): CawLiveClient {
  const baseUrl = input.baseUrl.replace(/\/+$/, "");
  const timeoutMs = input.timeoutMs ?? 10_000;
  const defaultWalletId = input.walletId;
  const ownerConfig = new Configuration({ apiKey: input.apiKey, basePath: baseUrl });
  const walletsApi = new WalletsApi(ownerConfig);
  const pactsApi = new PactsApi(ownerConfig);
  const auditApi = new AuditApi(ownerConfig);
  const requestOptions = { timeout: timeoutMs };
  const transactionsApiFor = (apiKey: string) =>
    new TransactionsApi(new Configuration({ apiKey, basePath: baseUrl }));
  return {
    async status() {
      try {
        const trust = cawEndpointTrust({
          endpoint: baseUrl,
          trustedHosts: input.trustedHosts,
          allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
          label: "CAW live API endpoint",
        });
        if (!trust.ok) {
          return {
            name: "caw_live",
            mode: "live",
            ready: false,
            reason: trust.reason,
            endpoint: baseUrl,
          };
        }
        if (!input.apiKey) {
          return {
            name: "caw_live",
            mode: "live",
            ready: false,
            reason: "CAW live API key is missing",
            endpoint: baseUrl,
          };
        }
        if (defaultWalletId) {
          await walletsApi.getWallet(defaultWalletId, false, input.apiKey, requestOptions);
        } else {
          await walletsApi.listWallets(undefined, undefined, undefined, 1, false, undefined, input.apiKey, requestOptions);
        }
        return {
          name: "caw_live",
          mode: "live",
          ready: true,
          reason: defaultWalletId ? "CAW live wallet endpoint is configured" : "CAW live wallet list endpoint is configured",
          endpoint: baseUrl,
        };
      } catch (error) {
        return {
          name: "caw_live",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "CAW live API readiness check failed",
          endpoint: baseUrl,
        };
      }
    },
    async getWallet(walletId: string) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      return cawSdkData((await walletsApi.getWallet(walletId, true, input.apiKey, requestOptions)).data);
    },
    async listWalletAddresses(walletId: string) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      return cawSdkData((await walletsApi.listWalletAddresses(walletId, input.apiKey, requestOptions)).data);
    },
    async submitPact(pact) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      return cawSdkData(
        (
          await pactsApi.submitPact(
            {
              wallet_id: pact.walletId,
              intent: pact.intent,
              ...(pact.originalIntent ? { original_intent: pact.originalIntent } : {}),
              ...(pact.name ? { name: pact.name } : {}),
              ...(pact.recipeSlugs && pact.recipeSlugs.length > 0 ? { recipe_slugs: pact.recipeSlugs } : {}),
              spec: pact.spec,
            },
            input.apiKey,
            requestOptions,
          )
        ).data,
      );
    },
    async getPact(pactId: string) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      return cawSdkData((await pactsApi.getPact(pactId, input.apiKey, requestOptions)).data);
    },
    async transferToken(transfer) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      const body = cawLiveTransferBody(transfer);
      return cawSdkData(
        (
          await transactionsApiFor(transfer.pactApiKey).transferTokens(
            transfer.walletId,
            body,
            transfer.pactApiKey,
            requestOptions,
          )
        ).data,
      );
    },
    async contractCall(call) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      const body = cawLiveContractCallBody(call);
      try {
        return cawSdkData(
          (
            await transactionsApiFor(call.pactApiKey).contractCall(
              call.walletId,
              body,
              call.pactApiKey,
              requestOptions,
            )
          ).data,
        );
      } catch (error) {
        const denied = cawSdkPolicyDenyResponse(error, call);
        if (denied) {
          return denied;
        }
        throw error;
      }
    },
    async listAuditLogs(query) {
      assertTrustedCawEndpoint({
        endpoint: baseUrl,
        trustedHosts: input.trustedHosts,
        allowInsecureTestEndpoint: input.allowInsecureTestEndpoint,
        label: "CAW live API endpoint",
      });
      return cawSdkData(
        (
          await auditApi.listAuditLogs(
            query.walletId,
            query.principalId,
            query.action,
            query.result,
            query.startTime,
            query.endTime,
            query.after,
            query.before,
            undefined,
            query.limit,
            input.apiKey,
            requestOptions,
          )
        ).data,
      );
    },
  };
}

function cawAuditFilterForOperationKind(operationKind: string | null): { action?: string; result?: string } {
  if (operationKind === "deny_probe") {
    return { action: "contract_call.denied", result: "denied" };
  }
  if (operationKind === "approve" || operationKind === "activate_tool") {
    return { action: "contract_call.allowed", result: "allowed" };
  }
  return {};
}

function cawLiveTransferBody(transfer: CawLiveTransferInput): TransferCreate {
  const body: Record<string, unknown> = {
    dst_addr: transfer.destinationAddress,
    amount: transfer.amount,
    ...(transfer.tokenId ? { token_id: transfer.tokenId } : {}),
    ...(transfer.chainId ? { chain_id: transfer.chainId } : {}),
    ...(transfer.requestId ? { request_id: transfer.requestId } : {}),
    ...(transfer.sourceAddress ? { src_addr: transfer.sourceAddress } : {}),
    ...(transfer.sponsor !== undefined ? { sponsor: transfer.sponsor } : {}),
    ...(transfer.gasProvider ? { gas_provider: transfer.gasProvider } : {}),
    ...(transfer.description ? { description: transfer.description } : {}),
    ...(transfer.fee !== undefined ? { fee: transfer.fee } : {}),
  };
  return body as unknown as TransferCreate;
}

function cawLiveContractCallBody(call: CawLiveContractCallInput): ContractCallCreate {
  const body: Record<string, unknown> = {
    chain_id: call.chainId,
    contract_addr: call.contractAddress,
    calldata: call.calldata,
    value: call.valueAtomic ?? "0",
    ...(call.requestId ? { request_id: call.requestId } : {}),
    ...(call.sourceAddress ? { src_addr: call.sourceAddress } : {}),
    ...(call.sponsor !== undefined ? { sponsor: call.sponsor } : {}),
    ...(call.gasProvider ? { gas_provider: call.gasProvider } : {}),
    ...(call.description ? { description: call.description } : {}),
    ...(call.fee !== undefined ? { fee: call.fee } : {}),
  };
  return body as unknown as ContractCallCreate;
}

function cawSdkData(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("CAW SDK response must return a JSON object");
  }
  return normalizeSdkValue(data) as Record<string, unknown>;
}

function cawSdkPolicyDenyResponse(error: unknown, call: CawLiveContractCallInput): Record<string, unknown> | null {
  const response = sdkErrorResponseData(error);
  if (!response) {
    return null;
  }
  const errorRecord =
    response.error && typeof response.error === "object" && !Array.isArray(response.error)
      ? response.error as Record<string, unknown>
      : {};
  const code = typeof errorRecord.code === "string" ? errorRecord.code : null;
  const reason =
    typeof errorRecord.reason === "string"
      ? errorRecord.reason
      : typeof errorRecord.message === "string"
        ? errorRecord.message
        : null;
  const joined = [code, reason, response.suggestion]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLowerCase();
  if (!/(deny|denied|policy|forbidden|not allowed|blocked)/.test(joined)) {
    return null;
  }
  return {
    success: false,
    status: "denied",
    status_display: "denied",
    code: code ?? "policy_denied",
    reason: reason ?? "policy_denied",
    request_id: call.requestId ?? null,
    transaction_hash: null,
    error: errorRecord,
    suggestion: typeof response.suggestion === "string" ? response.suggestion : undefined,
    result: {
      wallet_id: call.walletId,
      request_id: call.requestId ?? null,
      status: "denied",
      code: code ?? "policy_denied",
      reason: reason ?? "policy_denied",
      transaction_hash: null,
    },
  };
}

function sdkErrorResponseData(error: unknown): Record<string, unknown> | null {
  const response =
    error && typeof error === "object" && !Array.isArray(error)
      ? (error as { response?: { data?: unknown } }).response
      : null;
  const data = response?.data;
  return data && typeof data === "object" && !Array.isArray(data)
    ? (normalizeSdkValue(data) as Record<string, unknown>)
    : null;
}

function normalizeSdkValue(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeSdkValue(item));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (child !== undefined) {
        output[key] = normalizeSdkValue(child);
      }
    }
    return output;
  }
  return value;
}

export function createUnconfiguredMcpLeaseClient(): McpLeaseClient {
  return {
    async status() {
      return unconfiguredStatus("mcp_lease", "lease MCP endpoint is not configured");
    },
    async executeCleanLease() {
      throw new Error("lease MCP endpoint is unconfigured; cannot execute tools/list or tools/call");
    },
  };
}

export function createUnconfiguredArtifactDeliveryVerifier(): ArtifactDeliveryVerifier {
  return {
    async verify() {
      throw new Error("artifact delivery verifier is unconfigured; cannot perform server-owned live preflight");
    },
  };
}

export function createHttpArtifactDeliveryVerifier(input: { timeoutMs?: number; allowInsecureTestEndpoint?: boolean } = {}): ArtifactDeliveryVerifier {
  const timeoutMs = input.timeoutMs ?? 10_000;
  return {
    async verify(preflight) {
      assertTrustedArtifactDeliveryEndpoint(preflight.endpointUrl, input.allowInsecureTestEndpoint);
      const endpoint = await fetchJsonWithHash(preflight.endpointUrl, timeoutMs, "artifact delivery endpoint");
      const artifactPayload = jsonObjectChild(endpoint.json, "artifactPayload");
      if (!artifactPayload) {
        throw new Error("artifact delivery endpoint must return artifactPayload object");
      }
      const artifactPayloadHash = hashJson(artifactPayload);
      const artifactCid = `sha256:${artifactPayloadHash}`;
      if (artifactPayloadHash.toLowerCase() !== preflight.artifactHashPreview.toLowerCase()) {
        throw new Error("artifact delivery endpoint artifactPayload hash does not match preflight artifactHashPreview");
      }
      if (artifactCid.toLowerCase() !== preflight.artifactCid.toLowerCase()) {
        throw new Error("artifact delivery endpoint artifact CID does not match preflight artifactCid");
      }
      const manifestFetches = [];
      for (const manifest of preflight.sourceManifests) {
        assertTrustedArtifactDeliveryEndpoint(manifest.manifestUrl, input.allowInsecureTestEndpoint);
        const fetched = await fetchTextWithHash(manifest.manifestUrl, timeoutMs, "source manifest endpoint");
        if (fetched.bodyHash.toLowerCase() !== manifest.manifestHash.toLowerCase()) {
          throw new Error(`source manifest ${manifest.sourceHash} fetched hash does not match registered manifestHash`);
        }
        manifestFetches.push({
          sourceHash: manifest.sourceHash.toLowerCase(),
          manifestUrl: manifest.manifestUrl,
          manifestHash: manifest.manifestHash.toLowerCase(),
          status: fetched.status,
          contentType: fetched.contentType,
          bodyHash: fetched.bodyHash,
        });
      }
      const leaseDryRun = jsonObjectChild(endpoint.json, "leaseDryRun");
      if (!leaseDryRun || leaseDryRun.ok !== true) {
        throw new Error("artifact delivery endpoint must return leaseDryRun.ok=true");
      }
      const manifestFetchHash = hashJson({
        mode: "server_live_fetch",
        sessionId: preflight.sessionId,
        preflightId: preflight.preflightId,
        sourceManifests: manifestFetches,
      });
      const endpointResponseHash = hashJson({
        mode: "server_live_fetch",
        endpointUrl: preflight.endpointUrl,
        status: endpoint.status,
        contentType: endpoint.contentType,
        bodyHash: endpoint.bodyHash,
        artifactPayloadHash,
      });
      const leaseDryRunHash = hashJson({
        mode: "server_live_fetch",
        endpointUrl: preflight.endpointUrl,
        artifactPayloadHash,
        leaseDryRun,
      });
      return {
        artifactPayloadHash,
        artifactCid,
        manifestFetchHash,
        endpointResponseHash,
        leaseDryRunHash,
        evidenceHash: hashJson({
          mode: "server_live_fetch",
          artifactPayloadHash,
          artifactCid,
          manifestFetchHash,
          endpointResponseHash,
          leaseDryRunHash,
        }),
      };
    },
  };
}

export function createHttpJsonRpcMcpLeaseClient(input: {
  endpointUrl: string;
  toolName?: string;
  timeoutMs?: number;
  allowInsecureTestEndpoint?: boolean;
}): McpLeaseClient {
  const toolName = normalizeLeaseToolName(input.toolName ?? "pactfuse_code_scan");
  const timeoutMs = input.timeoutMs ?? 10_000;
  return {
    async status() {
      try {
        assertTrustedMcpEndpoint(input.endpointUrl, input.allowInsecureTestEndpoint);
        const response = await postJsonRpc(input.endpointUrl, jsonRpcRequest("tools/list", {}), Math.min(timeoutMs, 2_000));
        assertToolListed(response, toolName);
        return {
          name: "mcp_lease",
          mode: "live",
          ready: true,
          reason: "lease MCP JSON-RPC endpoint lists the required read-only tool",
          endpoint: input.endpointUrl,
        };
      } catch (error) {
        return {
          name: "mcp_lease",
          mode: "live",
          ready: false,
          reason: error instanceof Error ? error.message : "lease MCP readiness check failed",
          endpoint: input.endpointUrl,
        };
      }
    },
    async executeCleanLease(leaseInput) {
      assertTrustedMcpEndpoint(input.endpointUrl, input.allowInsecureTestEndpoint);
      const toolsListRequest = jsonRpcRequest("tools/list", {});
      const toolsListResponse = await withMcpStage("tools/list", async () => {
        const response = await postJsonRpc(input.endpointUrl, toolsListRequest, timeoutMs);
        const tools = assertToolListed(response, toolName);
        assertPinnedManifestTools(tools, leaseInput.pinnedManifestTools);
        return response;
      });
      const toolsCallRequest = jsonRpcRequest("tools/call", {
        name: toolName,
        arguments: {
          sessionId: leaseInput.sessionId,
          leaseRunId: leaseInput.leaseRunId,
          spendId: leaseInput.spendId,
          payer: leaseInput.payer,
          artifactHash: leaseInput.artifactHash,
          artifactPayloadHash: leaseInput.artifactPayloadHash,
          artifactPayload: leaseInput.artifactPayload,
          targetRepo: leaseInput.targetRepo,
          targetCommit: leaseInput.targetCommit,
        },
      });
      const toolsCallResponse = await withMcpStage("tools/call", async () => {
        const response = await postJsonRpc(input.endpointUrl, toolsCallRequest, timeoutMs);
        assertJsonRpcSuccess(response, "tools/call");
        return response;
      });
      return {
        toolName,
        toolsList: {
          method: "tools/list",
          request: toolsListRequest,
          response: toolsListResponse,
        },
        toolsCall: {
          method: "tools/call",
          request: toolsCallRequest,
          response: toolsCallResponse,
        },
        output: toolsCallResponse,
      } satisfies McpLeaseExecutionResult;
    },
  };
}

async function withMcpStage<T>(stage: "tools/list" | "tools/call", fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof Error) {
      (error as Error & { leaseStage?: string }).leaseStage = stage;
    }
    throw error;
  }
}

export function createLocalTemplateRegistry(): PactTemplateRegistry {
  const bindings = DEFAULT_TEMPLATES.map((template) => {
    const url = new URL(template.path, import.meta.url);
    const parsed = JSON.parse(readFileSync(url, "utf8")) as unknown;
    return {
      mode: template.mode,
      sourcePath: fileURLToPath(url),
      templateHash: hashJson(parsed),
    };
  });
  return createStaticTemplateRegistry(bindings);
}

function jsonRpcRequest(method: "tools/list" | "tools/call", params: Record<string, unknown>): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id: `${method}:${Date.now()}:${Math.random().toString(16).slice(2)}`,
    method,
    params,
  };
}

async function postJsonRpc(endpointUrl: string, request: Record<string, unknown>, timeoutMs: number): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpointUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify(request),
      redirect: "manual",
      signal: controller.signal,
    });
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_MCP_RESPONSE_BYTES) {
      throw new Error("lease MCP endpoint response exceeded 512 KiB");
    }
    if (!response.ok) {
      throw new Error(`lease MCP endpoint returned HTTP ${response.status}`);
    }
    let parsed: unknown = {};
    if (text.length > 0) {
      try {
        parsed = JSON.parse(text) as unknown;
      } catch {
        throw new Error("lease MCP endpoint returned non-JSON response");
      }
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("lease MCP endpoint must return a JSON-RPC object");
    }
    return parsed as Record<string, unknown>;
  } finally {
    clearTimeout(timeout);
  }
}

function assertJsonRpcSuccess(response: Record<string, unknown>, method: string): void {
  if (response.jsonrpc !== "2.0") {
    throw new Error(`${method} response is missing jsonrpc=2.0`);
  }
  if ("error" in response) {
    throw new Error(`${method} returned JSON-RPC error`);
  }
  if (!("result" in response)) {
    throw new Error(`${method} response is missing result`);
  }
}

function assertToolListed(response: Record<string, unknown>, toolName: string): Array<Record<string, unknown>> {
  assertJsonRpcSuccess(response, "tools/list");
  const result = response.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("tools/list result must be an object");
  }
  const tools = (result as Record<string, unknown>).tools;
  if (!Array.isArray(tools)) {
    throw new Error("tools/list result must include a tools array");
  }
  if (tools.length !== 1) {
    throw new Error("tools/list must expose exactly one PactFuse lease tool");
  }
  const [tool] = tools;
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) {
    throw new Error("tools/list tool entry must be an object");
  }
  const toolRecord = tool as Record<string, unknown>;
  if (toolRecord.name !== toolName) {
    throw new Error(`tools/list did not expose the required unique tool ${toolName}`);
  }
  assertLeaseToolDefinition(toolRecord);
  return [toolRecord];
}

function assertPinnedManifestTools(actualTools: Array<Record<string, unknown>>, pinnedTools: Array<Record<string, unknown>>): void {
  if (pinnedTools.length !== 1) {
    throw new Error("pinned source manifest must expose exactly one PactFuse lease tool");
  }
  if (hashJson(actualTools) !== hashJson(pinnedTools)) {
    throw new Error("tools/list is not bounded to the pinned source manifest");
  }
}

function normalizeLeaseToolName(toolName: string): string {
  if (!/^pactfuse_[a-z0-9_:-]{1,80}$/.test(toolName)) {
    throw new Error("lease MCP tool name must be a controlled pactfuse_* capability");
  }
  if (DANGEROUS_TOOL_NAME_PATTERN.test(toolName.toLowerCase())) {
    throw new Error("lease MCP tool name must not describe write, execution, transfer, or file capabilities");
  }
  return toolName;
}

function assertLeaseToolDefinition(tool: Record<string, unknown>): void {
  const annotations = tool.annotations;
  if (!annotations || typeof annotations !== "object" || Array.isArray(annotations) || (annotations as Record<string, unknown>).readOnlyHint !== true) {
    throw new Error("lease MCP tool must advertise annotations.readOnlyHint=true");
  }
  const inputSchema = tool.inputSchema;
  if (!inputSchema || typeof inputSchema !== "object" || Array.isArray(inputSchema)) {
    throw new Error("lease MCP tool must expose an inputSchema object");
  }
  const schema = inputSchema as Record<string, unknown>;
  if (schema.type !== "object") {
    throw new Error("lease MCP tool inputSchema.type must be object");
  }
  if (schema.additionalProperties !== false) {
    throw new Error("lease MCP tool inputSchema must set additionalProperties=false");
  }
  const properties = schema.properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    throw new Error("lease MCP tool inputSchema must declare properties");
  }
  const required = schema.required;
  if (!Array.isArray(required)) {
    throw new Error("lease MCP tool inputSchema must declare required fields");
  }
  const propertyNames = new Set(Object.keys(properties as Record<string, unknown>));
  const requiredNames = new Set(required.filter((field): field is string => typeof field === "string"));
  const missing = REQUIRED_LEASE_TOOL_ARGUMENTS.filter((field) => !propertyNames.has(field) || !requiredNames.has(field));
  if (missing.length > 0) {
    throw new Error(`lease MCP tool inputSchema is missing required PactFuse fields: ${missing.join(",")}`);
  }
}

export function createStaticTemplateRegistry(bindings: PactTemplateBinding[]): PactTemplateRegistry {
  const sorted = [...bindings].sort((a, b) => a.mode.localeCompare(b.mode));
  return {
    list: () => sorted.map((binding) => ({ ...binding })),
    require: (mode) => {
      const binding = sorted.find((candidate) => candidate.mode === mode);
      if (!binding) {
        throw new Error(`Pact template binding is missing for mode: ${mode}`);
      }
      return { ...binding };
    },
  };
}

function assertTrustedCawEndpoint(input: {
  endpoint: string;
  trustedHosts?: readonly string[] | undefined;
  allowInsecureTestEndpoint?: boolean | undefined;
  label: string;
}): void {
  const trust = cawEndpointTrust(input);
  if (!trust.ok) {
    throw new Error(trust.reason);
  }
}

function cawEndpointTrust(input: {
  endpoint: string;
  trustedHosts?: readonly string[] | undefined;
  allowInsecureTestEndpoint?: boolean | undefined;
  label: string;
}): { ok: true } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(input.endpoint);
  } catch {
    return { ok: false, reason: `${input.label} must be a valid URL` };
  }
  if (input.allowInsecureTestEndpoint) {
    return { ok: true };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: `${input.label} must use HTTPS` };
  }
  const trustedHosts = new Set(
    (input.trustedHosts && input.trustedHosts.length > 0 ? input.trustedHosts : OFFICIAL_COBO_API_HOSTS)
      .map((host) => host.trim().toLowerCase())
      .filter((host) => host.length > 0),
  );
  if (!trustedHosts.has(url.hostname.toLowerCase())) {
    return { ok: false, reason: `${input.label} host ${url.hostname} is not an official Cobo API host` };
  }
  return { ok: true };
}

function assertTrustedMcpEndpoint(endpointUrl: string, allowInsecureTestEndpoint?: boolean): void {
  const trust = mcpEndpointTrust(endpointUrl, allowInsecureTestEndpoint);
  if (!trust.ok) {
    throw new Error(trust.reason);
  }
}

function assertTrustedArtifactDeliveryEndpoint(endpointUrl: string, allowInsecureTestEndpoint?: boolean): void {
  const trust = mcpEndpointTrust(endpointUrl, allowInsecureTestEndpoint);
  if (!trust.ok) {
    throw new Error(`artifact delivery ${trust.reason}`);
  }
}

function mcpEndpointTrust(endpointUrl: string, allowInsecureTestEndpoint?: boolean): { ok: true } | { ok: false; reason: string } {
  let url: URL;
  try {
    url = new URL(endpointUrl);
  } catch {
    return { ok: false, reason: "lease MCP endpoint must be a valid URL" };
  }
  if (allowInsecureTestEndpoint) {
    return { ok: true };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: "lease MCP endpoint must use HTTPS" };
  }
  if (!isPublicHostname(url.hostname)) {
    return { ok: false, reason: "lease MCP endpoint must use a public hostname" };
  }
  return { ok: true };
}

function isPublicHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "example.com" ||
    host.endsWith(".example.com") ||
    host.endsWith(".example") ||
    host.endsWith(".test") ||
    host.endsWith(".local") ||
    host.endsWith(".lan") ||
    host.endsWith(".internal")
  ) {
    return false;
  }
  if (isPrivateIpv4(host)) {
    return false;
  }
  if (isPrivateIpv6(host)) {
    return false;
  }
  return host.includes(".");
}

async function fetchJsonWithHash(endpointUrl: string, timeoutMs: number, label: string): Promise<{
  json: Record<string, unknown>;
  status: number;
  contentType: string | null;
  bodyHash: `0x${string}`;
}> {
  const fetched = await fetchTextWithHash(endpointUrl, timeoutMs, label);
  let json: unknown;
  try {
    json = fetched.text.length > 0 ? JSON.parse(fetched.text) : {};
  } catch {
    throw new Error(`${label} returned non-JSON response`);
  }
  if (!json || typeof json !== "object" || Array.isArray(json)) {
    throw new Error(`${label} must return a JSON object`);
  }
  return { json: json as Record<string, unknown>, status: fetched.status, contentType: fetched.contentType, bodyHash: fetched.bodyHash };
}

async function fetchTextWithHash(endpointUrl: string, timeoutMs: number, label: string): Promise<{
  text: string;
  status: number;
  contentType: string | null;
  bodyHash: `0x${string}`;
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpointUrl, {
      method: "GET",
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: controller.signal,
    });
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_ARTIFACT_DELIVERY_RESPONSE_BYTES) {
      throw new Error(`${label} response exceeded 512 KiB`);
    }
    if (!response.ok) {
      throw new Error(`${label} returned HTTP ${response.status}`);
    }
    return {
      text,
      status: response.status,
      contentType: response.headers.get("content-type"),
      bodyHash: sha256Hex(text),
    };
  } finally {
    clearTimeout(timeout);
  }
}

function jsonObjectChild(record: Record<string, unknown>, key: string): Record<string, unknown> | null {
  const value = record[key];
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const octets = parts.map((part) => Number(part));
  if (octets.some((octet, index) => !Number.isInteger(octet) || octet < 0 || octet > 255 || String(octet) !== parts[index])) {
    return false;
  }
  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIpv6(host: string): boolean {
  const normalized = host.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80:");
}

function cawExportUrl(base: string, walletId: string | undefined, params: Record<string, string | number | undefined>): URL {
  const url = new URL(base);
  if (walletId) {
    url.searchParams.set("wallet_id", walletId);
  }
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function cawHeaders(apiKey: string | undefined): Headers {
  const headers = new Headers({ accept: "application/json" });
  if (apiKey) {
    headers.set("X-API-Key", apiKey);
    headers.set("authorization", `Bearer ${apiKey}`);
  }
  return headers;
}

async function parseCawResponse(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  let body: unknown = {};
  if (text.length > 0) {
    try {
      body = JSON.parse(text) as unknown;
    } catch {
      throw new Error("CAW export endpoint returned non-JSON response");
    }
  }
  if (!response.ok) {
    throw new Error(`CAW export endpoint returned HTTP ${response.status}`);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("CAW export endpoint must return a JSON object");
  }
  return body as Record<string, unknown>;
}

function extractCawReceiptItems(body: Record<string, unknown>): unknown[] {
  const result = body.result && typeof body.result === "object" && !Array.isArray(body.result) ? (body.result as Record<string, unknown>) : null;
  const candidates = [
    body.receipts,
    body.items,
    body.auditLogs,
    body.logs,
    result?.receipts,
    result?.items,
    result?.auditLogs,
    result?.logs,
  ];
  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate;
    }
  }
  return [];
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function optionalHex(value: unknown): string | undefined {
  return typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value) ? value : undefined;
}

function toRpcBlock(value: bigint): `0x${string}` {
  return `0x${value.toString(16)}`;
}

function toBigIntBlock(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return BigInt(value);
  }
  throw new Error("chain log query requires a decimal blockNumber");
}

function sameChainId(left: string, right: string): boolean {
  return canonicalChainId(left) === canonicalChainId(right);
}

function canonicalChainId(chainId: string): string {
  const normalized = chainId.trim().toUpperCase();
  if (normalized === "TBASE_SETH") {
    return "84532";
  }
  return normalized;
}

function normalizeChainValue(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeChainValue(item));
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      result[key] = normalizeChainValue(child);
    }
    return result;
  }
  return value;
}

function unconfiguredStatus(name: ProofProviderStatus["name"], reason: string): ProofProviderStatus {
  return {
    name,
    mode: "unconfigured",
    ready: false,
    reason,
  };
}
