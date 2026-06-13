/* Live on-chain re-verification. Keyless, read-only JSON-RPC reads against
 * public Base Sepolia endpoints, used to re-confirm that the already-signed,
 * replayed evidence is still on-chain right now. No keys, no writes, no wallet,
 * no secrets: just eth_blockNumber + eth_getTransactionByHash. Endpoints are
 * tried in order so one being down or rate-limited never breaks the check. */

export const CHAIN_ID = 84532; // Base Sepolia
export const RPCS = [
  "https://base-sepolia-rpc.publicnode.com",
  "https://sepolia.base.org",
  "https://base-sepolia.drpc.org",
];

async function rawCall(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`http ${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(j.error.message || "rpc error");
  return j.result;
}

// first endpoint that answers wins; throws only if every endpoint fails
async function anyRpc(method, params) {
  let lastErr;
  for (const url of RPCS) {
    try {
      return await rawCall(url, method, params);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr ?? new Error("all RPCs failed");
}

export async function getHead() {
  return parseInt(await anyRpc("eth_blockNumber", []), 16);
}

// returns the block number the tx was mined in, or null if no endpoint has it
export async function getTxBlock(hash) {
  for (const url of RPCS) {
    try {
      const r = await rawCall(url, "eth_getTransactionByHash", [hash]);
      if (r && r.blockNumber != null) return parseInt(r.blockNumber, 16);
    } catch {
      /* try the next endpoint */
    }
  }
  return null;
}

// ── keyless eth_call: read deployed-contract view state ─────────────────────
async function ethCall(to, data) {
  let lastErr;
  for (const url of RPCS) {
    try {
      const r = await rawCall(url, "eth_call", [{ to, data }, "latest"]);
      if (typeof r === "string" && r.length >= 66) return r;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr ?? new Error("eth_call failed");
}
const noHex = (h) => String(h).replace(/^0x/, "");

// SourceStateRegistry.sourceState(bytes32): 0 Unknown, 1 Active, 2 Challenged, 3 Revoked
export async function readSourceState(registry, sourceHash) {
  const out = await ethCall(registry, "0x447c24c0" + noHex(sourceHash));
  return parseInt(out.slice(-2), 16);
}
// ProcurementGate.registeredSpend(bytes32): state is the last of 10 return words.
// SpendState: 0 Unknown, 1 Registered, 2 Tripped, 3 Settled
export async function readSpendState(gate, spendId) {
  const out = await ethCall(gate, "0xef3bbc44" + noHex(spendId));
  return parseInt(out.slice(-2), 16);
}
