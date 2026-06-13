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
