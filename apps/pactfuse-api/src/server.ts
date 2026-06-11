import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { createRuntimeIndexerWorkerOptions, createServiceCtx } from "./runtime.js";
import { startIndexerWorkerLoop } from "./services/indexer-worker.js";

const port = Number(process.env.PORT ?? "8787");
const dbPath = process.env.PACTFUSE_DB_PATH ?? ".pactfuse/pactfuse.sqlite";
const ctx = createServiceCtx({ dbPath });
const app = createApp(ctx);
const indexerWorkerOptions = createRuntimeIndexerWorkerOptions();
const indexerWorker = indexerWorkerOptions ? startIndexerWorkerLoop(ctx, indexerWorkerOptions) : null;

serve({ fetch: app.fetch, port });
ctx.logger.info({ port, dbPath, indexerWorkerStarted: Boolean(indexerWorker?.started) }, "pactfuse-api listening");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    indexerWorker?.stop();
    ctx.db.sqlite.close();
    process.exit(0);
  });
}
