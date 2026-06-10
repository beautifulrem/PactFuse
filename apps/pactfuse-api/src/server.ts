import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { createServiceCtx } from "./runtime.js";

const port = Number(process.env.PORT ?? "8787");
const dbPath = process.env.PACTFUSE_DB_PATH ?? ".pactfuse/pactfuse.sqlite";
const ctx = createServiceCtx({ dbPath });
const app = createApp(ctx);

serve({ fetch: app.fetch, port });
ctx.logger.info({ port, dbPath }, "pactfuse-api listening");
