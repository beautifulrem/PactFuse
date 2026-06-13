#!/usr/bin/env node
/* Assembles the static PactFuse Console deploy bundle into dist/ for Vercel.
 *
 * The console is a zero-build vanilla ES-module app that fetches the checked-in
 * signed proof artifacts via a path relative to the repo root
 * (apps/fusebox/live/src -> ../../../../docs/evidence/live/<session>/). To deploy
 * it cleanly we copy ONLY the app + the live evidence into dist/, preserving that
 * exact relative structure — so the procurement-strategy/research docs and the
 * rest of the monorepo are never served on the demo domain. Uses node built-ins
 * only (no install step needed). */

import { cp, mkdir, rm, writeFile } from "node:fs/promises";

const OUT = "dist";

await rm(OUT, { recursive: true, force: true });
await mkdir(`${OUT}/apps/fusebox`, { recursive: true });
await mkdir(`${OUT}/docs/evidence`, { recursive: true });

await cp("apps/fusebox/live", `${OUT}/apps/fusebox/live`, { recursive: true });
await cp("docs/evidence/live", `${OUT}/docs/evidence/live`, { recursive: true });

await writeFile(
  `${OUT}/index.html`,
  `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="dark" />
<title>PactFuse Console</title>
<meta http-equiv="refresh" content="0; url=./apps/fusebox/live/" />
<link rel="canonical" href="./apps/fusebox/live/" />
<style>html,body{margin:0;height:100%;background:#07090d;color:#aab5c5;font:14px/1.6 ui-monospace,Menlo,monospace;display:grid;place-items:center}a{color:#82a0ff}</style>
</head>
<body>
<p>Loading PactFuse Console… <a href="./apps/fusebox/live/">enter&nbsp;→</a></p>
</body>
</html>
`,
);

console.log("built dist/ — PactFuse Console + live evidence");
