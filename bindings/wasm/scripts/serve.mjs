// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Minimal dev server that serves files with gzip compression for WASM binaries.
// Usage: node scripts/serve.mjs [port]

import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { resolve, extname, join } from "node:path";
import { createGzip } from "node:zlib";

const PORT = parseInt(process.argv[2] || "5173", 10);
const ROOT = resolve(import.meta.dirname, "..");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

// File extensions eligible for gzip compression.
const COMPRESSIBLE = new Set([".wasm", ".js", ".mjs", ".html", ".css", ".json"]);

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  let filePath = join(ROOT, decodeURIComponent(url.pathname));

  // Default to index.html for directory requests.
  if (filePath.endsWith("/")) filePath = join(filePath, "index.html");

  if (!existsSync(filePath) || !statSync(filePath).isFile()) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("404 Not Found");
    return;
  }

  const ext = extname(filePath);
  const contentType = MIME_TYPES[ext] || "application/octet-stream";

  const acceptEncoding = req.headers["accept-encoding"] || "";
  const useGzip = COMPRESSIBLE.has(ext) && acceptEncoding.includes("gzip");

  res.setHeader("Content-Type", contentType);
  res.setHeader("Cache-Control", "no-cache");
  // Required for SharedArrayBuffer / cross-origin isolation if needed.
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  if (useGzip) {
    res.setHeader("Content-Encoding", "gzip");
    res.writeHead(200);
    createReadStream(filePath).pipe(createGzip()).pipe(res);
  } else {
    const stat = statSync(filePath);
    res.setHeader("Content-Length", stat.size);
    res.writeHead(200);
    createReadStream(filePath).pipe(res);
  }
});

server.listen(PORT, () => {
  console.log(`Dev server running at http://localhost:${PORT}/`);
  console.log(`Serving files from ${ROOT} (gzip enabled for WASM/JS/CSS/HTML)`);
  console.log(`Open http://localhost:${PORT}/examples/chain_id.html`);
});
