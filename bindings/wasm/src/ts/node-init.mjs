// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Node entry point — copied to dist/node.js by the build. Wraps
// `uniffiInitAsync` so it can default to reading the bundled
// `index_bg.wasm` from disk (Node's `fetch` doesn't support `file://`
// URLs). Selected automatically by the `node` condition in `package.json`
// `exports`. The relative import resolves once this file sits in dist/.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { uniffiInitAsync as baseInit } from "./iota-sdk.js";

export * from "./iota-sdk.js";

export async function uniffiInitAsync(input) {
  if (input !== undefined) {
    return baseInit(input);
  }
  const wasmPath = fileURLToPath(new URL("./index_bg.wasm", import.meta.url));
  return baseInit(readFileSync(wasmPath));
}
