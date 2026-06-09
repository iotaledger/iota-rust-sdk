// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Node entry (selected by `exports`/`node`): defaults `initAsync` to
// reading the bundled wasm via `fs`, since Node's `fetch` doesn't take
// `file://` URLs. Copied to dist/node.js by the build.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { initAsync as baseInit } from "./iota-sdk.js";

export * from "./iota-sdk.js";

export async function initAsync(input) {
  if (input !== undefined) {
    return baseInit(input);
  }
  const wasmPath = fileURLToPath(new URL("./index_bg.wasm", import.meta.url));
  return baseInit(readFileSync(wasmPath));
}
