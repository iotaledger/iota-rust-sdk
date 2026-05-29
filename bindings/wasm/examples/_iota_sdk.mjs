// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
//
// Node-side bootstrap shared by the `.mjs` examples.
//
// Re-exports the full SDK from the published bundle, after loading the
// WASM bytes from disk and initialising the runtime. Browser users do not
// need this file — they import directly from `dist/iota-sdk.js` and pass
// a URL to `uniffiInitAsync`.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { uniffiInitAsync } from "../dist/iota-sdk.js";

const wasmPath = fileURLToPath(
  new URL("../dist/index_bg.wasm", import.meta.url),
);
await uniffiInitAsync(readFileSync(wasmPath));

export * from "../dist/iota-sdk.js";
