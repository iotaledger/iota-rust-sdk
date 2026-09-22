// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

export * from "./iota_sdk_ffi";
import * as iota_sdk_ffi from "./iota_sdk_ffi";
// Import the JS glue from wasm-bindgen (--target bundler).
// The __wbg_set_wasm function wires WASM exports into the JS glue.
import * as bg from "./wasm-bindgen/index_bg.js";

/**
 * Load and initialize the WASM module.
 *
 * @param input - One of:
 *   - `string` or `URL`: location of the `.wasm` binary to fetch (browser).
 *   - `ArrayBuffer` or `Uint8Array`: raw `.wasm` bytes (Node.js, where
 *     `fetch('file://…')` isn't reliably supported — pass
 *     `fs.readFileSync(...)` instead).
 *   - omitted: defaults to `index_bg.wasm` resolved relative to this JS module.
 */
export async function initAsync(
  input?: string | URL | ArrayBuffer | Uint8Array,
) {
  let bytes: ArrayBuffer | Uint8Array;
  if (input instanceof ArrayBuffer || input instanceof Uint8Array) {
    bytes = input;
  } else {
    const url = input ?? new URL("./index_bg.wasm", import.meta.url);
    const response = await fetch(url);
    bytes = await response.arrayBuffer();
  }

  const { instance } = await WebAssembly.instantiate(bytes, {
    "./index_bg.js": bg as any,
  });

  (bg as any).__wbg_set_wasm(instance.exports);
  // Run the WASM start function if present (some wasm-bindgen versions export it).
  if (typeof (instance.exports as any).__wbindgen_start === "function") {
    (instance.exports as any).__wbindgen_start();
  }
  iota_sdk_ffi.default.initialize();
}

export default { iota_sdk_ffi };
