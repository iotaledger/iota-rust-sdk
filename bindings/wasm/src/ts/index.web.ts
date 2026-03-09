export * from './iota_sdk_ffi';
import * as iota_sdk_ffi from './iota_sdk_ffi';
import initAsync from './wasm-bindgen/index.js';

/**
 * Load and initialise the WASM module.
 *
 * @param wasmUrl - URL to the .wasm binary.  When omitted the file
 *                  `index_bg.wasm` is resolved relative to this JS module
 *                  (works when both files sit in the same directory).
 */
export async function uniffiInitAsync(wasmUrl?: string | URL) {
  const url = wasmUrl ?? new URL('./index_bg.wasm', import.meta.url);
  await initAsync({ module_or_path: url });
  iota_sdk_ffi.default.initialize();
}

export default { iota_sdk_ffi };
