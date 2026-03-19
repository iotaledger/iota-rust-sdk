export * from './iota_sdk_ffi';
import * as iota_sdk_ffi from './iota_sdk_ffi';
// Import the JS glue from wasm-bindgen (--target bundler).
// The __wbg_set_wasm function wires WASM exports into the JS glue.
import * as bg from './wasm-bindgen/index_bg.js';

/**
 * Load and initialise the WASM module.
 *
 * @param wasmUrl - URL to the .wasm binary.  When omitted the file
 *                  `index_bg.wasm` is resolved relative to this JS module
 *                  (works when both files sit in the same directory).
 */
export async function uniffiInitAsync(wasmUrl?: string | URL) {
  const url = wasmUrl ?? new URL('./index_bg.wasm', import.meta.url);
  const response = await fetch(url);
  const bytes = await response.arrayBuffer();

  // The WASM binary imports ~400 UniFFI scaffold functions from an "env"
  // module.  These are checksum validators and function stubs that return 0.
  // The actual work is done through the ubrn_ wrappers in the JS glue.
  const envProxy = new Proxy({}, {
    get() { return () => 0; },
  });

  const { instance } = await WebAssembly.instantiate(bytes, {
    './index_bg.js': bg as any,
    'env': envProxy,
  });

  (bg as any).__wbg_set_wasm(instance.exports);
  // Run the WASM start function if present (some wasm-bindgen versions export it).
  if (typeof (instance.exports as any).__wbindgen_start === 'function') {
    (instance.exports as any).__wbindgen_start();
  }
  iota_sdk_ffi.default.initialize();
}

export default { iota_sdk_ffi };
