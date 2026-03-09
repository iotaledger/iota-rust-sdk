#[allow(unused_imports)]
use iota_sdk_ffi;
mod iota_sdk_ffi_module;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}
