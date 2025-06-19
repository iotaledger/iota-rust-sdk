// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

fn main() {
    #[cfg(feature = "uniffi")]
    {
        uniffi::uniffi_bindgen_main()
    }
    #[cfg(not(feature = "uniffi"))]
    {
        println!("enable the `uniffi` feature to generate bindings");
    }
}
