// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

fn main() {
    // Regenerate bcs-schema.abnf only when explicitly requested via:
    //
    //   BCS_SCHEMA=1 cargo check -p iota-sdk-move-types --features bcs-schema
    //
    // The env var (not just the feature) triggers the forced recompilation so
    // that `--all-features` builds remain incremental during normal development.
    println!("cargo:rerun-if-env-changed=BCS_SCHEMA");

    let enabled = cfg!(feature = "bcs-schema")
        && std::env::var("BCS_SCHEMA").is_ok_and(|v| !v.is_empty() && v != "0");

    if enabled {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let manifest_dir = Path::new(&manifest_dir);

        // 1. Remove the old schema file so we start fresh (no stale entries).
        let schema_file = manifest_dir.join("bcs-schema.abnf");
        let _ = std::fs::remove_file(&schema_file);

        // 2. Touch all .rs files under src/ to invalidate incremental caches, ensuring
        //    every #[derive(BcsSchema)] re-runs.
        let src_dir = manifest_dir.join("src");
        touch_all_rs(&src_dir);
    }
}

fn touch_all_rs(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = filetime::FileTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            touch_all_rs(&path);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let _ = filetime::set_file_mtime(&path, now);
        }
    }
}
