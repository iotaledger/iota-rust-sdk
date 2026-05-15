// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Regenerate `crates/iota-sdk-move-system-types/generated/` from the
//! upstream IOTA core Move source.
//!
//! Invocation:
//!
//! ```bash
//! cargo run -p iota-sdk-move-system-types --example regenerate
//! ```
//!
//! The script:
//!
//! 1. Clones the IOTA core repo into a temp dir at [`IOTA_REF`] — a
//!    *moving* upstream reference (the `develop` branch), not a SHA.
//! 2. Locates the four Move packages within that tree.
//! 3. Runs `moverox-build` on each, writing emitted Rust into
//!    `generated/`.
//! 4. Drops the temp dir on exit (auto-cleanup).
//!
//! # Layer-1 CI drift detection
//!
//! [`IOTA_REF`] tracks a *branch*, not a SHA. That means each
//! invocation pulls whatever the branch currently is, and the diff
//! against the committed snapshot is a live drift signal:
//!
//! ```bash
//! cargo run -p iota-sdk-move-system-types --example regenerate
//! git diff --exit-code crates/iota-sdk-move-system-types/generated/
//! ```
//!
//! A non-empty diff means upstream Move source changed in a way that
//! affects struct *shapes* — added/removed/reordered fields, renamed
//! structs, new structs. Function bodies, doc comments, whitespace,
//! tests, and internal helpers produce zero diff because moverox only
//! emits Rust for the data layouts. Every CI failure under this model
//! is therefore a meaningful "verify the snapshot and our hand-curated
//! types" signal.
//!
//! The fix when CI does fail: run `regenerate` locally, inspect the
//! diff, update our hand-curated types if needed, and commit the new
//! `generated/` baseline in the same PR.
//!
//! The Move source is *not* vendored in this repo. The pair
//! ([`IOTA_REPO_URL`], [`IOTA_REF`]) is the only place that decides
//! which upstream Move source we regenerate against — change either
//! and the next CI run will surface the new snapshot as a diff.

use std::path::Path;
use std::process::Command;

/// The upstream IOTA core repository providing the Move framework
/// packages.
const IOTA_REPO_URL: &str = "https://github.com/iotaledger/iota.git";

/// Upstream ref in [`IOTA_REPO_URL`] to fetch on every regeneration.
///
/// Currently a *moving* branch so CI fails fast when upstream changes
/// a struct shape — each regeneration pulls whatever `develop` is at the
/// moment of the run. Switch to a tag (e.g. `"v1.30.0"`) or a commit
/// SHA if you ever want strict reproducibility instead; the fetch
/// logic below handles all three kinds of refs.
const IOTA_REF: &str = "develop";

/// Path inside the IOTA core repo where the four Move packages live.
///
/// Adjust if the upstream layout changes.
const PACKAGES_SUBDIR: &str = "crates/iota-framework/packages";

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let generated = crate_root.join("generated");

    let workdir = tempfile::tempdir()?;
    let repo = workdir.path();
    eprintln!(
        "fetching {} @ {} into {}",
        IOTA_REPO_URL,
        IOTA_REF,
        repo.display()
    );
    fetch_ref(repo)?;

    let packages = repo.join(PACKAGES_SUBDIR);
    eprintln!(
        "running moverox-build on packages under {}",
        packages.display()
    );

    moverox_build::move_package(packages.join("move-stdlib"), "std")
        .published_at("0x1")
        .out_dir(&generated)
        .build()?;

    moverox_build::move_package(packages.join("iota-framework"), "iota")
        .published_at("0x2")
        .with_implicit_iota_imports()
        .map_address("std", "crate::move_stdlib")
        .out_dir(&generated)
        .build()?;

    moverox_build::move_package(packages.join("iota-system"), "iota_system")
        .published_at("0x3")
        .with_implicit_iota_imports()
        .map_address("std", "crate::move_stdlib")
        .map_address("iota", "crate::iota_framework")
        .out_dir(&generated)
        .build()?;

    moverox_build::move_package(packages.join("stardust"), "stardust")
        .published_at("0x107a")
        .with_implicit_iota_imports()
        .map_address("std", "crate::move_stdlib")
        .map_address("iota", "crate::iota_framework")
        .out_dir(&generated)
        .build()?;

    eprintln!(
        "regenerated {} from {}@{}",
        generated.display(),
        IOTA_REPO_URL,
        IOTA_REF
    );
    Ok(())
}

/// Shallow-fetch `IOTA_REPO_URL` at `IOTA_REF` into `dir`.
///
/// `init` + `fetch --depth 1 origin <ref>` + `checkout FETCH_HEAD`
/// handles all three kinds of refs uniformly: branches, tags, and
/// arbitrary commit SHAs (as long as the remote allows fetching by
/// SHA, which GitHub does).
fn fetch_ref(dir: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    run(Command::new("git").args(["init", "--quiet"]).arg(dir))?;
    run(Command::new("git").args([
        "-C",
        path_str(dir),
        "remote",
        "add",
        "origin",
        IOTA_REPO_URL,
    ]))?;
    run(Command::new("git").args([
        "-C",
        path_str(dir),
        "fetch",
        "--depth",
        "1",
        "--quiet",
        "origin",
        IOTA_REF,
    ]))?;
    run(Command::new("git").args([
        "-C",
        path_str(dir),
        "checkout",
        "--quiet",
        "FETCH_HEAD",
    ]))?;
    Ok(())
}

fn run(cmd: &mut Command) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let status = cmd.status()?;
    if !status.success() {
        return Err(format!("command failed: {cmd:?}").into());
    }
    Ok(())
}

fn path_str(p: &Path) -> &str {
    p.to_str().expect("path is not valid UTF-8")
}
