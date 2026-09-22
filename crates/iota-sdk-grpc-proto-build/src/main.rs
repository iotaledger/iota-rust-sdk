// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Proto build tool for generating gRPC types with field constants.
//!
//! Everything is written into `iota-sdk-grpc-types/src/proto/generated` and
//! committed, so a run that changes the output fails the build. The pipeline
//! is:
//!
//! 1. [`discover_proto_files`] — collect the `.proto` sources in a stable
//!    order.
//! 2. [`compile_proto_files`] — compile them with `protox` into a descriptor
//!    pool (name resolution, options) and a file descriptor set.
//! 3. [`generate_tonic`] — prost/tonic structs, clients and servers.
//! 4. [`add_license_headers`] — license headers and `super::google` rewrites on
//!    the files prost just wrote.
//! 5. Accessor generation — `with_`/`set_`/getter methods driven by the
//!    `iota.grpc.*_accessors` proto options.
//! 6. Service method paths, then field constants and `MessageFields` impls,
//!    which together back read masks and field path builders.
//! 7. [`verify_generated_files_committed`] — fail if the output drifted from
//!    what is committed.

mod codegen;
mod context;
mod extern_paths;
mod ident;

use std::path::{Path, PathBuf};

use prost_reflect::DescriptorPool;

use crate::context::Context;

/// Fields that prost boxes in the generated structs, which accessor generation
/// has to mirror in its signatures.
///
/// These are deliberately not passed to `Config::boxed`: prost boxes every
/// non-repeated message field lying on a reference cycle by itself, before it
/// consults its own config (`prost-build`, `Context::should_box_impl`), so
/// configuring them changes nothing. The list exists only as input to our own
/// accessor codegen.
///
/// Known gap, deliberately left alone:
/// `.iota.grpc.v1.types.TypeTagVector.inner_type` is boxed by prost and missing
/// here. No accessor is generated for it, so the omission is inert — adding it
/// would change generated output.
const PROST_BOXED_FIELDS: &[&str] = &[
    ".iota.grpc.v1.filter.EventFilter.negation",
    ".iota.grpc.v1.filter.TransactionFilter.negation",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTag.vector_tag",
];

/// Fields whose `MessageFields::FIELDS` must stop recursing, because the field
/// closes a reference cycle.
const BOXED_TYPES_FIELD_INFO: &[&str] = &[
    ".iota.grpc.v1.filter.AllEventFilter.filters",
    ".iota.grpc.v1.filter.AnyEventFilter.filters",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.AllTransactionFilter.filters",
    ".iota.grpc.v1.filter.AnyTransactionFilter.filters",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTagVector.inner_type",
];

/// Fields whose accessors take and return boxed values: the ones prost boxes,
/// plus those where a boxed signature is simply more ergonomic.
const BOXED_TYPES_ACCESSOR: &[&str] = &[
    ".iota.grpc.v1.filter.EventFilter.negation",
    ".iota.grpc.v1.filter.TransactionFilter.negation",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTag.vector_tag",
];

fn main() {
    let root_dir = PathBuf::from(std::env!("CARGO_MANIFEST_DIR"));

    let proto_dir = root_dir
        .join("../iota-sdk-grpc-types/proto")
        .canonicalize()
        .unwrap();
    let out_dir = root_dir
        .join("../iota-sdk-grpc-types/src/proto")
        .canonicalize()
        .unwrap()
        .join("generated");

    // The codegen entry points take owned paths, so widen the lists once here.
    let prost_boxed_fields = owned_paths(PROST_BOXED_FIELDS);
    let boxed_types_field_info = owned_paths(BOXED_TYPES_FIELD_INFO);
    let boxed_types_accessor = owned_paths(BOXED_TYPES_ACCESSOR);

    reset_out_dir(&out_dir);

    let proto_files = discover_proto_files(&proto_dir);
    let descriptor_pool = compile_proto_files(&proto_dir, &proto_files);

    generate_tonic(&proto_dir, &proto_files, &out_dir);
    add_license_headers(&out_dir);

    codegen::generate_service_methods::generate_service_method_paths(&descriptor_pool, &out_dir);

    let context = Context::build(descriptor_pool);

    codegen::accessors::generate_accessors(
        &context,
        &out_dir,
        &prost_boxed_fields,
        &boxed_types_accessor,
    );

    codegen::generate_fields::generate_field_info(&context, &out_dir, &boxed_types_field_info);

    verify_generated_files_committed(&out_dir);
}

fn owned_paths(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|path| (*path).to_owned()).collect()
}

/// Clears the output directory so that removed protos cannot leave stale
/// generated files behind.
fn reset_out_dir(out_dir: &Path) {
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir).unwrap();
    }
    std::fs::create_dir_all(out_dir).unwrap();
}

fn discover_proto_files(proto_dir: &Path) -> Vec<PathBuf> {
    let proto_ext = std::ffi::OsStr::new("proto");
    let mut proto_files = walkdir::WalkDir::new(proto_dir)
        .into_iter()
        .filter_map(|entry| {
            (|| {
                let entry = entry?;
                if entry.file_type().is_dir() {
                    return Ok(None);
                }

                let path = entry.into_path();
                if path.extension() != Some(proto_ext) {
                    return Ok(None);
                }

                Ok(Some(path))
            })()
            .transpose()
        })
        .collect::<Result<Vec<_>, walkdir::Error>>()
        .unwrap();
    // `walkdir` traversal order depends on the OS (and is non-deterministic on
    // Linux), so sort the paths to keep `compile_protos` output stable across
    // runs — without this, messages from different .proto files in the same
    // package can swap positions in the generated module.
    proto_files.sort();

    proto_files
}

fn compile_proto_files(proto_dir: &Path, proto_files: &[PathBuf]) -> DescriptorPool {
    let mut compiler_init = protox::Compiler::new([proto_dir]).unwrap();
    let compiler = compiler_init
        .include_source_info(true)
        .include_imports(true)
        .open_files(proto_files)
        .unwrap();

    compiler.descriptor_pool()
}

fn generate_tonic(proto_dir: &Path, proto_files: &[PathBuf], out_dir: &Path) {
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .bytes(".")
        .message_attribute(".iota.grpc", "#[non_exhaustive]")
        .enum_attribute(".iota.grpc", "#[non_exhaustive]")
        .btree_map(".")
        .out_dir(out_dir)
        .compile_protos(proto_files, &[proto_dir.to_path_buf()])
        .unwrap();
}

/// Adds IOTA license headers to the tonic-generated files and rewrites the
/// `super::google` paths prost emits, which do not resolve from the module the
/// generated files are included into.
fn add_license_headers(out_dir: &Path) {
    let google_import_regex = regex::Regex::new(r"(?:super::)+google").unwrap();

    for entry in std::fs::read_dir(out_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        // ignore google proto files
        if path.to_str().unwrap().contains("google") {
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && !path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("field_info")
        {
            let mut content = std::fs::read_to_string(&path).unwrap();

            // Add license header if missing
            if !content.starts_with("// Copyright") {
                content = format!(
                    "// Copyright (c) Mysten Labs, Inc.\n// Modifications Copyright (c) 2026 IOTA Stiftung\n// SPDX-License-Identifier: Apache-2.0\n\n{content}"
                );
            }

            // Replace all occurrences of super::google with crate::google (any number of
            // super::)
            content = google_import_regex
                .replace_all(&content, "crate::google")
                .to_string();
            std::fs::write(&path, content).unwrap();
        }
    }
}

/// Fails the build when a run changed the generated files, which are committed.
fn verify_generated_files_committed(out_dir: &Path) {
    let status = std::process::Command::new("git")
        .arg("diff")
        .arg("--exit-code")
        .arg("--")
        .arg(out_dir)
        .status();
    match status {
        Ok(status) if !status.success() => {
            eprintln!("Generated protobuf files have uncommitted changes. Please commit them.");
            std::process::exit(2); // Custom exit code for uncommitted changes
        }
        Err(error) => panic!("failed to run `git diff`: {error}"),
        Ok(_) => {}
    }
}
