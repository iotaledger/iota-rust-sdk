// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Proto build tool for generating gRPC types with field constants.
//!
//! Everything is written into `iota-sdk-grpc-types/src/proto/generated` and committed, so a run
//! that changes the output fails the build. The pipeline is:
//!
//! 1. [`discover_proto_files`] — collect the `.proto` sources in a stable order.
//! 2. [`compile_proto_files`] — compile them with `protox` into a descriptor pool (name resolution,
//!    options) and a file descriptor set.
//! 3. [`generate_tonic`] — prost/tonic structs, clients and servers.
//! 4. [`add_license_headers`] — license headers and `super::google` rewrites on the files prost
//!    just wrote.
//! 5. [`remove_eq_hash_derives`] — drop prost's automatic `Eq`/`Hash` from the messages listed in
//!    [`STRIP_EQ_HASH_MESSAGES`].
//! 6. Accessor generation — `with_`/`set_`/getter methods driven by the `iota.grpc.*_accessors`
//!    proto options.
//! 7. Service method paths, then field constants and `MessageFields` impls, which together back
//!    read masks and field path builders.
//! 8. [`verify_generated_files_committed`] — fail if the output drifted from what is committed.

mod codegen;
mod context;
mod extern_paths;
mod ident;

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
};

use prost_reflect::{DescriptorPool, Kind};

use crate::context::Context;

/// Fields that prost boxes in the generated structs, which accessor generation has to mirror in its
/// signatures.
///
/// These are deliberately not passed to `Config::boxed`: prost boxes every non-repeated message
/// field lying on a reference cycle by itself, before it consults its own config (`prost-build`,
/// `Context::should_box_impl`), so configuring them changes nothing. The list exists only as input
/// to our own accessor codegen.
///
/// Known gap, deliberately left alone: `.iota.grpc.v1.types.TypeTagVector.inner_type` is boxed by
/// prost and missing here. No accessor is generated for it, so the omission is inert — adding it
/// would change generated output.
const PROST_BOXED_FIELDS: &[&str] = &[
    ".iota.grpc.v1.filter.EventFilter.negation",
    ".iota.grpc.v1.filter.TransactionFilter.negation",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTag.vector_tag",
];

/// Fields whose `MessageFields::FIELDS` must stop recursing, because the field closes a reference
/// cycle.
const BOXED_TYPES_FIELD_INFO: &[&str] = &[
    ".iota.grpc.v1.filter.AllEventFilter.filters",
    ".iota.grpc.v1.filter.AnyEventFilter.filters",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.AllTransactionFilter.filters",
    ".iota.grpc.v1.filter.AnyTransactionFilter.filters",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTagVector.inner_type",
];

/// Fields whose accessors take and return boxed values: the ones prost boxes, plus those where a
/// boxed signature is simply more ergonomic.
const BOXED_TYPES_ACCESSOR: &[&str] = &[
    ".iota.grpc.v1.filter.EventFilter.negation",
    ".iota.grpc.v1.filter.TransactionFilter.negation",
    ".iota.grpc.v1.filter.NotEventFilter.filter",
    ".iota.grpc.v1.filter.NotTransactionFilter.filter",
    ".iota.grpc.v1.types.TypeTag.vector_tag",
];

/// Messages whose automatic `Eq`/`Hash` derives are stripped after generation.
///
/// prost derives `Eq, Hash` for every message whose fields are all hashable. For these BCS carriers
/// the digest is the identity, so the derives add nothing; dropping them now keeps a later decoded
/// `json` (`google.protobuf.Value`, which holds an `f64` and is not hashable) field from silently
/// removing the derives and breaking downstream `Eq`/`Hash` uses.
///
/// Only the intended roots are listed; [`eq_hash_strip_closure`] extends the set to every message
/// that transitively contains one, since those would otherwise still derive `Eq`/`Hash` around a
/// now-non-`Eq` field and fail to compile.
///
/// Entries are fully-qualified proto names so a message is addressed by its own package, never by a
/// bare name that another package could share.
const STRIP_EQ_HASH_MESSAGES: &[&str] = &[
    "iota.grpc.v1.transaction.Transaction",
    "iota.grpc.v1.transaction.TransactionEffects",
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
    remove_eq_hash_derives(
        &out_dir,
        &descriptor_pool,
        &eq_hash_strip_closure(&descriptor_pool, STRIP_EQ_HASH_MESSAGES),
    );

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

/// Clears the output directory so that removed protos cannot leave stale generated files behind.
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
    // `walkdir` traversal order depends on the OS (and is non-deterministic on Linux), so sort the
    // paths to keep `compile_protos` output stable across runs — without this, messages from
    // different .proto files in the same package can swap positions in the generated module.
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
        .message_attribute(".google.rpc", "#[non_exhaustive]")
        .enum_attribute(".google.rpc", "#[non_exhaustive]")
        .btree_map(".")
        .out_dir(out_dir)
        .compile_protos(proto_files, &[proto_dir.to_path_buf()])
        .unwrap();
}

/// Adds IOTA license headers to the tonic-generated files and rewrites the `super::google` paths
/// prost emits, which do not resolve from the module the generated files are included into.
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

            // Replace all occurrences of super::google with crate::google (any number of super::)
            content = google_import_regex
                .replace_all(&content, "crate::google")
                .to_string();
            std::fs::write(&path, content).unwrap();
        }
    }
}

/// Expands the configured roots to every message that transitively contains one of them through a
/// message-typed field.
///
/// A container that currently derives `Eq`/`Hash` must lose them too, otherwise the derive would
/// require `Eq`/`Hash` on a field whose type no longer has them. Walking the containment graph here
/// keeps [`STRIP_EQ_HASH_MESSAGES`] to the intended roots instead of a hand-maintained list of
/// every container.
fn eq_hash_strip_closure(pool: &DescriptorPool, roots: &[&str]) -> BTreeSet<String> {
    // Reverse containment edges, keyed by fully-qualified name: message -> the messages that hold
    // it in a field.
    let mut containers: HashMap<String, Vec<String>> = HashMap::new();
    for message in pool.all_messages() {
        for field in message.fields() {
            if let Kind::Message(field_type) = field.kind() {
                containers
                    .entry(field_type.full_name().to_owned())
                    .or_default()
                    .push(message.full_name().to_owned());
            }
        }
    }

    let mut closure = BTreeSet::new();
    let mut pending: Vec<String> = roots
        .iter()
        .map(|root| {
            assert!(
                pool.get_message_by_name(root).is_some(),
                "STRIP_EQ_HASH_MESSAGES names `{root}`, which is not a message in the proto set"
            );
            (*root).to_owned()
        })
        .collect();
    while let Some(message) = pending.pop() {
        if closure.insert(message.clone())
            && let Some(parents) = containers.get(&message)
        {
            pending.extend(parents.iter().cloned());
        }
    }
    closure
}

/// Removes `Eq` and `Hash` from the derive list of each given message.
///
/// See [`STRIP_EQ_HASH_MESSAGES`] for why. Each message is resolved through the descriptor pool to
/// its own generated file (`<package>.rs`) and struct name, so a name shared by another package
/// cannot be matched by mistake. Within that file the derive directly above the struct is
/// rewritten: `Eq` and `Hash` are dropped and every other derive is kept, whatever the set or
/// order. A message that no longer derives them (for example once it gains a non-hashable field) is
/// left unchanged. The struct must appear exactly once in the file, so a nested type sharing the
/// name fails the build rather than having the wrong struct stripped.
fn remove_eq_hash_derives(out_dir: &Path, pool: &DescriptorPool, messages: &BTreeSet<String>) {
    for message in messages {
        let descriptor = pool
            .get_message_by_name(message)
            .expect("closure members are message names taken from the descriptor pool");
        let struct_name = descriptor.name();
        let path = out_dir.join(format!("{}.rs", descriptor.package_name()));

        let derive = regex::Regex::new(&format!(
            r"#\[derive\(([^)]*)\)\]\npub struct {} \{{",
            regex::escape(struct_name)
        ))
        .unwrap();

        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {} for `{message}`: {e}", path.display()));

        let captures = derive.captures_iter(&content).collect::<Vec<_>>();
        assert!(
            captures.len() == 1,
            "expected exactly one `pub struct {struct_name}` with a derive in {}, found {}; \
             `{message}` needs module-aware matching",
            path.display(),
            captures.len()
        );

        let kept = captures[0][1]
            .split(',')
            .map(str::trim)
            .filter(|derive| !matches!(*derive, "" | "Eq" | "Hash"))
            .collect::<Vec<_>>()
            .join(", ");
        let replacement = format!("#[derive({kept})]\npub struct {struct_name} {{");

        let content = derive.replace(&content, regex::NoExpand(&replacement));
        std::fs::write(&path, content.as_bytes()).unwrap();
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
