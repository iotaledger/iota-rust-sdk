// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The single index over the compiled protobuf descriptors.
//!
//! `protox` produces a [`DescriptorPool`] that already resolves names, nesting,
//! map entries and options across files, so this type adds only what the pool
//! cannot know: where a message lands in the generated Rust module tree, which
//! version module a package belongs to, and which messages reference each other
//! in a cycle.
//!
//! Protobuf names come in two shapes: the pool uses bare names
//! (`iota.grpc.v1.types.Digest`), while `FieldDescriptorProto::type_name` and
//! the boxing config carry a leading dot. Everything here accepts either and
//! normalizes on the way in.

use std::collections::{BTreeMap, HashMap, HashSet};

use proc_macro2::TokenStream;
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use quote::{format_ident, quote};

use crate::{
    codegen::{
        accessor_config::{AccessorMap, parse_proto_accessors_from_pool},
        generate_fields::{TransparentInfo, parse_transparent_messages_from_pool},
    },
    ident::to_snake,
};

pub(crate) struct ProtoIndex {
    pool: DescriptorPool,
    /// Version module per package, e.g. `iota.grpc.v1.types` -> `v1`.
    versions: BTreeMap<String, String>,
    /// Accessor annotations, keyed as [`parse_proto_accessors_from_pool`]
    /// produces them.
    accessors: AccessorMap,
    /// Messages marked `field_mask_transparent`, keyed by fully qualified name
    /// with a leading dot.
    transparent: HashMap<String, TransparentInfo>,
}

impl ProtoIndex {
    pub(crate) fn build(pool: DescriptorPool) -> Self {
        let mut versions = BTreeMap::new();

        for file in pool.files() {
            // The version is the `vN` segment of the file path, e.g.
            // `iota/grpc/v1/types.proto` -> `v1`.
            let version = file
                .name()
                .split('/')
                .find(|part| {
                    part.starts_with('v')
                        && part.len() > 1
                        && part[1..].chars().all(|c| c.is_ascii_digit())
                })
                .unwrap_or("v1")
                .to_owned();
            versions.insert(file.package_name().to_owned(), version);
        }

        let accessors = parse_proto_accessors_from_pool(&pool);
        let transparent = parse_transparent_messages_from_pool(&pool);

        Self {
            pool,
            versions,
            accessors,
            transparent,
        }
    }

    /// Accessor annotations of every message, from the `iota.grpc` accessor
    /// options.
    pub(crate) fn accessor_map(&self) -> &AccessorMap {
        &self.accessors
    }

    /// Information about a `field_mask_transparent` wrapper, if the message is
    /// one. Takes a fully qualified name with or without the leading dot.
    pub(crate) fn transparent(&self, full_type_name: &str) -> Option<&TransparentInfo> {
        self.transparent
            .get(&format!(".{}", full_type_name.trim_start_matches('.')))
    }

    pub(crate) fn version(&self, package: &str) -> &str {
        self.versions
            .get(package)
            .map(String::as_str)
            .unwrap_or("v1")
    }

    /// Every package of every compiled file, sorted, without a leading dot.
    pub(crate) fn packages(&self) -> Vec<String> {
        let mut packages: Vec<String> = self
            .pool
            .files()
            .map(|file| file.package_name().to_owned())
            .collect();
        packages.sort();
        packages.dedup();
        packages
    }

    /// Root messages of a package in the order codegen emits them: files sorted
    /// by name, messages in declaration order. Nested messages are reached
    /// through [`MessageDescriptor::child_messages`].
    pub(crate) fn messages_in_declaration_order(&self, package: &str) -> Vec<MessageDescriptor> {
        let mut files: Vec<_> = self
            .pool
            .files()
            .filter(|file| file.package_name() == package)
            .collect();
        files.sort_by(|a, b| a.name().cmp(b.name()));

        files.iter().flat_map(|file| file.messages()).collect()
    }

    /// Every message of a package, nested ones included, in the order the proto
    /// files declare them: files by name, then each message followed by its own
    /// nested messages. Map entry messages are synthetic and have no generated
    /// type, so they are skipped.
    pub(crate) fn all_messages_in_declaration_order(
        &self,
        package: &str,
    ) -> Vec<MessageDescriptor> {
        fn push_with_children(message: MessageDescriptor, out: &mut Vec<MessageDescriptor>) {
            if message.is_map_entry() {
                return;
            }
            let children: Vec<_> = message.child_messages().collect();
            out.push(message);
            for child in children {
                push_with_children(child, out);
            }
        }

        let mut messages = Vec::new();
        for root in self.messages_in_declaration_order(package) {
            push_with_children(root, &mut messages);
        }
        messages
    }

    /// Resolves a message by fully qualified name, with or without the leading
    /// dot. Panics when unknown: every message a field can reference is
    /// compiled together with the field's own file.
    pub(crate) fn resolve(&self, full_type_name: &str) -> MessageDescriptor {
        let name = full_type_name.trim_start_matches('.');
        self.pool
            .get_message_by_name(name)
            .unwrap_or_else(|| panic!("unknown protobuf message type {full_type_name}"))
    }

    /// Path to the message type as prost generates it. Messages of
    /// `from_package` that are not nested are left unqualified — the generated
    /// file is included into that very module.
    pub(crate) fn message_path(
        &self,
        message: &MessageDescriptor,
        from_package: &str,
    ) -> TokenStream {
        let name = format_ident!("{}", message.name());
        let outer = outer_modules(message);

        if outer.is_empty() && message.package_name() == from_package {
            return quote! { #name };
        }

        let root = self.package_path(message.package_name());
        quote! { #root #(::#outer)* ::#name }
    }

    /// Path to the field path builder generated for the message.
    pub(crate) fn builder_path(
        &self,
        message: &MessageDescriptor,
        from_package: &str,
    ) -> TokenStream {
        let builder = format_ident!("{}FieldPathBuilder", message.name());
        let outer = outer_modules(message);

        if message.package_name() == from_package {
            // Builders are generated into `_field_impls` of the file being
            // written, mirroring the message nesting.
            return quote! { #(#outer::)* #builder };
        }

        let root = self.package_path(message.package_name());
        if outer.is_empty() {
            quote! { #root::#builder }
        } else {
            // At the package root the nested module is shadowed by the prost
            // module of the same name, so the builder is only reachable through
            // `_field_impls`.
            quote! { #root::_field_impls #(::#outer)* ::#builder }
        }
    }

    /// True when `to` reaches back to `from` through message-typed fields, i.e.
    /// the two sit on a reference cycle. Used to stop `MessageFields::FIELDS`
    /// from recursing forever.
    ///
    /// The walk is scoped to the package `from` belongs to: cycle breaking has
    /// always been decided per package, and a path leaving the package cannot
    /// close a cycle the generated code would recurse through.
    pub(crate) fn has_reference_cycle(&self, from: &str, to: &str) -> bool {
        let from = from.trim_start_matches('.');
        let package = self.resolve(from).package_name().to_owned();
        self.can_reach(
            to.trim_start_matches('.'),
            from,
            &package,
            &mut HashSet::new(),
        )
    }

    fn can_reach(
        &self,
        source: &str,
        target: &str,
        package: &str,
        visited: &mut HashSet<String>,
    ) -> bool {
        if source == target {
            return true;
        }
        if !visited.insert(source.to_owned()) {
            return false;
        }
        let Some(message) = self.pool.get_message_by_name(source) else {
            return false;
        };
        if message.package_name() != package {
            return false;
        }

        message.fields().any(|field| match field.kind() {
            Kind::Message(inner) => self.can_reach(inner.full_name(), target, package, visited),
            _ => false,
        })
    }

    /// `crate::v1::types` for package `iota.grpc.v1.types`.
    fn package_path(&self, package: &str) -> TokenStream {
        let version = format_ident!("{}", self.version(package));
        let module = format_ident!("{}", package.split('.').next_back().unwrap_or(package));
        quote! { crate::#version::#module }
    }
}

/// snake_case modules of the enclosing messages, outermost first.
fn outer_modules(message: &MessageDescriptor) -> Vec<proc_macro2::Ident> {
    let mut outer = Vec::new();
    let mut parent = message.parent_message();
    while let Some(message) = parent {
        outer.push(format_ident!("{}", to_snake(message.name())));
        parent = message.parent_message();
    }
    outer.reverse();
    outer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index() -> ProtoIndex {
        let fixtures =
            std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut compiler = protox::Compiler::new([&fixtures]).unwrap();
        compiler
            .open_files([
                "fixture/grpc/v1/nesting_a.proto",
                "fixture/grpc/v1/nesting_b.proto",
                "fixture/grpc/v2/nesting_a.proto",
            ])
            .unwrap();
        ProtoIndex::build(compiler.descriptor_pool())
    }

    fn message_path(full_type_name: &str, from_package: &str) -> String {
        let index = index();
        let message = index.resolve(full_type_name);
        index
            .message_path(&message, from_package)
            .to_string()
            .replace(' ', "")
    }

    fn builder_path(full_type_name: &str, from_package: &str) -> String {
        let index = index();
        let message = index.resolve(full_type_name);
        index
            .builder_path(&message, from_package)
            .to_string()
            .replace(' ', "")
    }

    #[test]
    fn same_name_in_different_packages_resolves_to_its_own_package() {
        assert_eq!(
            message_path(".fixture.grpc.v1.a.Input", "fixture.grpc.v1.b"),
            "crate::v1::a::Input"
        );
        assert_eq!(
            message_path(".fixture.grpc.v1.b.Input", "fixture.grpc.v1.a"),
            "crate::v1::b::Input"
        );
    }

    #[test]
    fn same_name_in_different_versions_keeps_its_own_version_module() {
        assert_eq!(
            message_path(".fixture.grpc.v2.a.Input", "fixture.grpc.v1.b"),
            "crate::v2::a::Input"
        );
        assert_eq!(index().version("fixture.grpc.v2.a"), "v2");
    }

    #[test]
    fn nested_messages_are_qualified_by_their_outer_messages() {
        assert_eq!(
            message_path(".fixture.grpc.v1.a.Argument.Input", "fixture.grpc.v1.b"),
            "crate::v1::a::argument::Input"
        );
        assert_eq!(
            message_path(".fixture.grpc.v1.a.Argument.Input", "fixture.grpc.v1.a"),
            "crate::v1::a::argument::Input"
        );
    }

    #[test]
    fn local_top_level_messages_are_unqualified() {
        assert_eq!(
            message_path(".fixture.grpc.v1.a.Input", "fixture.grpc.v1.a"),
            "Input"
        );
    }

    #[test]
    fn builders_of_the_same_package_are_relative_to_field_impls() {
        assert_eq!(
            builder_path(".fixture.grpc.v1.a.Input", "fixture.grpc.v1.a"),
            "InputFieldPathBuilder"
        );
        assert_eq!(
            builder_path(".fixture.grpc.v1.a.Argument.Input", "fixture.grpc.v1.a"),
            "argument::InputFieldPathBuilder"
        );
    }

    #[test]
    fn builders_of_other_packages_are_absolute() {
        assert_eq!(
            builder_path(".fixture.grpc.v1.a.Input", "fixture.grpc.v1.b"),
            "crate::v1::a::InputFieldPathBuilder"
        );
        assert_eq!(
            builder_path(".fixture.grpc.v1.a.Argument.Input", "fixture.grpc.v1.b"),
            "crate::v1::a::_field_impls::argument::InputFieldPathBuilder"
        );
    }

    #[test]
    fn resolve_accepts_both_leading_dot_and_bare_names() {
        assert_eq!(index().resolve(".fixture.grpc.v1.a.Input").name(), "Input");
        assert_eq!(index().resolve("fixture.grpc.v1.a.Input").name(), "Input");
    }

    #[test]
    fn map_entries_are_recognised() {
        assert!(
            index()
                .resolve(".fixture.grpc.v1.b.Input.EntriesEntry")
                .is_map_entry()
        );
        assert!(!index().resolve(".fixture.grpc.v1.b.Input").is_map_entry());
    }

    #[test]
    fn reference_cycles_are_detected_in_both_directions() {
        let index = index();
        assert!(index.has_reference_cycle(".fixture.grpc.v1.a.Loop", ".fixture.grpc.v1.a.Step"));
        assert!(index.has_reference_cycle(".fixture.grpc.v1.a.Step", ".fixture.grpc.v1.a.Loop"));
        assert!(!index.has_reference_cycle(".fixture.grpc.v1.a.Input", ".fixture.grpc.v1.a.Loop"));
    }

    /// The option extensions live in the real protos, so this one compiles
    /// those instead of the fixtures.
    #[test]
    fn proto_options_are_indexed() {
        let proto_dir = std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
            .join("../iota-sdk-grpc-types/proto")
            .canonicalize()
            .unwrap();
        let mut compiler = protox::Compiler::new([&proto_dir]).unwrap();
        compiler
            .open_files(["iota/grpc/v1/transaction.proto"])
            .unwrap();
        let index = ProtoIndex::build(compiler.descriptor_pool());

        // `BalanceChanges` is `field_mask_transparent`, `ExecutedTransaction` is not.
        assert!(
            index
                .transparent(".iota.grpc.v1.transaction.BalanceChanges")
                .is_some()
        );
        assert!(
            index
                .transparent("iota.grpc.v1.transaction.BalanceChanges")
                .is_some()
        );
        assert!(
            index
                .transparent(".iota.grpc.v1.transaction.ExecutedTransaction")
                .is_none()
        );

        assert!(!index.accessor_map().is_empty());
    }

    #[test]
    fn root_messages_are_yielded_in_declaration_order() {
        let names: Vec<_> = index()
            .messages_in_declaration_order("fixture.grpc.v1.a")
            .iter()
            .map(|message| message.name().to_owned())
            .collect();
        assert_eq!(names, ["Argument", "Input", "Loop", "Step"]);
    }

    #[test]
    fn all_messages_follow_each_parent_with_its_children_and_skip_map_entries() {
        let names: Vec<_> = index()
            .all_messages_in_declaration_order("fixture.grpc.v1.a")
            .iter()
            .map(|message| message.full_name().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "fixture.grpc.v1.a.Argument",
                "fixture.grpc.v1.a.Argument.Input",
                "fixture.grpc.v1.a.Input",
                "fixture.grpc.v1.a.Loop",
                "fixture.grpc.v1.a.Step",
            ]
        );

        // `Input.EntriesEntry` backs the map field and has no generated type.
        let names: Vec<_> = index()
            .all_messages_in_declaration_order("fixture.grpc.v1.b")
            .iter()
            .map(|message| message.full_name().to_owned())
            .collect();
        assert_eq!(names, ["fixture.grpc.v1.b.Input"]);
    }
}
