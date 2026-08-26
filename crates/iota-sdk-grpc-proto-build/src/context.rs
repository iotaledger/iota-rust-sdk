// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The single context over the compiled protobuf descriptors.
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

use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use proc_macro2::TokenStream;
use prost_reflect::{DescriptorPool, Kind, MessageDescriptor};
use quote::{format_ident, quote};

use crate::{
    codegen::{
        accessor_config::{AccessorMap, parse_proto_accessors_from_pool},
        generate_fields::{TransparentInfo, parse_transparent_messages_from_pool},
    },
    extern_paths::ExternPaths,
    ident::{to_snake, to_upper_camel},
};

pub(crate) struct Context {
    pool: DescriptorPool,
    /// Types resolved to a path outside the generated code, such as the
    /// `google.protobuf` well-known types.
    extern_paths: ExternPaths,
    /// Accessor annotations, keyed as [`parse_proto_accessors_from_pool`]
    /// produces them.
    accessors: AccessorMap,
    /// Messages marked `field_mask_transparent`, keyed by fully qualified name
    /// with a leading dot.
    transparent: HashMap<String, TransparentInfo>,
}

impl Context {
    pub(crate) fn build(pool: DescriptorPool) -> Self {
        let accessors = parse_proto_accessors_from_pool(&pool);
        let transparent = parse_transparent_messages_from_pool(&pool);

        Self {
            pool,
            extern_paths: ExternPaths::new(&[], true).expect("built-in extern paths are valid"),
            accessors,
            transparent,
        }
    }

    /// True when the type resolves outside the generated code and so has
    /// nothing generated for it.
    pub(crate) fn is_extern(&self, full_type_name: &str) -> bool {
        self.extern_paths
            .resolve_ident(&format!(".{}", full_type_name.trim_start_matches('.')))
            .is_some()
    }

    /// Resolves a protobuf type to a Rust path relative to `package`, the form
    /// accessor generation emits (`super::super::types::Digest`).
    ///
    /// Kept separate from [`Self::message_path`], which produces absolute
    /// `crate::` paths: accessors are written into a `_accessor_impls` module
    /// and address their types relatively from there.
    pub(crate) fn accessor_type_path(&self, package: &str, pb_ident: &str) -> String {
        // protoc should always give fully qualified identifiers.
        assert_eq!(".", &pb_ident[..1]);

        if let Some(proto_ident) = self.extern_paths.resolve_ident(pb_ident) {
            return proto_ident;
        }

        let mut local_path = package.split('.').peekable();

        // If no package is specified the start of the package name will be '.'
        // and split will return an empty string ("") which breaks resolution
        // The fix to this is to ignore the first item if it is empty.
        if local_path.peek().is_some_and(|s| s.is_empty()) {
            local_path.next();
        }

        let mut ident_path = pb_ident[1..].split('.');
        let ident_type = ident_path.next_back().unwrap();
        let mut ident_path = ident_path.peekable();

        // Skip path elements in common.
        while local_path.peek().is_some() && local_path.peek() == ident_path.peek() {
            local_path.next();
            ident_path.next();
        }

        local_path
            .map(|_| "super".to_string())
            .chain(ident_path.map(to_snake))
            .chain(std::iter::once(to_upper_camel(ident_type)))
            .join("::")
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

        let root = package_path(message.package_name());
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

        let root = package_path(message.package_name());
        if !outer.is_empty() {
            // A nested message's builder has no path from outside its own
            // package: `_field_impls` is private, and at the package root the
            // module holding the builder is shadowed by the prost module of the
            // same name, so the glob re-export never surfaces it.
            //
            // No proto references such a builder across packages today. Making
            // `_field_impls` `pub` is the one-line fix if one ever does — hence
            // failing loudly here rather than emitting a path that does not
            // resolve.
            panic!(
                "cannot reference the field path builder of nested message {} from package {from_package}: \
                 nested builders are only addressable inside their own package",
                message.full_name()
            );
        }

        quote! { #root::#builder }
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
}

/// Convert proto package to rust module path.
/// Generated rust modules live in `crate::proto`.
fn package_path(package: &str) -> TokenStream {
    let path = package.split('.').collect::<Vec<_>>().join("::");
    let module = if let Some(path) = path.strip_prefix("iota::grpc::v") {
        // `crate::proto::iota::grpc::v1` is re-exported as `crate::v1`
        format!("crate::v{path}")
    } else if let Some(path) = path.strip_prefix("google") {
        // `crate::proto::google` is re-exported as `crate::google`
        format!("crate::google{path}")
    } else {
        // generic case
        format!("crate::proto::{path}")
    };
    let path: syn::Path = syn::parse_str(module.as_str()).unwrap();
    quote! { #path }
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

    fn context() -> Context {
        let fixtures =
            std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut compiler = protox::Compiler::new([&fixtures]).unwrap();
        compiler
            .open_files([
                "iota/grpc/v1/a.proto",
                "iota/grpc/v1/b.proto",
                "iota/grpc/v2/a.proto",
            ])
            .unwrap();
        Context::build(compiler.descriptor_pool())
    }

    fn message_path(full_type_name: &str, from_package: &str) -> String {
        let context = context();
        let message = context.resolve(full_type_name);
        context
            .message_path(&message, from_package)
            .to_string()
            .replace(' ', "")
    }

    fn builder_path(full_type_name: &str, from_package: &str) -> String {
        let context = context();
        let message = context.resolve(full_type_name);
        context
            .builder_path(&message, from_package)
            .to_string()
            .replace(' ', "")
    }

    #[test]
    fn same_name_in_different_packages_resolves_to_its_own_package() {
        assert_eq!(
            message_path(".iota.grpc.v1.a.Input", "iota.grpc.v1.b"),
            "crate::v1::a::Input"
        );
        assert_eq!(
            message_path(".iota.grpc.v1.b.Input", "iota.grpc.v1.a"),
            "crate::v1::b::Input"
        );
    }

    #[test]
    fn nested_messages_are_qualified_by_their_outer_messages() {
        assert_eq!(
            message_path(".iota.grpc.v1.a.Argument.Input", "iota.grpc.v1.b"),
            "crate::v1::a::argument::Input"
        );
        assert_eq!(
            message_path(".iota.grpc.v1.a.Argument.Input", "iota.grpc.v1.a"),
            "crate::v1::a::argument::Input"
        );
    }

    #[test]
    fn local_top_level_messages_are_unqualified() {
        assert_eq!(
            message_path(".iota.grpc.v1.a.Input", "iota.grpc.v1.a"),
            "Input"
        );
    }

    #[test]
    fn builders_of_the_same_package_are_relative_to_field_impls() {
        assert_eq!(
            builder_path(".iota.grpc.v1.a.Input", "iota.grpc.v1.a"),
            "InputFieldPathBuilder"
        );
        assert_eq!(
            builder_path(".iota.grpc.v1.a.Argument.Input", "iota.grpc.v1.a"),
            "argument::InputFieldPathBuilder"
        );
    }

    #[test]
    fn builders_of_other_packages_are_absolute() {
        assert_eq!(
            builder_path(".iota.grpc.v1.a.Input", "iota.grpc.v1.b"),
            "crate::v1::a::InputFieldPathBuilder"
        );
    }

    /// A nested message's builder lives in the private `_field_impls` module,
    /// and at the package root its module is shadowed by the prost module
    /// of the same name, so no path reaches it from another package. Fail
    /// at codegen rather than emit a path that will not resolve.
    #[test]
    #[should_panic(expected = "nested builders are only addressable inside their own package")]
    fn builders_of_nested_messages_in_other_packages_are_rejected() {
        builder_path(".iota.grpc.v1.a.Argument.Input", "iota.grpc.v1.b");
    }

    #[test]
    fn resolve_accepts_both_leading_dot_and_bare_names() {
        assert_eq!(context().resolve(".iota.grpc.v1.a.Input").name(), "Input");
        assert_eq!(context().resolve("iota.grpc.v1.a.Input").name(), "Input");
    }

    #[test]
    fn map_entries_are_recognised() {
        assert!(
            context()
                .resolve(".iota.grpc.v1.b.Input.EntriesEntry")
                .is_map_entry()
        );
        assert!(!context().resolve(".iota.grpc.v1.b.Input").is_map_entry());
    }

    #[test]
    fn reference_cycles_are_detected_in_both_directions() {
        let context = context();
        assert!(context.has_reference_cycle(".iota.grpc.v1.a.Loop", ".iota.grpc.v1.a.Step"));
        assert!(context.has_reference_cycle(".iota.grpc.v1.a.Step", ".iota.grpc.v1.a.Loop"));
        assert!(!context.has_reference_cycle(".iota.grpc.v1.a.Input", ".iota.grpc.v1.a.Loop"));
    }

    /// The option extensions live in the real protos, so this one compiles
    /// those instead of the fixtures.
    #[test]
    fn proto_options_are_parsed() {
        let proto_dir = std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
            .join("../iota-sdk-grpc-types/proto")
            .canonicalize()
            .unwrap();
        let mut compiler = protox::Compiler::new([&proto_dir]).unwrap();
        compiler
            .open_files(["iota/grpc/v1/transaction.proto"])
            .unwrap();
        let context = Context::build(compiler.descriptor_pool());

        // `BalanceChanges` is `field_mask_transparent`, `ExecutedTransaction` is not.
        assert!(
            context
                .transparent(".iota.grpc.v1.transaction.BalanceChanges")
                .is_some()
        );
        assert!(
            context
                .transparent("iota.grpc.v1.transaction.BalanceChanges")
                .is_some()
        );
        assert!(
            context
                .transparent(".iota.grpc.v1.transaction.ExecutedTransaction")
                .is_none()
        );

        assert!(!context.accessor_map().is_empty());
    }

    #[test]
    fn root_messages_are_yielded_in_declaration_order() {
        let names: Vec<_> = context()
            .messages_in_declaration_order("iota.grpc.v1.a")
            .iter()
            .map(|message| message.name().to_owned())
            .collect();
        assert_eq!(names, ["Argument", "Input", "Loop", "Step"]);
    }

    #[test]
    fn all_messages_follow_each_parent_with_its_children_and_skip_map_entries() {
        let names: Vec<_> = context()
            .all_messages_in_declaration_order("iota.grpc.v1.a")
            .iter()
            .map(|message| message.full_name().to_owned())
            .collect();
        assert_eq!(
            names,
            [
                "iota.grpc.v1.a.Argument",
                "iota.grpc.v1.a.Argument.Input",
                "iota.grpc.v1.a.Input",
                "iota.grpc.v1.a.Loop",
                "iota.grpc.v1.a.Step",
            ]
        );

        // `Input.EntriesEntry` backs the map field and has no generated type.
        let names: Vec<_> = context()
            .all_messages_in_declaration_order("iota.grpc.v1.b")
            .iter()
            .map(|message| message.full_name().to_owned())
            .collect();
        assert_eq!(names, ["iota.grpc.v1.b.Input"]);
    }
}
