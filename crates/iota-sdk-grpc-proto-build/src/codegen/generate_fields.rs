// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use proc_macro2::TokenStream;
use prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorSet, field_descriptor_proto::Type,
};
use quote::quote;

use crate::{
    codegen::type_registry::TypeRegistry, dependency_graph::DependencyGraph, ident::to_snake,
};

/// Information about a transparent wrapper message (one that should be skipped
/// in read_mask paths / field path builders).
pub(crate) struct TransparentInfo {
    /// True when the single inner field is a map field.
    pub is_map: bool,
    /// Full protobuf type name of the inner message (e.g.
    /// ".iota.grpc.v1.event.Event"), None for maps.
    pub inner_full_type_name: Option<String>,
}

/// Parses the descriptor pool to find all messages with the
/// `field_mask_transparent` option set to true. Returns a map keyed by full
/// protobuf type name (e.g. `.iota.grpc.v1.event.Events`) with information
/// about the inner field that should be surfaced through the transparent
/// wrapper.
pub fn parse_transparent_messages_from_pool(
    pool: &prost_reflect::DescriptorPool,
) -> HashMap<String, TransparentInfo> {
    let mut map = HashMap::new();

    let transparent_ext = match pool.get_extension_by_name("iota.grpc.field_mask_transparent") {
        Some(ext) => ext,
        None => return map,
    };

    for message in pool.all_messages() {
        let options = message.options();
        if !options.has_extension(&transparent_ext) {
            continue;
        }

        let is_transparent = options
            .get_extension(&transparent_ext)
            .as_bool()
            .unwrap_or(false);

        if !is_transparent {
            continue;
        }

        // The wrapper must contain exactly one field.
        let fields: Vec<_> = message.fields().collect();
        if fields.len() != 1 {
            eprintln!(
                "Warning: transparent message {} has {} fields, expected 1 — skipping",
                message.full_name(),
                fields.len()
            );
            continue;
        }

        let inner_field = fields[0].clone();

        // Detect whether the inner field is a map field (a repeated field whose
        // message type has map_entry = true).
        let is_map = match inner_field.kind() {
            prost_reflect::Kind::Message(ref msg) => msg.is_map_entry(),
            _ => false,
        };

        let inner_full_type_name = match inner_field.kind() {
            prost_reflect::Kind::Message(ref msg) if !is_map => {
                Some(format!(".{}", msg.full_name()))
            }
            _ => None,
        };

        let full_type_name = format!(".{}", message.full_name());
        map.insert(
            full_type_name,
            TransparentInfo {
                is_map,
                inner_full_type_name,
            },
        );
    }

    map
}

#[derive(Default)]
pub(crate) struct FileDescriptorWithPackageVersion {
    pub fd_set: FileDescriptorSet,
    pub version: String,
}

/// What the generator needs to turn a field's protobuf type into Rust, shared
/// by every message of the package being generated.
struct PackageContext<'a> {
    /// Package being generated, e.g. `iota.grpc.v1.command`.
    package: &'a str,
    registry: &'a TypeRegistry,
    boxed_types: &'a [String],
    dependency_graph: &'a DependencyGraph,
    transparent_messages: &'a HashMap<String, TransparentInfo>,
}

impl PackageContext<'_> {
    fn message_path(&self, full_type_name: &str) -> TokenStream {
        self.registry
            .resolve(full_type_name)
            .message_path(self.package)
    }

    fn builder_path(&self, full_type_name: &str) -> TokenStream {
        self.registry
            .resolve(full_type_name)
            .builder_path(self.package)
    }

    fn is_map_entry(&self, full_type_name: &str) -> bool {
        self.registry.resolve(full_type_name).is_map_entry()
    }

    fn transparent(&self, full_type_name: &str) -> Option<&TransparentInfo> {
        self.transparent_messages.get(full_type_name)
    }

    /// True when prost boxes the field, which the field path builders have to
    /// mirror.
    fn is_boxed_field(&self, message_full_name: &str, field_name: &str) -> bool {
        let field_path = format!("{message_full_name}.{field_name}");
        self.boxed_types.iter().any(|boxed_path| {
            boxed_path.trim_start_matches('.') == field_path.trim_start_matches('.')
        })
    }
}

pub(crate) fn generate_field_info(
    packages: &BTreeMap<String, FileDescriptorWithPackageVersion>,
    out_dir: &Path,
    boxed_types: &[String],
    transparent_messages: &HashMap<String, TransparentInfo>,
) {
    let registry = TypeRegistry::new(packages);

    for (package, FileDescriptorWithPackageVersion { fd_set, .. }) in packages {
        if package.contains("google") {
            continue;
        }

        let package_full_name = format!(".{package}");

        let mut dependency_graph = DependencyGraph::new();
        for file in &fd_set.file {
            dependency_graph.add_messages(&file.message_type, &package_full_name);
        }

        let context = PackageContext {
            package,
            registry: &registry,
            boxed_types,
            dependency_graph: &dependency_graph,
            transparent_messages,
        };

        let mut stream = TokenStream::new();
        for file in &fd_set.file {
            stream.extend(generate_field_info_for_all_messages(
                &context,
                &package_full_name,
                &file.message_type,
            ));
        }

        // Only generate file if there's actual content in the stream
        if stream.is_empty() {
            continue;
        }

        // Types of other packages are referenced through their full module
        // path, so nothing but the traits has to be imported here. `_field_impls`
        // is public because the field path builders of nested messages are
        // shadowed at the package root by the prost module of the same name.
        let code = quote! {
            #[doc(hidden)]
            pub mod _field_impls {
                #![allow(clippy::wrong_self_convention)]

                use super::*;

                use crate::field::MessageFields;
                use crate::field::MessageField;

                #stream
            }

            pub use _field_impls::*;
        };

        let ast: syn::File = syn::parse2(code).expect("not a valid tokenstream");
        let code = prettyplease::unparse(&ast);

        // Add IOTA license header
        let mut buf = String::new();
        buf.push_str("// Copyright (c) Mysten Labs, Inc.\n");
        buf.push_str("// Modifications Copyright (c) 2026 IOTA Stiftung\n");
        buf.push_str("// SPDX-License-Identifier: Apache-2.0\n");
        buf.push('\n');
        buf.push_str(&code);

        let file_name = format!("{package}.field_info.rs");
        std::fs::write(out_dir.join(file_name), &buf).unwrap();
    }
}

// Helper function to recursively generate field info for all messages including
// nested ones
fn generate_field_info_for_all_messages(
    context: &PackageContext<'_>,
    parent_full_name: &str,
    messages: &[DescriptorProto],
) -> TokenStream {
    let mut stream = TokenStream::new();

    // First pass: Generate nested modules first so they're defined before being
    // used
    for message in messages {
        // Skip map entry messages
        if message.options.as_ref().is_some_and(|o| o.map_entry()) {
            continue;
        }

        // Generate nested modules for nested messages
        if !message.nested_type.is_empty() {
            let module_name = quote::format_ident!("{}", to_snake(message.name()));
            let nested_content = generate_field_info_for_all_messages(
                context,
                &format!("{parent_full_name}.{}", message.name()),
                &message.nested_type,
            );

            if !nested_content.is_empty() {
                stream.extend(quote! {
                    pub mod #module_name {
                        use super::*;

                        #nested_content
                    }
                });
            }
        }
    }

    // Second pass: Generate top-level messages after nested modules are defined
    for message in messages {
        // Skip map entry messages
        if message.options.as_ref().is_some_and(|o| o.map_entry()) {
            continue;
        }

        stream.extend(generate_field_info_for_message(
            context,
            &format!("{parent_full_name}.{}", message.name()),
            message,
        ));
    }

    stream
}

fn generate_field_info_for_message(
    context: &PackageContext<'_>,
    message_full_name: &str,
    message: &DescriptorProto,
) -> TokenStream {
    let message_path = context.message_path(message_full_name);

    let constants = generate_field_constants(context, message_full_name, message, &message_path);
    let oneof_constants = generate_oneof_name_constants(message, &message_path);
    let message_fields_impl = generate_message_fields_impl(message, &message_path);
    let field_path_builders =
        generate_field_path_builders_impl(context, message_full_name, message, &message_path);

    quote! {
        #constants
        #oneof_constants
        #message_fields_impl
        #field_path_builders
    }
}

/// Generates `pub const {NAME}_ONEOF: &'static str = "{name}";` constants for
/// each real `oneof` declaration in a message. Synthetic oneofs created by the
/// proto3-optional feature are excluded.
fn generate_oneof_name_constants(
    message: &DescriptorProto,
    message_path: &TokenStream,
) -> TokenStream {
    if message.oneof_decl.is_empty() {
        return TokenStream::new();
    }

    // Determine which oneof indices are "real" (not synthetic proto3-optional
    // oneofs). A synthetic oneof only contains fields with proto3_optional = true.
    let real_oneof_indices: HashSet<i32> = message
        .field
        .iter()
        .filter_map(|field| {
            if field.oneof_index.is_some() && !field.proto3_optional() {
                field.oneof_index
            } else {
                None
            }
        })
        .collect();

    if real_oneof_indices.is_empty() {
        return TokenStream::new();
    }

    let mut consts = TokenStream::new();

    for (idx, oneof) in message.oneof_decl.iter().enumerate() {
        if !real_oneof_indices.contains(&(idx as i32)) {
            continue;
        }
        let name = oneof.name();
        let ident = quote::format_ident!("{}_ONEOF", name.to_ascii_uppercase());
        consts.extend(quote! {
            pub const #ident: &'static str = #name;
        });
    }

    if consts.is_empty() {
        return TokenStream::new();
    }

    quote! {
        impl #message_path {
            #consts
        }
    }
}

fn generate_field_constants(
    context: &PackageContext<'_>,
    message_full_name: &str,
    message: &DescriptorProto,
    message_path: &TokenStream,
) -> TokenStream {
    let mut field_consts = TokenStream::new();

    for field in &message.field {
        field_consts.extend(generate_field_constant(context, message_full_name, field));
    }

    quote! {
        impl #message_path {
            #field_consts
        }
    }
}

fn generate_message_fields_impl(
    message: &DescriptorProto,
    message_path: &TokenStream,
) -> TokenStream {
    let mut field_refs = TokenStream::new();

    for field in &message.field {
        field_refs.extend(generate_field_reference(field));
    }

    // Collect real (non-synthetic) oneof names for the ONEOFS constant.
    let real_oneof_names = get_real_oneof_names(message);

    let oneofs_impl = if real_oneof_names.is_empty() {
        TokenStream::new()
    } else {
        let names = real_oneof_names.iter().map(|name| {
            quote! { #name, }
        });
        quote! {
            const ONEOFS: &'static [&'static str] = &[
                #(#names)*
            ];
        }
    };

    quote! {
        impl MessageFields for #message_path {
            const FIELDS: &'static [&'static MessageField] = &[
                #field_refs
            ];
            #oneofs_impl
        }
    }
}

/// Returns the names of real (non-synthetic proto3-optional) oneofs in a
/// message.
fn get_real_oneof_names(message: &DescriptorProto) -> Vec<String> {
    if message.oneof_decl.is_empty() {
        return Vec::new();
    }

    let real_oneof_indices: HashSet<i32> = message
        .field
        .iter()
        .filter_map(|field| {
            if field.oneof_index.is_some() && !field.proto3_optional() {
                field.oneof_index
            } else {
                None
            }
        })
        .collect();

    message
        .oneof_decl
        .iter()
        .enumerate()
        .filter_map(|(idx, oneof)| {
            if real_oneof_indices.contains(&(idx as i32)) {
                Some(oneof.name().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn generate_field_constant(
    context: &PackageContext<'_>,
    message_full_name: &str,
    field: &FieldDescriptorProto,
) -> TokenStream {
    let ident = quote::format_ident!("{}_FIELD", field.name().to_ascii_uppercase());
    let name = field.name();
    let json_name = field.json_name();
    let number = field.number();

    // Check if the field is optional in the proto definition
    let is_proto3_optional = field.proto3_optional.unwrap_or(false);

    let (is_map, message_fields) =
        if matches!(field.r#type(), Type::Message) && !field.type_name().contains("google") {
            let full_type_name = field.type_name();

            // Check for circular references that need to be broken:
            // 1. Self-reference
            // 2. Map entry types
            // 3. Fields that are boxed AND create circular dependencies in the message
            //    graph
            let is_circular_reference = context.is_boxed_field(message_full_name, field.name())
                && context
                    .dependency_graph
                    .has_circular_dependency(message_full_name, full_type_name);

            if full_type_name == message_full_name || is_circular_reference {
                (quote! { false }, quote! { None })
            } else if context.is_map_entry(full_type_name) {
                (quote! { true }, quote! { None })
            } else if let Some(info) = context.transparent(full_type_name) {
                // Field points to a transparent wrapper: flatten through it.
                if info.is_map {
                    // The wrapper's inner field is a map → treat this field as a map directly.
                    (quote! { true }, quote! { None })
                } else if let Some(inner_full_name) = &info.inner_full_type_name {
                    // The wrapper's inner field is a repeated message → use the inner type's
                    // FIELDS.
                    let inner = context.message_path(inner_full_name);
                    (quote! { false }, quote! { Some(#inner::FIELDS) })
                } else {
                    (quote! { false }, quote! { None })
                }
            } else {
                let field_message = context.message_path(full_type_name);
                (quote! { false }, quote! { Some(#field_message::FIELDS) })
            }
        } else {
            (quote! { false }, quote! { None })
        };

    quote! {
        pub const #ident: &'static MessageField = &MessageField {
            name: #name,
            json_name: #json_name,
            number: #number,
            is_optional: #is_proto3_optional,
            is_map: #is_map,
            message_fields: #message_fields,
        };
    }
}

fn generate_field_reference(field: &FieldDescriptorProto) -> TokenStream {
    let ident = quote::format_ident!("{}_FIELD", field.name().to_ascii_uppercase());

    quote! {
        Self::#ident,
    }
}

fn generate_field_path_builders_impl(
    context: &PackageContext<'_>,
    message_full_name: &str,
    message: &DescriptorProto,
    message_path: &TokenStream,
) -> TokenStream {
    let builder_ident = quote::format_ident!("{}FieldPathBuilder", message.name());

    let mut field_chain_methods = TokenStream::new();

    for field in &message.field {
        field_chain_methods.extend(generate_field_chain_methods(
            context,
            message_full_name,
            message_path,
            field,
        ));
    }

    quote! {
        impl #message_path {
            pub fn path_builder() -> #builder_ident {
                #builder_ident::new()
            }
        }

        pub struct #builder_ident {
            path: Vec<&'static str>,
        }

        impl #builder_ident {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self {
                    path: Default::default(),
                }
            }

            #[doc(hidden)]
            pub fn new_with_base(base: Vec<&'static str>) -> Self {
                Self { path: base }
            }

            pub fn finish(self) -> String {
                self.path.join(".")
            }

            #field_chain_methods
        }
    }
}

fn generate_field_chain_methods(
    context: &PackageContext<'_>,
    message_full_name: &str,
    message_path: &TokenStream,
    field: &FieldDescriptorProto,
) -> TokenStream {
    let field_const = quote::format_ident!("{}_FIELD", field.name().to_ascii_uppercase());
    let name = if field.name() == "type" {
        quote::format_ident!("r#{}", field.name())
    } else {
        quote::format_ident!("{}", field.name())
    };

    let leaf_method = quote! {
        pub fn #name(mut self) -> String {
            self.path.push(#message_path::#field_const.name);
            self.finish()
        }
    };

    // we need to ignore google types, because we don't generate builders for them
    if !matches!(field.r#type(), Type::Message) || field.type_name().contains("google") {
        return leaf_method;
    }

    let full_type_name = field.type_name();

    if full_type_name == message_full_name || context.is_map_entry(full_type_name) {
        return leaf_method;
    }

    // A field pointing at a transparent wrapper chains into the wrapped type.
    let target_type_name = match context.transparent(full_type_name) {
        Some(info) => match &info.inner_full_type_name {
            // The wrapper wraps a map, so the field is a leaf.
            _ if info.is_map => return leaf_method,
            Some(inner_full_name) => inner_full_name.as_str(),
            None => return leaf_method,
        },
        None => full_type_name,
    };

    let return_type = context.builder_path(target_type_name);

    quote! {
        pub fn #name(mut self) -> #return_type {
            self.path.push(#message_path::#field_const.name);
            #return_type::new_with_base(self.path)
        }
    }
}
