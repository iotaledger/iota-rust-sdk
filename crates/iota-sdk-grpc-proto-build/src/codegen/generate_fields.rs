// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, path::Path};

use proc_macro2::TokenStream;
use prost_reflect::{FieldDescriptor, Kind, MessageDescriptor};
use quote::quote;

use crate::{ident::to_snake, index::ProtoIndex};

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
            Kind::Message(ref msg) => msg.is_map_entry(),
            _ => false,
        };

        let inner_full_type_name = match inner_field.kind() {
            Kind::Message(ref msg) if !is_map => Some(format!(".{}", msg.full_name())),
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

/// What the generator needs to turn a field's protobuf type into Rust, shared
/// by every message of the package being generated.
struct PackageContext<'a> {
    /// Package being generated, e.g. `iota.grpc.v1.command`.
    package: &'a str,
    index: &'a ProtoIndex,
    boxed_types: &'a [String],
}

impl PackageContext<'_> {
    fn message_path(&self, full_type_name: &str) -> TokenStream {
        self.index
            .message_path(&self.index.resolve(full_type_name), self.package)
    }

    fn builder_path(&self, full_type_name: &str) -> TokenStream {
        self.index
            .builder_path(&self.index.resolve(full_type_name), self.package)
    }

    fn is_map_entry(&self, full_type_name: &str) -> bool {
        self.index.resolve(full_type_name).is_map_entry()
    }

    fn transparent(&self, full_type_name: &str) -> Option<&TransparentInfo> {
        self.index.transparent(full_type_name)
    }

    /// True when prost boxes the field, which the field constants have to
    /// mirror by not recursing into it.
    fn is_boxed_field(&self, message: &MessageDescriptor, field: &FieldDescriptor) -> bool {
        let field_path = format!("{}.{}", message.full_name(), field.name());
        self.boxed_types
            .iter()
            .any(|boxed_path| boxed_path.trim_start_matches('.') == field_path)
    }
}

pub(crate) fn generate_field_info(index: &ProtoIndex, out_dir: &Path, boxed_types: &[String]) {
    for package in index.packages() {
        if package.contains("google") {
            continue;
        }

        let context = PackageContext {
            package: &package,
            index,
            boxed_types,
        };

        let stream = generate_field_info_for_all_messages(
            &context,
            &index.messages_in_declaration_order(&package),
        );

        // Only generate file if there's actual content in the stream
        if stream.is_empty() {
            continue;
        }

        // Types of other packages are referenced through their full module path,
        // so nothing but the traits has to be imported here.
        let code = quote! {
            mod _field_impls {
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
    messages: &[MessageDescriptor],
) -> TokenStream {
    let mut stream = TokenStream::new();

    // First pass: Generate nested modules first so they're defined before being
    // used
    for message in messages {
        // Skip map entry messages
        if message.is_map_entry() {
            continue;
        }

        // Generate nested modules for nested messages
        let children: Vec<_> = message.child_messages().collect();
        if !children.is_empty() {
            let module_name = quote::format_ident!("{}", to_snake(message.name()));
            let nested_content = generate_field_info_for_all_messages(context, &children);

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
        if message.is_map_entry() {
            continue;
        }

        stream.extend(generate_field_info_for_message(context, message));
    }

    stream
}

fn generate_field_info_for_message(
    context: &PackageContext<'_>,
    message: &MessageDescriptor,
) -> TokenStream {
    let message_path = context.message_path(message.full_name());

    let constants = generate_field_constants(context, message, &message_path);
    let oneof_constants = generate_oneof_name_constants(message, &message_path);
    let message_fields_impl = generate_message_fields_impl(message, &message_path);
    let field_path_builders = generate_field_path_builders_impl(context, message, &message_path);

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
    message: &MessageDescriptor,
    message_path: &TokenStream,
) -> TokenStream {
    let mut consts = TokenStream::new();

    for oneof in message.oneofs().filter(|oneof| !oneof.is_synthetic()) {
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
    message: &MessageDescriptor,
    message_path: &TokenStream,
) -> TokenStream {
    let mut field_consts = TokenStream::new();

    for field in message.fields() {
        field_consts.extend(generate_field_constant(context, message, &field));
    }

    quote! {
        impl #message_path {
            #field_consts
        }
    }
}

fn generate_message_fields_impl(
    message: &MessageDescriptor,
    message_path: &TokenStream,
) -> TokenStream {
    let mut field_refs = TokenStream::new();

    for field in message.fields() {
        field_refs.extend(generate_field_reference(&field));
    }

    // Collect real (non-synthetic) oneof names for the ONEOFS constant.
    let real_oneof_names: Vec<String> = message
        .oneofs()
        .filter(|oneof| !oneof.is_synthetic())
        .map(|oneof| oneof.name().to_owned())
        .collect();

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

fn generate_field_constant(
    context: &PackageContext<'_>,
    message: &MessageDescriptor,
    field: &FieldDescriptor,
) -> TokenStream {
    let descriptor = field.field_descriptor_proto();
    let ident = quote::format_ident!("{}_FIELD", field.name().to_ascii_uppercase());
    let name = field.name();
    let json_name = field.json_name();
    let number = descriptor.number();

    // Check if the field is optional in the proto definition
    let is_proto3_optional = descriptor.proto3_optional.unwrap_or(false);

    let (is_map, message_fields) = match field.kind() {
        // we skip google types
        Kind::Message(_) if !descriptor.type_name().contains("google") => {
            let full_type_name = descriptor.type_name();

            // Check for circular references that need to be broken:
            // 1. Self-reference
            // 2. Map entry types
            // 3. Fields that are boxed AND create circular dependencies in the message
            //    graph
            let is_circular_reference = context.is_boxed_field(message, field)
                && context
                    .index
                    .has_reference_cycle(message.full_name(), full_type_name);

            if full_type_name.trim_start_matches('.') == message.full_name()
                || is_circular_reference
            {
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
        }
        _ => (quote! { false }, quote! { None }),
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

fn generate_field_reference(field: &FieldDescriptor) -> TokenStream {
    let ident = quote::format_ident!("{}_FIELD", field.name().to_ascii_uppercase());

    quote! {
        Self::#ident,
    }
}

fn generate_field_path_builders_impl(
    context: &PackageContext<'_>,
    message: &MessageDescriptor,
    message_path: &TokenStream,
) -> TokenStream {
    let builder_ident = quote::format_ident!("{}FieldPathBuilder", message.name());

    let mut field_chain_methods = TokenStream::new();

    for field in message.fields() {
        field_chain_methods.extend(generate_field_chain_methods(
            context,
            message,
            message_path,
            &field,
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
    message: &MessageDescriptor,
    message_path: &TokenStream,
    field: &FieldDescriptor,
) -> TokenStream {
    let descriptor = field.field_descriptor_proto();
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
    if !matches!(field.kind(), Kind::Message(_)) || descriptor.type_name().contains("google") {
        return leaf_method;
    }

    let full_type_name = descriptor.type_name();

    if full_type_name.trim_start_matches('.') == message.full_name()
        || context.is_map_entry(full_type_name)
    {
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
