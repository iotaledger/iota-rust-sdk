// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{path::Path, str::FromStr};

use heck::ToPascalCase;
use proc_macro2::TokenStream;
use prost_reflect::{FieldDescriptor, MessageDescriptor, OneofDescriptor};
use prost_types::{
    FieldDescriptorProto,
    field_descriptor_proto::{Label, Type},
};
use quote::quote;

use crate::{
    codegen::accessor_config::{AccessorMap, AccessorTypes},
    ident::sanitize_identifier,
    context::Context,
};

/// The fields prost stores directly on the generated struct: everything that is
/// not a member of a real `oneof`. A synthetic proto3-optional oneof is not a
/// oneof as far as prost is concerned, so its field belongs here.
fn struct_fields(message: &MessageDescriptor) -> Vec<FieldDescriptor> {
    message
        .fields()
        .filter(|field| {
            field
                .containing_oneof()
                .is_none_or(|oneof| oneof.is_synthetic())
        })
        .collect()
}

/// The `oneof` declarations prost turns into an enum, in declaration order.
fn real_oneofs(message: &MessageDescriptor) -> Vec<OneofDescriptor> {
    message
        .oneofs()
        .filter(|oneof| !oneof.is_synthetic())
        .collect()
}

/// Key and value fields of the entry message backing a map field, or `None`
/// when the field is not a map.
fn map_entry_fields(
    field: &FieldDescriptor,
) -> Option<(FieldDescriptorProto, FieldDescriptorProto)> {
    if !field.is_map() {
        return None;
    }
    let entry = field.kind().as_message()?.clone();
    Some((
        entry.map_entry_key_field().field_descriptor_proto().clone(),
        entry
            .map_entry_value_field()
            .field_descriptor_proto()
            .clone(),
    ))
}

/// Whether prost wrapped the field in `Option`, which decides the shape of
/// every accessor generated for it.
///
/// Deliberately not [`FieldDescriptor::supports_presence`], which is also true
/// for scalar members of a oneof — prost keeps those in the oneof enum rather
/// than an `Option`.
fn is_optional(field: &FieldDescriptorProto) -> bool {
    if field.proto3_optional.unwrap_or(false) {
        return true;
    }

    if field.label() != Label::Optional {
        return false;
    }

    matches!(field.r#type(), Type::Message)
}

fn is_repeated(field: &FieldDescriptorProto) -> bool {
    field.label() == Label::Repeated
}

fn is_message(field: &FieldDescriptorProto) -> bool {
    matches!(field.r#type(), Type::Message)
}

fn is_enum(field: &FieldDescriptorProto) -> bool {
    matches!(field.r#type(), Type::Enum)
}

fn is_well_known_type(field: &FieldDescriptorProto) -> bool {
    field.type_name().starts_with(".google.protobuf")
}

/// Fully qualified name with the leading dot protobuf paths carry and the
/// descriptor pool omits.
fn qualified(name: &str) -> String {
    format!(".{name}")
}

pub(crate) fn generate_accessors(
    context: &Context,
    out_dir: &Path,
    boxed_types_prost: &[String],
    boxed_types_accessor: &[String],
    accessor_map: &AccessorMap,
) {
    for package in context.packages() {
        let mut buf = String::new();
        let mut stream = TokenStream::new();

        // Emit in the order the protos declare their messages, so a generated
        // file reads like the `.proto` it comes from.
        let messages = context
            .all_messages_in_declaration_order(&package)
            .into_iter()
            .filter(|message| !context.is_extern(message.full_name()));

        for message in messages {
            stream.extend(generate_accessors_for_message(
                context,
                &message,
                boxed_types_prost,
                boxed_types_accessor,
                accessor_map,
            ));
        }

        // If we didn't generate anything then just skip
        if !stream.is_empty() {
            let code = quote! {
                mod _accessor_impls {
                    #![allow(clippy::useless_conversion)]

                    #stream
                }
            };

            let ast: syn::File = syn::parse2(code).expect("not a valid tokenstream");
            let code = prettyplease::unparse(&ast);

            // Add IOTA license header
            buf.push_str("// Copyright (c) Mysten Labs, Inc.\n");
            buf.push_str("// Modifications Copyright (c) 2026 IOTA Stiftung\n");
            buf.push_str("// SPDX-License-Identifier: Apache-2.0\n");
            buf.push('\n');
            buf.push_str(&code);

            let file_name = format!("{package}.accessors.rs");
            std::fs::write(out_dir.join(file_name), &buf).unwrap();
        }
    }
}

fn generate_accessors_for_message(
    context: &Context,
    message: &MessageDescriptor,
    boxed_types_prost: &[String],
    boxed_types_accessor: &[String],
    accessor_map: &AccessorMap,
) -> TokenStream {
    let package = format!("{}.__accessors", qualified(message.package_name()));
    let message_rust_path =
        TokenStream::from_str(&context.accessor_type_path(&package, &qualified(message.full_name())))
            .unwrap();

    let mut functions = TokenStream::new();

    // Check if any field in this message needs the default_instance function, and
    // generate it if so. We do this at the message level (instead of per-field)
    // to avoid generating multiple default_instance functions for the same message
    // if multiple fields need it.
    let needs_default_instance = message_needs_default_instance(message, accessor_map);

    if needs_default_instance {
        functions.extend(generate_const_default_functions(
            message,
            &message_rust_path,
        ));
    }

    functions.extend(generate_accessors_functions(
        context,
        message,
        boxed_types_prost,
        boxed_types_accessor,
        accessor_map,
    ));

    // Only generate the impl block if there are any functions
    if functions.is_empty() {
        return TokenStream::new();
    }

    quote! {
        impl #message_rust_path {

            #functions
        }
    }
}

/// Check if any field in the message needs the default_instance function
/// This is needed when:
/// 1. DEFAULT is explicitly requested, OR
/// 2. GETTER is requested AND a getter method will actually be generated
fn message_needs_default_instance(message: &MessageDescriptor, accessor_map: &AccessorMap) -> bool {
    let message_full_name = message.full_name();

    // Check regular fields
    for field in struct_fields(message) {
        let descriptor = field.field_descriptor_proto();
        if let Some(accessor_types) =
            AccessorTypes::from_field(descriptor, accessor_map, message_full_name)
        {
            // Always generate if DEFAULT is explicitly set
            if accessor_types.contains(AccessorTypes::DEFAULT) {
                return true;
            }

            // Check if GETTER is set AND will actually generate a getter method
            if accessor_types.contains(AccessorTypes::GETTER) {
                // Maps and repeated fields always generate getters
                if field.is_map() || is_repeated(descriptor) {
                    return true;
                }
                // Optional fields only generate getters for message types (non-well-known)
                if is_optional(descriptor)
                    && is_message(descriptor)
                    && !is_well_known_type(descriptor)
                {
                    return true;
                }
                // Required/implicit optional fields don't generate getters, so
                // no default needed
            }
        }
    }

    // Check oneof fields - these always generate getters if GETTER is set
    for oneof in real_oneofs(message) {
        for field in oneof.fields() {
            if let Some(accessor_types) = AccessorTypes::from_field(
                field.field_descriptor_proto(),
                accessor_map,
                message_full_name,
            ) {
                if accessor_types.contains(AccessorTypes::DEFAULT) {
                    return true;
                }
                // Oneof fields always generate getters when GETTER is set
                if accessor_types.contains(AccessorTypes::GETTER) {
                    return true;
                }
            }
        }
    }

    false
}

fn generate_accessors_functions(
    context: &Context,
    message: &MessageDescriptor,
    boxed_types_prost: &[String],
    boxed_types_accessor: &[String],
    accessor_map: &AccessorMap,
) -> TokenStream {
    let mut accessors = TokenStream::new();

    for field in struct_fields(message) {
        accessors.extend(generate_accessors_functions_for_field(
            context,
            message,
            &field,
            None,
            boxed_types_prost,
            boxed_types_accessor,
            accessor_map,
        ));
    }

    for oneof in real_oneofs(message) {
        for field in oneof.fields() {
            accessors.extend(generate_accessors_functions_for_field(
                context,
                message,
                &field,
                Some(&oneof),
                boxed_types_prost,
                boxed_types_accessor,
                accessor_map,
            ));
        }
    }

    accessors
}

fn is_field_boxed_from_config(
    message: &MessageDescriptor,
    field: &FieldDescriptor,
    boxed_types: &[String],
) -> bool {
    // Create the field path pattern and check against boxed_types config
    let field_path = format!("{}.{}", qualified(message.full_name()), field.name());

    boxed_types
        .iter()
        .any(|boxed_path| boxed_path == &field_path)
}

fn generate_accessors_functions_for_field(
    context: &Context,
    message: &MessageDescriptor,
    field: &FieldDescriptor,
    oneof: Option<&OneofDescriptor>,
    boxed_types_prost: &[String],
    boxed_types_accessor: &[String],
    accessor_map: &AccessorMap,
) -> TokenStream {
    // Check if this field has the accessors custom option
    let accessor_types = match AccessorTypes::from_field(
        field.field_descriptor_proto(),
        accessor_map,
        message.full_name(),
    ) {
        Some(types) => types,
        None => return TokenStream::new(), // No option, skip this field
    };

    // Generate only the requested accessor types
    generate_selective_accessors_for_field(
        context,
        message,
        field,
        oneof,
        boxed_types_prost,
        boxed_types_accessor,
        accessor_types,
    )
}

fn generate_selective_accessors_for_field(
    context: &Context,
    message: &MessageDescriptor,
    field: &FieldDescriptor,
    oneof: Option<&OneofDescriptor>,
    boxed_types_prost: &[String],
    boxed_types_accessor: &[String],
    accessor_types: AccessorTypes,
) -> TokenStream {
    let descriptor = field.field_descriptor_proto();
    let package = format!("{}.__accessors", qualified(message.package_name()));
    let name = quote::format_ident!("{}", sanitize_identifier(field.name()));
    let name_opt = quote::format_ident!("{}_opt", field.name());
    let set_name = quote::format_ident!("set_{}", field.name());
    let name_mut = quote::format_ident!("{}_mut", field.name());
    let name_opt_mut = quote::format_ident!("{}_opt_mut", field.name());
    let with_name = quote::format_ident!("with_{}", field.name());

    // doc comments

    let name_comments = vec![format!(
        " Returns the value of `{name}`, or the default value if `{name}` is unset."
    )];
    let name_opt_comments = vec![format!(
        " If `{name}` is set, returns [`Some`] with the value; otherwise returns [`None`]."
    )];
    let mut set_name_comments = vec![format!(" Sets `{name}` with the provided value.")];
    let mut name_mut_comments = vec![
        format!(" Returns a mutable reference to `{name}`."),
        " If the field is unset, it is first initialized with the default value.".to_owned(),
    ];
    let name_opt_mut_comments = vec![format!(
        " If `{name}` is set, returns [`Some`] with a mutable reference to the value; otherwise returns [`None`]."
    )];

    let is_boxed_in_accessor = is_field_boxed_from_config(message, field, boxed_types_accessor);
    let is_boxed_in_prost = is_field_boxed_from_config(message, field, boxed_types_prost);
    let base_field_type_path = field_type_path(descriptor, context, &package);
    let field_type_path = if is_boxed_in_accessor {
        TokenStream::from_str(&format!(
            "::prost::alloc::boxed::Box<{base_field_type_path}>"
        ))
        .unwrap()
    } else {
        TokenStream::from_str(&base_field_type_path).unwrap()
    };

    // Conversion logic based on boxing configuration:
    // - If both accessor and proto are boxed: field.into() (Box -> Box)
    // - If accessor is boxed but proto is not: *field.into() (Box -> T by unboxing)
    // - If accessor is not boxed: field.into() (T -> T with Into conversions)
    let into_conversion = if is_boxed_in_accessor {
        if is_boxed_in_prost {
            quote! { field.into() }
        } else {
            quote! { *field.into() }
        }
    } else {
        quote! { field.into() }
    };

    let setter_assignment_value = if use_into_for_setter(descriptor) {
        quote! { #into_conversion }
    } else {
        quote! { field }
    };

    let set_param_type = if use_into_for_setter(descriptor) {
        quote! { <T: Into<#field_type_path>>(&mut self, field: T) }
    } else {
        quote! { (&mut self, field: #field_type_path) }
    };

    let with_param_type = if use_into_for_setter(descriptor) {
        quote! { <T: Into<#field_type_path>>(mut self, field: T) }
    } else {
        quote! { (mut self, field: #field_type_path) }
    };

    let default_instance =
        TokenStream::from_str(&type_default(descriptor, context, &package)).unwrap();
    let ref_return_type =
        TokenStream::from_str(&ref_return_type(descriptor, context, &package)).unwrap();
    let field_as = if is_ref_return(descriptor) {
        quote! {field as _}
    } else {
        quote! {*field}
    };

    if let Some((key, value)) = &map_entry_fields(field) {
        // Map Types
        let key_type = TokenStream::from_str(&map_entry_type_path(key, context, &package)).unwrap();
        let value_type =
            TokenStream::from_str(&map_entry_type_path(value, context, &package)).unwrap();

        let mut accessors = TokenStream::new();

        if accessor_types.contains(AccessorTypes::GETTER) {
            accessors.extend(quote! {
                #( #[doc = #name_comments] )*
                pub fn #name(&self) -> &::std::collections::BTreeMap<#key_type, #value_type> {
                    &self.#name
                }
            });
        }

        if accessor_types.contains(AccessorTypes::MUT) {
            accessors.extend(quote! {
                #( #[doc = #name_mut_comments] )*
                pub fn #name_mut(&mut self) -> &mut ::std::collections::BTreeMap<#key_type, #value_type> {
                    &mut self.#name
                }
            });
        }

        if accessor_types.contains(AccessorTypes::SET) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #set_name(&mut self, field: ::std::collections::BTreeMap<#key_type, #value_type>) {
                    self.#name = field;
                }
            });
        }

        if accessor_types.contains(AccessorTypes::WITH) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #with_name(mut self, field: ::std::collections::BTreeMap<#key_type, #value_type>) -> Self {
                    self.#name = field;
                    self
                }
            });
        }

        accessors
    } else if is_repeated(descriptor) {
        let mut accessors = TokenStream::new();

        // For repeated enum fields, prost stores them as Vec<i32>
        let is_enum = is_enum(descriptor);
        let storage_type = if is_enum {
            TokenStream::from_str("i32").unwrap()
        } else {
            field_type_path
        };

        if accessor_types.contains(AccessorTypes::GETTER) {
            accessors.extend(quote! {
                #( #[doc = #name_comments] )*
                pub fn #name(&self) -> &[#storage_type] {
                    &self.#name
                }
            });
        }

        if accessor_types.contains(AccessorTypes::MUT) {
            accessors.extend(quote! {
                #( #[doc = #name_mut_comments] )*
                pub fn #name_mut(&mut self) -> &mut Vec<#storage_type> {
                    &mut self.#name
                }
            });
        }

        if accessor_types.contains(AccessorTypes::SET) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #set_name(&mut self, field: Vec<#storage_type>) {
                    self.#name = field;
                }
            });
        }

        if accessor_types.contains(AccessorTypes::WITH) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #with_name(mut self, field: Vec<#storage_type>) -> Self {
                    self.#name = field;
                    self
                }
            });
        }

        accessors
    } else if let Some(oneof) = oneof {
        if descriptor.type_name() == ".google.protobuf.Empty" {
            return TokenStream::new();
        }

        let oneof_field = quote::format_ident!("{}", sanitize_identifier(oneof.name()));
        let oneof_type_path = TokenStream::from_str(&context.accessor_type_path(
            &package,
            &format!(
                "{}.{}",
                qualified(message.full_name()),
                oneof.name().to_pascal_case()
            ),
        ))
        .unwrap();
        let variant = quote::format_ident!("{}", field.name().to_pascal_case());

        name_mut_comments.push(
            " If any other oneof field in the same oneof is set, it will be cleared.".to_owned(),
        );
        set_name_comments.push(
            " If any other oneof field in the same oneof is set, it will be cleared.".to_owned(),
        );

        let mut accessors = TokenStream::new();

        if accessor_types.contains(AccessorTypes::GETTER) {
            accessors.extend(quote! {
                #( #[doc = #name_comments] )*
                pub fn #name(&self) -> #ref_return_type {
                    if let Some(#oneof_type_path::#variant(field)) = &self.#oneof_field {
                        #field_as
                    } else {
                        #default_instance
                    }
                }
            });
        }

        if accessor_types.contains(AccessorTypes::GETTER_OPT) {
            accessors.extend(quote! {
                #( #[doc = #name_opt_comments] )*
                pub fn #name_opt(&self) -> Option<#ref_return_type> {
                    if let Some(#oneof_type_path::#variant(field)) = &self.#oneof_field {
                        Some(#field_as)
                    } else {
                        None
                    }
                }
            });
        }

        if accessor_types.contains(AccessorTypes::MUT_OPT) {
            accessors.extend(quote! {
                #( #[doc = #name_opt_mut_comments] )*
                pub fn #name_opt_mut(&mut self) -> Option<&mut #field_type_path> {
                    if let Some(#oneof_type_path::#variant(field)) = &mut self.#oneof_field {
                        Some(field as _)
                    } else {
                        None
                    }
                }
            });
        }

        if accessor_types.contains(AccessorTypes::MUT) {
            let (field_access, default_value) = if is_boxed_in_accessor {
                (
                    quote! { field as _ },
                    quote! { ::prost::alloc::boxed::Box::default() },
                )
            } else {
                (quote! { field }, quote! { #field_type_path::default() })
            };

            accessors.extend(quote! {
                #( #[doc = #name_mut_comments] )*
                pub fn #name_mut(&mut self) -> &mut #field_type_path {
                    if let Some(#oneof_type_path::#variant(field)) = &mut self.#oneof_field {
                        #field_access
                    } else {
                        self.#oneof_field = Some(#oneof_type_path::#variant(#default_value));
                        if let Some(#oneof_type_path::#variant(field)) = &mut self.#oneof_field {
                            #field_access
                        } else {
                            unreachable!()
                        }
                    }
                }
            });
        }

        if accessor_types.contains(AccessorTypes::SET) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #set_name #set_param_type {
                    self.#oneof_field = Some(#oneof_type_path::#variant(#setter_assignment_value));
                }
            });
        }

        if accessor_types.contains(AccessorTypes::WITH) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #with_name #with_param_type -> Self {
                    self.#oneof_field = Some(#oneof_type_path::#variant(#setter_assignment_value));
                    self
                }
            });
        }

        accessors
    } else if is_optional(descriptor) {
        let mut accessors = TokenStream::new();

        // only include "bare getter" for message types
        if accessor_types.contains(AccessorTypes::GETTER)
            && is_message(descriptor)
            && !is_well_known_type(descriptor)
        {
            accessors.extend(quote! {
                #( #[doc = #name_comments] )*
                pub fn #name(&self) -> #ref_return_type {
                    self.#name
                        .as_ref()
                        .map(|field| field as _)
                        .unwrap_or_else(|| #default_instance)
                }
            });
        }

        // Only include mut getters for non bytes/enum types
        if !matches!(descriptor.r#type(), Type::Bytes | Type::Enum) {
            if accessor_types.contains(AccessorTypes::MUT_OPT) {
                accessors.extend(quote! {
                    #( #[doc = #name_opt_mut_comments] )*
                    pub fn #name_opt_mut(&mut self) -> Option<&mut #field_type_path> {
                        self.#name
                            .as_mut()
                            .map(|field| field as _)
                    }
                });
            }

            if accessor_types.contains(AccessorTypes::MUT) {
                accessors.extend(quote! {
                    #( #[doc = #name_mut_comments] )*
                    pub fn #name_mut(&mut self) -> &mut #field_type_path {
                        self.#name
                            .get_or_insert_default()
                    }
                });
            }
        }

        // only include _opt and set for non enums (as this already exists for enums
        // from prost)
        if !matches!(descriptor.r#type(), Type::Enum)
            && accessor_types.contains(AccessorTypes::GETTER_OPT)
        {
            accessors.extend(quote! {
                #( #[doc = #name_opt_comments] )*
                pub fn #name_opt(&self) -> Option<#ref_return_type> {
                    self.#name
                        .as_ref()
                        .map(|field| #field_as)
                }
            });
        }

        if !matches!(descriptor.r#type(), Type::Enum) && accessor_types.contains(AccessorTypes::SET)
        {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #set_name #set_param_type {
                    self.#name = Some(#setter_assignment_value);
                }
            });
        }

        if accessor_types.contains(AccessorTypes::WITH) {
            // For optional enum fields, prost stores as Option<i32>.
            // Take the enum type and convert via .into().
            if is_enum(descriptor) {
                accessors.extend(quote! {
                    #( #[doc = #set_name_comments] )*
                    pub fn #with_name(mut self, field: #field_type_path) -> Self {
                        self.#name = Some(field.into());
                        self
                    }
                });
            } else {
                accessors.extend(quote! {
                    #( #[doc = #set_name_comments] )*
                    pub fn #with_name #with_param_type -> Self {
                        self.#name = Some(#setter_assignment_value);
                        self
                    }
                });
            }
        }

        accessors
    } else {
        // maybe required or implicit optional

        let mut accessors = TokenStream::new();

        // For enum fields, prost stores the value as i32 but
        // field_type_path resolves to the enum type. We need special
        // handling: take the enum type as parameter and convert via
        // .into() for assignment.
        if is_enum(descriptor) {
            if accessor_types.contains(AccessorTypes::SET) {
                accessors.extend(quote! {
                    #( #[doc = #set_name_comments] )*
                    pub fn #set_name(&mut self, field: #field_type_path) {
                        self.#name = field.into();
                    }
                });
            }

            if accessor_types.contains(AccessorTypes::WITH) {
                accessors.extend(quote! {
                    #( #[doc = #set_name_comments] )*
                    pub fn #with_name(mut self, field: #field_type_path) -> Self {
                        self.#name = field.into();
                        self
                    }
                });
            }

            return accessors;
        }

        if descriptor.r#type() != Type::Bytes && accessor_types.contains(AccessorTypes::MUT) {
            accessors.extend(quote! {
            #( #[doc = #name_mut_comments] )*
                pub fn #name_mut(&mut self) -> &mut #field_type_path {
                    &mut self.#name
                }
            });
        }

        if accessor_types.contains(AccessorTypes::SET) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #set_name #set_param_type {
                    self.#name = #setter_assignment_value;
                }
            });
        }

        if accessor_types.contains(AccessorTypes::WITH) {
            accessors.extend(quote! {
                #( #[doc = #set_name_comments] )*
                pub fn #with_name #with_param_type -> Self {
                    self.#name = #setter_assignment_value;
                    self
                }
            });
        }

        accessors
    }
}

fn generate_const_default_functions(
    message: &MessageDescriptor,
    message_rust_path: &TokenStream,
) -> TokenStream {
    let mut const_default_fields = TokenStream::new();

    for field in struct_fields(message) {
        let descriptor = field.field_descriptor_proto();
        let field_name = quote::format_ident!("{}", sanitize_identifier(field.name()));

        let field_default = if field.is_map() {
            quote! {
                #field_name: std::collections::BTreeMap::new(),
            }
        } else if is_repeated(descriptor) {
            quote! {
                #field_name: Vec::new(),
            }
        } else if is_optional(descriptor) {
            quote! {
                #field_name: None,
            }
        } else {
            // maybe required or implicit optional
            match descriptor.r#type() {
                Type::Double
                | Type::Float
                | Type::Int64
                | Type::Uint64
                | Type::Int32
                | Type::Fixed64
                | Type::Fixed32
                | Type::Uint32
                | Type::Enum
                | Type::Sfixed32
                | Type::Sfixed64
                | Type::Sint32
                | Type::Sint64 => {
                    quote! {
                        #field_name: 0,
                    }
                }

                Type::Bool => {
                    quote! {
                        #field_name: false,
                    }
                }
                Type::String => {
                    quote! {
                        #field_name: String::new(),
                    }
                }
                Type::Bytes => {
                    quote! {
                        #field_name: ::prost::bytes::Bytes::new(),
                    }
                }
                Type::Group | Type::Message => {
                    panic!("messages are optional");
                }
            }
        };

        const_default_fields.extend(field_default);
    }

    for oneof in real_oneofs(message) {
        let oneof_field = quote::format_ident!("{}", sanitize_identifier(oneof.name()));
        const_default_fields.extend(quote! {
            #oneof_field: None,
        });
    }

    quote! {
        pub const fn const_default() -> Self {
            Self {
                #const_default_fields
            }
        }

        #[doc(hidden)]
        pub fn default_instance() -> &'static Self {
            static DEFAULT: #message_rust_path = #message_rust_path::const_default();
            &DEFAULT
        }
    }
}

fn type_default(field: &FieldDescriptorProto, context: &Context, package: &str) -> String {
    match field.r#type() {
        Type::Float => String::from("0.0f32"),
        Type::Double => String::from("0.0f64"),
        Type::Uint32 | Type::Fixed32 => String::from("0u32"),
        Type::Uint64 | Type::Fixed64 => String::from("0u64"),
        Type::Int32 | Type::Sfixed32 | Type::Sint32 | Type::Enum => String::from("0i32"),
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => String::from("0i64"),
        Type::Bool => String::from("false"),
        Type::String => String::from("\"\""),
        Type::Bytes => String::from("&[]"),
        Type::Group | Type::Message => {
            let ty = context.accessor_type_path(package, field.type_name());
            format!("{ty}::default_instance() as _")
        }
    }
}

fn ref_return_type(field: &FieldDescriptorProto, context: &Context, package: &str) -> String {
    match field.r#type() {
        Type::Float => String::from("f32"),
        Type::Double => String::from("f64"),
        Type::Uint32 | Type::Fixed32 => String::from("u32"),
        Type::Uint64 | Type::Fixed64 => String::from("u64"),
        Type::Int32 | Type::Sfixed32 | Type::Sint32 | Type::Enum => String::from("i32"),
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => String::from("i64"),
        Type::Bool => String::from("bool"),
        Type::String => String::from("&str"),
        Type::Bytes => String::from("&[u8]"),
        Type::Group | Type::Message => {
            let ty = context.accessor_type_path(package, field.type_name());
            format!("&{ty}")
        }
    }
}

fn is_ref_return(field: &FieldDescriptorProto) -> bool {
    match field.r#type() {
        Type::Float => false,
        Type::Double => false,
        Type::Uint32 | Type::Fixed32 => false,
        Type::Uint64 | Type::Fixed64 => false,
        Type::Int32 | Type::Sfixed32 | Type::Sint32 | Type::Enum => false,
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => false,
        Type::Bool => false,
        Type::String => true,
        Type::Bytes => true,
        Type::Group | Type::Message => true,
    }
}

fn use_into_for_setter(field: &FieldDescriptorProto) -> bool {
    match field.r#type() {
        Type::Float => false,
        Type::Double => false,
        Type::Uint32 | Type::Fixed32 => false,
        Type::Uint64 | Type::Fixed64 => false,
        Type::Int32 | Type::Sfixed32 | Type::Sint32 => false,
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => false,
        Type::Bool => false,
        Type::Enum => true,
        Type::String => true,
        Type::Bytes => true,
        Type::Group | Type::Message => true,
    }
}

/// The type an accessor takes and returns for the field, as a path relative to
/// `package`.
///
/// Enums resolve to the generated enum type, not to the `i32` prost stores them
/// in: the accessors convert with `.into()` at the assignment. Contrast
/// [`map_entry_type_path`], which has to name the storage type.
fn field_type_path(field: &FieldDescriptorProto, context: &Context, package: &str) -> String {
    match field.r#type() {
        Type::Float => String::from("f32"),
        Type::Double => String::from("f64"),
        Type::Uint32 | Type::Fixed32 => String::from("u32"),
        Type::Uint64 | Type::Fixed64 => String::from("u64"),
        Type::Int32 | Type::Sfixed32 | Type::Sint32 => String::from("i32"),
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => String::from("i64"),
        Type::Bool => String::from("bool"),
        Type::String => String::from("String"),
        Type::Bytes => String::from("::prost::bytes::Bytes"),
        Type::Group | Type::Message | Type::Enum => {
            context.accessor_type_path(package, field.type_name())
        }
    }
}

/// The Rust type prost stores a map key or value in, as a path relative to
/// `package`. Enum values are stored as `i32`.
fn map_entry_type_path(field: &FieldDescriptorProto, context: &Context, package: &str) -> String {
    match field.r#type() {
        Type::Float => String::from("f32"),
        Type::Double => String::from("f64"),
        Type::Uint32 | Type::Fixed32 => String::from("u32"),
        Type::Uint64 | Type::Fixed64 => String::from("u64"),
        Type::Int32 | Type::Sfixed32 | Type::Sint32 | Type::Enum => String::from("i32"),
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => String::from("i64"),
        Type::Bool => String::from("bool"),
        Type::String => String::from("String"),
        Type::Bytes => String::from("::prost::bytes::Bytes"),
        Type::Group | Type::Message => context.accessor_type_path(package, field.type_name()),
    }
}
