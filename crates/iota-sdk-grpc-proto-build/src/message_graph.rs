// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use itertools::{Either, Itertools};
use prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, OneofDescriptorProto,
    field_descriptor_proto::{Label, Type},
};

/// The messages of every compiled file, keyed by fully qualified name, and the
/// set of packages they belong to. Both carry a leading dot.
pub struct DescriptorGraph {
    pub packages: BTreeSet<String>,
    pub messages: BTreeMap<String, Message>,
}

impl DescriptorGraph {
    pub(crate) fn new<'a>(files: impl Iterator<Item = &'a FileDescriptorProto>) -> DescriptorGraph {
        let mut graph = DescriptorGraph {
            messages: BTreeMap::new(),
            packages: BTreeSet::new(),
        };

        for file in files {
            let package = format!(
                "{}{}",
                if file.package.is_some() { "." } else { "" },
                file.package.as_deref().unwrap_or("")
            );

            graph.packages.insert(package);
            FileParser::parse(&mut graph, file.clone());
        }

        graph
    }
}

struct FileParser<'a> {
    graph: &'a mut DescriptorGraph,
    package: String,
    type_path: Vec<String>,
    path: Vec<i32>,
}

impl<'a> FileParser<'a> {
    fn parse(graph: &'a mut DescriptorGraph, file: FileDescriptorProto) {
        let package = format!(
            "{}{}",
            if file.package.is_some() { "." } else { "" },
            file.package.as_deref().unwrap_or("")
        );

        let mut parser = Self {
            graph,
            package,
            type_path: Vec::new(),
            path: Vec::new(),
        };

        // Messages
        parser.path.push(4);
        for (idx, message) in file.message_type.into_iter().enumerate() {
            parser.path.push(idx as i32);
            parser.process_message(message);
            parser.path.pop();
        }
        parser.path.pop();
    }

    fn process_message(&mut self, descriptor: DescriptorProto) {
        let type_name = self.fq_name(descriptor.name());

        // Split the nested message types into a vector of normal nested message types,
        // and a map of the map field entry types. The path index of the nested
        // message types is preserved so that comments can be retrieved.
        type NestedTypes = Vec<(DescriptorProto, usize)>;
        type MapTypes = BTreeMap<String, (FieldDescriptorProto, FieldDescriptorProto)>;
        let (nested_types, map_types): (NestedTypes, MapTypes) = descriptor
            .nested_type
            .iter()
            .enumerate()
            .partition_map(|(idx, nested_type)| {
                if nested_type
                    .options
                    .as_ref()
                    .and_then(|options| options.map_entry)
                    .unwrap_or(false)
                {
                    let key = nested_type.field[0].clone();
                    let value = nested_type.field[1].clone();
                    assert_eq!("key", key.name());
                    assert_eq!("value", value.name());

                    let name = format!("{type_name}.{}", nested_type.name());
                    Either::Right((name, (key, value)))
                } else {
                    Either::Left((nested_type.clone(), idx))
                }
            });

        // Split the fields into a vector of the normal fields, and oneof fields.
        // Path indexes are preserved so that comments can be retrieved.
        let mut fields: Vec<Field> = Vec::new();
        let mut oneof_map: BTreeMap<i32, Vec<Field>> = Default::default();
        self.path.push(2);
        for (idx, proto) in descriptor.field.iter().enumerate() {
            self.path.push(idx as i32);
            let map = map_types.get(proto.type_name()).cloned();

            if let Some(oneof_index) = proto.oneof_index {
                if !proto.proto3_optional() {
                    // oneof
                    oneof_map.entry(oneof_index).or_default().push(Field {
                        inner: proto.clone(),
                        map,
                    });
                } else {
                    // normal field
                    fields.push(Field {
                        inner: proto.clone(),
                        map,
                    });
                }
            } else {
                // normal field
                fields.push(Field {
                    inner: proto.clone(),
                    map,
                });
            }
            self.path.pop();
        }
        self.path.pop();

        self.path.push(8);
        let oneof_fields: Vec<OneofField> = descriptor
            .oneof_decl
            .iter()
            .enumerate()
            .filter_map(|(idx, proto)| {
                let idx = idx as i32;
                self.path.push(idx);
                let oneof = oneof_map.remove(&idx).map(|fields| OneofField {
                    descriptor: proto.clone(),
                    fields,
                });
                self.path.pop();
                oneof
            })
            .collect();
        self.path.pop();

        // Handle Nested Messages
        self.type_path.push(descriptor.name().to_owned());

        self.path.push(3);
        for (nested_type, idx) in nested_types {
            self.path.push(idx as i32);
            self.process_message(nested_type);
            self.path.pop();
        }
        self.path.pop();

        self.type_path.pop();

        let message = Message {
            package: self.package.clone(),
            type_name,
            fields,
            oneof_fields,
        };
        self.graph
            .messages
            .insert(message.type_name.clone(), message);
    }

    /// Returns the fully-qualified name, starting with a dot
    fn fq_name(&self, message_name: &str) -> String {
        format!(
            "{}{}{}{}.{}",
            if self.package.is_empty() { "" } else { "." },
            self.package.trim_matches('.'),
            if self.type_path.is_empty() { "" } else { "." },
            self.type_path.join("."),
            message_name,
        )
    }
}

#[derive(Debug)]
pub struct Message {
    pub type_name: String,
    pub package: String,
    pub fields: Vec<Field>,
    pub oneof_fields: Vec<OneofField>,
}

#[derive(Debug)]
pub struct Field {
    pub inner: FieldDescriptorProto,
    pub map: Option<(FieldDescriptorProto, FieldDescriptorProto)>,
}

impl Field {
    pub fn rust_struct_field_name(&self) -> String {
        crate::ident::sanitize_identifier(self.inner.name())
    }

    pub fn is_optional(&self) -> bool {
        if self.inner.proto3_optional.unwrap_or(false) {
            return true;
        }

        if self.inner.label() != Label::Optional {
            return false;
        }

        matches!(self.inner.r#type(), Type::Message)
    }

    pub fn is_map(&self) -> bool {
        self.map.is_some()
    }

    pub fn is_repeated(&self) -> bool {
        self.inner.label() == Label::Repeated
    }

    pub fn resolve_rust_type_path(
        &self,
        context: &crate::context::Context,
        package: &str,
    ) -> String {
        match self.inner.r#type() {
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
                context.resolve_ident(package, self.inner.type_name())
            }
        }
    }

    pub fn is_message(&self) -> bool {
        matches!(self.inner.r#type(), Type::Message)
    }

    pub fn is_well_known_type(&self) -> bool {
        self.inner.type_name().starts_with(".google.protobuf")
    }

    pub fn is_enum(&self) -> bool {
        matches!(self.inner.r#type(), Type::Enum)
    }
}

#[derive(Debug)]
pub struct OneofField {
    pub descriptor: OneofDescriptorProto,
    pub fields: Vec<Field>,
}

impl OneofField {
    pub fn rust_struct_field_name(&self) -> String {
        crate::ident::sanitize_identifier(self.descriptor.name())
    }
}
