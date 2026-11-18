// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _field_impls {
    #![allow(clippy::wrong_self_convention)]
    use super::*;
    use crate::field::MessageFields;
    use crate::field::MessageField;
    impl Object {
        pub const REFERENCE_FIELD: &'static MessageField = &MessageField {
            name: "reference",
            json_name: "reference",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::types::ObjectReference::FIELDS),
        };
        pub const BCS_FIELD: &'static MessageField = &MessageField {
            name: "bcs",
            json_name: "bcs",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::bcs::BcsData::FIELDS),
        };
        pub const JSON_FIELD: &'static MessageField = &MessageField {
            name: "json",
            json_name: "json",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const DISPLAY_FIELD: &'static MessageField = &MessageField {
            name: "display",
            json_name: "display",
            number: 4i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(Display::FIELDS),
        };
    }
    impl crate::field::sealed::Sealed for Object {}
    impl MessageFields for Object {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::REFERENCE_FIELD,
            Self::BCS_FIELD,
            Self::JSON_FIELD,
            Self::DISPLAY_FIELD,
        ];
    }
    impl Object {
        pub fn path_builder() -> ObjectFieldPathBuilder {
            ObjectFieldPathBuilder::new()
        }
    }
    pub struct ObjectFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn reference(mut self) -> crate::v1::types::ObjectReferenceFieldPathBuilder {
            self.path.push(Object::REFERENCE_FIELD.name);
            crate::v1::types::ObjectReferenceFieldPathBuilder::new_with_base(self.path)
        }
        pub fn bcs(mut self) -> crate::v1::bcs::BcsDataFieldPathBuilder {
            self.path.push(Object::BCS_FIELD.name);
            crate::v1::bcs::BcsDataFieldPathBuilder::new_with_base(self.path)
        }
        pub fn json(mut self) -> String {
            self.path.push(Object::JSON_FIELD.name);
            self.finish()
        }
        pub fn display(mut self) -> DisplayFieldPathBuilder {
            self.path.push(Object::DISPLAY_FIELD.name);
            DisplayFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl Display {
        pub const OUTPUT_FIELD: &'static MessageField = &MessageField {
            name: "output",
            json_name: "output",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const ERRORS_FIELD: &'static MessageField = &MessageField {
            name: "errors",
            json_name: "errors",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl crate::field::sealed::Sealed for Display {}
    impl MessageFields for Display {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::OUTPUT_FIELD,
            Self::ERRORS_FIELD,
        ];
    }
    impl Display {
        pub fn path_builder() -> DisplayFieldPathBuilder {
            DisplayFieldPathBuilder::new()
        }
    }
    pub struct DisplayFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl DisplayFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn output(mut self) -> String {
            self.path.push(Display::OUTPUT_FIELD.name);
            self.finish()
        }
        pub fn errors(mut self) -> String {
            self.path.push(Display::ERRORS_FIELD.name);
            self.finish()
        }
    }
    impl Objects {
        pub const OBJECTS_FIELD: &'static MessageField = &MessageField {
            name: "objects",
            json_name: "objects",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(Object::FIELDS),
        };
    }
    impl crate::field::sealed::Sealed for Objects {}
    impl MessageFields for Objects {
        const FIELDS: &'static [&'static MessageField] = &[Self::OBJECTS_FIELD];
    }
    impl Objects {
        pub fn path_builder() -> ObjectsFieldPathBuilder {
            ObjectsFieldPathBuilder::new()
        }
    }
    pub struct ObjectsFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ObjectsFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn objects(mut self) -> ObjectFieldPathBuilder {
            self.path.push(Objects::OBJECTS_FIELD.name);
            ObjectFieldPathBuilder::new_with_base(self.path)
        }
    }
}
pub use _field_impls::*;
