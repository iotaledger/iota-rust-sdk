// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::move_core::struct_tag::StructTag;

/// Type of a move value
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-tag = %d00            ; Bool
///          / %d01            ; U8
///          / %d02            ; U64
///          / %d03            ; U128
///          / %d04            ; Address
///          / %d05            ; Signer
///          / %d06 type-tag   ; Vector
///          / %d07 struct-tag ; Struct
///          / %d08            ; U16
///          / %d09            ; U32
///          / %d10            ; U256
/// ```
#[derive(
    Debug,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct TypeTag(pub iota_sdk::types::TypeTag);

#[uniffi::export]
impl TypeTag {
    #[inline]
    /// Checks if this type tag is a u8.
    pub fn is_u8(&self) -> bool {
        self.0.is_u8()
    }

    #[inline]
    /// Checks if this type tag is a u16.
    pub fn is_u16(&self) -> bool {
        self.0.is_u16()
    }

    #[inline]
    /// Checks if this type tag is a u32.
    pub fn is_u32(&self) -> bool {
        self.0.is_u32()
    }

    #[inline]
    /// Checks if this type tag is a u64.
    pub fn is_u64(&self) -> bool {
        self.0.is_u64()
    }

    #[inline]
    /// Checks if this type tag is a u128.
    pub fn is_u128(&self) -> bool {
        self.0.is_u128()
    }

    #[inline]
    /// Checks if this type tag is a u256.
    pub fn is_u256(&self) -> bool {
        self.0.is_u256()
    }

    #[inline]
    /// Checks if this type tag is a boolean.
    pub fn is_bool(&self) -> bool {
        self.0.is_bool()
    }

    #[inline]
    /// Checks if this type tag is an address.
    pub fn is_address(&self) -> bool {
        self.0.is_address()
    }

    #[inline]
    /// Checks if this type tag is a signer.
    pub fn is_signer(&self) -> bool {
        self.0.is_signer()
    }

    #[inline]
    /// Checks if this type tag is a vector.
    pub fn is_vector(&self) -> bool {
        self.0.is_vector()
    }

    #[inline]
    /// Converts this type tag into the inner type tag of a vector, if it is
    /// one, or returns `None` otherwise.
    pub fn as_opt_vector_type_tag(&self) -> Option<Arc<TypeTag>> {
        self.0
            .as_opt_vector_type_tag()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    #[inline]
    /// Converts this type tag into the inner type tag of a vector, if it is
    /// one, or panics otherwise.
    pub fn as_vector_type_tag(&self) -> TypeTag {
        self.0.as_vector_type_tag().clone().into()
    }

    #[inline]
    /// Checks if this type tag is a struct.
    pub fn is_struct(&self) -> bool {
        self.0.is_struct()
    }

    #[inline]
    /// Converts this type tag into a struct tag, if it is one, or returns
    /// `None` otherwise.
    pub fn as_opt_struct_tag(&self) -> Option<Arc<StructTag>> {
        self.0
            .as_opt_struct_tag()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    #[inline]
    /// Converts this type tag into a struct tag, if it is one, or panics
    /// otherwise.
    pub fn as_struct_tag(&self) -> StructTag {
        self.0.as_struct_tag().clone().into()
    }

    #[uniffi::constructor]
    pub fn new_u8() -> Self {
        Self(iota_sdk::types::TypeTag::U8)
    }

    #[uniffi::constructor]
    pub fn new_u16() -> Self {
        Self(iota_sdk::types::TypeTag::U16)
    }

    #[uniffi::constructor]
    pub fn new_u32() -> Self {
        Self(iota_sdk::types::TypeTag::U32)
    }

    #[uniffi::constructor]
    pub fn new_u64() -> Self {
        Self(iota_sdk::types::TypeTag::U64)
    }

    #[uniffi::constructor]
    pub fn new_u128() -> Self {
        Self(iota_sdk::types::TypeTag::U128)
    }

    #[uniffi::constructor]
    pub fn new_u256() -> Self {
        Self(iota_sdk::types::TypeTag::U256)
    }

    #[uniffi::constructor]
    pub fn new_bool() -> Self {
        Self(iota_sdk::types::TypeTag::Bool)
    }

    #[uniffi::constructor]
    pub fn new_address() -> Self {
        Self(iota_sdk::types::TypeTag::Address)
    }

    #[uniffi::constructor]
    pub fn new_signer() -> Self {
        Self(iota_sdk::types::TypeTag::Signer)
    }

    #[uniffi::constructor]
    pub fn new_vector(type_tag: &TypeTag) -> Self {
        Self(iota_sdk::types::TypeTag::Vector(Box::new(
            type_tag.0.clone(),
        )))
    }

    #[uniffi::constructor]
    pub fn new_struct(struct_tag: &StructTag) -> Self {
        Self(iota_sdk::types::TypeTag::Struct(Box::new(
            struct_tag.0.clone(),
        )))
    }

    /// Returns the string representation of this type tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }
}

crate::export_iota_types_objects_bcs_conversion!(TypeTag);
crate::export_iota_types_objects_json_conversion!(TypeTag);
