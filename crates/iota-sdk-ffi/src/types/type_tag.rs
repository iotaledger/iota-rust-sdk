// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::struct_tag::StructTag;

/// Type of a move value
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-tag = type-tag-u8 \
///            type-tag-u16 \
///            type-tag-u32 \
///            type-tag-u64 \
///            type-tag-u128 \
///            type-tag-u256 \
///            type-tag-bool \
///            type-tag-address \
///            type-tag-signer \
///            type-tag-vector \
///            type-tag-struct
///
/// type-tag-u8 = %x01
/// type-tag-u16 = %x08
/// type-tag-u32 = %x09
/// type-tag-u64 = %x02
/// type-tag-u128 = %x03
/// type-tag-u256 = %x0a
/// type-tag-bool = %x00
/// type-tag-address = %x04
/// type-tag-signer = %x05
/// type-tag-vector = %x06 type-tag
/// type-tag-struct = %x07 struct-tag
/// ```
#[derive(derive_more::Display, derive_more::From, uniffi::Object)]
#[uniffi::export(Display)]
pub struct TypeTag(pub iota_sdk::types::TypeTag);

#[uniffi::export]
impl TypeTag {
    #[inline]
    pub fn is_u8(&self) -> bool {
        self.0.is_u8()
    }

    #[inline]
    pub fn is_u16(&self) -> bool {
        self.0.is_u16()
    }

    #[inline]
    pub fn is_u32(&self) -> bool {
        self.0.is_u32()
    }

    #[inline]
    pub fn is_u64(&self) -> bool {
        self.0.is_u64()
    }

    #[inline]
    pub fn is_u128(&self) -> bool {
        self.0.is_u128()
    }

    #[inline]
    pub fn is_u256(&self) -> bool {
        self.0.is_u256()
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        self.0.is_bool()
    }

    #[inline]
    pub fn is_address(&self) -> bool {
        self.0.is_address()
    }

    #[inline]
    pub fn is_signer(&self) -> bool {
        self.0.is_signer()
    }

    #[inline]
    pub fn is_vector(&self) -> bool {
        self.0.is_vector()
    }

    #[inline]
    pub fn as_vector_type_tag_opt(&self) -> Option<Arc<TypeTag>> {
        self.0
            .as_vector_type_tag_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    #[inline]
    pub fn as_vector_type_tag(&self) -> TypeTag {
        self.0.as_vector_type_tag().clone().into()
    }

    #[inline]
    pub fn is_struct(&self) -> bool {
        self.0.is_struct()
    }

    #[inline]
    pub fn as_struct_tag_opt(&self) -> Option<Arc<StructTag>> {
        self.0
            .as_struct_tag_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    #[inline]
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
