// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{StructTag, TypeParseError};

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
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum TypeTag {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Bool,
    Address,
    Signer,
    #[cfg_attr(feature = "proptest", weight(0))]
    Vector(Box<TypeTag>),
    Struct(Box<StructTag>),
}

impl TypeTag {
    crate::def_is!(U8, U16, U32, U64, U128, U256, Bool, Address, Signer);

    pub fn is_vector(&self) -> bool {
        matches!(self, Self::Vector(_))
    }

    pub fn as_vector_type_tag_opt(&self) -> Option<&TypeTag> {
        if let Self::Vector(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn as_vector_type_tag(&self) -> &TypeTag {
        self.as_vector_type_tag_opt().expect("not a Vector")
    }

    pub fn into_vector_type_tag_opt(self) -> Option<TypeTag> {
        if let Self::Vector(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    pub fn into_vector_type_tag(self) -> TypeTag {
        self.into_vector_type_tag_opt().expect("not a Vector")
    }

    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct(_))
    }

    pub fn as_struct_tag_opt(&self) -> Option<&StructTag> {
        if let Self::Struct(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn as_struct_tag(&self) -> &StructTag {
        self.as_struct_tag_opt().expect("not a Struct")
    }

    pub fn into_struct_tag_opt(self) -> Option<StructTag> {
        if let Self::Struct(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    pub fn into_struct_tag(self) -> StructTag {
        self.into_struct_tag_opt().expect("not a Struct")
    }

    pub fn u8() -> Self {
        Self::U8
    }

    pub fn u16() -> Self {
        Self::U16
    }

    pub fn u32() -> Self {
        Self::U32
    }

    pub fn u64() -> Self {
        Self::U64
    }

    pub fn u128() -> Self {
        Self::U128
    }

    pub fn u256() -> Self {
        Self::U256
    }

    pub fn bool() -> Self {
        Self::Bool
    }

    pub fn address() -> Self {
        Self::Address
    }

    pub fn signer() -> Self {
        Self::Signer
    }

    /// Returns the string representation of this type tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        match self {
            TypeTag::U8 => "u8".to_owned(),
            TypeTag::U16 => "u16".to_owned(),
            TypeTag::U32 => "u32".to_owned(),
            TypeTag::U64 => "u64".to_owned(),
            TypeTag::U128 => "u128".to_owned(),
            TypeTag::U256 => "u256".to_owned(),
            TypeTag::Bool => "bool".to_owned(),
            TypeTag::Address => "address".to_owned(),
            TypeTag::Signer => "signer".to_owned(),
            TypeTag::Vector(t) => {
                format!("vector<{}>", t.to_canonical_string(with_prefix))
            }
            TypeTag::Struct(s) => s.to_canonical_string(with_prefix),
        }
    }
}

impl std::fmt::Display for TypeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeTag::U8 => write!(f, "u8"),
            TypeTag::U16 => write!(f, "u16"),
            TypeTag::U32 => write!(f, "u32"),
            TypeTag::U64 => write!(f, "u64"),
            TypeTag::U128 => write!(f, "u128"),
            TypeTag::U256 => write!(f, "u256"),
            TypeTag::Bool => write!(f, "bool"),
            TypeTag::Address => write!(f, "address"),
            TypeTag::Signer => write!(f, "signer"),
            TypeTag::Vector(t) => write!(f, "vector<{t}>"),
            TypeTag::Struct(s) => write!(f, "{s}"),
        }
    }
}

impl std::str::FromStr for TypeTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::move_core::parse::parse_type_tag(s).map_err(|_| TypeParseError { source: s.into() })
    }
}

impl From<StructTag> for TypeTag {
    fn from(value: StructTag) -> Self {
        Self::Struct(Box::new(value))
    }
}
