// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{StructTag, TypeParseError};

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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    /// Checks if this type tag is a vector.
    pub fn is_vector(&self) -> bool {
        matches!(self, Self::Vector(_))
    }

    /// Returns a reference to the inner type tag if this type tag is a vector,
    /// or `None` otherwise.
    pub fn as_opt_vector_type_tag(&self) -> Option<&TypeTag> {
        if let Self::Vector(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// Returns a reference to the inner type tag if this type tag is a vector,
    /// or panics otherwise.
    pub fn as_vector_type_tag(&self) -> &TypeTag {
        self.as_opt_vector_type_tag().expect("not a Vector")
    }

    /// Converts this type tag into the inner type tag of a vector, if it is
    /// one, or returns `None` otherwise.
    pub fn into_opt_vector_type_tag(self) -> Option<TypeTag> {
        if let Self::Vector(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    /// Converts this type tag into the inner type tag of a vector, if it is
    /// one, or panics otherwise.
    pub fn into_vector_type_tag(self) -> TypeTag {
        self.into_opt_vector_type_tag().expect("not a Vector")
    }

    /// Checks if this type tag is a struct.
    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct(_))
    }

    /// Returns a reference to the struct tag if this type tag is a struct, or
    /// `None` otherwise.
    pub fn as_opt_struct_tag(&self) -> Option<&StructTag> {
        if let Self::Struct(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// Returns a reference to the struct tag if this type tag is a struct, or
    /// panics otherwise.
    pub fn as_struct_tag(&self) -> &StructTag {
        self.as_opt_struct_tag().expect("not a Struct")
    }

    /// Converts this type tag into a struct tag, if it is one, or returns
    /// `None` otherwise.
    pub fn into_opt_struct_tag(self) -> Option<StructTag> {
        if let Self::Struct(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    /// Converts this type tag into a struct tag, if it is one, or panics
    /// otherwise.
    pub fn into_struct_tag(self) -> StructTag {
        self.into_opt_struct_tag().expect("not a Struct")
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

impl From<TypeTag> for String {
    fn from(value: TypeTag) -> Self {
        value.to_string()
    }
}

impl From<&TypeTag> for String {
    fn from(value: &TypeTag) -> Self {
        value.to_string()
    }
}

impl std::str::FromStr for TypeTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use winnow::Parser;
        crate::move_core::parse::parse_type_tag
            .parse(s)
            .map_err(|e| e.into_inner())
    }
}

impl From<StructTag> for TypeTag {
    fn from(value: StructTag) -> Self {
        Self::Struct(Box::new(value))
    }
}
