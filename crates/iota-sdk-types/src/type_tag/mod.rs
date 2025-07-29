// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod parse;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization;

use super::Address;

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
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Clone, Hash)]
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
    pub fn vector_type_opt(&self) -> Option<&TypeTag> {
        if let Self::Vector(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn vector_type(&self) -> &TypeTag {
        let Self::Vector(inner) = self else {
            panic!("not a Vector");
        };
        inner
    }

    pub fn struct_tag_opt(&self) -> Option<&StructTag> {
        if let Self::Struct(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn struct_tag(&self) -> &StructTag {
        let Self::Struct(inner) = self else {
            panic!("not a Struct");
        };
        inner
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

    crate::def_is!(U8, U16, U32, U64, U128, U256, Bool, Address, Signer);

    pub fn is_vector(&self) -> bool {
        matches!(self, Self::Vector(_))
    }

    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct(_))
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
            TypeTag::Vector(t) => {
                write!(f, "vector<{t}>")
            }
            TypeTag::Struct(s) => s.fmt(f),
        }
    }
}

impl std::str::FromStr for TypeTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_type_tag(s).map_err(|_| TypeParseError { source: s.into() })
    }
}

impl From<StructTag> for TypeTag {
    fn from(value: StructTag) -> Self {
        Self::Struct(Box::new(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object), uniffi::export(Display))]
pub struct TypeParseError {
    source: String,
}

impl std::fmt::Display for TypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for TypeParseError {}

/// A move identifier
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// identifier = %x01-80    ; length of the identifier
///              (ALPHA *127(ALPHA / DIGIT / UNDERSCORE)) /
///              (UNDERSCORE 1*127(ALPHA / DIGIT / UNDERSCORE))
///
/// UNDERSCORE = %x95
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Identifier(
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Strategy::prop_map(
            "[a-zA-Z][a-zA-Z0-9_]{0,127}",
            Into::into
        ))
    )]
    Box<str>,
);

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Identifier, String, {
    lower: |id| id.0.into(),
    try_lift: |s| Ok(Identifier::new(s)?),
});

impl Identifier {
    pub fn new(identifier: impl AsRef<str>) -> Result<Self, TypeParseError> {
        parse::parse_identifier(identifier.as_ref())
            .map(|ident| Self(ident.into()))
            .map_err(|_| TypeParseError {
                source: identifier.as_ref().into(),
            })
    }

    pub fn into_inner(self) -> Box<str> {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Identifier {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_identifier(s)
            .map(|ident| Self(ident.into()))
            .map_err(|_| TypeParseError { source: s.into() })
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref() == other
    }
}

/// Type information for a move struct
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// struct-tag = address            ; address of the package
///              identifier         ; name of the module
///              identifier         ; name of the type
///              (vector type-tag)  ; type parameters
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct StructTag {
    pub address: Address,
    pub module: Identifier,
    pub name: Identifier,
    #[cfg_attr(feature = "proptest", strategy(proptest::strategy::Just(Vec::new())))]
    pub type_params: Vec<TypeTag>,
}

impl StructTag {
    pub fn coin(type_tag: TypeTag) -> Self {
        Self {
            address: Address::TWO,
            module: Identifier::new("coin").unwrap(),
            name: Identifier::new("Coin").unwrap(),
            type_params: vec![type_tag],
        }
    }

    /// Checks if this is a Coin type
    pub fn coin_type_opt(&self) -> Option<&crate::TypeTag> {
        let Self {
            address,
            module,
            name,
            type_params,
        } = self;

        if address == &Address::TWO && module == "coin" && name == "Coin" && type_params.len() == 1
        {
            type_params.first()
        } else {
            None
        }
    }

    /// Checks if this is a Coin type
    pub fn coin_type(&self) -> &TypeTag {
        self.coin_type_opt().expect("not a coin")
    }

    pub fn gas_coin() -> Self {
        let iota = Self {
            address: Address::TWO,
            module: Identifier::new("iota").unwrap(),
            name: Identifier::new("IOTA").unwrap(),
            type_params: vec![],
        };

        Self::coin(TypeTag::Struct(Box::new(iota)))
    }

    pub fn staked_iota() -> Self {
        Self {
            address: Address::THREE,
            module: Identifier::new("staking_pool").unwrap(),
            name: Identifier::new("StakedIota").unwrap(),
            type_params: vec![],
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

impl std::fmt::Display for StructTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}::{}", self.address, self.module, self.name)?;

        if let Some(first_type) = self.type_params.first() {
            write!(f, "<")?;
            write!(f, "{first_type}")?;
            for ty in self.type_params.iter().skip(1) {
                write!(f, ", {ty}")?;
            }
            write!(f, ">")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for StructTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_struct_tag(s).map_err(|_| TypeParseError { source: s.into() })
    }
}
