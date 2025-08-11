// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{address::Address, type_tag::TypeTag};

#[derive(Clone, Debug, derive_more::From, uniffi::Record)]
pub struct TypeParseError {
    source: String,
}

impl From<TypeParseError> for iota_types::TypeParseError {
    fn from(value: TypeParseError) -> Self {
        iota_types::TypeParseError {
            source: value.source,
        }
    }
}

impl From<iota_types::TypeParseError> for TypeParseError {
    fn from(value: iota_types::TypeParseError) -> Self {
        TypeParseError {
            source: value.source,
        }
    }
}

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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Identifier(iota_types::Identifier);

impl Identifier {
    #[uniffi::constructor]
    pub fn new(identifier: impl AsRef<str>) -> Result<Self, TypeParseError> {
        Ok(Self(iota_types::Identifier::new(identifier)?))
    }

    pub fn into_inner(self) -> Box<str> {
        self.0.into_inner()
    }

    pub fn as_str(&self) -> &str {
        &self.0.as_str()
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct StructTag(pub iota_types::StructTag);

#[uniffi::export]
impl StructTag {
    #[uniffi::constructor]
    pub fn new(
        address: &Address,
        module: &Identifier,
        name: &Identifier,
        type_params: Vec<Arc<TypeTag>>,
    ) -> Self {
        Self(iota_types::StructTag {
            address: address.0.clone(),
            module: module.0.clone(),
            name: name.0.clone(),
            type_params: type_params
                .iter()
                .map(|type_tag| type_tag.0.clone())
                .collect(),
        })
    }

    #[uniffi::constructor]
    pub fn coin(type_tag: &TypeTag) -> Self {
        Self(iota_types::StructTag::coin(type_tag.0.clone()))
    }

    /// Checks if this is a Coin type
    pub fn coin_type_opt(&self) -> Option<Arc<TypeTag>> {
        self.0
            .coin_type_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Checks if this is a Coin type
    pub fn coin_type(&self) -> TypeTag {
        self.0.coin_type().clone().into()
    }

    #[uniffi::constructor]
    pub fn gas_coin() -> Self {
        Self(iota_types::StructTag::gas_coin())
    }

    #[uniffi::constructor]
    pub fn staked_iota() -> Self {
        Self(iota_types::StructTag::staked_iota())
    }

    pub fn address(&self) -> Address {
        self.0.address().into()
    }
}
