// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

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
    pub fn coin(type_tag: &super::type_tag::TypeTag) -> Self {
        Self(iota_types::StructTag::coin(type_tag.0.clone()))
    }

    /// Checks if this is a Coin type
    pub fn coin_type_opt(&self) -> Option<Arc<super::type_tag::TypeTag>> {
        self.0
            .coin_type_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Checks if this is a Coin type
    pub fn coin_type(&self) -> super::type_tag::TypeTag {
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

    pub fn address(&self) -> super::address::Address {
        self.0.address().into()
    }
}
