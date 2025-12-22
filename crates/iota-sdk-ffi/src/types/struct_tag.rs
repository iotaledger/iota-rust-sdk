// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    types::{address::Address, type_tag::TypeTag},
};

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
#[derive(PartialEq, Eq, Hash, derive_more::From, uniffi::Object)]
#[uniffi::export(Hash)]
pub struct Identifier(pub iota_sdk::types::Identifier);

#[uniffi::export]
impl Identifier {
    #[uniffi::constructor]
    pub fn new(identifier: String) -> Result<Self> {
        Ok(Self(iota_sdk::types::Identifier::new(identifier)?))
    }

    pub fn as_str(&self) -> String {
        self.0.as_str().to_owned()
    }
}

macro_rules! export_struct_tag_ctors {
    ($($name:ident),+ $(,)?) => { paste::paste! {
        #[uniffi::export]
        impl StructTag {$(
            #[uniffi::constructor]
            pub fn [< new_ $name:snake >]() -> Self {
                Self(iota_sdk::types::StructTag::[< new_ $name:snake >]())
            }
        )+}
    } }
}

macro_rules! export_struct_tag_from_type_tag_ctors {
    ($($name:ident),+ $(,)?) => { paste::paste! {
        #[uniffi::export]
        impl StructTag {$(
            #[uniffi::constructor]
            pub fn [< new_ $name:snake >](type_tag: &TypeTag) -> Self {
                Self(iota_sdk::types::StructTag::[< new_ $name:snake >](type_tag.0.clone()))
            }
        )+}
    } }
}

macro_rules! export_struct_tag_from_struct_tag_ctors {
    ($($name:ident),+ $(,)?) => { paste::paste! {
        #[uniffi::export]
        impl StructTag {$(
            #[uniffi::constructor]
            pub fn [< new_ $name:snake >](struct_tag: &StructTag) -> Self {
                Self(iota_sdk::types::StructTag::[< new_ $name:snake >](struct_tag.0.clone()))
            }
        )+}
    } }
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
#[derive(derive_more::From, derive_more::Display, uniffi::Object, PartialEq, Eq)]
#[uniffi::export(Display, Eq)]
pub struct StructTag(pub iota_sdk::types::StructTag);

#[uniffi::export]
impl StructTag {
    #[uniffi::constructor(default(type_params = []))]
    pub fn new(
        address: &Address,
        module: &Identifier,
        name: &Identifier,
        type_params: Vec<Arc<TypeTag>>,
    ) -> Self {
        Self(iota_sdk::types::StructTag {
            address: address.0,
            module: module.0.clone(),
            name: name.0.clone(),
            type_params: type_params
                .iter()
                .map(|type_tag| type_tag.0.clone())
                .collect(),
        })
    }

    #[uniffi::constructor]
    pub fn new_name(address: &Address) -> Self {
        Self(iota_sdk::types::StructTag::new_name(address.0))
    }

    #[uniffi::constructor]
    pub fn new_field(key: &TypeTag, value: &TypeTag) -> Self {
        Self(iota_sdk::types::StructTag::new_field(
            key.0.clone(),
            value.0.clone(),
        ))
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

    /// Returns the address part of a `StructTag`
    pub fn address(&self) -> Address {
        self.0.address().into()
    }

    /// Returns the module part of a `StructTag`
    pub fn module(&self) -> Identifier {
        self.0.module().clone().into()
    }

    /// Returns the name part of a `StructTag`
    pub fn name(&self) -> Identifier {
        self.0.name().clone().into()
    }

    /// Returns the type params part of a `StructTag`
    pub fn type_args(&self) -> Vec<Arc<TypeTag>> {
        self.0
            .type_params()
            .iter()
            .cloned()
            .map(TypeTag::from)
            .map(Arc::new)
            .collect()
    }

    /// Returns the string representation of this struct tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }
}

export_struct_tag_ctors!(
    AsciiString,
    Clock,
    Config,
    DenyListAddressKey,
    DenyListConfigKey,
    DenyListGlobalPauseKey,
    GasCoin,
    Id,
    IotaCoinType,
    IotaSystemAdminCap,
    IotaSystemState,
    IotaTreasuryCap,
    UpgradeCap,
    UpgradeTicket,
    UpgradeReceipt,
    StakedIota,
    String,
    SystemEpochInfoEvent,
    TimelockedStakedIota,
    TransferReceiving,
    Uid,
);
export_struct_tag_from_type_tag_ctors!(
    Balance,
    ConfigSetting,
    DynamicObjectFieldWrapper,
    Coin,
    TimeLock
);
export_struct_tag_from_struct_tag_ctors!(
    CoinManager,
    CoinMetadata,
    DisplayCreated,
    TreasuryCap,
    VersionUpdated,
);

crate::export_iota_types_objects_bcs_conversion!(Identifier, StructTag);
