// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address,
    move_core::{identifier::Identifier, type_tag::TypeTag},
};

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
#[derive(Debug, derive_more::Display, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Display, Eq, Hash)]
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
        Self(iota_sdk::types::StructTag::new(
            address.0,
            module.0.clone(),
            name.0.clone(),
            type_params
                .iter()
                .map(|type_tag| type_tag.0.clone())
                .collect(),
        ))
    }

    /// Creates a new IOTA-Names `Name` struct tag
    /// with the given package address.
    #[uniffi::constructor]
    pub fn new_name(address: &Address) -> Self {
        Self(iota_sdk::types::StructTag::new_name(address.0))
    }

    /// Checks if this is an IOTA-Names `Name` type.
    /// Note that this does not check the package address, so it will return
    /// true for any struct with the correct module and type name with no
    /// type params.
    pub fn is_name(&self) -> bool {
        self.0.is_name()
    }

    /// Creates a new dynamic field struct tag
    /// (`0x2::dynamic_field::Field<KeyType, ValueType>`)
    #[uniffi::constructor]
    pub fn new_dynamic_field(key: &TypeTag, value: &TypeTag) -> Self {
        Self(iota_sdk::types::StructTag::new_dynamic_field(
            key.0.clone(),
            value.0.clone(),
        ))
    }

    /// Checks if this is a Dynamic Field type
    /// (`0x2::dynamic_field::Field<KeyType, ValueType>`)
    pub fn is_dynamic_field(&self) -> bool {
        self.0.is_dynamic_field()
    }

    /// Returns the coin type part of a `StructTag`, if this is a Coin type
    pub fn opt_coin_type(&self) -> Option<Arc<TypeTag>> {
        self.0
            .opt_coin_type()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Returns the coin type part of a `StructTag`, panics if this is not a
    /// Coin type
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

    /// Returns whether the type (excluding the type params) is the same as
    /// another struct tag.
    pub fn is_same_type_as(&self, other: &StructTag) -> bool {
        self.0.is_same_type_as(&other.0)
    }

    /// Checks if this is an IOTA balance type
    /// (`0x2::balance::Balance<0x2::iota::IOTA>`)
    pub fn is_gas_balance(&self) -> bool {
        self.0.is_gas_balance()
    }

    /// Checks if this is a timelocked coin balance `TimeLock<Balance<T>>`
    pub fn is_timelocked_balance(&self) -> bool {
        self.0.is_timelocked_balance()
    }

    /// Creates a new timelocked IOTA balance struct tag
    /// (`0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>`)
    #[uniffi::constructor]
    pub fn new_timelocked_gas_balance() -> Self {
        Self(iota_sdk::types::StructTag::new_timelocked_gas_balance())
    }

    /// Checks if this is a timelocked IOTA balance type
    /// (`0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>`)
    pub fn is_timelocked_gas_balance(&self) -> bool {
        self.0.is_timelocked_gas_balance()
    }

    /// Returns the string representation of this struct tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
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

            pub fn [< is_ $name:snake >](&self) -> bool {
                self.0.[< is_ $name:snake >]()
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

            pub fn [< is_ $name:snake >](&self) -> bool {
                self.0.[< is_ $name:snake >]()
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

            pub fn [< is_ $name:snake >](&self) -> bool {
                self.0.[< is_ $name:snake >]()
            }
        )+}
    } }
}

export_struct_tag_ctors!(
    AsciiString,
    Clock,
    DenyListAddressKey,
    DenyListConfigKey,
    DenyListGlobalPauseKey,
    Gas,
    GasCoin,
    Id,
    IotaSystemAdminCap,
    IotaSystemState,
    IotaTreasuryCap,
    Random,
    UpgradeCap,
    UpgradeTicket,
    UpgradeReceipt,
    StakedIota,
    String,
    SystemEpochInfoEvent,
    TimelockedStakedIota,
    Uid,
    Url,
    Bag,
    ObjectBag,
    TxContext,
    Alias,
    Nft,
    Irc27Metadata,
    Kiosk,
    KioskOwnerCap,
    Publisher,
    PackageMetadataKey,
    AuthenticatorFunctionRefV1Key
);
export_struct_tag_from_type_tag_ctors!(
    Balance,
    Config,
    ConfigSetting,
    DynamicObjectFieldWrapper,
    Coin,
    RegulatedCoinMetadata,
    DenyCapV1,
    TimeLock,
    Option,
    TransferReceiving,
    BasicOutput,
    NftOutput,
    AliasOutput,
);
export_struct_tag_from_struct_tag_ctors!(
    CoinManager,
    CoinMetadata,
    DisplayCreated,
    TreasuryCap,
    DisplayVersionUpdated,
);

crate::export_iota_types_objects_bcs_conversion!(Identifier, StructTag);
crate::export_iota_types_objects_json_conversion!(Identifier, StructTag);
