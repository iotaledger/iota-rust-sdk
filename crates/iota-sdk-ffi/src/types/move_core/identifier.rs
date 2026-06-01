// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;

/// A move identifier
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// identifier = %d1-128    ; length of the identifier
///              (ALPHA *127(ALPHA / DIGIT / UNDERSCORE)) /
///              (UNDERSCORE 1*127(ALPHA / DIGIT / UNDERSCORE))
///
/// UNDERSCORE = %x95
/// ```
#[derive(Debug, derive_more::Display, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Display, Eq, Hash)]
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

macro_rules! export_identifier_consts {
    ($($name:ident),+ $(,)?) => { paste::paste! {
        #[uniffi::export]
        impl Identifier {$(
            #[uniffi::constructor]
            pub fn [< $name:lower >]() -> Self {
                Self(iota_sdk::types::Identifier::$name)
            }
        )+}
    } }
}

export_identifier_consts!(
    // Module name constants
    ASCII_MODULE,
    AUTHENTICATOR_STATE_MODULE,
    BAG_MODULE,
    BALANCE_MODULE,
    CLOCK_MODULE,
    COIN_MODULE,
    COIN_MANAGER_MODULE,
    CONFIG_MODULE,
    DENY_LIST_MODULE,
    DISPLAY_MODULE,
    DYNAMIC_FIELD_MODULE,
    DYNAMIC_OBJECT_FIELD_MODULE,
    IOTA_MODULE,
    IOTA_SYSTEM_MODULE,
    IOTA_SYSTEM_STATE_INNER_MODULE,
    NAME_MODULE,
    OBJECT_MODULE,
    OBJECT_BAG_MODULE,
    OPTION_MODULE,
    PACKAGE_MODULE,
    PAY_MODULE,
    RANDOM_MODULE,
    STAKING_POOL_MODULE,
    STRING_MODULE,
    SYSTEM_ADMIN_CAP_MODULE,
    TIMELOCK_MODULE,
    TIMELOCKED_STAKING_MODULE,
    TRANSFER_MODULE,
    TX_CONTEXT_MODULE,
    URL_MODULE,
    // Struct/type name constants
    ADDRESS_KEY,
    AUTHENTICATOR_STATE,
    BAG,
    BALANCE,
    CLOCK,
    COIN,
    COIN_MANAGER,
    COIN_METADATA,
    CONFIG,
    CONFIG_KEY,
    DISPLAY_CREATED,
    FIELD,
    GLOBAL_PAUSE_KEY,
    ID,
    IOTA,
    IOTA_SYSTEM_ADMIN_CAP,
    IOTA_SYSTEM_STATE,
    IOTA_TREASURY_CAP,
    NAME,
    OBJECT_BAG,
    OPTION,
    RANDOM,
    RECEIVING,
    SETTING,
    STAKED_IOTA,
    STRING,
    SYSTEM_EPOCH_INFO_EVENT,
    SYSTEM_EPOCH_INFO_EVENT_V1,
    SYSTEM_EPOCH_INFO_EVENT_V2,
    TIME_LOCK,
    TIMELOCKED_STAKED_IOTA,
    TREASURY_CAP,
    TX_CONTEXT,
    UID,
    UPGRADE_CAP,
    UPGRADE_RECEIPT,
    UPGRADE_TICKET,
    URL,
    VERSION_UPDATED,
    WRAPPER,
);
