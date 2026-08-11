// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use bytestring::ByteString;

use crate::{TypeParseError, move_core::parse::MAX_IDENTIFIER_LENGTH};

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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "string")
)]
pub struct Identifier(
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Strategy::prop_map(
            "[a-zA-Z][a-zA-Z0-9_]{0,127}",
            Into::into
        ))
    )]
    ByteString,
);

impl Identifier {
    /// Creates a new `Identifier` from the given string slice, checking
    /// that it is a valid Move identifier and returning an error if not.
    pub fn new(identifier: impl AsRef<str>) -> Result<Self, TypeParseError> {
        identifier.as_ref().parse()
    }

    /// Creates a new `Identifier` from the given string slice without
    /// validation.
    ///
    /// The caller must ensure that the provided string is a valid Move
    /// identifier. Otherwise this method is safe to use, but invalid
    /// identifiers will lead to downstream errors.
    pub fn new_unchecked(identifier: impl AsRef<str>) -> Self {
        Self(identifier.as_ref().into())
    }

    /// Creates a new `Identifier` from the given static string slice.
    ///
    /// This function will panic if the string is not a valid Move identifier.
    pub const fn from_static(s: &'static str) -> Self {
        if !Self::is_valid(s) {
            panic!("String is not a valid Move identifier");
        }

        Self(ByteString::from_static(s))
    }

    /// Returns the string slice representation of the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the byte slice representation of the identifier.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the length of the identifier.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Returns `true` if the identifier has a length of zero.
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Returns `true` if the provided string is a valid Move identifier. Valid
    /// identifiers must start with an alphabetic character (a-z, A-Z) or an
    /// underscore (_), and may be followed by up to 127 alphanumeric
    /// characters (a-z, A-Z, 0-9) or underscores (_). The maximum length of
    /// an identifier is 128 characters.
    ///
    /// Note: this function allows the special identifier `<SELF>`.
    pub const fn is_valid(s: &str) -> bool {
        if s.is_empty() || s.len() > MAX_IDENTIFIER_LENGTH {
            return false;
        }

        /// Returns `true` if all bytes in `b` after the offset `start_offset`
        /// are valid ASCII identifier characters.
        const fn all_bytes_valid(b: &[u8], start_offset: usize) -> bool {
            let mut i = start_offset;
            while i < b.len() {
                if !Identifier::is_valid_char(b[i] as char) {
                    return false;
                }
                i += 1;
            }
            true
        }
        // Rust const fn's don't currently support slicing or indexing &str's, so we
        // have to operate on the underlying byte slice. This is not a problem as
        // valid identifiers are (currently) ASCII-only.
        let b = s.as_bytes();
        match b {
            b"<SELF>" => true,
            [b'a'..=b'z', ..] | [b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
            [b'_', ..] if b.len() > 1 => all_bytes_valid(b, 1),
            _ => false,
        }
    }

    /// Return true if this character can appear in a Move identifier.
    ///
    /// Note: there are stricter restrictions on whether a character can begin a
    /// Move identifier--only alphabetic characters are allowed here.
    #[inline]
    pub const fn is_valid_char(c: char) -> bool {
        matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9')
    }

    // ========================================================================
    // Module name constants
    // ========================================================================

    pub const ASCII_MODULE: Self = Self::from_static("ascii");
    pub const AUTHENTICATOR_STATE_MODULE: Self = Self::from_static("authenticator_state");
    pub const BAG_MODULE: Self = Self::from_static("bag");
    pub const BALANCE_MODULE: Self = Self::from_static("balance");
    pub const CLOCK_MODULE: Self = Self::from_static("clock");
    pub const COIN_MODULE: Self = Self::from_static("coin");
    pub const COIN_MANAGER_MODULE: Self = Self::from_static("coin_manager");
    pub const CONFIG_MODULE: Self = Self::from_static("config");
    pub const DENY_LIST_MODULE: Self = Self::from_static("deny_list");
    pub const DISPLAY_MODULE: Self = Self::from_static("display");
    pub const DYNAMIC_FIELD_MODULE: Self = Self::from_static("dynamic_field");
    pub const DYNAMIC_OBJECT_FIELD_MODULE: Self = Self::from_static("dynamic_object_field");
    pub const IOTA_MODULE: Self = Self::from_static("iota");
    pub const IOTA_SYSTEM_MODULE: Self = Self::from_static("iota_system");
    pub const IOTA_SYSTEM_STATE_INNER_MODULE: Self = Self::from_static("iota_system_state_inner");
    pub const NAME_MODULE: Self = Self::from_static("name");
    pub const OBJECT_MODULE: Self = Self::from_static("object");
    pub const OBJECT_BAG_MODULE: Self = Self::from_static("object_bag");
    pub const OPTION_MODULE: Self = Self::from_static("option");
    pub const PACKAGE_MODULE: Self = Self::from_static("package");
    pub const PAY_MODULE: Self = Self::from_static("pay");
    pub const RANDOM_MODULE: Self = Self::from_static("random");
    pub const STAKING_POOL_MODULE: Self = Self::from_static("staking_pool");
    pub const STRING_MODULE: Self = Self::from_static("string");
    pub const SYSTEM_ADMIN_CAP_MODULE: Self = Self::from_static("system_admin_cap");
    pub const TIMELOCK_MODULE: Self = Self::from_static("timelock");
    pub const TIMELOCKED_STAKING_MODULE: Self = Self::from_static("timelocked_staking");
    pub const TRANSFER_MODULE: Self = Self::from_static("transfer");
    pub const TX_CONTEXT_MODULE: Self = Self::from_static("tx_context");
    pub const URL_MODULE: Self = Self::from_static("url");

    // ========================================================================
    // Type/struct name constants
    // ========================================================================

    pub const ADDRESS_KEY: Self = Self::from_static("AddressKey");
    pub const AUTHENTICATOR_STATE: Self = Self::from_static("AuthenticatorState");
    pub const BAG: Self = Self::from_static("Bag");
    pub const BALANCE: Self = Self::from_static("Balance");
    pub const CLOCK: Self = Self::from_static("Clock");
    pub const COIN: Self = Self::from_static("Coin");
    pub const COIN_MANAGER: Self = Self::from_static("CoinManager");
    pub const COIN_METADATA: Self = Self::from_static("CoinMetadata");
    pub const CONFIG: Self = Self::from_static("Config");
    pub const CONFIG_KEY: Self = Self::from_static("ConfigKey");
    pub const DISPLAY_CREATED: Self = Self::from_static("DisplayCreated");
    pub const FIELD: Self = Self::from_static("Field");
    pub const GLOBAL_PAUSE_KEY: Self = Self::from_static("GlobalPauseKey");
    pub const ID: Self = Self::from_static("ID");
    pub const IOTA: Self = Self::from_static("IOTA");
    pub const IOTA_SYSTEM_ADMIN_CAP: Self = Self::from_static("IotaSystemAdminCap");
    pub const IOTA_SYSTEM_STATE: Self = Self::from_static("IotaSystemState");
    pub const IOTA_TREASURY_CAP: Self = Self::from_static("IotaTreasuryCap");
    pub const NAME: Self = Self::from_static("Name");
    pub const OBJECT_BAG: Self = Self::from_static("ObjectBag");
    pub const OPTION: Self = Self::from_static("Option");
    pub const RANDOM: Self = Self::from_static("Random");
    pub const RECEIVING: Self = Self::from_static("Receiving");
    pub const SETTING: Self = Self::from_static("Setting");
    pub const STAKED_IOTA: Self = Self::from_static("StakedIota");
    pub const STRING: Self = Self::from_static("String");
    pub const SYSTEM_EPOCH_INFO_EVENT: Self = Self::from_static("SystemEpochInfoEvent");
    pub const SYSTEM_EPOCH_INFO_EVENT_V1: Self = Self::from_static("SystemEpochInfoEventV1");
    pub const SYSTEM_EPOCH_INFO_EVENT_V2: Self = Self::from_static("SystemEpochInfoEventV2");
    pub const TIME_LOCK: Self = Self::from_static("TimeLock");
    pub const TIMELOCKED_STAKED_IOTA: Self = Self::from_static("TimelockedStakedIota");
    pub const TREASURY_CAP: Self = Self::from_static("TreasuryCap");
    pub const TX_CONTEXT: Self = Self::from_static("TxContext");
    pub const UID: Self = Self::from_static("UID");
    pub const UPGRADE_CAP: Self = Self::from_static("UpgradeCap");
    pub const UPGRADE_RECEIPT: Self = Self::from_static("UpgradeReceipt");
    pub const UPGRADE_TICKET: Self = Self::from_static("UpgradeTicket");
    pub const URL: Self = Self::from_static("Url");
    pub const VERSION_UPDATED: Self = Self::from_static("VersionUpdated");
    pub const WRAPPER: Self = Self::from_static("Wrapper");
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl From<Identifier> for String {
    fn from(value: Identifier) -> Self {
        value.to_string()
    }
}

impl From<&Identifier> for String {
    fn from(value: &Identifier) -> Self {
        value.to_string()
    }
}

impl std::str::FromStr for Identifier {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use winnow::Parser;
        crate::move_core::parse::parse_identifier
            .parse(s)
            .map_err(|e| e.into_inner())
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Identifier {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<Identifier> for str {
    fn eq(&self, other: &Identifier) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<Identifier> for String {
    fn eq(&self, other: &Identifier) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<String> for Identifier {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl std::ops::Deref for Identifier {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl From<&'static str> for Identifier {
    fn from(s: &'static str) -> Self {
        Self::from_static(s)
    }
}
