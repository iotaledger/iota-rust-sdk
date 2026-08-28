// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

/// Unique identifier for an Account on the IOTA blockchain.
///
/// An `Address` is a 32-byte pseudonymous identifier used to uniquely identify
/// an account and asset-ownership on the IOTA blockchain. Often, human-readable
/// addresses are encoded in hexadecimal with a `0x` prefix. For example, this
/// is a valid IOTA address:
/// `0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331`.
///
/// # Deriving an Address
///
/// Addresses are cryptographically derived from a number of user account
/// authenticators, the simplest of which is an
/// `Ed25519PublicKey`.
///
/// Deriving an address consists of the Blake2b256 hash of the sequence of bytes
/// of its corresponding authenticator, prefixed with a domain-separator (except
/// ed25519, for compatibility reasons). For each other authenticator, this
/// domain-separator is the single byte-value of its
/// `SignatureScheme` flag. E.g. `hash(signature schema flag || authenticator
/// bytes)`.
///
/// Each authenticator has a method for deriving its `Address` as well as
/// documentation for the specifics of how the derivation is done. See
/// `Ed25519PublicKey::derive_address` for an example.
///
/// ## Relationship to ObjectIds
///
/// `ObjectId`s and `Address`es share the same 32-byte addressable space but
/// are derived leveraging different domain-separator values to ensure that,
/// cryptographically, there won't be any overlap, e.g. there can't be a
/// valid `Object` who's `ObjectId` is equal to that of the `Address` of a user
/// account.
///
/// # BCS
///
/// An `Address`'s BCS serialized form is defined by the following:
///
/// ```text
/// address = 32OCTET
/// ```
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Address(pub iota_sdk::types::Address);

#[uniffi::export]
impl Address {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_bytes(bytes)?))
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// with or without a `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_hex(hex)?))
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// with a mandatory `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    #[uniffi::constructor]
    pub fn from_prefixed_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_prefixed_hex(hex)?))
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// without a `0x` prefix. Will return an error if the string has a `0x`
    /// prefix or is not exactly 64 hex characters long.
    #[uniffi::constructor]
    pub fn from_raw_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_raw_hex(hex)?))
    }

    /// Parses an Address from a hex string, with or without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    #[uniffi::constructor]
    pub fn from_short_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_short_hex(hex)?))
    }

    /// Parses an Address from a hex string with a mandatory `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    #[uniffi::constructor]
    pub fn from_prefixed_short_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_prefixed_short_hex(
            hex,
        )?))
    }

    /// Parses an Address from a hex string without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s. Will return an error if
    /// the string has a `0x` prefix.
    #[uniffi::constructor]
    pub fn from_raw_short_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Address::from_raw_short_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn random() -> Self {
        Self(iota_sdk::types::Address::random())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    /// Returns the string representation of this address in hex format with
    /// `0x` prefix.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the string representation of this address in hex format without
    /// `0x` prefix.
    pub fn to_raw_hex(&self) -> String {
        self.0.to_raw_hex()
    }

    /// Returns the string representation of this address using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }

    /// Returns the shortest possible string representation of the address (i.e.
    /// with leading zeroes trimmed).
    pub fn to_short_hex(&self) -> String {
        self.0.to_short_hex()
    }

    /// Returns the shortest possible string representation of the address (i.e.
    /// with leading zeroes trimmed), without `0x` prefix.
    pub fn to_raw_short_hex(&self) -> String {
        self.0.to_raw_short_hex()
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        Self(self.0.next_lexicographical())
    }

    /// Returns the next digest in byte-increasing order, or `None` if the
    /// result would overflow.
    pub fn next_lexicographical_opt(&self) -> Option<Arc<Self>> {
        self.0.next_lexicographical_opt().map(Self).map(Arc::new)
    }
}

macro_rules! named_address {
    ($($constant:ident),+ $(,)?) => {
        paste::paste! {
            #[uniffi::export]
            impl Address {$(
                #[uniffi::constructor]
                pub const fn [< $constant:lower >]() -> Self {
                    Self(iota_sdk::types::Address::$constant)
                }
            )+}
        }
    }
}

named_address!(
    ZERO,
    MAX,
    STD,
    FRAMEWORK,
    SYSTEM,
    GENESIS_BRIDGE,
    STARDUST,
    SYSTEM_STATE,
    CLOCK,
    AUTHENTICATOR_STATE,
    RANDOMNESS_STATE,
    GENESIS_IOTA_BRIDGE,
    DENY_LIST,
    TRANSACTION_DENY_RULES
);

crate::export_iota_types_objects_bcs_conversion!(Address);
crate::export_iota_types_objects_json_conversion!(Address);
