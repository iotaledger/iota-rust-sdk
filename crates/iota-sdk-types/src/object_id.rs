// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, address::AddressParseError};

/// An `ObjectId` is a 32-byte identifier used to uniquely identify an object on
/// the IOTA blockchain.
///
/// ## Relationship to Address
///
/// [`Address`]es and `ObjectId`s share the same 32-byte addressable space but
/// are derived leveraging different domain-separator values to ensure,
/// cryptographically, that there won't be any overlap, e.g. there can't be a
/// valid `Object` whose `ObjectId` is equal to that of the `Address` of a user
/// account.
///
/// # BCS
///
/// An `ObjectId`'s BCS serialized form is defined by the following:
///
/// ```text
/// object-id = address
/// ```
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ObjectId(pub(crate) Address);

impl ObjectId {
    pub const LENGTH: usize = Address::LENGTH;
    pub const ZERO: Self = Self(Address::ZERO);
    pub const MAX: Self = Self(Address::MAX);
    pub const STD: Self = Self(Address::STD);
    pub const FRAMEWORK: Self = Self(Address::FRAMEWORK);
    pub const SYSTEM: Self = Self(Address::SYSTEM);
    pub const GENESIS_BRIDGE: Self = Self(Address::GENESIS_BRIDGE);
    pub const STARDUST: Self = Self(Address::STARDUST);
    pub const SYSTEM_STATE: Self = Self(Address::SYSTEM_STATE);
    pub const CLOCK: Self = Self(Address::CLOCK);
    pub const AUTHENTICATOR_STATE: Self = Self(Address::AUTHENTICATOR_STATE);
    pub const RANDOMNESS_STATE: Self = Self(Address::RANDOMNESS_STATE);
    pub const GENESIS_IOTA_BRIDGE: Self = Self(Address::GENESIS_IOTA_BRIDGE);
    pub const DENY_LIST: Self = Self(Address::DENY_LIST);

    /// Generates a new ObjectId from the provided byte array.
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Address::new(bytes))
    }

    /// Creates an `ObjectId` from a `u16` suffix by setting the last two bytes.
    pub const fn from_u16(suffix: u16) -> Self {
        Self(Address::from_u16(suffix))
    }

    /// Checks if the object id is one of the system package ids.
    /// The system packages are:
    /// - STD
    /// - FRAMEWORK
    /// - SYSTEM
    /// - GENESIS_BRIDGE
    /// - STARDUST
    pub fn is_system_package(&self) -> bool {
        self.0.is_system_package()
    }

    /// Returns the string representation of this object id in hex format with
    /// `0x` prefix.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the string representation of this object id in hex format
    /// without `0x` prefix.
    pub fn to_raw_hex(&self) -> String {
        self.0.to_raw_hex()
    }

    /// Returns the shortest possible string representation of the object ID
    /// (i.e. with leading zeroes trimmed).
    pub fn to_short_hex(&self) -> String {
        self.0.to_short_hex()
    }

    /// Returns the shortest possible string representation of the object id
    /// (i.e. with leading zeroes trimmed), without `0x` prefix.
    pub fn to_raw_short_hex(&self) -> String {
        self.0.to_raw_short_hex()
    }

    /// Parses an ObjectId from a full-length hex string (64 hex characters),
    /// with or without a `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        Address::from_hex(hex).map(Self)
    }

    /// Parses an ObjectId from a full-length hex string (64 hex characters),
    /// with a mandatory `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    pub fn from_prefixed_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        Address::from_prefixed_hex(hex).map(Self)
    }

    /// Parses an ObjectId from a hex string, with or without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    pub fn from_short_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        Address::from_short_hex(hex).map(Self)
    }

    /// Parses an ObjectId from a hex string with a mandatory `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    pub fn from_prefixed_short_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        Address::from_prefixed_short_hex(hex).map(Self)
    }

    pub const fn from_address(address: Address) -> Self {
        Self(address)
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, AddressParseError> {
        Address::from_bytes(bytes).map(Self)
    }

    /// Returns the underlying byte array of an ObjectId.
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0.into_bytes()
    }

    /// Returns a reference to the underlying byte array of an ObjectId.
    pub const fn bytes(&self) -> &[u8; Self::LENGTH] {
        self.0.bytes()
    }

    /// Returns a slice of bytes of an ObjectId.
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the underlying Address of an ObjectId.
    pub const fn as_address(&self) -> &Address {
        &self.0
    }

    /// Returns the string representation of this object ID using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }

    /// Returns the next object id in byte-increasing order.
    pub const fn next_lexicographical(&self) -> Self {
        Self::new(crate::next_lexicographical_array(self.bytes()))
    }

    /// Returns the next object id in byte-increasing order, or `None` if the
    /// result would overflow.
    pub const fn next_lexicographical_opt(&self) -> Option<Self> {
        match crate::next_lexicographical_array_opt(self.bytes()) {
            Some(val) => Some(Self::new(val)),
            None => None,
        }
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn generate<R>(rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        Self::from_address(Address::generate(rng))
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random() -> Self {
        Self::generate(rand_core::OsRng)
    }
}

impl AsRef<[u8]> for ObjectId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8; 32]> for ObjectId {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<ObjectId> for [u8; 32] {
    fn from(object_id: ObjectId) -> Self {
        object_id.into_bytes()
    }
}

impl From<[u8; 32]> for ObjectId {
    fn from(object_id: [u8; 32]) -> Self {
        Self::new(object_id)
    }
}

impl From<Address> for ObjectId {
    fn from(value: Address) -> Self {
        Self(value)
    }
}

impl From<ObjectId> for Vec<u8> {
    fn from(value: ObjectId) -> Self {
        value.0.into()
    }
}

impl std::str::FromStr for ObjectId {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).map(Self)
    }
}

impl std::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectId(\"{self}\")")
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string(true).fmt(f)
    }
}
