// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::Address;

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
/// object-id = 32*OCTET
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ObjectId(Address);

impl ObjectId {
    pub const LENGTH: usize = Address::LENGTH;
    pub const ZERO: Self = Self(Address::ZERO);
    pub const SYSTEM: Self = Self(Address::from_u8(5));
    pub const CLOCK: Self = Self(Address::from_u8(6));

    /// Generates a new ObjectId from the provided byte array.
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(Address::new(bytes))
    }

    pub fn to_hex(&self) -> String {
        self.to_string()
    }

    /// Parse an ObjectId from a hex string.
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, super::address::AddressParseError> {
        Address::from_hex(hex).map(Self)
    }

    /// Returns the underlying byte array of an ObjectId.
    pub const fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0.into_inner()
    }

    /// Returns a reference to the underlying byte array of an ObjectId.
    pub const fn inner(&self) -> &[u8; Self::LENGTH] {
        self.0.inner()
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

    /// Returns the shortest possible string representation of the object ID
    /// (i.e. with leading zeroes trimmed).
    pub fn to_short_string(&self, with_prefix: bool) -> String {
        self.0.to_short_string(with_prefix)
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
        object_id.into_inner()
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
    type Err = super::address::AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::from_str(s).map(Self)
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string(true).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    // --- Construction & Accessors ---

    #[test]
    fn new_returns_correct_bytes() {
        let bytes = [42u8; ObjectId::LENGTH];
        let id = ObjectId::new(bytes);
        assert_eq!(*id.inner(), bytes, "inner bytes must match input");
        assert_eq!(id.into_inner(), bytes, "into_inner must match input");
    }

    #[test]
    fn as_bytes_returns_full_slice() {
        let bytes = [7u8; ObjectId::LENGTH];
        let id = ObjectId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes[..]);
    }

    // --- Well-known constants ---

    #[test]
    fn zero_constant() {
        assert_eq!(ObjectId::ZERO, ObjectId::new([0u8; 32]));
    }

    #[test]
    fn system_constant() {
        let mut expected = [0u8; 32];
        expected[31] = 5;
        assert_eq!(ObjectId::SYSTEM, ObjectId::new(expected));
    }

    #[test]
    fn clock_constant() {
        let mut expected = [0u8; 32];
        expected[31] = 6;
        assert_eq!(ObjectId::CLOCK, ObjectId::new(expected));
    }

    // --- Hex parsing ---

    #[test]
    fn from_hex_with_prefix() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000005";
        let id = ObjectId::from_hex(hex).unwrap();
        assert_eq!(id, ObjectId::SYSTEM);
    }

    #[test]
    fn from_hex_short_form() {
        // Short hex should be left-padded with zeros to 32 bytes
        let id = ObjectId::from_hex("0x6").unwrap();
        assert_eq!(id, ObjectId::CLOCK);
    }

    #[test]
    fn from_hex_invalid_characters() {
        let result = ObjectId::from_hex("0xZZZZ");
        assert!(result.is_err(), "non-hex characters should fail");
    }

    // --- Display & FromStr roundtrip ---

    #[test]
    fn display_shows_canonical_hex_with_prefix() {
        let display = ObjectId::ZERO.to_string();
        assert!(
            display.starts_with("0x"),
            "Display should start with 0x prefix"
        );
        assert_eq!(display.len(), 66, "0x + 64 hex chars = 66 chars");
    }

    #[proptest]
    fn roundtrip_display_fromstr(id: ObjectId) {
        let s = id.to_string();
        let parsed: ObjectId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    // --- String representations ---

    #[test]
    fn to_canonical_string_with_and_without_prefix() {
        let id = ObjectId::SYSTEM;
        let with_prefix = id.to_canonical_string(true);
        let without_prefix = id.to_canonical_string(false);
        assert!(with_prefix.starts_with("0x"));
        assert!(!without_prefix.starts_with("0x"));
        assert_eq!(with_prefix[2..], without_prefix);
    }

    #[test]
    fn to_short_string_trims_leading_zeros() {
        let id = ObjectId::SYSTEM;
        assert_eq!(id.to_short_string(true), "0x5");
        assert_eq!(id.to_short_string(false), "5");
    }

    #[test]
    fn to_short_string_zero_address_shows_zero() {
        let id = ObjectId::ZERO;
        assert_eq!(id.to_short_string(true), "0x0");
        assert_eq!(id.to_short_string(false), "0");
    }

    // --- Conversions ---

    #[test]
    fn from_address_roundtrip() {
        let addr = Address::new([0xAB; 32]);
        let id = ObjectId::from(addr);
        assert_eq!(*id.as_address(), addr);
    }

    #[test]
    fn into_byte_array() {
        let bytes = [0xFF; 32];
        let id = ObjectId::new(bytes);
        let out: [u8; 32] = id.into();
        assert_eq!(out, bytes);
    }

    #[test]
    fn into_vec_u8() {
        let bytes = [0xCC; 32];
        let id = ObjectId::new(bytes);
        let vec: Vec<u8> = id.into();
        assert_eq!(&vec[..], &bytes[..]);
    }

    #[test]
    fn as_ref_u8_slice() {
        let bytes = [0x11; 32];
        let id = ObjectId::new(bytes);
        let slice: &[u8] = id.as_ref();
        assert_eq!(slice, &bytes[..]);
    }

    #[test]
    fn as_ref_u8_array() {
        let bytes = [0x22; 32];
        let id = ObjectId::new(bytes);
        let arr: &[u8; 32] = id.as_ref();
        assert_eq!(arr, &bytes);
    }

    #[test]
    fn to_hex_matches_display() {
        let id = ObjectId::CLOCK;
        assert_eq!(id.to_hex(), id.to_string());
    }
}
