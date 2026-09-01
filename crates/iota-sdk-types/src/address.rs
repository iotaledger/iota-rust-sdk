// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::ObjectId;

/// Unique identifier for an Account on the IOTA blockchain.
///
/// An `Address` is a 32-byte pseudonymous identifier used to uniquely identify
/// an account and asset-ownership on the IOTA blockchain. Often, human-readable
/// addresses are encoded in hexadecimal with a `0x` prefix. For example, this
/// is a valid IOTA address:
/// `0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331`.
///
/// ```
/// use iota_sdk_types::Address;
///
/// let hex = "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
/// let address = Address::from_hex(hex).unwrap();
/// println!("Address: {}", address);
/// assert_eq!(hex, address.to_string());
/// ```
///
/// # Deriving an Address
///
/// Addresses are cryptographically derived from a number of user account
/// authenticators, the simplest of which is an
/// [`Ed25519PublicKey`](crate::Ed25519PublicKey).
///
/// Deriving an address consists of the Blake2b256 hash of the sequence of bytes
/// of its corresponding authenticator, prefixed with a domain-separator (except
/// ed25519, for compatibility reasons). For each other authenticator, this
/// domain-separator is the single byte-value of its
/// [`SignatureScheme`](crate::SignatureScheme) flag. E.g. `hash(signature
/// schema flag || authenticator bytes)`.
///
/// Each authenticator has a method for deriving its `Address` as well as
/// documentation for the specifics of how the derivation is done. See
/// [`Ed25519PublicKey::derive_address`] for an example.
///
/// [`Ed25519PublicKey::derive_address`]: crate::Ed25519PublicKey::derive_address
///
/// ## Relationship to ObjectIds
///
/// [`ObjectId`]s and [`Address`]es share the same 32-byte addressable space but
/// are derived leveraging different domain-separator values to ensure that,
/// cryptographically, there won't be any overlap, e.g. there can't be a
/// valid `Object` who's `ObjectId` is equal to that of the `Address` of a user
/// account.
///
/// [`ObjectId`]: crate::ObjectId
///
/// # BCS
///
/// An `Address`'s BCS serialized form is defined by the following:
///
/// ```text
/// address = 32OCTET
/// ```
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "32OCTET")
)]
pub struct Address(
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_with::As::<::serde_with::IfIsHumanReadable<ReadableAddress>>")
    )]
    [u8; Self::LENGTH],
);

impl Address {
    pub const LENGTH: usize = 32;
    pub const ZERO: Self = Self([0u8; Self::LENGTH]);
    pub const MAX: Self = Self([u8::MAX; Self::LENGTH]);
    pub const STD: Self = Self::from_u16(1);
    pub const FRAMEWORK: Self = Self::from_u16(2);
    pub const SYSTEM: Self = Self::from_u16(3);
    pub const GENESIS_BRIDGE: Self = Self::from_u16(0xb);
    pub const STARDUST: Self = Self::from_u16(0x107a);
    pub const SYSTEM_STATE: Self = Self::from_u16(5);
    pub const CLOCK: Self = Self::from_u16(6);
    pub const AUTHENTICATOR_STATE: Self = Self::from_u16(7);
    pub const RANDOMNESS_STATE: Self = Self::from_u16(8);
    pub const GENESIS_IOTA_BRIDGE: Self = Self::from_u16(9);
    pub const DENY_LIST: Self = Self::from_u16(0x403);
    pub const TRANSACTION_DENY_RULES: Self = Self::from_u16(0xde9);

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates an `Address` from a `u16` suffix by setting the last two bytes.
    pub const fn from_u16(suffix: u16) -> Self {
        let mut address = Self::ZERO;
        let [hi, lo] = suffix.to_be_bytes();
        address.0[Address::LENGTH - 2] = hi;
        address.0[Address::LENGTH - 1] = lo;
        address
    }

    /// Checks if the address is one of the system package addresses.
    /// The system packages are:
    /// - STD
    /// - FRAMEWORK
    /// - SYSTEM
    /// - GENESIS_BRIDGE
    /// - STARDUST
    pub fn is_system_package(&self) -> bool {
        [
            Self::STD,
            Self::FRAMEWORK,
            Self::SYSTEM,
            Self::GENESIS_BRIDGE,
            Self::STARDUST,
        ]
        .contains(self)
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random_with<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random() -> Self {
        Self::random_with(rand_core::OsRng)
    }

    /// Return the underlying byte array of a Address.
    pub const fn into_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub const fn bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub const fn from_object_id(object_id: ObjectId) -> Self {
        object_id.0
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// with or without a `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        let hex = hex.as_ref();
        let hex = if hex.starts_with(b"0x") {
            &hex[2..]
        } else {
            hex
        };
        if hex.len() != Self::LENGTH * 2 {
            return Err(AddressParseError::FromHex(
                hex::FromHexError::InvalidStringLength,
            ));
        }
        <[u8; Self::LENGTH] as hex::FromHex>::from_hex(hex)
            .map(Self)
            .map_err(AddressParseError::FromHex)
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// with a mandatory `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    pub fn from_prefixed_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        if !hex.as_ref().starts_with(b"0x") {
            return Err(AddressParseError::MissingPrefix);
        }
        Self::from_hex(hex)
    }

    /// Parses an Address from a full-length hex string (64 hex characters),
    /// without a `0x` prefix. Will return an error if the string has a `0x`
    /// prefix or is not exactly 64 hex characters long.
    pub fn from_raw_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        if hex.as_ref().starts_with(b"0x") {
            return Err(AddressParseError::UnexpectedPrefix);
        }
        Self::from_hex(hex)
    }

    /// Parses an Address from a hex string, with or without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    pub fn from_short_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        let hex = hex.as_ref();
        let hex = if hex.starts_with(b"0x") {
            &hex[2..]
        } else {
            hex
        };

        // If the string is too short we'll need to pad with 0's
        if hex.len() < Self::LENGTH * 2 {
            let mut buf = [b'0'; Self::LENGTH * 2];
            let pad_length = (Self::LENGTH * 2) - hex.len();

            buf[pad_length..].copy_from_slice(hex);

            <[u8; Self::LENGTH] as hex::FromHex>::from_hex(buf)
        } else {
            <[u8; Self::LENGTH] as hex::FromHex>::from_hex(hex)
        }
        .map(Self)
        .map_err(AddressParseError::FromHex)
    }

    /// Parses an Address from a hex string with a mandatory `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    pub fn from_prefixed_short_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        if !hex.as_ref().starts_with(b"0x") {
            return Err(AddressParseError::MissingPrefix);
        }
        Self::from_short_hex(hex)
    }

    /// Parses an Address from a hex string without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s. Will return an error if
    /// the string has a `0x` prefix.
    pub fn from_raw_short_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        if hex.as_ref().starts_with(b"0x") {
            return Err(AddressParseError::UnexpectedPrefix);
        }
        Self::from_short_hex(hex)
    }

    /// Returns the string representation of this address in hex format with
    /// `0x` prefix.
    pub fn to_hex(&self) -> String {
        self.to_canonical_string(true)
    }

    /// Returns the string representation of this address in hex format without
    /// `0x` prefix.
    pub fn to_raw_hex(&self) -> String {
        self.to_canonical_string(false)
    }

    /// Returns the shortest possible string representation of the address (i.e.
    /// with leading zeroes trimmed).
    pub fn to_short_hex(&self) -> String {
        format!("0x{}", self.to_raw_short_hex())
    }

    /// Returns the shortest possible string representation of the address (i.e.
    /// with leading zeroes trimmed), without `0x` prefix.
    pub fn to_raw_short_hex(&self) -> String {
        let full_str = self.to_canonical_string(false);
        let trimmed = full_str.trim_start_matches('0');
        let hex_str = if trimmed.is_empty() { "0" } else { trimmed };
        hex_str.to_owned()
    }

    /// Returns the string representation of this address using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        let hex_str = hex::encode(self.0);
        if with_prefix {
            format!("0x{hex_str}")
        } else {
            hex_str
        }
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, AddressParseError> {
        let bytes = bytes.as_ref();
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|_| AddressParseError::InvalidByteLength {
                actual: bytes.len(),
            })
            .map(Self)
    }

    /// Returns the next address in byte-increasing order.
    pub const fn next_lexicographical(&self) -> Self {
        Self::new(crate::next_lexicographical_array(self.bytes()))
    }

    /// Returns the next address in byte-increasing order, or `None` if the
    /// result would overflow.
    pub const fn next_lexicographical_opt(&self) -> Option<Self> {
        match crate::next_lexicographical_array_opt(self.bytes()) {
            Some(val) => Some(Self::new(val)),
            None => None,
        }
    }
}

impl std::str::FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // If the string is not prefixed, we only accept full-length hex
        if s.starts_with("0x") {
            Self::from_prefixed_short_hex(s)
        } else {
            Self::from_hex(s)
        }
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for Address {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<Address> for [u8; 32] {
    fn from(address: Address) -> Self {
        address.into_bytes()
    }
}

impl From<[u8; 32]> for Address {
    fn from(address: [u8; 32]) -> Self {
        Self::new(address)
    }
}

impl From<Address> for Vec<u8> {
    fn from(value: Address) -> Self {
        value.0.to_vec()
    }
}

impl From<super::ObjectId> for Address {
    fn from(value: super::ObjectId) -> Self {
        Self::from_object_id(value)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string(true).fmt(f)
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Address")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
struct ReadableAddress;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl serde_with::SerializeAs<[u8; Address::LENGTH]> for ReadableAddress {
    fn serialize_as<S>(source: &[u8; Address::LENGTH], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = Address::new(*source);
        serde_with::DisplayFromStr::serialize_as(&address, serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl<'de> serde_with::DeserializeAs<'de, [u8; Address::LENGTH]> for ReadableAddress {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; Address::LENGTH], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let address: Address = serde_with::DisplayFromStr::deserialize_as(deserializer)?;
        Ok(address.into_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressParseError {
    #[error("address must be hex string of length {}", Address::LENGTH * 2)]
    FromHex(#[from] hex::FromHexError),
    #[error(
        "invalid address byte length: expected {}, got {actual}",
        Address::LENGTH
    )]
    InvalidByteLength { actual: usize },
    #[error("address hex string missing `0x` prefix")]
    MissingPrefix,
    #[error("address hex string has unexpected `0x` prefix")]
    UnexpectedPrefix,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "proptest")]
    mod proptests {
        use test_strategy::proptest;

        use super::super::Address;

        #[proptest]
        fn roundtrip_display_fromstr(address: Address) {
            assert_eq!(address, address.to_string().parse().unwrap());
        }
    }

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{Address, AddressParseError};

    #[test]
    fn parse_address_with_0x_prefix() {
        let hex = "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
        let address = Address::from_short_hex(hex).unwrap();
        assert_eq!(address.to_string(), hex);
    }

    #[test]
    fn parse_address_without_0x_prefix() {
        let hex = "02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
        let address = Address::from_short_hex(hex).unwrap();
        assert_eq!(
            address.to_string(),
            "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331"
        );
    }

    #[test]
    fn parse_short_address_single_digit() {
        let address = Address::from_short_hex("0x1").unwrap();
        assert_eq!(address, Address::STD);
        assert_eq!(
            address.to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn parse_short_address_without_prefix() {
        let address = Address::from_short_hex("3").unwrap();
        assert_eq!(address, Address::SYSTEM);
    }

    #[test]
    fn parse_zero_address() {
        let address = Address::from_short_hex("0x0").unwrap();
        assert_eq!(address, Address::ZERO);

        let address = Address::from_short_hex("0").unwrap();
        assert_eq!(address, Address::ZERO);

        let address = Address::from_short_hex(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(address, Address::ZERO);
    }

    #[test]
    fn parse_address_invalid_hex_char() {
        let result = Address::from_short_hex("0xGGGG");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(AddressParseError::FromHex(
                hex::FromHexError::InvalidHexCharacter { .. }
            ))
        ));
    }

    #[test]
    fn parse_address_too_long() {
        // 65 hex chars (one more than allowed 64)
        let result = Address::from_short_hex(
            "0x002a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331",
        );
        assert!(matches!(
            result,
            Err(AddressParseError::FromHex(hex::FromHexError::OddLength))
        ));

        // 66 hex chars (two more than allowed 64)
        let result = Address::from_short_hex(
            "0x002a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f3316",
        );
        assert!(matches!(
            result,
            Err(AddressParseError::FromHex(
                hex::FromHexError::InvalidStringLength
            ))
        ));
    }

    #[test]
    fn parse_raw_hex() {
        let hex = "02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
        let address = Address::from_raw_hex(hex).unwrap();
        assert_eq!(address.to_raw_hex(), hex);

        let result = Address::from_raw_hex(format!("0x{hex}"));
        assert!(matches!(result, Err(AddressParseError::UnexpectedPrefix)));
    }

    #[test]
    fn parse_raw_short_hex() {
        let address = Address::from_raw_short_hex("2").unwrap();
        assert_eq!(address, Address::FRAMEWORK);

        let result = Address::from_raw_short_hex("0x2");
        assert!(matches!(result, Err(AddressParseError::UnexpectedPrefix)));
    }

    #[test]
    fn from_bytes_valid() {
        let bytes = [0u8; 32];
        let address = Address::from_bytes(bytes).unwrap();
        assert_eq!(address, Address::ZERO);
    }

    #[test]
    fn from_bytes_invalid_length() {
        let bytes = [0u8; 31];
        let result = Address::from_bytes(bytes);
        assert!(matches!(
            result,
            Err(AddressParseError::InvalidByteLength { actual: 31 })
        ));

        let bytes = [0u8; 33];
        let result = Address::from_bytes(bytes);
        assert!(matches!(
            result,
            Err(AddressParseError::InvalidByteLength { actual: 33 })
        ));
    }

    #[test]
    fn to_short_string_formats() {
        let address = Address::from_short_hex("0x2").unwrap();
        assert_eq!(address.to_short_hex(), "0x2");
        assert_eq!(address.to_raw_short_hex(), "2");

        let zero = Address::ZERO;
        assert_eq!(zero.to_short_hex(), "0x0");
        assert_eq!(zero.to_raw_short_hex(), "0");
    }

    #[test]
    fn to_canonical_string_formats() {
        let address = Address::from_short_hex("0x2").unwrap();
        assert_eq!(
            address.to_canonical_string(true),
            "0x0000000000000000000000000000000000000000000000000000000000000002"
        );
        assert_eq!(
            address.to_canonical_string(false),
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn formats() {
        let actual = Address::from_short_hex("0x2").unwrap();

        println!("{}", serde_json::to_string(&actual).unwrap());
        println!("{:?}", bcs::to_bytes(&actual).unwrap());
        let a: Address = serde_json::from_str("\"0x2\"").unwrap();
        println!("{a}");
    }
}
