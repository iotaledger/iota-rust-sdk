// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
    pub const STD_LIB: Self = Self::from_u8(1);
    pub const FRAMEWORK: Self = Self::from_u8(2);
    pub const SYSTEM: Self = Self::from_u8(3);

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn from_u8(byte: u8) -> Self {
        let mut address = Self::ZERO;
        address.0[31] = byte;
        address
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    /// Return the underlying byte array of a Address.
    pub const fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub const fn inner(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, AddressParseError> {
        let hex = hex.as_ref();

        if !hex.starts_with(b"0x") {
            return Err(AddressParseError);
        }

        let hex = &hex[2..];

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
        // TODO fix error to contain hex parse error
        .map_err(|_| AddressParseError)
    }

    pub fn to_hex(&self) -> String {
        self.to_string()
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

    /// Returns the shortest possible string representation of the address (i.e.
    /// with leading zeroes trimmed).
    pub fn to_short_string(&self, with_prefix: bool) -> String {
        let full_str = self.to_canonical_string(false);
        let trimmed = full_str.trim_start_matches('0');
        let hex_str = if trimmed.is_empty() { "0" } else { trimmed };
        if with_prefix {
            format!("0x{hex_str}")
        } else {
            hex_str.to_owned()
        }
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, AddressParseError> {
        <[u8; Self::LENGTH]>::try_from(bytes.as_ref())
            .map_err(|_| AddressParseError)
            .map(Self)
    }
}

impl std::str::FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
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
        address.into_inner()
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
        Self::new(value.into_inner())
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
        Ok(address.into_inner())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressParseError;

impl std::fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Unable to parse Address (must be hex string of length {})",
            2 * Address::LENGTH
        )
    }
}

impl std::error::Error for AddressParseError {}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Address {
    fn schema_name() -> String {
        "Address".to_owned()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, Metadata, SchemaObject, StringValidation};

        let hex_length = Address::LENGTH * 2;
        SchemaObject {
            metadata: Some(Box::new(Metadata {
                title: Some(Self::schema_name()),
                description: Some("A 32-byte IOTA address, encoded as a hex string.".to_owned()),
                examples: vec![serde_json::to_value(Address::FRAMEWORK).unwrap()],
                ..Default::default()
            })),
            instance_type: Some(InstanceType::String.into()),
            format: Some("hex".to_owned()),
            string: Some(Box::new(StringValidation {
                max_length: Some((hex_length + 2) as u32),
                min_length: None,
                pattern: Some(format!("0x[a-z0-9]{{1,{hex_length}}}")),
            })),
            ..Default::default()
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn hex_parsing() {
        let actual = Address::from_hex("0x2").unwrap();
        let expected = "0x0000000000000000000000000000000000000000000000000000000000000002";

        assert_eq!(actual.to_string(), expected);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn formats() {
        let actual = Address::from_hex("0x2").unwrap();

        println!("{}", serde_json::to_string(&actual).unwrap());
        println!("{:?}", bcs::to_bytes(&actual).unwrap());
        let a: Address = serde_json::from_str("\"0x2\"").unwrap();
        println!("{a}");
    }

    #[proptest]
    fn roundtrip_display_fromstr(address: Address) {
        let s = address.to_string();
        let a = s.parse::<Address>().unwrap();
        assert_eq!(address, a);
    }
}
