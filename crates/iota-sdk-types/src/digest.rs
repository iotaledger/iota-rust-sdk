// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

const OBJECT_DIGEST_DELETED_BYTE_VAL: u8 = 99;
const OBJECT_DIGEST_WRAPPED_BYTE_VAL: u8 = 88;
const OBJECT_DIGEST_CANCELLED_BYTE_VAL: u8 = 77;

/// A 32-byte Blake2b256 hash output.
///
/// # BCS
///
/// A `Digest`'s BCS serialized form is defined by the following:
///
/// ```text
/// digest = %d32 32OCTET
/// ```
///
/// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
/// IOTA's binary representation of a `Digest` is prefixed with its length
/// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
/// compact 32 bytes.
#[derive(Clone, Copy, Default, derive_more::Deref, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "%d32 32OCTET")
)]
pub struct Digest(
    #[cfg_attr(feature = "serde", serde(with = "DigestSerialization"))] [u8; Self::LENGTH],
);

impl Digest {
    /// A constant representing the length of a digest in bytes.
    pub const LENGTH: usize = 32;

    /// A constant representing a zero digest.
    pub const ZERO: Self = Self([0; Self::LENGTH]);

    /// The lexicographically minimum digest
    pub const MIN: Self = Self([u8::MIN; 32]);

    /// The lexicographically maximum digest
    pub const MAX: Self = Self([u8::MAX; 32]);

    /// A marker that signifies the object is deleted.
    pub const OBJECT_DELETED: Self = Self([OBJECT_DIGEST_DELETED_BYTE_VAL; 32]);

    /// A marker that signifies the object is wrapped into another object.
    pub const OBJECT_WRAPPED: Self = Self([OBJECT_DIGEST_WRAPPED_BYTE_VAL; 32]);

    /// A marker that signifies the object is cancelled.
    pub const OBJECT_CANCELLED: Self = Self([OBJECT_DIGEST_CANCELLED_BYTE_VAL; 32]);

    /// A digest used to signify the parent transaction was the genesis.
    /// Note that this is not the same as the digest of the genesis transaction,
    /// which cannot be known ahead of time.
    pub const GENESIS_MARKER: Self = Self::ZERO;

    /// Generates a new digest from the provided 32 byte array containing [`u8`]
    /// values.
    pub const fn new(digest: [u8; Self::LENGTH]) -> Self {
        Self(digest)
    }

    /// Generates a new digest from the provided random number generator.
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

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random() -> Self {
        Self::generate(rand_core::OsRng)
    }

    /// Returns a slice to the inner array representation of this digest.
    pub const fn inner(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Returns the inner array representation of this digest.
    pub const fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Returns a slice of bytes representing the digest.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes a digest from a Base58 encoded string.
    pub fn from_base58<T: AsRef<[u8]>>(base58: T) -> Result<Self, DigestParseError> {
        Self::from_bytes(bs58::decode(base58).into_vec()?)
    }

    /// Returns a Base58 encoded string representation of this digest.
    pub fn to_base58(&self) -> String {
        self.to_string()
    }

    /// Generates a digest from bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, DigestParseError> {
        let bytes = bytes.as_ref();
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|_| DigestParseError::InvalidByteLength {
                actual: bytes.len(),
            })
            .map(Self)
    }

    /// Returns the next digest in byte-increasing order.
    pub const fn next_lexicographical(&self) -> Self {
        Self(crate::next_lexicographical_array(&self.0))
    }

    /// Returns the next digest in byte-increasing order, or `None` if the
    /// result would overflow.
    pub const fn next_lexicographical_opt(&self) -> Option<Self> {
        match crate::next_lexicographical_array_opt(&self.0) {
            Some(val) => Some(Self(val)),
            None => None,
        }
    }

    /// Returns whether the digest represents an object that is neither deleted
    /// nor wrapped
    pub fn is_object_alive(&self) -> bool {
        !self.is_object_deleted() && !self.is_object_wrapped()
    }

    /// Returns whether the digest represents a deleted object
    pub fn is_object_deleted(&self) -> bool {
        *self == Self::OBJECT_DELETED
    }

    /// Returns whether the digest represents an object wrapped in another
    /// object.
    pub fn is_object_wrapped(&self) -> bool {
        *self == Self::OBJECT_WRAPPED
    }
}

impl std::str::FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base58(s)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; Self::LENGTH]> for Digest {
    fn as_ref(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<Digest> for [u8; Digest::LENGTH] {
    fn from(digest: Digest) -> Self {
        digest.into_inner()
    }
}

impl From<[u8; Self::LENGTH]> for Digest {
    fn from(digest: [u8; Self::LENGTH]) -> Self {
        Self::new(digest)
    }
}

impl PartialEq<[u8; Self::LENGTH]> for Digest {
    fn eq(&self, other: &[u8; Self::LENGTH]) -> bool {
        &self.0 == other
    }
}

impl PartialEq<Digest> for [u8; Digest::LENGTH] {
    fn eq(&self, other: &Digest) -> bool {
        self == &other.0
    }
}

impl PartialEq<Digest> for &[u8] {
    fn eq(&self, other: &Digest) -> bool {
        *self == other.0.as_slice()
    }
}

impl PartialEq<&[u8]> for Digest {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0.as_slice() == *other
    }
}

impl PartialEq<Vec<u8>> for Digest {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0.as_slice() == other.as_slice()
    }
}

impl PartialEq<Digest> for Vec<u8> {
    fn eq(&self, other: &Digest) -> bool {
        self.as_slice() == other.0.as_slice()
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // output size is determined via the following formula:
        //      N * log(256) / log(58) + 1 (round up)
        // where N = 32 this results in a value of 45
        let mut buf = [0; 45];

        let len = bs58::encode(&self.0).onto(&mut buf[..]).unwrap();
        let encoded = std::str::from_utf8(&buf[..len]).unwrap();

        f.write_str(encoded)
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Digest")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

impl std::fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl std::fmt::UpperHex for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }

        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }

        Ok(())
    }
}

// Unfortunately IOTA's binary representation of digests is prefixed with its
// length meaning its serialized binary form is 33 bytes long (in bcs) vs a more
// compact 32 bytes.
#[cfg(feature = "serde")]
type DigestSerialization =
    ::serde_with::As<::serde_with::IfIsHumanReadable<ReadableDigest, ::serde_with::Bytes>>;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
struct ReadableDigest;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl serde_with::SerializeAs<[u8; Digest::LENGTH]> for ReadableDigest {
    fn serialize_as<S>(source: &[u8; Digest::LENGTH], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let digest = Digest::new(*source);
        serde_with::DisplayFromStr::serialize_as(&digest, serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl<'de> serde_with::DeserializeAs<'de, [u8; Digest::LENGTH]> for ReadableDigest {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; Digest::LENGTH], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let digest: Digest = serde_with::DisplayFromStr::deserialize_as(deserializer)?;
        Ok(digest.into_inner())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DigestParseError {
    #[error("digest must be Base58 string of length 44")]
    Base58(#[from] bs58::decode::Error),
    #[error(
        "invalid digest byte length: expected {}, got {actual}",
        Digest::LENGTH
    )]
    InvalidByteLength { actual: usize },
}

// Don't implement like the other digest type since this isn't intended to be
// serialized
pub type SigningDigest = [u8; Digest::LENGTH];

#[cfg(all(test, feature = "proptest"))]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn roundtrip_display_fromstr(digest: Digest) {
        let s = digest.to_string();
        let d = s.parse::<Digest>().unwrap();
        assert_eq!(digest, d);
    }

    #[test]
    fn parse_valid_base58() {
        // A valid Base58 encoded digest (32 bytes)
        let digest = Digest::new([1u8; 32]);
        let base58 = digest.to_base58();
        let parsed = Digest::from_base58(&base58).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn parse_invalid_base58_characters() {
        // '0', 'O', 'I', 'l' are not valid Base58 characters
        let result = Digest::from_base58("0OIl");
        assert_eq!(
            result,
            Err(DigestParseError::Base58(
                bs58::decode::Error::InvalidCharacter {
                    character: '0',
                    index: 0
                }
            ))
        );
    }

    #[test]
    fn parse_empty_string() {
        let result = Digest::from_base58("");
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 0 })
        );
    }

    #[test]
    fn parse_too_short_base58() {
        // This decodes to fewer than 32 bytes
        let result = Digest::from_base58("abc");
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 3 })
        );
    }

    #[test]
    fn parse_too_long_base58() {
        // Create a string that would decode to more than 32 bytes
        let long_base58 = "1".repeat(100);
        let result = Digest::from_base58(&long_base58);
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 100 })
        );
    }

    #[test]
    fn from_bytes_valid() {
        let bytes = [42u8; 32];
        let digest = Digest::from_bytes(bytes).unwrap();
        assert_eq!(digest.into_inner(), bytes);
    }

    #[test]
    fn from_bytes_too_short() {
        let bytes = [1u8; 31];
        let result = Digest::from_bytes(bytes);
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 31 })
        );
    }

    #[test]
    fn from_bytes_too_long() {
        let bytes = [1u8; 33];
        let result = Digest::from_bytes(bytes);
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 33 })
        );
    }

    #[test]
    fn partial_eq_array_u8() {
        let digest = Digest::new([1u8; 32]);
        let matching = [1u8; 32];
        let non_matching = [2u8; 32];

        assert_eq!(digest, matching);
        assert_eq!(matching, digest);
        assert_ne!(digest, non_matching);
        assert_ne!(non_matching, digest);
    }

    #[test]
    fn partial_eq_vec_u8() {
        let digest = Digest::new([1u8; 32]);
        let matching = vec![1u8; 32];
        let non_matching = vec![2u8; 32];
        let wrong_length = vec![1u8; 31];

        assert_eq!(digest, matching);
        assert_eq!(matching, digest);
        assert_ne!(digest, non_matching);
        assert_ne!(non_matching, digest);
        assert_ne!(digest, wrong_length);
        assert_ne!(wrong_length, digest);
    }

    #[test]
    fn from_bytes_empty() {
        let bytes: [u8; 0] = [];
        let result = Digest::from_bytes(bytes);
        assert_eq!(
            result,
            Err(DigestParseError::InvalidByteLength { actual: 0 })
        );
    }
}
