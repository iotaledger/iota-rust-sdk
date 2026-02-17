// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// A 32-byte Blake2b256 hash output.
///
/// # BCS
///
/// A `Digest`'s BCS serialized form is defined by the following:
///
/// ```text
/// digest = %x20 32OCTET
/// ```
///
/// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
/// IOTA's binary representation of a `Digest` is prefixed with its length
/// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
/// compact 32 bytes.
#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Digest(
    #[cfg_attr(feature = "serde", serde(with = "DigestSerialization"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base58"))]
    [u8; Self::LENGTH],
);

impl Digest {
    /// A constant representing the length of a digest in bytes.
    pub const LENGTH: usize = 32;
    /// A constant representing a zero digest.
    pub const ZERO: Self = Self([0; Self::LENGTH]);

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
        let mut buf = [0; Self::LENGTH];

        bs58::decode(base58)
            .onto(&mut buf)
            // TODO fix error to contain bs58 parse error
            .map_err(|_| DigestParseError)?;

        Ok(Self(buf))
    }

    /// Returns a Base58 encoded string representation of this digest.
    pub fn to_base58(&self) -> String {
        self.to_string()
    }

    /// Generates a digest from bytes.
    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, DigestParseError> {
        <[u8; Self::LENGTH]>::try_from(bytes.as_ref())
            .map_err(|_| DigestParseError)
            .map(Self)
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        let mut next_digest = *self;
        for byte in next_digest.0.iter_mut().rev() {
            let (new_byte, overflow) = byte.overflowing_add(1);
            *byte = new_byte;
            if !overflow {
                break;
            }
        }
        next_digest
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DigestParseError;

impl std::fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Unable to parse Digest (must be Base58 string of length {})",
            44,
        )
    }
}

impl std::error::Error for DigestParseError {}

// Don't implement like the other digest type since this isn't intended to be
// serialized
pub type SigningDigest = [u8; Digest::LENGTH];

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn roundtrip_display_fromstr(digest: Digest) {
        let s = digest.to_string();
        let d = s.parse::<Digest>().unwrap();
        assert_eq!(digest, d);
    }

    // --- Construction ---

    #[test]
    fn new_and_inner_roundtrip() {
        let bytes = [0xABu8; 32];
        let digest = Digest::new(bytes);
        assert_eq!(*digest.inner(), bytes);
        assert_eq!(digest.into_inner(), bytes);
    }

    #[test]
    fn zero_constant_is_all_zeros() {
        assert_eq!(Digest::ZERO, Digest::new([0u8; 32]));
        assert_eq!(Digest::ZERO.as_bytes(), &[0u8; 32]);
    }

    // --- from_bytes ---

    #[test]
    fn from_bytes_valid_32_bytes() {
        let bytes = vec![0xFFu8; 32];
        let digest = Digest::from_bytes(&bytes).unwrap();
        assert_eq!(digest.as_bytes(), &bytes[..]);
    }

    #[test]
    fn from_bytes_invalid_length_too_short() {
        let bytes = vec![0u8; 31];
        let result = Digest::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_invalid_length_too_long() {
        let bytes = vec![0u8; 33];
        let result = Digest::from_bytes(&bytes);
        assert!(result.is_err());
    }

    // --- from_base58 ---

    #[test]
    fn from_base58_invalid_string() {
        // "0OIl" contains characters invalid in Base58
        let result = Digest::from_base58("0OIl");
        assert!(result.is_err());
    }

    #[test]
    fn from_base58_too_long() {
        // A valid Base58 string that decodes to more than 32 bytes
        let long_b58 = "1111111111111111111111111111111111111111111111111111111111111111111111";
        let result = Digest::from_base58(long_b58);
        assert!(result.is_err());
    }

    // --- Display, Debug, LowerHex formatting ---

    #[test]
    fn lower_hex_without_prefix() {
        let digest = Digest::new([0x01; 32]);
        let hex = format!("{:x}", digest);
        assert_eq!(hex.len(), 64, "hex without prefix should be 64 chars");
        assert!(!hex.starts_with("0x"));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn lower_hex_with_alternate_prefix() {
        let digest = Digest::new([0x01; 32]);
        let hex = format!("{:#x}", digest);
        assert!(
            hex.starts_with("0x"),
            "alternate hex should have 0x prefix"
        );
        assert_eq!(hex.len(), 66);
    }

    #[test]
    fn debug_format_includes_display() {
        let digest = Digest::new([0x01; 32]);
        let debug = format!("{:?}", digest);
        let display = format!("{}", digest);
        // Debug format wraps the display inside Digest("...")
        assert!(
            debug.contains(&display),
            "Debug format should contain the Display string"
        );
        assert!(debug.starts_with("Digest("));
    }

    // --- Conversions ---

    #[test]
    fn from_byte_array() {
        let bytes = [0xCD; 32];
        let digest = Digest::from(bytes);
        assert_eq!(digest, Digest::new(bytes));
    }

    #[test]
    fn into_byte_array() {
        let bytes = [0xEF; 32];
        let digest = Digest::new(bytes);
        let out: [u8; 32] = digest.into();
        assert_eq!(out, bytes);
    }

    #[test]
    fn as_ref_returns_slice() {
        let bytes = [0x99; 32];
        let digest = Digest::new(bytes);
        let slice: &[u8] = digest.as_ref();
        assert_eq!(slice, &bytes[..]);
    }

    #[test]
    fn as_ref_returns_array() {
        let bytes = [0x88; 32];
        let digest = Digest::new(bytes);
        let arr: &[u8; 32] = digest.as_ref();
        assert_eq!(arr, &bytes);
    }

    // --- Existing tests below ---

    #[test]
    fn test_lexical_order() {
        fn digest_from_str(s: &str) -> Digest {
            Digest::new(hex::decode(s).unwrap().try_into().unwrap())
        }
        assert_eq!(
            digest_from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .next_lexicographical(),
            digest_from_str("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(
            digest_from_str("000000000000000000000000000000000000000000000000000000000000ffff")
                .next_lexicographical(),
            digest_from_str("0000000000000000000000000000000000000000000000000000000000010000"),
        );
        assert_eq!(
            digest_from_str("000000000000000000000000000000000000000000000000000000000001002c")
                .next_lexicographical(),
            digest_from_str("000000000000000000000000000000000000000000000000000000000001002d"),
        );
        assert_eq!(
            digest_from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .next_lexicographical(),
            digest_from_str("0000000000000000000000000000000000000000000000000000000000000000"),
        );
    }
}
