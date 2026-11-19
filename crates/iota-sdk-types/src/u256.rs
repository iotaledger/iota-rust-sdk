// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// A 256-bit unsigned integer matching Move's `u256` primitive type.
///
/// Parsed from and displayed as a decimal number.
///
/// ```
/// use iota_sdk_types::U256;
///
/// let value: U256 = "340282366920938463463374607431768211456".parse()?;
/// assert_eq!(value.to_le_bytes()[16], 1);
/// assert_eq!(U256::from(7u64).to_string(), "7");
/// # Ok::<_, iota_sdk_types::U256ParseError>(())
/// ```
///
/// # BCS
///
/// The BCS serialized form of this type is its 32 little-endian bytes, the
/// form Move reads a `u256` in. In human-readable formats it is a decimal
/// string.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    feature = "bcs-schema",
    derive(iota_bcs_schema::BcsSchema),
    bcs_schema(definition = "32OCTET")
)]
pub struct U256(bnum::BUintD8<{ Self::LENGTH }>);

impl U256 {
    /// The length of a `u256` in bytes.
    pub const LENGTH: usize = 32;

    /// The smallest value, `0`.
    pub const ZERO: Self = Self(bnum::BUintD8::ZERO);

    /// The value `1`.
    pub const ONE: Self = Self(bnum::BUintD8::ONE);

    /// The largest value, `2^256 - 1`.
    pub const MAX: Self = Self(bnum::BUintD8::MAX);

    /// Create a `U256` from its 32 little-endian bytes.
    pub const fn from_le_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bnum::BUintD8::from_digits(bytes))
    }

    /// Return the 32 little-endian bytes of this value.
    pub const fn to_le_bytes(self) -> [u8; Self::LENGTH] {
        *self.0.digits()
    }
}

/// Error returned when a string cannot be parsed into a [`U256`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum U256ParseError {
    #[error("cannot parse a u256 from an empty string")]
    Empty,
    #[error("invalid digit found in u256 string")]
    InvalidDigit,
    #[error("number too large to fit in a u256")]
    Overflow,
}

macro_rules! impl_from_primitive {
    ($($ty:ty),+) => {
        $(
            impl From<$ty> for U256 {
                fn from(value: $ty) -> Self {
                    Self(bnum::BUintD8::from(value))
                }
            }
        )+
    };
}

impl_from_primitive!(u8, u16, u32, u64, u128);

impl std::str::FromStr for U256 {
    type Err = U256ParseError;

    /// Parse a decimal number made of ASCII digits only.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(U256ParseError::Empty);
        }
        if !s.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(U256ParseError::InvalidDigit);
        }
        bnum::BUintD8::from_str_radix(s, 10)
            .map(Self)
            .map_err(|_| U256ParseError::Overflow)
    }
}

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad_integral(true, "", &self.0.to_str_radix(10))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for U256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serde::Serialize::serialize(&self.to_le_bytes(), serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for U256 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s: std::borrow::Cow<'de, str> = serde::Deserialize::deserialize(deserializer)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            let bytes: [u8; Self::LENGTH] = serde::Deserialize::deserialize(deserializer)?;
            Ok(Self::from_le_bytes(bytes))
        }
    }
}

#[cfg(feature = "proptest")]
impl proptest::arbitrary::Arbitrary for U256 {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_map(Self::from_le_bytes)
            .boxed()
    }
}

#[cfg(all(test, feature = "proptest"))]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;
    use proptest::prelude::*;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn le_bytes() {
        let mut one = [0; U256::LENGTH];
        one[0] = 1;
        assert_eq!(U256::ONE.to_le_bytes(), one);
        assert_eq!(U256::from_le_bytes(one), U256::ONE);
        assert_eq!(U256::ZERO.to_le_bytes(), [0; U256::LENGTH]);
        assert_eq!(U256::MAX.to_le_bytes(), [0xff; U256::LENGTH]);
        assert_eq!(U256::default(), U256::ZERO);
    }

    #[test]
    fn from_primitives() {
        assert_eq!(U256::from(1u8), U256::ONE);
        assert_eq!(U256::from(1u16), U256::ONE);
        assert_eq!(U256::from(1u32), U256::ONE);
        assert_eq!(U256::from(1u64), U256::ONE);
        assert_eq!(U256::from(1u128), U256::ONE);

        let mut bytes = [0; U256::LENGTH];
        bytes[..16].copy_from_slice(&u128::MAX.to_le_bytes());
        assert_eq!(U256::from(u128::MAX).to_le_bytes(), bytes);
    }

    #[test]
    fn parse() {
        const MAX: &str =
            "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        const MAX_PLUS_ONE: &str =
            "115792089237316195423570985008687907853269984665640564039457584007913129639936";

        assert_eq!(U256::from_str("0"), Ok(U256::ZERO));
        assert_eq!(U256::from_str("0001"), Ok(U256::ONE));
        assert_eq!(U256::from_str(MAX), Ok(U256::MAX));
        assert_eq!(U256::MAX.to_string(), MAX);
        assert_eq!(
            format!(
                "{:08}|{:>6}|{:.2}",
                U256::from(12345u64),
                U256::ONE,
                U256::from(12345u64)
            ),
            "00012345|     1|12345"
        );

        assert_eq!(U256::from_str(""), Err(U256ParseError::Empty));
        assert_eq!(U256::from_str(MAX_PLUS_ONE), Err(U256ParseError::Overflow));
        for invalid in ["+1", "-1", " 1", "1 ", "0x1", "1_000", "1.0", "١"] {
            assert_eq!(
                U256::from_str(invalid),
                Err(U256ParseError::InvalidDigit),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn ordering_is_numeric() {
        let mut high = [0; U256::LENGTH];
        high[31] = 1;
        assert!(U256::from_le_bytes(high) > U256::from(u128::MAX));
        assert!(U256::ZERO < U256::ONE);
        assert!(U256::ONE < U256::MAX);
    }

    #[proptest]
    fn decimal_matches_big_integer(value: U256) {
        let expected = BigUint::from_bytes_le(&value.to_le_bytes()).to_str_radix(10);
        assert_eq!(value.to_string(), expected);
        assert_eq!(U256::from_str(&expected), Ok(value));
    }

    #[proptest]
    fn too_large_numbers_are_rejected(
        #[strategy(proptest::collection::vec(any::<u8>(), 32..64))] mut bytes: Vec<u8>,
    ) {
        // Set a bit above the 256th.
        bytes.push(1);
        let too_large = BigUint::from_bytes_le(&bytes).to_str_radix(10);
        assert_eq!(U256::from_str(&too_large), Err(U256ParseError::Overflow));
    }

    #[cfg(feature = "serde")]
    #[proptest]
    fn bcs_is_32_little_endian_bytes(value: U256) {
        let bytes = bcs::to_bytes(&value).unwrap();
        assert_eq!(bytes, value.to_le_bytes());
        assert_eq!(bcs::from_bytes::<U256>(&bytes).unwrap(), value);
    }

    #[cfg(feature = "serde")]
    #[proptest]
    fn json_is_a_decimal_string(value: U256) {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json, serde_json::Value::String(value.to_string()));
        assert_eq!(serde_json::from_value::<U256>(json).unwrap(), value);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_rejects_numbers_and_invalid_strings() {
        serde_json::from_str::<U256>("1").unwrap_err();
        serde_json::from_str::<U256>("\"0x1\"").unwrap_err();
        serde_json::from_str::<U256>("\"\"").unwrap_err();
    }
}
