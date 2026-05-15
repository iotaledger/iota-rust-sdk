// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Move standard library (system package `0x1`).

/// Types from `0x1::fixed_point32`.
pub mod fixed_point32 {
    /// Rust version of the Move `std::fixed_point32::FixedPoint32` type.
    ///
    /// A fixed-point numeric type with 32 fractional bits, represented by an
    /// underlying `u64`.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct FixedPoint32 {
        pub value: u64,
    }

    impl FixedPoint32 {
        pub const fn new(value: u64) -> Self {
            Self { value }
        }
    }
}

/// Types from `0x1::ascii`.
pub mod ascii {
    /// Rust version of the Move `std::ascii::String` type.
    ///
    /// The Move type guarantees that all bytes are valid ASCII. This Rust
    /// mirror does **not** enforce that invariant — it is up to the caller.
    /// Wire format: a length-prefixed byte vector.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct String {
        pub bytes: Vec<u8>,
    }

    impl String {
        pub const fn new(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
    }

    /// Rust version of the Move `std::ascii::Char` type.
    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Char {
        pub byte: u8,
    }

    impl Char {
        pub const fn new(byte: u8) -> Self {
            Self { byte }
        }
    }
}

/// Types from `0x1::string`.
pub mod string {
    /// Rust version of the Move `std::string::String` type.
    ///
    /// The Move type holds a UTF-8 encoded byte sequence. This Rust mirror
    /// does **not** enforce that invariant. Wire format: a length-prefixed
    /// byte vector — identical to Rust's [`prim@String`].
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct String {
        pub bytes: Vec<u8>,
    }

    impl String {
        pub const fn new(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
    }
}

/// Types from `0x1::uq32_32`.
pub mod uq32_32 {
    /// Rust version of the Move `std::uq32_32::UQ32_32` type.
    ///
    /// An unsigned fixed-point numeric type with 32 integer bits and 32
    /// fractional bits, represented by an underlying `u64`.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct UQ32_32(pub u64);

    impl UQ32_32 {
        pub const fn new(value: u64) -> Self {
            Self(value)
        }
    }
}

/// Types from `0x1::uq64_64`.
pub mod uq64_64 {
    /// Rust version of the Move `std::uq64_64::UQ64_64` type.
    ///
    /// An unsigned fixed-point numeric type with 64 integer bits and 64
    /// fractional bits, represented by an underlying `u128`.
    #[allow(non_camel_case_types)]
    #[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct UQ64_64(pub u128);

    impl UQ64_64 {
        pub const fn new(value: u128) -> Self {
            Self(value)
        }
    }
}

/// Types from `0x1::bit_vector`.
pub mod bit_vector {
    /// Rust version of the Move `std::bit_vector::BitVector` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct BitVector {
        pub length: u64,
        pub bit_field: Vec<bool>,
    }

    impl BitVector {
        pub const fn new(length: u64, bit_field: Vec<bool>) -> Self {
            Self { length, bit_field }
        }
    }
}

/// Types from `0x1::type_name`.
pub mod type_name {
    use super::ascii::String as AsciiString;

    /// Rust version of the Move `std::type_name::TypeName` type.
    ///
    /// String representation of a Move type, using its source syntax. For
    /// example: `00000000000000000000000000000001::string::String`, or
    /// for nested generics:
    /// `0000…0a::module_name1::type_name1<0000…0a::module_name2::type_name2<u64>>`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TypeName {
        pub name: AsciiString,
    }

    impl TypeName {
        pub const fn new(name: AsciiString) -> Self {
            Self { name }
        }
    }
}

/// Types from `0x1::option`.
pub mod option {
    /// Rust version of the Move `std::option::Option<Element>` type.
    ///
    /// Move encodes optional values as a `vector` of length 0 or 1. The wire
    /// format is identical to Rust's prelude [`prim@Option`], so most code
    /// can use that instead — this mirror is provided for parity with the
    /// Move source.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Option<Element> {
        pub vec: Vec<Element>,
    }

    impl<Element> Option<Element> {
        pub const fn new(vec: Vec<Element>) -> Self {
            Self { vec }
        }
    }

    impl<Element> Default for Option<Element> {
        fn default() -> Self {
            Self { vec: Vec::new() }
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn fixed_point32_bcs_roundtrip() {
        let f = fixed_point32::FixedPoint32::new(0xdead_beef);
        let bytes = bcs::to_bytes(&f).unwrap();
        let decoded: fixed_point32::FixedPoint32 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn ascii_string_bcs_roundtrip() {
        let s = ascii::String::new(b"hello".to_vec());
        let bytes = bcs::to_bytes(&s).unwrap();
        // Wire format: length-prefixed bytes — identical to a `Vec<u8>`.
        assert_eq!(bytes, bcs::to_bytes(&b"hello".to_vec()).unwrap());
        let decoded: ascii::String = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn ascii_char_bcs_roundtrip() {
        let c = ascii::Char::new(b'A');
        let bytes = bcs::to_bytes(&c).unwrap();
        assert_eq!(bytes, [b'A']);
        let decoded: ascii::Char = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn string_bcs_roundtrip() {
        let s = string::String::new("héllo".as_bytes().to_vec());
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: string::String = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn option_none_bcs_roundtrip() {
        let o: option::Option<u64> = option::Option::default();
        let bytes = bcs::to_bytes(&o).unwrap();
        // Move `option::Option<T>` is wire-compatible with Rust's `Option<T>`:
        //   None → [0]; Some(x) → [1, <x>].
        assert_eq!(bytes, bcs::to_bytes::<Option<u64>>(&None).unwrap());
        let decoded: option::Option<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(o, decoded);
    }

    #[test]
    fn option_some_bcs_roundtrip() {
        let o: option::Option<u64> = option::Option::new(vec![42]);
        let bytes = bcs::to_bytes(&o).unwrap();
        assert_eq!(bytes, bcs::to_bytes::<Option<u64>>(&Some(42)).unwrap());
        let decoded: option::Option<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(o, decoded);
    }

    #[test]
    fn uq32_32_bcs_roundtrip() {
        let q = uq32_32::UQ32_32::new(0xdead_beef_cafe_babe);
        let bytes = bcs::to_bytes(&q).unwrap();
        assert_eq!(bytes, 0xdead_beef_cafe_babe_u64.to_le_bytes());
        let decoded: uq32_32::UQ32_32 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn uq64_64_bcs_roundtrip() {
        let q = uq64_64::UQ64_64::new(0xdead_beef);
        let bytes = bcs::to_bytes(&q).unwrap();
        assert_eq!(bytes, 0xdead_beef_u128.to_le_bytes());
        let decoded: uq64_64::UQ64_64 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn bit_vector_bcs_roundtrip() {
        let bv = bit_vector::BitVector::new(3, vec![true, false, true]);
        let bytes = bcs::to_bytes(&bv).unwrap();
        let decoded: bit_vector::BitVector = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(bv, decoded);
    }

    // -------------------------------------------------------------
    // moverox-parity tests
    // -------------------------------------------------------------

    use crate::parity_check::assert_parity;

    #[test]
    fn fixed_point32_moverox_parity() {
        let sample = fixed_point32::FixedPoint32::new(42);
        assert_parity::<_, crate::generated::std::fixed_point32::FixedPoint32>(&sample);
    }

    #[test]
    fn uq32_32_moverox_parity() {
        let sample = uq32_32::UQ32_32::new(42);
        assert_parity::<_, crate::generated::std::uq32_32::UQ32_32>(&sample);
    }

    #[test]
    fn uq64_64_moverox_parity() {
        let sample = uq64_64::UQ64_64::new(42);
        assert_parity::<_, crate::generated::std::uq64_64::UQ64_64>(&sample);
    }

    #[test]
    fn bit_vector_moverox_parity() {
        let sample = bit_vector::BitVector::new(3, vec![true, false, true]);
        assert_parity::<_, crate::generated::std::bit_vector::BitVector>(&sample);
    }

    #[test]
    fn string_moverox_parity() {
        let sample = string::String::new(b"hello".to_vec());
        assert_parity::<_, crate::generated::std::string::String>(&sample);
    }

    #[test]
    fn ascii_string_and_char_moverox_parity() {
        let s = ascii::String::new(b"hi".to_vec());
        assert_parity::<_, crate::generated::std::ascii::String>(&s);
        let c = ascii::Char::new(b'A');
        assert_parity::<_, crate::generated::std::ascii::Char>(&c);
    }

    #[test]
    fn option_moverox_parity() {
        let none: option::Option<u64> = option::Option::default();
        assert_parity::<_, crate::generated::std::option::Option<u64>>(&none);
        let some: option::Option<u64> = option::Option::new(vec![42]);
        assert_parity::<_, crate::generated::std::option::Option<u64>>(&some);
    }

    #[test]
    fn type_name_moverox_parity() {
        let sample =
            type_name::TypeName::new(ascii::String::new(b"0x2::iota::IOTA".to_vec()));
        assert_parity::<_, crate::generated::std::type_name::TypeName>(&sample);
    }
}
