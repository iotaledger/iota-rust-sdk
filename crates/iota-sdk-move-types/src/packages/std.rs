// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the Move standard library (system package `0x1`).

/// Types from `0x1::fixed_point32`.
pub mod fixed_point32 {
    /// Rust version of the Move `std::fixed_point32::FixedPoint32` type.
    ///
    /// A fixed-point numeric type with 32 fractional bits, represented by an
    /// underlying `u64`.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct String {
        pub bytes: Vec<u8>,
    }

    impl String {
        pub const fn new(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
    }

    /// Rust version of the Move `std::ascii::Char` type.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    /// byte vector — identical to Rust's [`struct@String`].
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    use super::ascii;

    /// Rust version of the Move `std::type_name::TypeName` type.
    ///
    /// String representation of a Move type, using its source syntax. For
    /// example: `00000000000000000000000000000001::string::String`, or
    /// for nested generics:
    /// `0a::module_name1::type_name1<0a::module_name2::type_name2<u64>>`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct TypeName {
        pub name: ascii::String,
    }

    impl TypeName {
        pub const fn new(name: ascii::String) -> Self {
            Self { name }
        }
    }
}

/// Types from `0x1::option`.
pub mod option {
    /// Rust version of the Move `std::option::Option<Element>` type.
    ///
    /// Move encodes optional values as a `vector` of length 0 or 1. The wire
    /// format is identical to Rust's prelude [`struct@Option`], so most code
    /// can use that instead — this mirror is provided for parity with the
    /// Move source.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
