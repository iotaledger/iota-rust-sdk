// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust representations of Move types used by the IOTA blockchain.
//!
//! Each top-level module corresponds to a system package, identified by the
//! address constants on [`iota_types::Address`]:
//!
//! - [`std`]         — `0x1`, the Move standard library
//! - [`framework`]   — `0x2`, the IOTA framework
//! - [`iota_system`] — `0x3`, the IOTA system package
//! - [`stardust`]    — `0x107a`, the Stardust migration package
//!
//! Inside each package, every Move source module is mirrored 1:1 as a Rust
//! `pub mod`. Generic Move types stay generic in Rust (with a
//! `PhantomData<T>` placeholder for phantom parameters).

mod packages;
pub use packages::{framework, iota_system, stardust, std};

#[cfg(test)]
mod move_shape;

#[cfg(all(test, feature = "serde"))]
mod move_shape_compare;

/// Error returned by the `try_from_object` constructors on type mirrors.
///
/// All Tier 1 types share this error shape: the caller passed an `Object`
/// that either isn't a Move struct, has a type tag that doesn't match the
/// expected type, or whose BCS contents fail to decode.
#[cfg(feature = "serde")]
#[derive(Debug)]
#[non_exhaustive]
pub enum FromObjectError {
    /// The object is a package, not a Move struct.
    NotAMoveStruct,
    /// The Move struct's type tag does not match the expected type.
    WrongType,
    /// BCS decoding of the struct contents failed.
    Bcs(bcs::Error),
}

#[cfg(feature = "serde")]
impl core::fmt::Display for FromObjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAMoveStruct => f.write_str("object is not a Move struct"),
            Self::WrongType => f.write_str("object's type tag does not match expected type"),
            Self::Bcs(e) => write!(f, "bcs decoding failed: {e}"),
        }
    }
}

#[cfg(feature = "serde")]
impl core::error::Error for FromObjectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bcs(e) => Some(e),
            _ => None,
        }
    }
}
