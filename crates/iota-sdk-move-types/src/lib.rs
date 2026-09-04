// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust representations of Move types used by the IOTA blockchain.
//!
//! Each top-level module corresponds to a system package, identified by the
//! address constants on [`iota_types::Address`]:
//!
//! - [`move_stdlib`]    — `0x1`, the Move standard library
//! - [`iota_framework`] — `0x2`, the IOTA framework
//! - [`iota_system`]    — `0x3`, the IOTA system package
//! - [`stardust`]       — `0x107a`, the Stardust migration package
//!
//! Inside each package, every Move source module is mirrored 1:1 as a Rust
//! `pub mod`. Generic Move types stay generic in Rust (with a
//! `PhantomData<T>` placeholder for phantom parameters).

#[macro_use]
mod macros;

mod packages;
pub use packages::{iota_framework, iota_system, move_stdlib, stardust};

// The shape machinery (this module, the `MoveShape` derives on every
// mirror, and the comparator below) is native-only: the comparator reads
// the fetched package artifacts from disk at test time (no `std::fs` on
// wasm32), and its checks are target-independent — running them on one
// target covers all.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod move_shape;

#[cfg(all(test, feature = "serde", not(target_arch = "wasm32")))]
mod move_shape_compare;

/// A Rust type that knows the Move type tag it represents.
///
/// Generic mirrors like [`iota_framework::coin::CoinMetadata`] or
/// [`stardust::basic_output::BasicOutput`] take a marker type (e.g.
/// [`iota_framework::iota::IOTA`]) as their phantom type argument. Implementing
/// this trait declares which on-chain type the marker represents, which
/// lets the `try_from_object` constructors verify the object's type tag
/// against `T`. The marker is phantom, so the BCS bytes of e.g. a
/// `BasicOutput<IOTA>` and a `BasicOutput<OTHER>` are identical — the type
/// tag is the only place the coin type is recorded, and without this check
/// one would silently decode as the other.
///
/// To decode objects holding your own coin type, define an empty marker
/// struct and implement this trait for it. The `try_from_object`
/// constructors also require `T: serde::de::DeserializeOwned` (an artifact
/// of the serde derive on the generic mirrors — the phantom marker itself
/// is never deserialized), so derive `Deserialize` as well:
///
/// ```
/// #[derive(serde::Deserialize)]
/// struct FOO;
///
/// impl iota_sdk_move_types::MoveType for FOO {
///     fn type_tag() -> iota_types::TypeTag {
///         "0x123::foo::FOO".parse().unwrap()
///     }
/// }
/// ```
///
/// For coin types only known at runtime, use the
/// `try_from_object_with_type` constructors instead, which take the
/// expected [`TypeTag`](iota_types::TypeTag) as a value.
#[cfg(feature = "serde")]
pub trait MoveType {
    /// The Move type tag this type represents (e.g. `0x2::iota::IOTA`).
    fn type_tag() -> iota_types::TypeTag;
}

/// A Rust mirror that knows the Move struct tag of the objects it decodes.
///
/// Where [`MoveType`] names the type a *phantom marker* stands for, this names
/// the type of the object itself, so a caller holding only `T` can ask what to
/// fetch. Every mirror with a `TryFrom<&Object>` constructor implements it.
///
/// Generic mirrors take their type parameter's tag from [`MoveType`], so
/// `Coin<IOTA>` reports `0x2::coin::Coin<0x2::iota::IOTA>` while `Coin<T>` for
/// a marker of your own reports whatever that marker's [`MoveType`] impl
/// returns.
///
/// # Panics
///
/// [`iota_framework::coin::CoinMetadata`],
/// [`iota_framework::coin::TreasuryCap`]
/// and [`iota_framework::coin_manager::CoinManager`] are parameterised by a
/// coin *struct* rather than an arbitrary type, so their `struct_tag` panics if
/// the parameter's [`MoveType`] impl returns a primitive. Move has no such
/// type, so this only fires on a hand-written [`MoveType`] impl that is wrong.
#[cfg(feature = "serde")]
pub trait MoveObject:
    Sized + for<'a> TryFrom<&'a iota_types::Object, Error = FromObjectError>
{
    /// The Move struct tag of the objects this type mirrors.
    fn struct_tag() -> iota_types::StructTag;
}

/// Error returned when converting an `Object` into a typed mirror.
///
/// Every mirror's `TryFrom<&Object>` (and `try_from_object_with_type`)
/// conversion returns this on failure: the object either isn't a Move
/// struct, carries a type tag that doesn't match the expected type, or has
/// BCS contents that fail to decode.
#[cfg(feature = "serde")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FromObjectError {
    /// The object is a package, not a Move struct.
    #[error("object is not a Move struct")]
    NotAMoveStruct,
    /// The Move struct's type tag does not match the expected type.
    #[error("object's type tag does not match expected type")]
    WrongType,
    /// BCS decoding of the struct contents failed.
    #[error("bcs decoding failed: {0}")]
    Bcs(#[from] bcs::Error),
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;
    use crate::{
        iota_framework::{
            coin::{Coin, CoinMetadata},
            iota::IOTA,
        },
        iota_system::staking_pool::StakedIota,
    };

    #[test]
    fn non_generic_mirror_reports_its_move_type() {
        assert_eq!(
            StakedIota::struct_tag().to_string(),
            "0x3::staking_pool::StakedIota"
        );
    }

    #[test]
    fn generic_mirror_composes_its_type_parameter() {
        assert_eq!(
            Coin::<IOTA>::struct_tag().to_string(),
            "0x2::coin::Coin<0x2::iota::IOTA>"
        );
    }

    /// `CoinMetadata`'s tag constructor takes a `StructTag` rather than a
    /// `TypeTag`, so it goes through the macro's `@struct_param` arm.
    #[test]
    fn struct_parameterised_mirror_composes_its_type_parameter() {
        assert_eq!(
            CoinMetadata::<IOTA>::struct_tag().to_string(),
            "0x2::coin::CoinMetadata<0x2::iota::IOTA>"
        );
    }

    /// The tag a mirror advertises has to be the one its `TryFrom<&Object>`
    /// accepts. Both come from the same `add_struct_tag_ctor!` registration but
    /// through different halves of it, so a mismatched pairing in the macro
    /// would otherwise only surface as an empty result set at runtime.
    #[test]
    fn advertised_tag_satisfies_the_predicate_try_from_checks() {
        assert!(StakedIota::struct_tag().is_staked_iota());
        assert!(Coin::<IOTA>::struct_tag().is_coin());
        assert!(CoinMetadata::<IOTA>::struct_tag().is_coin_metadata());
    }
}
