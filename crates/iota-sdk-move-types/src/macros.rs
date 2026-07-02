// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Internal macros generating the `Object` constructors that every `key`
//! Move-object mirror shares.
//!
//! The mirrors differ only in their type, the [`StructTag`] predicate that
//! identifies them, and (for generic mirrors) their single type parameter, so
//! the `TryFrom<&Object>` / `try_from_object_with_type` bodies are otherwise
//! identical boilerplate. `from_bcs` and the field accessors stay hand-written
//! per type.
//!
//! [`StructTag`]: iota_types::StructTag

/// Generate the `TryFrom<&Object>` constructor for a non-generic mirror.
///
/// `$is_fn` is the [`StructTag`](iota_types::StructTag) predicate matching the
/// mirror's on-chain type (e.g. `is_clock` for `0x2::clock::Clock`).
macro_rules! impl_try_from_object {
    ($ty:ident, $is_fn:ident $(,)?) => {
        #[cfg(feature = "serde")]
        #[doc = concat!(
            "Decode a [`",
            stringify!($ty),
            "`] from an on-chain object, validating that the object's Move type tag matches."
        )]
        impl TryFrom<&::iota_types::Object> for $ty {
            type Error = $crate::FromObjectError;

            fn try_from(object: &::iota_types::Object) -> Result<Self, Self::Error> {
                let move_struct = object
                    .as_struct_opt()
                    .ok_or($crate::FromObjectError::NotAMoveStruct)?;
                if !move_struct.object_type().$is_fn() {
                    return Err($crate::FromObjectError::WrongType);
                }
                ::bcs::from_bytes(move_struct.contents()).map_err($crate::FromObjectError::Bcs)
            }
        }
    };
}

/// Generate `try_from_object_with_type` and the `TryFrom<&Object>` constructor
/// for a mirror with a single type parameter.
///
/// `$is_fn` is the [`StructTag`](iota_types::StructTag) predicate matching the
/// mirror's on-chain type (e.g. `is_coin` for `0x2::coin::Coin`); the tag's
/// single type parameter is checked against the caller's `type_param` (runtime)
/// or `$param`'s [`MoveType`](crate::MoveType) tag (compile time).
macro_rules! impl_try_from_object_generic {
    ($ty:ident<$param:ident>, $is_fn:ident $(,)?) => {
        #[cfg(feature = "serde")]
        impl<$param> $ty<$param>
        where
            $param: ::serde::de::DeserializeOwned,
        {
            #[doc = concat!(
                "Decode a [`",
                stringify!($ty),
                "`] from an on-chain object, validating its Move type tag and that its type parameter equals `type_param`.\n\nEscape hatch for type parameters only known at runtime; nothing ties `type_param` to `",
                stringify!($param),
                "`. Prefer the `TryFrom` impl when the type parameter is known at compile time."
            )]
            pub fn try_from_object_with_type(
                object: &::iota_types::Object,
                type_param: &::iota_types::TypeTag,
            ) -> Result<Self, $crate::FromObjectError> {
                let move_struct = object
                    .as_struct_opt()
                    .ok_or($crate::FromObjectError::NotAMoveStruct)?;
                let tag = move_struct.struct_tag();
                if !tag.$is_fn() || tag.type_params() != ::core::slice::from_ref(type_param) {
                    return Err($crate::FromObjectError::WrongType);
                }
                ::bcs::from_bytes(move_struct.contents()).map_err($crate::FromObjectError::Bcs)
            }
        }

        #[cfg(feature = "serde")]
        #[doc = concat!(
            "Decode a [`",
            stringify!($ty),
            "`] from an on-chain object, validating its full Move type tag including the type parameter."
        )]
        impl<$param> TryFrom<&::iota_types::Object> for $ty<$param>
        where
            $param: ::serde::de::DeserializeOwned + $crate::MoveType,
        {
            type Error = $crate::FromObjectError;

            fn try_from(object: &::iota_types::Object) -> Result<Self, Self::Error> {
                Self::try_from_object_with_type(object, &<$param as $crate::MoveType>::type_tag())
            }
        }
    };
}
