// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Internal macros generating the `Object` constructors that every `key`
//! Move-object mirror shares.
//!
//! The mirrors differ only in their type and (for generic mirrors) their
//! single type parameter, so the [`MoveObject`](crate::MoveObject) impl and
//! the `TryFrom<&Object>` / `try_from_object_with_type` bodies are otherwise
//! identical boilerplate. `from_bcs` and the field accessors stay hand-written
//! per type.
//!
//! The struct tag comes from the [`StructTag`] constructor derived from the
//! mirror's name as `new_<name:snake>` — the same `paste` snake-casing that
//! generated that constructor in the first place, applied to the same
//! identifier. `TryFrom<&Object>` accepts exactly the tag `struct_tag` returns.
//!
//! [`StructTag`]: iota_types::StructTag

/// Generate the [`MoveObject`](crate::MoveObject) impl and the
/// `TryFrom<&Object>` constructor for a non-generic mirror.
macro_rules! impl_try_from_object {
    ($ty:ident $(,)?) => {
        #[cfg(feature = "serde")]
        impl $crate::MoveObject for $ty {
            fn struct_tag() -> ::iota_types::StructTag {
                ::paste::paste! { ::iota_types::StructTag::[< new_ $ty:snake >]() }
            }
        }

        #[cfg(feature = "serde")]
        #[doc = concat!(
            "Decode a [`",
            stringify!($ty),
            "`] from an on-chain object, validating that the object's Move type tag matches."
        )]
        impl TryFrom<&::iota_types::Object> for $ty {
            type Error = $crate::FromObjectError;

            fn try_from(object: &::iota_types::Object) -> Result<Self, Self::Error> {
                $crate::decode_move_struct(object, &<Self as $crate::MoveObject>::struct_tag())
            }
        }
    };
}

/// Generate the [`MoveObject`](crate::MoveObject) impl,
/// `try_from_object_with_type` and the `TryFrom<&Object>` constructor for a
/// mirror with a single type parameter.
///
/// Mark the parameter `phantom` when it is phantom in Move (it only shows up
/// in `PhantomData` fields of the mirror). `try_from_object_with_type` is then
/// only implemented on `$ty<()>`, so callers don't have to name a type
/// parameter that the runtime type tag already decides.
macro_rules! impl_try_from_object_generic {
    ($ty:ident<phantom $param:ident> $(,)?) => {
        impl_try_from_object_generic!(@move_object $ty<$param>);

        #[cfg(feature = "serde")]
        impl $ty<()> {
            #[doc = concat!(
                "Decode a [`",
                stringify!($ty),
                "`] from an on-chain object, validating its Move type tag and that its type parameter equals `type_param`.\n\nFor type parameters only known at runtime; the result is `",
                stringify!($ty),
                "<()>` because the type parameter is phantom. Prefer the `TryFrom` impl when the type parameter is known at compile time."
            )]
            pub fn try_from_object_with_type(
                object: &::iota_types::Object,
                type_param: &::iota_types::TypeTag,
            ) -> Result<Self, $crate::FromObjectError> {
                impl_try_from_object_generic!(@decode_with_type $ty, object, type_param)
            }
        }
    };
    ($ty:ident<$param:ident> $(,)?) => {
        impl_try_from_object_generic!(@move_object $ty<$param>);

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
                impl_try_from_object_generic!(@decode_with_type $ty, object, type_param)
            }
        }
    };
    (@decode_with_type $ty:ident, $object:ident, $type_param:ident) => {
        ::paste::paste! {
            $crate::decode_move_struct(
                $object,
                &::iota_types::StructTag::[< new_ $ty:snake >]($type_param.clone()),
            )
        }
    };
    (@move_object $ty:ident<$param:ident>) => {
        #[cfg(feature = "serde")]
        impl<$param> $crate::MoveObject for $ty<$param>
        where
            $param: ::serde::de::DeserializeOwned + $crate::MoveType,
        {
            fn struct_tag() -> ::iota_types::StructTag {
                ::paste::paste! {
                    ::iota_types::StructTag::[< new_ $ty:snake >](
                        <$param as $crate::MoveType>::type_tag(),
                    )
                }
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
                $crate::decode_move_struct(object, &<Self as $crate::MoveObject>::struct_tag())
            }
        }
    };
}
