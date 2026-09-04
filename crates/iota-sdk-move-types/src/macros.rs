// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Internal macros generating the `Object` constructors that every `key`
//! Move-object mirror shares.
//!
//! The mirrors differ only in their type and (for generic mirrors) their
//! single type parameter, so the `TryFrom<&Object>` /
//! `try_from_object_with_type` bodies are otherwise identical boilerplate.
//! `from_bcs` and the field accessors stay hand-written per type.
//!
//! The [`StructTag`] predicate a mirror validates against is derived from its
//! name as `is_<name:snake>` — the same `paste` snake-casing that generated
//! that predicate in the first place, applied to the same identifier, so it
//! always matches for a type registered on a plain `add_struct_tag_ctor!` arm.
//! A type whose predicate lives under a different name — one registered with
//! `@with_module` (predicate `is_<module>_<name>`), or a mirror whose Rust name
//! diverges from the Move struct name — passes its predicate explicitly as a
//! second argument.
//!
//! [`StructTag`]: iota_types::StructTag

/// Generate the `TryFrom<&Object>` constructor for a non-generic mirror.
///
/// The predicate defaults to `is_<TypeName:snake>`; pass it explicitly as a
/// second argument when it lives under a different name (e.g. an
/// `@with_module` registration, whose predicate is `is_<module>_<name>`).
macro_rules! impl_try_from_object {
    ($ty:ident, $is_fn:ident, $new_fn:ident $(,)?) => {
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
                    .as_opt_struct()
                    .ok_or($crate::FromObjectError::NotAMoveStruct)?;
                if !move_struct.object_type().$is_fn() {
                    return Err($crate::FromObjectError::WrongType);
                }
                ::bcs::from_bytes(move_struct.contents()).map_err($crate::FromObjectError::Bcs)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::MoveObject for $ty {
            fn struct_tag() -> ::iota_types::StructTag {
                ::iota_types::StructTag::$new_fn()
            }
        }
    };
    ($ty:ident $(,)?) => {
        ::paste::paste! {
            impl_try_from_object!($ty, [< is_ $ty:snake >], [< new_ $ty:snake >]);
        }
    };
}

/// Generate `try_from_object_with_type` and the `TryFrom<&Object>` constructor
/// for a mirror with a single type parameter.
///
/// The predicate defaults to `is_<TypeName:snake>`; pass it explicitly as a
/// second argument when it lives under a different name (e.g. an
/// `@with_module` registration, whose predicate is `is_<module>_<name>`).
macro_rules! impl_try_from_object_generic {
    (@common $ty:ident<$param:ident>, $is_fn:ident $(,)?) => {
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
                    .as_opt_struct()
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
    // A mirror whose Move type parameter is a coin *struct* rather than an
    // arbitrary type, so its tag constructor takes a `StructTag`.
    (@struct_param $ty:ident<$param:ident>, $is_fn:ident, $new_fn:ident $(,)?) => {
        impl_try_from_object_generic!(@common $ty<$param>, $is_fn);

        #[cfg(feature = "serde")]
        impl<$param> $crate::MoveObject for $ty<$param>
        where
            $param: ::serde::de::DeserializeOwned + $crate::MoveType,
        {
            fn struct_tag() -> ::iota_types::StructTag {
                ::iota_types::StructTag::$new_fn(
                    <$param as $crate::MoveType>::type_tag()
                        .into_opt_struct_tag()
                        .expect(concat!(
                            "the Move type parameter of ",
                            stringify!($ty),
                            " is a struct, so its MoveType impl must return a struct tag"
                        )),
                )
            }
        }
    };
    (@struct_param $ty:ident<$param:ident> $(,)?) => {
        ::paste::paste! {
            impl_try_from_object_generic!(
                @struct_param $ty<$param>, [< is_ $ty:snake >], [< new_ $ty:snake >]
            );
        }
    };
    ($ty:ident<$param:ident>, $is_fn:ident, $new_fn:ident $(,)?) => {
        impl_try_from_object_generic!(@common $ty<$param>, $is_fn);

        #[cfg(feature = "serde")]
        impl<$param> $crate::MoveObject for $ty<$param>
        where
            $param: ::serde::de::DeserializeOwned + $crate::MoveType,
        {
            fn struct_tag() -> ::iota_types::StructTag {
                ::iota_types::StructTag::$new_fn(<$param as $crate::MoveType>::type_tag())
            }
        }
    };
    ($ty:ident<$param:ident> $(,)?) => {
        ::paste::paste! {
            impl_try_from_object_generic!($ty<$param>, [< is_ $ty:snake >], [< new_ $ty:snake >]);
        }
    };
}
