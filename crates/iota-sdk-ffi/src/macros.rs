// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Define the FFI wrapper for a `key` Move-object mirror decoded at a fixed
/// Move type tag (a non-generic mirror, or a fixed instantiation such as
/// `<IOTA>`): the `uniffi::Object` newtype plus its `try_from_object` /
/// `try_from_bcs` constructors. Type-specific field accessors go in the
/// trailing block and are spliced into the exported impl. For mirrors whose
/// type parameter is chosen by the caller at runtime, use
/// [`crate::ffi_move_object_generic`].
#[macro_export]
macro_rules! ffi_move_object {
    (
        $(#[$meta:meta])*
        $name:ident($core:ty) { $($accessors:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, derive_more::From, uniffi::Object)]
        #[uniffi::export(Debug)]
        pub struct $name(pub $core);

        #[uniffi::export]
        impl $name {
            /// Decode from an on-chain object, validating its Move type tag.
            #[uniffi::constructor]
            pub fn try_from_object(
                object: &$crate::types::object::Object,
            ) -> $crate::error::Result<Self> {
                Ok(<$core>::try_from(&object.0)?.into())
            }

            /// Decode from BCS bytes, without validating the on-chain type tag.
            #[uniffi::constructor]
            pub fn try_from_bcs(bytes: Vec<u8>) -> $crate::error::Result<Self> {
                Ok(::bcs::from_bytes::<$core>(&bytes)?.into())
            }

            /// The object's ID.
            pub fn id(&self) -> $crate::types::object::ObjectId {
                (*self.0.id.object_id()).into()
            }

            $($accessors)*
        }
    };
}

/// Define the FFI wrapper for a Move event mirror: the `uniffi::Object`
/// newtype plus a `try_from_bcs` constructor. Events are not objects (no
/// `key` ability, no `UID`), so there is no `try_from_object` and no `id`;
/// they are decoded from the BCS `contents` of an event query result.
/// Type-specific field accessors go in the trailing block and are spliced
/// into the exported impl.
#[macro_export]
macro_rules! ffi_move_event {
    (
        $(#[$meta:meta])*
        $name:ident($core:ty) { $($accessors:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, derive_more::From, uniffi::Object)]
        #[uniffi::export(Debug)]
        pub struct $name(pub $core);

        #[uniffi::export]
        impl $name {
            /// Decode from the BCS contents of an emitted event.
            #[uniffi::constructor]
            pub fn try_from_bcs(bytes: Vec<u8>) -> $crate::error::Result<Self> {
                Ok(::bcs::from_bytes::<$core>(&bytes)?.into())
            }

            $($accessors)*
        }
    };
}

/// Like [`ffi_move_object`], but for a mirror with a single (phantom) type
/// parameter. `$core` is the type instantiated at `IOTA` (a phantom marker, so
/// the BCS layout is the same for every coin type); the object constructor
/// validates the on-chain type parameter against a caller-provided `TypeTag`.
#[macro_export]
macro_rules! ffi_move_object_generic {
    (
        $(#[$meta:meta])*
        $name:ident($core:ty) { $($accessors:tt)* }
    ) => {
        $(#[$meta])*
        #[derive(Debug, derive_more::From, uniffi::Object)]
        #[uniffi::export(Debug)]
        pub struct $name(pub $core);

        #[uniffi::export]
        impl $name {
            /// Decode from an on-chain object, validating its Move type tag,
            /// including that its type parameter equals `type_param`.
            #[uniffi::constructor]
            pub fn try_from_object_with_type(
                object: &$crate::types::object::Object,
                type_param: &$crate::types::move_core::TypeTag,
            ) -> $crate::error::Result<Self> {
                Ok(<$core>::try_from_object_with_type(&object.0, &type_param.0)?.into())
            }

            /// Decode from BCS bytes, without validating the on-chain type tag.
            #[uniffi::constructor]
            pub fn try_from_bcs(bytes: Vec<u8>) -> $crate::error::Result<Self> {
                Ok(::bcs::from_bytes::<$core>(&bytes)?.into())
            }

            /// The object's ID.
            pub fn id(&self) -> $crate::types::object::ObjectId {
                (*self.0.id.object_id()).into()
            }

            $($accessors)*
        }
    };
}

#[macro_export]
macro_rules! export_iota_types_bcs_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            /// Create this type from BCS encoded bytes.
            #[uniffi::export]
            pub fn [< $name:snake _from_bcs >](bcs: Vec<u8>) -> $crate::error::Result<$name> {
                let data = bcs::from_bytes::<iota_sdk::types::$name>(&bcs)?;
                Ok(data.into())
            }

            /// Convert this type to BCS encoded bytes.
            #[uniffi::export]
            pub fn [< $name:snake _to_bcs >](data: $name) -> $crate::error::Result<Vec<u8>> {
                let data: iota_sdk::types::$name = data.into();
                Ok(bcs::to_bytes(&data)?)
            }
        )+}
    }
}

#[macro_export]
macro_rules! export_iota_types_objects_bcs_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            /// Create this type from BCS encoded bytes.
            #[uniffi::export]
            pub fn [< $name:snake _from_bcs >](bcs: Vec<u8>) -> $crate::error::Result<$name> {
                Ok($name(bcs::from_bytes::<iota_sdk::types::$name>(&bcs)?))
            }

            /// Convert this type to BCS encoded bytes.
            #[uniffi::export]
            pub fn [< $name:snake _to_bcs >](data: std::sync::Arc<$name>) -> $crate::error::Result<Vec<u8>> {
                Ok(bcs::to_bytes(&data.0)?)
            }
        )+}
    }
}

#[macro_export]
macro_rules! export_primitive_types_bcs_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste!{$(
        #[doc = "Create a " $name " from BCS encoded bytes."]
        #[uniffi::export]
        pub fn [< $name:snake _from_bcs >](input: &[u8]) -> $crate::error::Result<$name> {
            Ok(bcs::from_bytes(input)?)
        }

        #[doc = "Convert this " $name " to BCS encoded bytes."]
        #[uniffi::export]
        pub fn [< $name:snake _to_bcs >](input: $name) -> $crate::error::Result<Vec<u8>> {
            Ok(bcs::to_bytes(&input)?)
        }
        )+}
    };
}

#[macro_export]
macro_rules! export_iota_types_json_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            /// Create this type from JSON encoded string.
            #[uniffi::export]
            pub fn [< $name:snake _from_json >](json: &str) -> $crate::error::Result<$name> {
                let data = serde_json::from_str::<iota_sdk::types::$name>(json)?;
                Ok(data.into())
            }

            /// Convert this type to JSON encoded string.
            #[uniffi::export]
            pub fn [< $name:snake _to_json >](data: $name) -> $crate::error::Result<String> {
                let data: iota_sdk::types::$name = data.into();
                Ok(serde_json::to_string(&data)?)
            }
        )+}
    }
}

#[macro_export]
macro_rules! export_iota_types_objects_json_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            /// Create this type from JSON encoded string.
            #[uniffi::export]
            pub fn [< $name:snake _from_json >](json: &str) -> $crate::error::Result<$name> {
                Ok($name(serde_json::from_str::<iota_sdk::types::$name>(json)?))
            }

            /// Convert this type to JSON encoded string.
            #[uniffi::export]
            pub fn [< $name:snake _to_json >](data: std::sync::Arc<$name>) -> $crate::error::Result<String> {
                Ok(serde_json::to_string(&data.0)?)
            }
        )+}
    }
}

#[macro_export]
macro_rules! export_primitive_types_json_conversion {
    ($($name:ty),+ $(,)?) => {
        paste::paste!{$(
        #[doc = "Create a " $name " from JSON encoded string."]
        #[uniffi::export]
        pub fn [< $name:snake _from_json >](input: &str) -> $crate::error::Result<$name> {
            Ok(serde_json::from_str(input)?)
        }

        #[doc = "Convert this " $name " to JSON encoded string."]
        #[uniffi::export]
        pub fn [< $name:snake _to_json >](input: $name) -> $crate::error::Result<String> {
            Ok(serde_json::to_string(&input)?)
        }
        )+}
    };
}

#[macro_export]
macro_rules! export_iota_types_display {
    ($($core:ty => $name:ident),+ $(,)?) => {
        paste::paste! {$(
            /// Render this type as human-readable text.
            #[uniffi::export]
            pub fn [< $name:snake _to_display_string >](data: $name) -> String {
                <$core>::from(data).to_string()
            }
        )+}
    };
    ($($name:ident),+ $(,)?) => {
        $crate::export_iota_types_display!($(iota_sdk::types::$name => $name),+);
    };
}

#[macro_export]
macro_rules! export_iota_types_objects_display {
    ($($name:ident),+ $(,)?) => {
        $(
            #[uniffi::export]
            impl $name {
                /// Render this type as human-readable text.
                ///
                /// Some types also print this through the binding's native
                /// string conversion; this method is the one spelling every
                /// type has.
                pub fn to_display_string(&self) -> String {
                    self.0.to_string()
                }
            }
        )+
    }
}
