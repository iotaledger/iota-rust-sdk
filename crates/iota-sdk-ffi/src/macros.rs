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

/// Export BCS conversions for a `uniffi::Record` or `uniffi::Enum` mirrored
/// from `iota_sdk::types`.
///
/// `from_bcs` is a free function because no language backend renders
/// `Record::constructors`.
#[macro_export]
macro_rules! export_iota_types_bcs_conversion {
    ($($name:ident),+ $(,)?) => {
        paste::paste! {$(
            #[uniffi::export]
            impl $name {
                /// Convert this type to BCS encoded bytes.
                pub fn to_bcs(&self) -> $crate::error::Result<Vec<u8>> {
                    let data: iota_sdk::types::$name = self.clone().try_into()?;
                    Ok(::bcs::to_bytes(&data)?)
                }
            }

            /// Create this type from BCS encoded bytes.
            #[uniffi::export]
            pub fn [< $name:snake _from_bcs >](bcs: Vec<u8>) -> $crate::error::Result<$name> {
                let data = ::bcs::from_bytes::<iota_sdk::types::$name>(&bcs)?;
                Ok(data.into())
            }
        )+}
    }
}

/// Export BCS conversions for a `uniffi::Object` newtype wrapping a type from
/// `iota_sdk::types`.
#[macro_export]
macro_rules! export_iota_types_objects_bcs_conversion {
    ($($name:ident),+ $(,)?) => {$(
        #[uniffi::export]
        impl $name {
            /// Create this type from BCS encoded bytes.
            #[uniffi::constructor]
            pub fn from_bcs(bcs: Vec<u8>) -> $crate::error::Result<Self> {
                Ok($name(::bcs::from_bytes::<iota_sdk::types::$name>(&bcs)?))
            }

            /// Convert this type to BCS encoded bytes.
            pub fn to_bcs(&self) -> $crate::error::Result<Vec<u8>> {
                Ok(::bcs::to_bytes(&self.0)?)
            }
        }
    )+}
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

/// JSON counterpart of [`crate::export_iota_types_bcs_conversion`].
#[macro_export]
macro_rules! export_iota_types_json_conversion {
    ($($name:ident),+ $(,)?) => {
        paste::paste! {$(
            #[uniffi::export]
            impl $name {
                /// Convert this type to a JSON encoded string.
                pub fn to_json(&self) -> $crate::error::Result<String> {
                    let data: iota_sdk::types::$name = self.clone().try_into()?;
                    Ok(serde_json::to_string(&data)?)
                }
            }

            /// Create this type from a JSON encoded string.
            #[uniffi::export]
            pub fn [< $name:snake _from_json >](json: &str) -> $crate::error::Result<$name> {
                let data = serde_json::from_str::<iota_sdk::types::$name>(json)?;
                Ok(data.into())
            }
        )+}
    }
}

/// JSON counterpart of [`crate::export_iota_types_objects_bcs_conversion`].
#[macro_export]
macro_rules! export_iota_types_objects_json_conversion {
    ($($name:ident),+ $(,)?) => {$(
        #[uniffi::export]
        impl $name {
            /// Create this type from a JSON encoded string.
            #[uniffi::constructor]
            pub fn from_json(json: &str) -> $crate::error::Result<Self> {
                Ok($name(serde_json::from_str::<iota_sdk::types::$name>(json)?))
            }

            /// Convert this type to a JSON encoded string.
            pub fn to_json(&self) -> $crate::error::Result<String> {
                Ok(serde_json::to_string(&self.0)?)
            }
        }
    )+}
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
        $(
            #[uniffi::export]
            impl $name {
                /// Render this type as human-readable text.
                ///
                /// The layout is meant for reading and can change between
                /// releases. Use the JSON or BCS conversions for output that
                /// gets parsed.
                pub fn to_display_string(&self) -> String {
                    <$core>::from(self.clone()).to_string()
                }
            }
        )+
    };
    ($($name:ident),+ $(,)?) => {
        $(
            #[uniffi::export]
            impl $name {
                /// Render this type as human-readable text.
                ///
                /// The layout is meant for reading and can change between
                /// releases. Use the JSON or BCS conversions for output that
                /// gets parsed.
                pub fn to_display_string(&self) -> String {
                    iota_sdk::types::$name::from(self.clone()).to_string()
                }
            }
        )+
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
                /// string conversion; this method is the spelling every object
                /// type has.
                ///
                /// The layout is meant for reading and can change between
                /// releases. Use the JSON or BCS conversions for output that
                /// gets parsed.
                pub fn to_display_string(&self) -> String {
                    self.0.to_string()
                }
            }
        )+
    }
}

#[macro_export]
macro_rules! ffi_map {
    (@map-objects $(#[$meta:meta])* $name:ident<$key:ty, $value:ty>) => {
        paste::paste! {
            $(#[$meta])*
            #[derive(uniffi::Object)]
            pub struct $name(::std::collections::HashMap<::std::sync::Arc<$key>, $value>);

            #[doc = "An entry in the " $name " map."]
            #[derive(Clone, uniffi::Record)]
            pub struct [<$name Entry>] {
                /// The entry's key.
                pub key: ::std::sync::Arc<$key>,
                /// The value stored under it.
                pub value: $value,
            }

            #[uniffi::export]
            impl $name {
                /// Collect entries into a map. A key repeated across entries keeps
                /// the value of the last one.
                #[uniffi::constructor]
                pub fn from_entries(entries: Vec<[<$name Entry>]>) -> Self {
                    Self::from_iter(entries.into_iter().map(|entry| (entry.key, entry.value)))
                }

                /// The value stored under `key`, or `None` if there is none.
                pub fn get(&self, key: &$key) -> Option<$value> {
                    self.0.get(key).cloned()
                }

                /// Whether a value is stored under `key`.
                pub fn contains_key(&self, key: &$key) -> bool {
                    self.0.contains_key(key)
                }

                /// The number of entries.
                pub fn len(&self) -> u64 {
                    self.0.len() as _
                }

                /// Whether the map holds no entries.
                pub fn is_empty(&self) -> bool {
                    self.0.is_empty()
                }

                /// Every key, in no particular order.
                pub fn keys(&self) -> Vec<::std::sync::Arc<$key>> {
                    self.0.keys().cloned().collect()
                }

                /// Every value, in no particular order.
                pub fn values(&self) -> Vec<$value> {
                    self.0.values().cloned().collect()
                }

                /// Every entry, in no particular order.
                pub fn entries(&self) -> Vec<[<$name Entry>]> {
                    self.0
                        .iter()
                        .map(|(key, value)| [<$name Entry>] {
                            key: key.clone(),
                            value: value.clone(),
                        })
                        .collect()
                }
            }

            impl $name {
                /// Borrow the entries, the way the native map this stands in
                /// for is read.
                pub fn iter(&self) -> impl Iterator<Item = (&::std::sync::Arc<$key>, &$value)> {
                    self.0.iter()
                }
            }

            impl FromIterator<(::std::sync::Arc<$key>, $value)> for $name {
                fn from_iter<I: IntoIterator<Item = (::std::sync::Arc<$key>, $value)>>(iter: I) -> Self {
                    Self(iter.into_iter().collect())
                }
            }
        }
    };
    (@hashmap $(#[$meta:meta])* $name:ident<$key:ty, $value:ty>) => {
        $(#[$meta])*
        pub(crate) type $name = ::std::collections::HashMap<::std::sync::Arc<$key>, $value>;
    };
    ($(#[$meta:meta])* $name:ident<$key:ty, $value:ty>) => {
        #[cfg(feature = "map-objects")]
        $crate::ffi_map!(@map-objects $(#[$meta])* $name<$key, $value>);

        #[cfg(not(feature = "map-objects"))]
        $crate::ffi_map!(@hashmap $(#[$meta])* $name<$key, $value>);

    };
}

/// Declares an FFI map object backed by a [`std::collections::BTreeMap`], for
/// maps read out of an ordered Rust map.
///
/// Unlike [`ffi_map!`], which hands the bindings a native map unless
/// `map-objects` is enabled, this one is always an object: a native map keeps
/// the key order in some binding languages and drops it in others.
///
/// The key type is written as it is stored — `Arc<ObjectId>`, `String` — and
/// lookups take its [`Deref`](std::ops::Deref) target.
#[macro_export]
macro_rules! ffi_btree_map {
    ($(#[$meta:meta])* $name:ident<$key:ty, $value:ty>) => {
        paste::paste! {
            $(#[$meta])*
            #[derive(Clone, Debug, uniffi::Object)]
            pub struct $name(::std::collections::BTreeMap<$key, $value>);

            #[doc = "An entry in the " $name " map."]
            #[derive(Clone, Debug, uniffi::Record)]
            pub struct [<$name Entry>] {
                /// The entry's key.
                pub key: $key,
                /// The value stored under it.
                pub value: $value,
            }

            #[uniffi::export]
            impl $name {
                /// Collect entries into a map. A key repeated across entries keeps
                /// the value of the last one.
                #[uniffi::constructor]
                pub fn from_entries(entries: Vec<[<$name Entry>]>) -> Self {
                    Self::from_iter(entries.into_iter().map(|entry| (entry.key, entry.value)))
                }

                /// The value stored under `key`, or `None` if there is none.
                pub fn get(&self, key: &<$key as ::std::ops::Deref>::Target) -> Option<$value> {
                    self.0.get(key).cloned()
                }

                /// Whether a value is stored under `key`.
                pub fn contains_key(&self, key: &<$key as ::std::ops::Deref>::Target) -> bool {
                    self.0.contains_key(key)
                }

                /// The number of entries.
                pub fn len(&self) -> u64 {
                    self.0.len() as _
                }

                /// Whether the map holds no entries.
                pub fn is_empty(&self) -> bool {
                    self.0.is_empty()
                }

                /// Every key, in key order.
                pub fn keys(&self) -> Vec<$key> {
                    self.0.keys().cloned().collect()
                }

                /// Every value, ordered by the key it is stored under.
                pub fn values(&self) -> Vec<$value> {
                    self.0.values().cloned().collect()
                }

                /// Every entry, in key order.
                pub fn entries(&self) -> Vec<[<$name Entry>]> {
                    self.0
                        .iter()
                        .map(|(key, value)| [<$name Entry>] {
                            key: key.clone(),
                            value: value.clone(),
                        })
                        .collect()
                }
            }

            impl $name {
                /// Borrow the entries, the way the native map this stands in
                /// for is read.
                pub fn iter(&self) -> impl Iterator<Item = (&$key, &$value)> {
                    self.0.iter()
                }
            }

            impl FromIterator<($key, $value)> for $name {
                fn from_iter<I: IntoIterator<Item = ($key, $value)>>(iter: I) -> Self {
                    Self(iter.into_iter().collect())
                }
            }

            impl Default for $name {
                fn default() -> Self {
                    Self(::std::collections::BTreeMap::new())
                }
            }
        }
    };
}
