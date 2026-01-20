// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

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

/// Macro to generate proptest-based JSON roundtrip tests for types.
/// Used in test modules only.
#[macro_export]
macro_rules! test_json_roundtrip {
    ($($name:ident),+ $(,)?) => {
        paste::paste! {$(
            #[test_strategy::proptest]
            fn [< test_ $name:snake _json_roundtrip >](original: iota_sdk::types::$name) {
                let json = serde_json::to_string(&original).expect("failed to serialize to JSON");
                let parsed: iota_sdk::types::$name = serde_json::from_str(&json).expect("failed to deserialize from JSON");
                assert_eq!(
                    bcs::to_bytes(&original).unwrap(),
                    bcs::to_bytes(&parsed).unwrap(),
                    "JSON roundtrip failed for {}",
                    stringify!($name)
                );
            }
        )+}
    };
}

/// Macro to generate proptest-based BCS roundtrip tests for types.
/// Used in test modules only.
#[macro_export]
macro_rules! test_bcs_roundtrip {
    ($($name:ident),+ $(,)?) => {
        paste::paste! {$(
            #[test_strategy::proptest]
            fn [< test_ $name:snake _bcs_roundtrip >](original: iota_sdk::types::$name) {
                let bytes = bcs::to_bytes(&original).expect("failed to serialize to BCS");
                let parsed: iota_sdk::types::$name = bcs::from_bytes(&bytes).expect("failed to deserialize from BCS");
                assert_eq!(
                    original,
                    parsed,
                    "BCS roundtrip failed for {}",
                    stringify!($name)
                );
            }
        )+}
    };
}

/// Macro to generate proptest-based BCS roundtrip tests for primitive types.
/// Used in test modules only.
#[macro_export]
macro_rules! test_primitive_bcs_roundtrip {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            #[test_strategy::proptest]
            fn [< test_ $name:snake _bcs_roundtrip >](original: $name) {
                let bytes = bcs::to_bytes(&original).expect("failed to serialize to BCS");
                let parsed: $name = bcs::from_bytes(&bytes).expect("failed to deserialize from BCS");
                assert_eq!(
                    original,
                    parsed,
                    "BCS roundtrip failed for {}",
                    stringify!($name)
                );
            }
        )+}
    };
}

/// Macro to generate proptest-based JSON roundtrip tests for primitive types.
/// Used in test modules only.
#[macro_export]
macro_rules! test_primitive_json_roundtrip {
    ($($name:ty),+ $(,)?) => {
        paste::paste! {$(
            #[test_strategy::proptest]
            fn [< test_ $name:snake _json_roundtrip >](original: $name) {
                let json = serde_json::to_string(&original).expect("failed to serialize to JSON");
                let parsed: $name = serde_json::from_str(&json).expect("failed to deserialize from JSON");
                assert_eq!(
                    original,
                    parsed,
                    "JSON roundtrip failed for {}",
                    stringify!($name)
                );
            }
        )+}
    };
}
