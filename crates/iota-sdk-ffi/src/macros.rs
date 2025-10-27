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
