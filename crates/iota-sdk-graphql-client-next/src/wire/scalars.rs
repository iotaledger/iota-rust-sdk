// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Scalars that decode while the response is deserialized, so a response
//! either has the expected shape or fails as a whole with the reason.

use std::{borrow::Cow, fmt::Display, str::FromStr};

use base64ct::Encoding;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

use super::schema;

/// Base64 that decodes into the BCS encoding of `T`.
#[derive(Debug)]
pub(crate) struct Bcs<T>(pub(crate) T);

impl<'de, T: DeserializeOwned> Deserialize<'de> for Bcs<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let Bytes(bytes) = Bytes::deserialize(deserializer)?;
        bcs::from_bytes(&bytes).map(Bcs).map_err(|error| {
            serde::de::Error::custom(format!(
                "invalid BCS for {}: {error}",
                std::any::type_name::<T>()
            ))
        })
    }
}

impl<T> cynic::schema::IsScalar<schema::Base64> for Bcs<T> {
    type SchemaType = schema::Base64;
}

impl<T> cynic::coercions::CoercesTo<schema::Base64> for Bcs<T> {}

/// Base64 that decodes into raw bytes.
#[derive(Debug)]
pub(crate) struct Bytes(pub(crate) Vec<u8>);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = Cow::<'de, str>::deserialize(deserializer)?;
        base64ct::Base64::decode_vec(&encoded)
            .map(Bytes)
            .map_err(|error| serde::de::Error::custom(format!("invalid Base64: {error}")))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64ct::Base64::encode_string(&self.0))
    }
}

cynic::impl_scalar!(Bytes, schema::Base64);

/// An ISO 8601 timestamp, kept as the server renders it.
#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct DateTime(pub(crate) String);

cynic::impl_scalar!(DateTime, schema::DateTime);

/// A `BigInt` string that parses into `T`.
#[derive(Debug)]
pub(crate) struct Num<T>(pub(crate) T);

impl<T> Num<T> {
    pub(crate) fn into_inner(self) -> T {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for Num<T>
where
    T: FromStr,
    T::Err: Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let digits = Cow::<'de, str>::deserialize(deserializer)?;
        digits.parse().map(Num).map_err(|error| {
            serde::de::Error::custom(format!(
                "invalid {} `{digits}`: {error}",
                std::any::type_name::<T>()
            ))
        })
    }
}

impl<T> cynic::schema::IsScalar<schema::BigInt> for Num<T> {
    type SchemaType = schema::BigInt;
}

impl<T> cynic::coercions::CoercesTo<schema::BigInt> for Num<T> {}

#[cfg(test)]
mod tests {
    use iota_types::Address;

    use super::*;

    #[test]
    fn bcs_decodes_base64_into_the_value() {
        let encoded = base64ct::Base64::encode_string(&bcs::to_bytes(&Address::FRAMEWORK).unwrap());
        let Bcs(address): Bcs<Address> =
            serde_json::from_value(serde_json::json!(encoded)).unwrap();
        assert_eq!(address, Address::FRAMEWORK);
    }

    #[test]
    fn bcs_names_the_type_it_could_not_decode() {
        let error = serde_json::from_value::<Bcs<Address>>(serde_json::json!("AQI=")).unwrap_err();
        assert!(error.to_string().contains("invalid BCS for iota_sdk_types"));
    }

    #[test]
    fn num_parses_big_int_strings() {
        let num: Num<u64> = serde_json::from_value(serde_json::json!("1000")).unwrap();
        assert_eq!(num.into_inner(), 1000);
        assert!(serde_json::from_value::<Num<u64>>(serde_json::json!("-1")).is_err());
    }
}
