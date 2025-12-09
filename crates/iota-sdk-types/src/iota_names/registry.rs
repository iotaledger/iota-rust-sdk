// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    Address, ObjectId,
    iota_names::{constants::IOTA_NAMES_LEAF_EXPIRATION_TIMESTAMP, name::Name},
};

/// Rust version of the Move `iota::table::Table` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Table {
    pub id: ObjectId,
    pub size: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Registry {
    /// The `registry` table maps `Name` to `NameRecord`.
    /// Added / replaced in the `add_record` function.
    pub registry: Table,
    /// The `reverse_registry` table maps `Address` to `Name`.
    /// Updated in the `set_reverse_lookup` function.
    pub reverse_registry: Table,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RegistryEntry {
    pub id: ObjectId,
    pub name: Name,
    pub name_record: NameRecord,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReverseRegistryEntry {
    pub id: ObjectId,
    pub address: Address,
    pub name: Name,
}

/// A single record in the registry.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NameRecord {
    /// The ID of the registration NFT assigned to this record.
    ///
    /// The owner of the corresponding registration NFT has the rights to be
    /// able to change and adjust the `target_address` of this name.
    ///
    /// It is possible that the ID changes if the record expires and is
    /// purchased by someone else.
    pub nft_id: ObjectId,
    /// Timestamp in milliseconds when the record expires.
    pub expiration_timestamp_ms: u64,
    /// The target address that this name points to.
    pub target_address: Option<Address>,
    /// Additional data which may be stored in a record.
    #[cfg_attr(feature = "serde", serde(with = "serde_vecmap"))]
    pub data: HashMap<String, String>,
}

#[cfg(feature = "serde")]
mod serde_vecmap {
    use std::collections::HashMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
    pub struct VecMap<K, V> {
        pub contents: Vec<Entry<K, V>>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
    pub struct Entry<K, V> {
        pub key: K,
        pub value: V,
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = VecMap::deserialize(deserializer)?;
        Ok(map.contents.into_iter().map(|e| (e.key, e.value)).collect())
    }

    pub fn serialize<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        VecMap {
            contents: value
                .iter()
                .map(|(key, value)| Entry {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<crate::Object> for NameRecord {
    type Error = crate::iota_names::error::IotaNamesError;

    fn try_from(object: crate::Object) -> Result<Self, crate::iota_names::error::IotaNamesError> {
        #[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
        pub struct Field<N, V> {
            pub id: ObjectId,
            pub name: N,
            pub value: V,
        }

        object
            .to_rust::<Field<Name, Self>>()
            .map(|record| record.value)
            .map_err(|_| {
                crate::iota_names::error::IotaNamesError::MalformedObject(object.object_id())
            })
    }
}

impl NameRecord {
    /// Leaf records expire when their parent expires.
    /// The `expiration_timestamp_ms` is set to `0` (on-chain) to indicate this.
    pub fn is_leaf_record(&self) -> bool {
        self.expiration_timestamp_ms == IOTA_NAMES_LEAF_EXPIRATION_TIMESTAMP
    }

    /// Validates that a `NameRecord` is a valid parent of a child `NameRecord`.
    ///
    /// WARNING: This only applies for `leaf` records.
    pub fn is_valid_leaf_parent(&self, child: &NameRecord) -> bool {
        self.nft_id == child.nft_id
    }

    /// Checks if a `node` name record has expired.
    /// Expects the latest checkpoint's timestamp.
    pub fn is_node_expired(&self, checkpoint_timestamp_ms: u64) -> bool {
        self.expiration_timestamp_ms < checkpoint_timestamp_ms
    }

    /// Gets the expiration time as a [`SystemTime`].
    pub fn expiration_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.expiration_timestamp_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expirations() {
        let system_time: u64 = 100;

        let mut name = NameRecord {
            nft_id: ObjectId::ZERO,
            data: Default::default(),
            target_address: Some(Address::ZERO),
            expiration_timestamp_ms: system_time + 10,
        };

        assert!(!name.is_node_expired(system_time));

        name.expiration_timestamp_ms = system_time - 10;

        assert!(name.is_node_expired(system_time));
    }
}
