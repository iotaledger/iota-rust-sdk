// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod config;
pub mod constants;
pub mod error;
pub mod name;
pub mod registry;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use self::name::{Name, NameFormat};
use crate::{Address, ObjectId, StructTag, type_tag::IdentifierRef};

/// An object to manage a second-level name (SLN).
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct NameRegistration {
    id: ObjectId,
    name: Name,
    name_str: String,
    expiration_timestamp_ms: u64,
}

impl NameRegistration {
    pub fn new(id: ObjectId, name: Name, name_str: String, expiration_timestamp_ms: u64) -> Self {
        Self {
            id,
            name,
            name_str,
            expiration_timestamp_ms,
        }
    }
}

impl crate::TreeDisplay for NameRegistration {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Name Registration")?;
        w.leaf("ID", &self.id, false)?;
        w.leaf("Name", &self.name, false)?;
        w.leaf("Name String", &self.name_str, false)?;
        w.leaf("Expiration (ms)", &self.expiration_timestamp_ms, true)
    }
}

/// An object to manage a subname.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SubnameRegistration {
    id: ObjectId,
    nft: NameRegistration,
}

impl SubnameRegistration {
    pub fn new(id: ObjectId, nft: NameRegistration) -> Self {
        Self { id, nft }
    }

    pub fn into_inner(self) -> NameRegistration {
        self.nft
    }
}

impl crate::TreeDisplay for SubnameRegistration {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Subname Registration")?;
        w.leaf("ID", &self.id, false)?;
        w.child("NFT", &self.nft, true)
    }
}

crate::impl_tree_display!(NameRegistration, SubnameRegistration);

/// Unifying trait for [`NameRegistration`] and [`SubnameRegistration`]
pub trait IotaNamesNft {
    const MODULE: &IdentifierRef;
    const TYPE_NAME: &IdentifierRef;

    fn type_(package_id: Address) -> StructTag {
        StructTag::new(
            package_id,
            Self::MODULE.into(),
            Self::TYPE_NAME.into(),
            Vec::new(),
        )
    }

    fn name(&self) -> &Name;

    fn name_str(&self) -> &str;

    fn expiration_timestamp_ms(&self) -> u64;

    fn expiration_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.expiration_timestamp_ms())
    }

    fn has_expired(&self) -> bool {
        self.expiration_time() <= SystemTime::now()
    }

    fn id(&self) -> ObjectId;
}

impl IotaNamesNft for NameRegistration {
    const MODULE: &IdentifierRef = IdentifierRef::const_new("name_registration");
    const TYPE_NAME: &IdentifierRef = IdentifierRef::const_new("NameRegistration");

    fn name(&self) -> &Name {
        &self.name
    }

    fn name_str(&self) -> &str {
        &self.name_str
    }

    fn expiration_timestamp_ms(&self) -> u64 {
        self.expiration_timestamp_ms
    }

    fn id(&self) -> ObjectId {
        self.id
    }
}

impl IotaNamesNft for SubnameRegistration {
    const MODULE: &IdentifierRef = IdentifierRef::const_new("subname_registration");
    const TYPE_NAME: &IdentifierRef = IdentifierRef::const_new("SubnameRegistration");

    fn name(&self) -> &Name {
        self.nft.name()
    }

    fn name_str(&self) -> &str {
        self.nft.name_str()
    }

    fn expiration_timestamp_ms(&self) -> u64 {
        self.nft.expiration_timestamp_ms()
    }

    fn id(&self) -> ObjectId {
        self.id
    }
}
