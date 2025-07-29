// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_types::Version;

use crate::{
    error::Result,
    types::{address::Address, digest::ObjectDigest},
};

#[derive(Clone, Debug, derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct ObjectId(pub iota_types::ObjectId);

#[uniffi::export]
impl ObjectId {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_types::ObjectId::from(
            iota_types::Address::from_bytes(bytes)?,
        )))
    }

    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_types::ObjectId::from_str(hex)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    pub fn to_hex(&self) -> String {
        self.0.as_address().to_hex()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectReference(pub iota_types::ObjectReference);

#[uniffi::export]
impl ObjectReference {
    #[uniffi::constructor]
    pub fn new(object_id: &ObjectId, version: Version, digest: &ObjectDigest) -> Self {
        Self(iota_types::ObjectReference::new(
            **object_id,
            version,
            **digest,
        ))
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Object(pub iota_types::Object);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectData(pub iota_types::ObjectData);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MovePackage(pub iota_types::MovePackage);
