// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    types::{digest::Digest, object::ObjectId},
};

/// Representation of upgrade policy constants in `iota::package`.
#[derive(derive_more::From, derive_more::Display, uniffi::Object, PartialEq, Eq)]
#[uniffi::export(Display, Eq)]
pub struct UpgradePolicy(pub iota_sdk::types::UpgradePolicy);

#[uniffi::export]
impl UpgradePolicy {
    /// The least restrictive policy. Permits changes to all function
    /// implementations, the removal of ability constraints on generic type
    /// parameters in function signatures, and modifications to private,
    /// public(friend), and entry function signatures. However, public function
    /// signatures and existing types cannot be changed.
    #[uniffi::constructor]
    pub fn compatible() -> Self {
        Self(iota_sdk::types::UpgradePolicy::Compatible)
    }

    /// Allows adding new functionalities (e.g., new public functions or
    /// structs) but restricts changes to existing functionalities.
    #[uniffi::constructor]
    pub fn additive() -> Self {
        Self(iota_sdk::types::UpgradePolicy::Additive)
    }

    /// Limits modifications to the package’s dependencies only.
    #[uniffi::constructor]
    pub fn dep_only() -> Self {
        Self(iota_sdk::types::UpgradePolicy::DepOnly)
    }

    /// Returns the internal representation.
    pub fn as_u8(&self) -> u8 {
        self.0 as u8
    }
}

/// Type corresponding to the output of `iota move build
/// --dump-bytecode-as-base64`
#[derive(derive_more::From, uniffi::Object)]
pub struct MovePackageData(pub iota_sdk::types::MovePackageData);

#[uniffi::export]
impl MovePackageData {
    #[uniffi::constructor]
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_sdk::types::MovePackageData::new(
            modules,
            dependencies.into_iter().map(|o| **o).collect(),
        ))
    }

    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[uniffi::constructor]
    pub fn from_base64(base64: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::MovePackageData::from_base64(base64)?))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).expect("failed to serialize move package data")
    }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self(serde_json::from_str(json)?))
    }

    /// Returns the package modules.
    pub fn modules(&self) -> Vec<Vec<u8>> {
        self.0.modules.clone()
    }

    /// Returns the package dependencies.
    pub fn dependencies(&self) -> Vec<Arc<ObjectId>> {
        self.0
            .dependencies
            .iter()
            .copied()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }

    /// Returns the package digest.
    pub fn digest(&self) -> Digest {
        self.0.digest.into()
    }
}
