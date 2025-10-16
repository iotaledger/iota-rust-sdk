// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{error::Result, types::object::ObjectId};

#[derive(derive_more::From, uniffi::Object)]
pub struct MovePackageData(pub iota_types::MovePackageData);

#[uniffi::export]
impl MovePackageData {
    #[uniffi::constructor]
    pub fn new(modules: Vec<Vec<u8>>, dependencies: Vec<Arc<ObjectId>>) -> Self {
        Self(iota_types::MovePackageData::new(
            modules,
            dependencies.into_iter().map(|o| **o).collect(),
        ))
    }

    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[uniffi::constructor]
    pub fn from_base64(base64: &str) -> Result<Self> {
        Ok(Self(iota_types::MovePackageData::from_base64(base64)?))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.0).expect("failed to serialize move package data")
    }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(Self(serde_json::from_str(json)?))
    }
}
