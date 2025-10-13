// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, str::FromStr};

use base64ct::Encoding;
use iota_types::{Digest, ObjectId};
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
pub enum PublishType {
    Path(PathBuf),
    Compiled(MovePackageData),
}

impl From<&str> for PublishType {
    fn from(value: &str) -> Self {
        Self::from(PathBuf::from(value))
    }
}

impl From<String> for PublishType {
    fn from(value: String) -> Self {
        Self::from(PathBuf::from(value))
    }
}

impl From<PathBuf> for PublishType {
    fn from(value: PathBuf) -> Self {
        Self::Path(value)
    }
}

impl From<MovePackageData> for PublishType {
    fn from(value: MovePackageData) -> Self {
        Self::Compiled(value)
    }
}

/// Type corresponding to the output of `iota move build
/// --dump-bytecode-as-base64`
#[derive(serde::Deserialize, Debug, Clone)]
pub struct MovePackageData {
    /// The package modules as a series of bytes
    #[serde(deserialize_with = "bcs_from_str")]
    pub modules: Vec<Vec<u8>>,
    /// The package dependencies, specified by their object IDs.
    #[serde(deserialize_with = "deps_from_str")]
    pub dependencies: Vec<ObjectId>,
    /// The package digest.
    #[serde(deserialize_with = "deser_digest")]
    pub digest: Option<Digest>,
}

fn bcs_from_str<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let bcs = Vec::<String>::deserialize(deserializer)?;
    bcs.into_iter()
        .map(|s| base64ct::Base64::decode_vec(&s).map_err(serde::de::Error::custom))
        .collect()
}

fn deps_from_str<'de, D>(deserializer: D) -> Result<Vec<ObjectId>, D::Error>
where
    D: Deserializer<'de>,
{
    let deps = Vec::<String>::deserialize(deserializer)?;
    deps.into_iter()
        .map(|s| ObjectId::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

fn deser_digest<'de, D>(deserializer: D) -> Result<Option<Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    Digest::from_bytes(bytes)
        .map(Some)
        .map_err(|e| serde::de::Error::custom(format!("{e}")))
}
