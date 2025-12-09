// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_sdk::types::iota_names::{IotaNamesNft, NameFormat};

use crate::{error::Result, types::object::ObjectId};

/// An object to manage a second-level name (SLN).
#[derive(derive_more::From, uniffi::Object)]
pub struct NameRegistration(iota_sdk::types::iota_names::NameRegistration);

#[uniffi::export]
impl NameRegistration {
    #[uniffi::constructor]
    pub fn new(id: &ObjectId, name: &Name, name_str: String, expiration_timestamp_ms: u64) -> Self {
        Self(iota_sdk::types::iota_names::NameRegistration::new(
            **id,
            name.0.clone(),
            name_str,
            expiration_timestamp_ms,
        ))
    }

    pub fn id(&self) -> ObjectId {
        self.0.id().into()
    }

    pub fn name(&self) -> Name {
        self.0.name().clone().into()
    }

    pub fn name_str(&self) -> String {
        self.0.name_str().to_owned()
    }

    pub fn expiration_timestamp_ms(&self) -> u64 {
        iota_sdk::types::iota_names::NameRegistration::MODULE;
        self.0.expiration_timestamp_ms()
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Name(iota_sdk::types::iota_names::Name);

#[uniffi::export]
impl Name {
    #[uniffi::constructor]
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(iota_sdk::types::iota_names::Name::from_str(s)?.into())
    }

    // Derive the parent name for a given name. Only subnames have
    /// parents; second-level names return `None`.
    pub fn parent(&self) -> Option<Arc<Self>> {
        self.0.parent().map(Into::into).map(Arc::new)
    }

    /// Returns whether this name is a second-level name (Ex. `test.iota`)
    pub fn is_sln(&self) -> bool {
        self.num_labels() == 2
    }

    /// Returns whether this name is a subname (Ex. `sub.test.iota`)
    pub fn is_subname(&self) -> bool {
        self.num_labels() >= 3
    }

    /// Returns the number of labels including TLN.
    pub fn num_labels(&self) -> u32 {
        self.0.num_labels() as _
    }

    /// Get the label at the given index
    pub fn label(&self, index: u32) -> Option<String> {
        self.0.label(index as _).cloned()
    }

    /// Get all of the labels. NOTE: These are in reverse order starting with
    /// the top-level name and proceeding to subnames.
    pub fn labels(&self) -> Vec<String> {
        self.0.labels().to_vec()
    }

    /// Formats a name into a string based on the available output formats.
    /// The default separator is `.`
    pub fn format(&self, format: NameFormat) -> String {
        self.0.format(format)
    }
}

/// Two different view options for a name.
/// `At` -> `test@example` | `Dot` -> `test.example.iota`
#[uniffi::remote(Enum)]
pub enum NameFormat {
    At,
    Dot,
}
