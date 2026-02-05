// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::error::Result;

/// A move identifier
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// identifier = %x01-80    ; length of the identifier
///              (ALPHA *127(ALPHA / DIGIT / UNDERSCORE)) /
///              (UNDERSCORE 1*127(ALPHA / DIGIT / UNDERSCORE))
///
/// UNDERSCORE = %x95
/// ```
#[derive(Debug, PartialEq, Eq, Hash, derive_more::From, derive_more::Display, uniffi::Object)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Identifier(pub iota_sdk::types::Identifier);

#[uniffi::export]
impl Identifier {
    #[uniffi::constructor]
    pub fn new(identifier: String) -> Result<Self> {
        Ok(Self(iota_sdk::types::Identifier::new(identifier)?))
    }

    pub fn as_str(&self) -> String {
        self.0.as_str().to_owned()
    }
}
