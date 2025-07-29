// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::AddressParseError;

#[derive(Copy, Clone, Debug, derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct Address(pub iota_types::Address);

#[uniffi::export]
impl Address {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, AddressParseError> {
        Ok(Self(iota_types::Address::from_bytes(bytes)?))
    }

    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self, AddressParseError> {
        Ok(Self(iota_types::Address::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(iota_types::Address::generate(&mut rng))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}
