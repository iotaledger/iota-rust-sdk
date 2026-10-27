// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{address::Address, crypto::passkey::PasskeyAuthenticator},
};

#[derive(Debug, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct PasskeyVerifier(pub iota_sdk::crypto::passkey::PasskeyVerifier);

#[uniffi::export]
impl PasskeyVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_sdk::crypto::passkey::PasskeyVerifier::new())
    }

    /// Only accept signatures from the passkey whose public key derives to
    /// `address`.
    pub fn with_address(&self, address: &Address) -> Arc<Self> {
        Arc::new(Self(self.0.clone().with_address(address.0)))
    }

    pub fn verify(&self, message: &[u8], authenticator: &PasskeyAuthenticator) -> Result<()> {
        Ok(self.0.verify(message, &authenticator.0)?)
    }
}
