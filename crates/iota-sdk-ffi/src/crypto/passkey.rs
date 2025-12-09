// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{crypto::passkey::PasskeyAuthenticator, signature::SimpleSignature},
};

#[derive(uniffi::Object)]
pub struct PasskeyVerifier(iota_sdk::crypto::passkey::PasskeyVerifier);

#[uniffi::export]
impl PasskeyVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_sdk::crypto::passkey::PasskeyVerifier::new())
    }

    pub fn verify(&self, message: &[u8], authenticator: &PasskeyAuthenticator) -> Result<()> {
        Ok(self.0.verify(message, &authenticator.0)?)
    }
}
