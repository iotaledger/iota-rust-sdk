// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use iota_sdk::{
    crypto::Verifier,
    types::{Jwk, JwkId},
};

use crate::{error::Result, types::crypto::zklogin::ZkLoginAuthenticator};

#[derive(derive_more::From, uniffi::Object)]
pub struct ZkloginVerifier(pub iota_sdk::crypto::zklogin::ZkloginVerifier);

#[uniffi::export]
impl ZkloginVerifier {
    #[uniffi::constructor]
    pub fn new_mainnet() -> Self {
        Self(iota_sdk::crypto::zklogin::ZkloginVerifier::new_mainnet())
    }

    /// Load a fixed verifying key from zkLogin.vkey output. This is based on a
    /// local setup and should not be used in production.
    #[uniffi::constructor]
    pub fn new_dev() -> Self {
        Self(iota_sdk::crypto::zklogin::ZkloginVerifier::new_dev())
    }

    pub fn jwks(&self) -> HashMap<JwkId, Jwk> {
        self.0.jwks().clone()
    }

    pub fn with_jwks(&self, jwks: HashMap<JwkId, Jwk>) -> Self {
        let mut verifier = self.0.clone();
        *verifier.jwks_mut() = jwks;
        Self(verifier)
    }

    pub fn verify(&self, message: &[u8], authenticator: &ZkLoginAuthenticator) -> Result<()> {
        Ok(self.0.verify(message, &authenticator.0)?)
    }
}
