// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{address::Address, crypto::passkey::PasskeyAuthenticator},
};

#[derive(Debug, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct PasskeyVerifier(pub RwLock<iota_sdk::crypto::passkey::PasskeyVerifier>);

#[uniffi::export]
impl PasskeyVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(RwLock::default())
    }

    /// Only accept signatures from the passkey whose public key derives to
    /// `address`.
    pub fn with_address(self: Arc<Self>, address: &Address) -> Arc<Self> {
        {
            let mut lock = self.0.write().expect("error writing to verifier");
            *lock = std::mem::take(&mut *lock).with_address(address.0);
        }
        self
    }

    pub fn verify(&self, message: &[u8], authenticator: &PasskeyAuthenticator) -> Result<()> {
        Ok(self
            .0
            .read()
            .expect("error reading verifier")
            .verify(message, &authenticator.0)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iota_sdk::types::UserSignature;

    use super::PasskeyVerifier;
    use crate::types::{address::Address, crypto::passkey::PasskeyAuthenticator};

    #[test]
    fn with_address_mutates_in_place() {
        let signature = "BiVJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XYx0AAAAAhgF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCJjaGFsbGVuZ2UiOiJXellBZmVvbHcweU15bEFheDRvbzNjVC1rdEVaM0xmenZXcURqakxKZVRvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfWICfOgpQ38QYao9Gj0/bqmWYNkuxvbuN3lz4uzFcXeVMEVivX41eC9H+tk+UnvUvKzThtf+uMLFzerU0zZLi8le4QJJsAUcyjsP/1UPAesax8UOC14M62FjAqtqaR46wR7jCg==";
        let UserSignature::PasskeyAuthenticator(authenticator) =
            UserSignature::from_base64(signature).unwrap()
        else {
            panic!("expected a passkey authenticator");
        };
        let message = authenticator.challenge().to_vec();
        let authenticator = PasskeyAuthenticator(authenticator);

        let verifier = Arc::new(PasskeyVerifier::new());
        verifier.verify(&message, &authenticator).unwrap();

        verifier
            .clone()
            .with_address(&Address(iota_sdk::types::Address::ZERO));
        let err = verifier.verify(&message, &authenticator).unwrap_err();
        assert!(err.to_string().contains("Invalid author"), "{err}");
    }
}
