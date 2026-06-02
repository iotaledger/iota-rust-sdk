// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Address, PasskeyAuthenticator, SimpleSignature, UserSignature};
use signature::Verifier;

use crate::{SignatureError, secp256r1::Secp256r1VerifyingKey};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PasskeyVerifier {
    address: Option<Address>,
}

impl PasskeyVerifier {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }
}

impl Verifier<PasskeyAuthenticator> for PasskeyVerifier {
    fn verify(
        &self,
        message: &[u8],
        authenticator: &PasskeyAuthenticator,
    ) -> Result<(), SignatureError> {
        if let Some(address) = &self.address
            && authenticator.public_key().derive_address() != *address
        {
            return Err(SignatureError::from_source("Invalid author"));
        }

        let SimpleSignature::Secp256r1 {
            signature,
            public_key,
        } = authenticator.signature()
        else {
            return Err(SignatureError::from_source("not a secp256r1 signature"));
        };

        if message != authenticator.challenge() {
            return Err(SignatureError::from_source(
                "passkey challenge does not match expected message",
            ));
        }

        // Construct passkey signing message = authenticator_data ||
        // sha256(client_data_json).
        let mut message = authenticator.authenticator_data().to_owned();
        let client_data_hash = {
            use sha2::Digest;

            let mut hasher = sha2::Sha256::new();
            hasher.update(authenticator.client_data_json().as_bytes());
            hasher.finalize()
        };
        message.extend_from_slice(&client_data_hash);

        Secp256r1VerifyingKey::new(&public_key)?.verify(&message, &signature)
    }
}

impl Verifier<UserSignature> for PasskeyVerifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::PasskeyAuthenticator(authenticator) = signature else {
            return Err(SignatureError::from_source("not a passkey authenticator"));
        };

        <Self as Verifier<PasskeyAuthenticator>>::verify(self, message, authenticator)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::Transaction;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::IotaVerifier;

    #[test]
    fn transaction_signing_fixture() {
        let transaction = "AAAAACdZawPnpJRjmVcwDu6xrIumtq5NLO+6GHbs0iGdCoD7AQ0T0TolicYERdSvyCRjSSduDZLbSpBsZBoib+lF48EBcgAAAAAAAAAgpQr/Mudl9BdzyBdkbqTlqBw4/aJ21kAD/jpJKa05im4nWWsD56SUY5lXMA7usayLprauTSzvuhh27NIhnQqA++gDAAAAAAAAgIQeAAAAAAAA";
        let signature = "BiVJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XYx0AAAAAhgF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCJjaGFsbGVuZ2UiOiJXellBZmVvbHcweU15bEFheDRvbzNjVC1rdEVaM0xmenZXcURqakxKZVRvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfWICfOgpQ38QYao9Gj0/bqmWYNkuxvbuN3lz4uzFcXeVMEVivX41eC9H+tk+UnvUvKzThtf+uMLFzerU0zZLi8le4QJJsAUcyjsP/1UPAesax8UOC14M62FjAqtqaR46wR7jCg==";

        let transaction: Transaction = {
            use base64ct::Encoding;
            let bytes = base64ct::Base64::decode_vec(transaction).unwrap();
            bcs::from_bytes(&bytes).unwrap()
        };
        let signature = UserSignature::from_base64(signature).unwrap();

        let verifier = PasskeyVerifier::default();
        verifier
            .verify_transaction(&transaction, &signature)
            .unwrap();
    }
}
