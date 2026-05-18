// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::SignatureScheme;

use crate::types::crypto::{
    Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey, passkey::PasskeyPublicKey,
};

/// Enum of valid public keys for the signature schemes supported by IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// public-key = ed25519-public-key-variant /
///              secp256k1-public-key-variant /
///              secp256r1-public-key-variant /
///              zklogin-public-key-variant-deprecated /
///              passkey-public-key-variant
///
/// ed25519-public-key-variant              = %d00 ed25519-public-key
/// secp256k1-public-key-variant            = %d01 secp256k1-public-key
/// secp256r1-public-key-variant            = %d02 secp256r1-public-key
/// zklogin-public-key-variant-deprecated   = %d03
/// passkey-public-key-variant              = %d04 passkey-public-key
/// ```
///
/// There is also a base64 encoding for this type defined as:
///
/// ```text
/// base64-public-key = string ; which is valid base64 encoded
///                            ; and the decoded bytes are defined
///                            ; by flagged-public-key
/// flagged-public-key = (ed25519-flag ed25519-public-key) /
///                      (secp256k1-flag secp256k1-public-key) /
///                      (secp256r1-flag secp256r1-public-key) /
///                      (zklogin-flag-deprecated) /
///                      (passkey-flag passkey-public-key)
/// ```
#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct PublicKey(pub iota_sdk::types::PublicKey);

#[uniffi::export]
impl PublicKey {
    pub fn is_ed25519(&self) -> bool {
        self.0.is_ed25519()
    }

    pub fn as_ed25519_opt(&self) -> Option<Arc<Ed25519PublicKey>> {
        self.0
            .as_ed25519_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_ed25519(&self) -> Ed25519PublicKey {
        (*self.0.as_ed25519()).into()
    }

    pub fn is_secp256k1(&self) -> bool {
        self.0.is_secp256k1()
    }

    pub fn as_secp256k1_opt(&self) -> Option<Arc<Secp256k1PublicKey>> {
        self.0
            .as_secp256k1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256k1(&self) -> Secp256k1PublicKey {
        (*self.0.as_secp256k1()).into()
    }

    pub fn is_secp256r1(&self) -> bool {
        self.0.is_secp256r1()
    }

    pub fn as_secp256r1_opt(&self) -> Option<Arc<Secp256r1PublicKey>> {
        self.0
            .as_secp256r1_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_secp256r1(&self) -> Secp256r1PublicKey {
        (*self.0.as_secp256r1()).into()
    }

    pub fn is_passkey(&self) -> bool {
        self.0.is_passkey()
    }

    pub fn as_passkey_opt(&self) -> Option<Arc<PasskeyPublicKey>> {
        self.0
            .as_passkey_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_passkey(&self) -> PasskeyPublicKey {
        self.0.as_passkey().clone().into()
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}
