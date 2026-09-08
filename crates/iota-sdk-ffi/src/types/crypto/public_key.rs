// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    types::{
        crypto::{
            Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey, passkey::PasskeyPublicKey,
        },
        signature::SignatureScheme,
    },
};

/// Enum of valid public keys for the signature schemes supported by IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// public-key = %d00 ed25519-public-key /
///              %d01 secp256k1-public-key /
///              %d02 secp256r1-public-key /
///              %d04 passkey-public-key
/// ```
///
/// The gap in the flag values is intentional, as not all signature scheme
/// support public keys.
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
///                      (passkey-flag passkey-public-key)
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct PublicKey(pub iota_sdk::types::PublicKey);

#[uniffi::export]
impl PublicKey {
    pub fn is_ed25519(&self) -> bool {
        self.0.is_ed25519()
    }

    pub fn as_opt_ed25519(&self) -> Option<Arc<Ed25519PublicKey>> {
        self.0
            .as_opt_ed25519()
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

    pub fn as_opt_secp256k1(&self) -> Option<Arc<Secp256k1PublicKey>> {
        self.0
            .as_opt_secp256k1()
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

    pub fn as_opt_secp256r1(&self) -> Option<Arc<Secp256r1PublicKey>> {
        self.0
            .as_opt_secp256r1()
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

    pub fn as_opt_passkey(&self) -> Option<Arc<PasskeyPublicKey>> {
        self.0
            .as_opt_passkey()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_passkey(&self) -> PasskeyPublicKey {
        self.0.as_passkey().clone().into()
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme().into()
    }

    /// Encode this public key as a base64 string of its scheme-flagged byte
    /// representation
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Decode a public key from a base64 string of its scheme-flagged byte
    /// representation
    #[uniffi::constructor]
    pub fn from_base64(s: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::PublicKey::from_base64(s)?))
    }
}
