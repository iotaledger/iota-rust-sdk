// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::SignatureScheme;

use crate::types::crypto::{
    Ed25519PublicKey, Secp256k1PublicKey, Secp256r1PublicKey, passkey::PasskeyPublicKey,
};

/// Enum of valid public keys for multisig committee members
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// multisig-member-public-key = ed25519-multisig-member-public-key /
///                              secp256k1-multisig-member-public-key /
///                              secp256r1-multisig-member-public-key /
///                              zklogin-multisig-member-public-key-deprecated /
///                              passkey-multisig-member-public-key
///
/// ed25519-multisig-member-public-key              = %d00 ed25519-public-key
/// secp256k1-multisig-member-public-key            = %d01 secp256k1-public-key
/// secp256r1-multisig-member-public-key            = %d02 secp256r1-public-key
/// zklogin-multisig-member-public-key-deprecated   = %d03
/// passkey-multisig-member-public-key              = %d04 passkey-public-key
/// ```
///
/// There is also a legacy encoding for this type defined as:
///
/// ```text
/// legacy-multisig-member-public-key = string ; which is valid base64 encoded
///                                            ; and the decoded bytes are defined
///                                            ; by legacy-public-key
/// legacy-public-key = (ed25519-flag ed25519-public-key) /
///                     (secp256k1-flag secp256k1-public-key) /
///                     (secp256r1-flag secp256r1-public-key)
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
