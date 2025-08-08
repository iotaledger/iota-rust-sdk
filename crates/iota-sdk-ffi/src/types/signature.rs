// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_types::{SignatureScheme, ZkLoginClaim};

use crate::{
    error::Result,
    types::crypto::{
        Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature,
        Secp256r1PublicKey, Secp256r1Signature, multisig::MultisigAggregatedSignature,
        passkey::PasskeyAuthenticator, zklogin::ZkLoginAuthenticator,
    },
};

#[uniffi::remote(Enum)]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
    Multisig = 0x03,
    Bls12381 = 0x04,
    ZkLogin = 0x05,
    Passkey = 0x06,
}

/// A signature from a user
///
/// A `UserSignature` is most commonly used to authorize the execution and
/// inclusion of a transaction to the blockchain.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// user-signature-bcs = bytes ; where the contents of the bytes are defined by <user-signature>
/// user-signature = simple-signature / multisig / multisig-legacy / zklogin / passkey
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct UserSignature(pub iota_types::UserSignature);

#[uniffi::export]
impl UserSignature {
    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        match &self.0 {
            iota_types::UserSignature::Simple(simple) => simple.scheme(),
            iota_types::UserSignature::Multisig(_) => SignatureScheme::Multisig,
            iota_types::UserSignature::ZkLogin(_) => SignatureScheme::ZkLogin,
            iota_types::UserSignature::Passkey(_) => SignatureScheme::Passkey,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(iota_types::UserSignature::from_bytes(&bytes).map(Self)?)
    }

    #[uniffi::constructor]
    pub fn from_base64(base64: String) -> Result<Self> {
        Ok(iota_types::UserSignature::from_base64(&base64).map(Self)?)
    }

    pub fn is_simple(&self) -> bool {
        matches!(self.0, iota_types::UserSignature::Simple(_))
    }

    pub fn as_simple_opt(&self) -> Option<Arc<SimpleSignature>> {
        if let iota_types::UserSignature::Simple(sig) = self.0.clone() {
            Some(Arc::new(SimpleSignature(sig)))
        } else {
            None
        }
    }

    pub fn as_simple(&self) -> Arc<SimpleSignature> {
        self.as_simple_opt().expect("not a simple signature")
    }

    pub fn is_multisig(&self) -> bool {
        matches!(self.0, iota_types::UserSignature::Multisig(_))
    }

    pub fn as_multisig_opt(&self) -> Option<Arc<MultisigAggregatedSignature>> {
        if let iota_types::UserSignature::Multisig(sig) = self.0.clone() {
            Some(Arc::new(MultisigAggregatedSignature(sig)))
        } else {
            None
        }
    }

    pub fn as_multisig(&self) -> Arc<MultisigAggregatedSignature> {
        self.as_multisig_opt().expect("not a multi-signature")
    }

    pub fn is_zklogin(&self) -> bool {
        matches!(self.0, iota_types::UserSignature::ZkLogin(_))
    }

    pub fn as_zklogin_opt(&self) -> Option<Arc<ZkLoginAuthenticator>> {
        if let iota_types::UserSignature::ZkLogin(sig) = self.0.clone() {
            Some(Arc::new(ZkLoginAuthenticator(*sig)))
        } else {
            None
        }
    }

    pub fn as_zklogin(&self) -> Arc<ZkLoginAuthenticator> {
        self.as_zklogin_opt().expect("not a zklogin authenticator")
    }

    pub fn is_passkey(&self) -> bool {
        matches!(self.0, iota_types::UserSignature::Passkey(_))
    }

    pub fn as_passkey_opt(&self) -> Option<Arc<PasskeyAuthenticator>> {
        if let iota_types::UserSignature::Passkey(sig) = self.0.clone() {
            Some(Arc::new(sig.into()))
        } else {
            None
        }
    }

    pub fn as_passkey(&self) -> Arc<PasskeyAuthenticator> {
        self.as_passkey_opt().expect("not a passkey signature")
    }
}

/// A basic signature
///
/// This enumeration defines the set of simple or basic signature schemes
/// supported by IOTA. Most signature schemes supported by IOTA end up
/// comprising of a at least one simple signature scheme.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// simple-signature-bcs = bytes ; where the contents of the bytes are defined by <simple-signature>
/// simple-signature = (ed25519-flag ed25519-signature ed25519-public-key) /
///                    (secp256k1-flag secp256k1-signature secp256k1-public-key) /
///                    (secp256r1-flag secp256r1-signature secp256r1-public-key)
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct SimpleSignature(pub iota_types::SimpleSignature);

#[uniffi::export]
impl SimpleSignature {
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn is_ed25519(&self) -> bool {
        matches!(self.0, iota_types::SimpleSignature::Ed25519 { .. })
    }

    pub fn ed25519_sig_opt(&self) -> Option<Arc<Ed25519Signature>> {
        if let iota_types::SimpleSignature::Ed25519 { signature, .. } = self.0.clone() {
            Some(Arc::new(signature.into()))
        } else {
            None
        }
    }

    pub fn ed25519_sig(&self) -> Arc<Ed25519Signature> {
        self.ed25519_sig_opt().expect("not an ed25519 signature")
    }

    pub fn ed25519_pub_key_opt(&self) -> Option<Arc<Ed25519PublicKey>> {
        if let iota_types::SimpleSignature::Ed25519 { public_key, .. } = self.0.clone() {
            Some(Arc::new(public_key.into()))
        } else {
            None
        }
    }

    pub fn ed25519_pub_key(&self) -> Arc<Ed25519PublicKey> {
        self.ed25519_pub_key_opt()
            .expect("not an ed25519 public key")
    }

    pub fn is_secp256k1(&self) -> bool {
        matches!(self.0, iota_types::SimpleSignature::Secp256k1 { .. })
    }

    pub fn secp256k1_sig_opt(&self) -> Option<Arc<Secp256k1Signature>> {
        if let iota_types::SimpleSignature::Secp256k1 { signature, .. } = self.0.clone() {
            Some(Arc::new(signature.into()))
        } else {
            None
        }
    }

    pub fn secp256k1_sig(&self) -> Arc<Secp256k1Signature> {
        self.secp256k1_sig_opt()
            .expect("not an secp256k1 signature")
    }

    pub fn secp256k1_pub_key_opt(&self) -> Option<Arc<Secp256k1PublicKey>> {
        if let iota_types::SimpleSignature::Secp256k1 { public_key, .. } = self.0.clone() {
            Some(Arc::new(public_key.into()))
        } else {
            None
        }
    }

    pub fn secp256k1_pub_key(&self) -> Arc<Secp256k1PublicKey> {
        self.secp256k1_pub_key_opt()
            .expect("not an secp256k1 public key")
    }

    pub fn is_secp256r1(&self) -> bool {
        matches!(self.0, iota_types::SimpleSignature::Secp256r1 { .. })
    }

    pub fn secp256r1_sig_opt(&self) -> Option<Arc<Secp256r1Signature>> {
        if let iota_types::SimpleSignature::Secp256r1 { signature, .. } = self.0.clone() {
            Some(Arc::new(signature.into()))
        } else {
            None
        }
    }

    pub fn secp256r1_sig(&self) -> Arc<Secp256r1Signature> {
        self.secp256r1_sig_opt()
            .expect("not an secp256r1 signature")
    }

    pub fn secp256r1_pub_key_opt(&self) -> Option<Arc<Secp256r1PublicKey>> {
        if let iota_types::SimpleSignature::Secp256r1 { public_key, .. } = self.0.clone() {
            Some(Arc::new(public_key.into()))
        } else {
            None
        }
    }

    pub fn secp256r1_pub_key(&self) -> Arc<Secp256r1PublicKey> {
        self.secp256r1_pub_key_opt()
            .expect("not an secp256r1 public key")
    }
}
