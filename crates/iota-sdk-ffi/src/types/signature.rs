// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::{SignatureScheme, ZkLoginClaim};

use crate::{
    error::Result,
    types::crypto::{
        Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature,
        Secp256r1PublicKey, Secp256r1Signature, multisig::MultisigAggregatedSignature,
        passkey::PasskeyAuthenticator, zklogin::ZkLoginAuthenticator,
    },
};

/// Flag use to disambiguate the signature schemes supported by IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// signature-scheme = ed25519-flag / secp256k1-flag / secp256r1-flag /
///                    multisig-flag / bls-flag / zklogin-flag / passkey-flag
/// ed25519-flag     = %x00
/// secp256k1-flag   = %x01
/// secp256r1-flag   = %x02
/// multisig-flag    = %x03
/// bls-flag         = %x04
/// zklogin-flag     = %x05
/// passkey-flag     = %x06
/// ```
#[uniffi::remote(Enum)]
#[repr(u8)]
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
#[derive(derive_more::From, uniffi::Object)]
pub struct UserSignature(pub iota_sdk::types::UserSignature);

#[uniffi::export]
impl UserSignature {
    #[uniffi::constructor]
    pub fn new_simple(signature: &SimpleSignature) -> Self {
        Self(iota_sdk::types::UserSignature::Simple(signature.0.clone()))
    }

    #[uniffi::constructor]
    pub fn new_multisig(signature: &MultisigAggregatedSignature) -> Self {
        Self(iota_sdk::types::UserSignature::Multisig(
            signature.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_zklogin(authenticator: &ZkLoginAuthenticator) -> Self {
        Self(iota_sdk::types::UserSignature::ZkLogin(Box::new(
            authenticator.0.clone(),
        )))
    }

    #[uniffi::constructor]
    pub fn new_passkey(authenticator: &PasskeyAuthenticator) -> Self {
        Self(iota_sdk::types::UserSignature::Passkey(
            authenticator.0.clone(),
        ))
    }

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(iota_sdk::types::UserSignature::from_bytes(&bytes).map(Self)?)
    }

    #[uniffi::constructor]
    pub fn from_base64(base64: String) -> Result<Self> {
        Ok(iota_sdk::types::UserSignature::from_base64(&base64).map(Self)?)
    }

    pub fn is_simple(&self) -> bool {
        self.0.is_simple()
    }

    pub fn as_simple_opt(&self) -> Option<Arc<SimpleSignature>> {
        self.0
            .as_simple_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_simple(&self) -> SimpleSignature {
        self.0.as_simple().clone().into()
    }

    pub fn is_multisig(&self) -> bool {
        self.0.is_multisig()
    }

    pub fn as_multisig_opt(&self) -> Option<Arc<MultisigAggregatedSignature>> {
        self.0
            .as_multisig_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_multisig(&self) -> MultisigAggregatedSignature {
        self.0.as_multisig().clone().into()
    }

    pub fn is_zklogin(&self) -> bool {
        self.0.is_zklogin()
    }

    pub fn as_zklogin_opt(&self) -> Option<Arc<ZkLoginAuthenticator>> {
        self.0
            .as_zklogin_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_zklogin(&self) -> ZkLoginAuthenticator {
        self.0.as_zklogin().clone().into()
    }

    pub fn is_passkey(&self) -> bool {
        self.0.is_passkey()
    }

    pub fn as_passkey_opt(&self) -> Option<Arc<PasskeyAuthenticator>> {
        self.0
            .as_passkey_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_passkey(&self) -> PasskeyAuthenticator {
        self.0.as_passkey().clone().into()
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
#[derive(derive_more::From, uniffi::Object)]
pub struct SimpleSignature(pub iota_sdk::types::SimpleSignature);

#[uniffi::export]
impl SimpleSignature {
    #[uniffi::constructor]
    pub fn new_ed25519(signature: &Ed25519Signature, public_key: &Ed25519PublicKey) -> Self {
        Self(iota_sdk::types::SimpleSignature::Ed25519 {
            signature: **signature,
            public_key: **public_key,
        })
    }

    #[uniffi::constructor]
    pub fn new_secp256k1(signature: &Secp256k1Signature, public_key: &Secp256k1PublicKey) -> Self {
        Self(iota_sdk::types::SimpleSignature::Secp256k1 {
            signature: **signature,
            public_key: **public_key,
        })
    }

    #[uniffi::constructor]
    pub fn new_secp256r1(signature: &Secp256r1Signature, public_key: &Secp256r1PublicKey) -> Self {
        Self(iota_sdk::types::SimpleSignature::Secp256r1 {
            signature: **signature,
            public_key: **public_key,
        })
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn is_ed25519(&self) -> bool {
        self.0.is_ed25519()
    }

    pub fn ed25519_sig_opt(&self) -> Option<Arc<Ed25519Signature>> {
        self.0
            .as_ed25519_sig_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn ed25519_sig(&self) -> Ed25519Signature {
        (*self.0.as_ed25519_sig()).into()
    }

    pub fn ed25519_pub_key_opt(&self) -> Option<Arc<Ed25519PublicKey>> {
        self.0
            .as_ed25519_pub_key_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn ed25519_pub_key(&self) -> Ed25519PublicKey {
        (*self.0.as_ed25519_pub_key()).into()
    }

    pub fn is_secp256k1(&self) -> bool {
        self.0.is_secp256k1()
    }

    pub fn secp256k1_sig_opt(&self) -> Option<Arc<Secp256k1Signature>> {
        self.0
            .as_secp256k1_sig_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn secp256k1_sig(&self) -> Secp256k1Signature {
        (*self.0.as_secp256k1_sig()).into()
    }

    pub fn secp256k1_pub_key_opt(&self) -> Option<Arc<Secp256k1PublicKey>> {
        self.0
            .as_secp256k1_pub_key_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn secp256k1_pub_key(&self) -> Secp256k1PublicKey {
        (*self.0.as_secp256k1_pub_key()).into()
    }

    pub fn is_secp256r1(&self) -> bool {
        self.0.is_secp256r1()
    }

    pub fn secp256r1_sig_opt(&self) -> Option<Arc<Secp256r1Signature>> {
        self.0
            .as_secp256r1_sig_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn secp256r1_sig(&self) -> Secp256r1Signature {
        (*self.0.as_secp256r1_sig()).into()
    }

    pub fn secp256r1_pub_key_opt(&self) -> Option<Arc<Secp256r1PublicKey>> {
        self.0
            .as_secp256r1_pub_key_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn secp256r1_pub_key(&self) -> Secp256r1PublicKey {
        (*self.0.as_secp256r1_pub_key()).into()
    }
}

crate::export_iota_types_objects_bcs_conversion!(UserSignature, SimpleSignature);
