// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    types::crypto::{
        Ed25519PublicKey, Ed25519Signature, Secp256k1PublicKey, Secp256k1Signature,
        Secp256r1PublicKey, Secp256r1Signature, move_authenticator::MoveAuthenticator,
        multisig::MultisigAggregatedSignature, passkey::PasskeyAuthenticator,
        public_key::PublicKey,
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
///                    multisig-flag / bls-flag / passkey-auth-flag /
///                    move-auth-flag
/// ed25519-flag                    = %d00
/// secp256k1-flag                  = %d01
/// secp256r1-flag                  = %d02
/// multisig-flag                   = %d03
/// bls-flag                        = %d04
/// passkey-auth-flag               = %d06
/// move-auth-flag                  = %d07
/// ```
///
/// Flag `%d05` is reserved: it was formerly used for the now-removed zklogin
/// authenticator (which was never enabled on chain) and is intentionally
/// skipped.
#[derive(Clone, uniffi::Enum)]
#[repr(u8)]
pub enum SignatureScheme {
    Ed25519 = 0x00,
    Secp256k1 = 0x01,
    Secp256r1 = 0x02,
    Multisig = 0x03,
    Bls12381 = 0x04,
    PasskeyAuthenticator = 0x06,
    MoveAuthenticator = 0x07,
}

impl From<iota_sdk::types::SignatureScheme> for SignatureScheme {
    fn from(value: iota_sdk::types::SignatureScheme) -> Self {
        match value {
            iota_sdk::types::SignatureScheme::Ed25519 => Self::Ed25519,
            iota_sdk::types::SignatureScheme::Secp256k1 => Self::Secp256k1,
            iota_sdk::types::SignatureScheme::Secp256r1 => Self::Secp256r1,
            iota_sdk::types::SignatureScheme::Multisig => Self::Multisig,
            iota_sdk::types::SignatureScheme::Bls12381 => Self::Bls12381,
            iota_sdk::types::SignatureScheme::PasskeyAuthenticator => Self::PasskeyAuthenticator,
            iota_sdk::types::SignatureScheme::MoveAuthenticator => Self::MoveAuthenticator,
            _ => unimplemented!("a new SignatureScheme variant was added and needs to be handled"),
        }
    }
}

impl From<SignatureScheme> for iota_sdk::types::SignatureScheme {
    fn from(value: SignatureScheme) -> Self {
        match value {
            SignatureScheme::Ed25519 => Self::Ed25519,
            SignatureScheme::Secp256k1 => Self::Secp256k1,
            SignatureScheme::Secp256r1 => Self::Secp256r1,
            SignatureScheme::Multisig => Self::Multisig,
            SignatureScheme::Bls12381 => Self::Bls12381,
            SignatureScheme::PasskeyAuthenticator => Self::PasskeyAuthenticator,
            SignatureScheme::MoveAuthenticator => Self::MoveAuthenticator,
        }
    }
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
/// user-signature = bytes ; where the contents of the bytes are defined by
///                        ; <user-signature-body>
/// user-signature-body = (%d00 ed25519-signature ed25519-public-key) /
///                       (%d01 secp256k1-signature secp256k1-public-key) /
///                       (%d02 secp256r1-signature secp256r1-public-key) /
///                       (%d03 multisig-aggregated-signature) /
///                       (%d06 passkey-authenticator) /
///                       (%d07 move-authenticator)
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
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
    pub fn new_passkey_authenticator(authenticator: &PasskeyAuthenticator) -> Self {
        Self(iota_sdk::types::UserSignature::PasskeyAuthenticator(
            authenticator.0.clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn new_move_authenticator(authenticator: &MoveAuthenticator) -> Self {
        Self(iota_sdk::types::UserSignature::MoveAuthenticator(
            authenticator.0.clone(),
        ))
    }

    /// Return the flag for this signature scheme
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
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

    /// Check if this signature is a simple signature
    pub fn is_simple(&self) -> bool {
        self.0.is_simple()
    }

    /// Convert this signature into a simple signature if it is one, or return
    /// `None` otherwise
    pub fn as_opt_simple(&self) -> Option<Arc<SimpleSignature>> {
        self.0
            .as_opt_simple()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this signature into a simple signature if it is one, or panic
    /// otherwise
    pub fn as_simple(&self) -> SimpleSignature {
        self.0.as_simple().clone().into()
    }

    /// Check if this signature is a multisig aggregated signature
    pub fn is_multisig(&self) -> bool {
        self.0.is_multisig()
    }

    /// Convert this signature into a multisig aggregated signature if it is
    /// one, or return `None` otherwise
    pub fn as_opt_multisig(&self) -> Option<Arc<MultisigAggregatedSignature>> {
        self.0
            .as_opt_multisig()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this signature into a multisig aggregated signature if it is
    /// one, or panic otherwise
    pub fn as_multisig(&self) -> MultisigAggregatedSignature {
        self.0.as_multisig().clone().into()
    }

    /// Check if this signature is a passkey authenticator
    pub fn is_passkey_authenticator(&self) -> bool {
        self.0.is_passkey_authenticator()
    }

    /// Convert this signature into a passkey authenticator if it is one, or
    /// return `None` otherwise
    pub fn as_opt_passkey_authenticator(&self) -> Option<Arc<PasskeyAuthenticator>> {
        self.0
            .as_opt_passkey_authenticator()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this signature into a passkey authenticator if it is one, or
    /// panic otherwise
    pub fn as_passkey_authenticator(&self) -> PasskeyAuthenticator {
        self.0.as_passkey_authenticator().clone().into()
    }

    /// Check if this signature is a move authenticator
    pub fn is_move_authenticator(&self) -> bool {
        self.0.is_move_authenticator()
    }

    /// Convert this signature into a move authenticator if it is one, or return
    /// `None` otherwise
    pub fn as_opt_move_authenticator(&self) -> Option<Arc<MoveAuthenticator>> {
        self.0
            .as_opt_move_authenticator()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this signature into a move authenticator if it is one, or panic
    /// otherwise
    pub fn as_move_authenticator(&self) -> MoveAuthenticator {
        self.0.as_move_authenticator().clone().into()
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
/// simple-signature = bytes ; where the contents of the bytes are defined by
///                          ; <simple-signature-body>
/// simple-signature-body = (ed25519-flag ed25519-signature ed25519-public-key) /
///                         (secp256k1-flag secp256k1-signature secp256k1-public-key) /
///                         (secp256r1-flag secp256r1-signature secp256r1-public-key)
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Debug, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq, Hash)]
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
        self.0.scheme().into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Base64-encode this signature as its `flag || sig || pubkey` bytes.
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }

    /// Decode a signature from the Base64 form produced by `to_base64`, i.e.
    /// base64 over the `flag || sig || pubkey` bytes.
    #[uniffi::constructor]
    pub fn from_base64(base64: String) -> Result<Self> {
        Ok(iota_sdk::types::SimpleSignature::from_base64(&base64).map(Self)?)
    }

    /// The raw signature bytes, without the scheme flag or the public key.
    pub fn signature_bytes(&self) -> Vec<u8> {
        self.0.signature_bytes().to_vec()
    }

    /// The public key embedded in this signature.
    pub fn to_public_key(&self) -> PublicKey {
        self.0.to_public_key().into()
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
crate::export_iota_types_objects_json_conversion!(UserSignature, SimpleSignature);
crate::export_iota_types_display!(SignatureScheme);
crate::export_iota_types_objects_display!(UserSignature, SimpleSignature);
