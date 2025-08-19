// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_crypto::{Signer, Verifier};
use iota_types::SignatureScheme;

use crate::{
    error::SdkFfiError,
    types::{
        crypto::{Secp256r1PublicKey, Secp256r1Signature},
        signature::{SimpleSignature, UserSignature},
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256r1PrivateKey(pub iota_crypto::secp256r1::Secp256r1PrivateKey);

#[uniffi::export]
impl Secp256r1PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(iota_crypto::secp256r1::Secp256r1PrivateKey::new(
            bytes.try_into().unwrap(),
        ))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    /// Get the public key corresponding to this private key.
    pub fn public_key(&self) -> Secp256r1PublicKey {
        self.0.public_key().into()
    }

    /// Sign a message and return a Secp256r1Signature.
    pub fn try_sign(&self, message: Vec<u8>) -> Secp256r1Signature {
        <iota_crypto::secp256r1::Secp256r1PrivateKey as iota_crypto::Signer<
            iota_types::Secp256r1Signature,
        >>::try_sign(&self.0, &message)
        .unwrap()
        .into()
    }

    /// Sign a message and return a SimpleSignature.
    pub fn try_sign_simple(&self, message: Vec<u8>) -> SimpleSignature {
        <iota_crypto::secp256r1::Secp256r1PrivateKey as iota_crypto::Signer<
            iota_types::SimpleSignature,
        >>::try_sign(&self.0, &message)
        .unwrap()
        .into()
    }

    /// Sign a message and return a UserSignature.
    pub fn try_sign_user(&self, message: Vec<u8>) -> UserSignature {
        <iota_crypto::secp256r1::Secp256r1PrivateKey as iota_crypto::Signer<
            iota_types::UserSignature,
        >>::try_sign(&self.0, &message)
        .unwrap()
        .into()
    }

    pub fn verifying_key(&self) -> Secp256r1VerifyingKey {
        self.0.verifying_key().into()
    }

    /// Generate a new random Secp256r1PrivateKey
    #[uniffi::constructor]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self(iota_crypto::secp256r1::Secp256r1PrivateKey::generate(OsRng))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: Vec<u8>) -> Result<Self, SdkFfiError> {
        iota_crypto::secp256r1::Secp256r1PrivateKey::from_der(&bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>, SdkFfiError> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self, SdkFfiError> {
        iota_crypto::secp256r1::Secp256r1PrivateKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String, SdkFfiError> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256r1VerifyingKey(pub iota_crypto::secp256r1::Secp256r1VerifyingKey);

#[uniffi::export]
impl Secp256r1VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Secp256r1PublicKey) -> Result<Self, SdkFfiError> {
        iota_crypto::secp256r1::Secp256r1VerifyingKey::new(public_key)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    pub fn public_key(&self) -> Secp256r1PublicKey {
        self.0.public_key().into()
    }

    pub fn verify(&self, message: Vec<u8>, signature: &Secp256r1Signature) -> bool {
        self.0.verify(&message, &signature.0).is_ok()
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[uniffi::constructor]
    pub fn from_der(bytes: Vec<u8>) -> Result<Self, SdkFfiError> {
        iota_crypto::secp256r1::Secp256r1VerifyingKey::from_der(&bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key as DER-encoded data.
    pub fn to_der(&self) -> Result<Vec<u8>, SdkFfiError> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize public key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self, SdkFfiError> {
        iota_crypto::secp256r1::Secp256r1VerifyingKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key into PEM.
    pub fn to_pem(&self) -> Result<String, SdkFfiError> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256r1Verifier(pub iota_crypto::secp256r1::Secp256r1Verifier);

#[uniffi::export]
impl Secp256r1Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_crypto::secp256r1::Secp256r1Verifier::new())
    }

    pub fn verify_simple(&self, message: Vec<u8>, signature: &SimpleSignature) -> bool {
        <iota_crypto::secp256r1::Secp256r1Verifier as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, &message, &signature.0)
        .is_ok()
    }

    pub fn verify_user(&self, message: Vec<u8>, signature: &UserSignature) -> bool {
        <iota_crypto::secp256r1::Secp256r1Verifier as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, &message, &signature.0)
        .is_ok()
    }
}
