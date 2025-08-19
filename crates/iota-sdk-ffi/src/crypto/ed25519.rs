// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::SignatureScheme;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        crypto::{Ed25519PublicKey, Ed25519Signature},
        signature::{SimpleSignature, UserSignature},
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Ed25519PrivateKey(iota_crypto::ed25519::Ed25519PrivateKey);

#[uniffi::export]
impl Ed25519PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(iota_crypto::ed25519::Ed25519PrivateKey::new(
            bytes.try_into().unwrap(),
        ))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        self.0.public_key().into()
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self(iota_crypto::ed25519::Ed25519PrivateKey::generate(OsRng))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        iota_crypto::ed25519::Ed25519PrivateKey::from_der(bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>, SdkFfiError> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        iota_crypto::ed25519::Ed25519PrivateKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String, SdkFfiError> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }

    pub fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, SdkFfiError> {
        <iota_crypto::ed25519::Ed25519PrivateKey as iota_crypto::Signer<
            iota_types::Ed25519Signature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_simple(&self, msg: &[u8]) -> Result<SimpleSignature, SdkFfiError> {
        <iota_crypto::ed25519::Ed25519PrivateKey as iota_crypto::Signer<
            iota_types::SimpleSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_user(&self, msg: &[u8]) -> Result<UserSignature, SdkFfiError> {
        <iota_crypto::ed25519::Ed25519PrivateKey as iota_crypto::Signer<
            iota_types::UserSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Ed25519VerifyingKey(iota_crypto::ed25519::Ed25519VerifyingKey);

#[uniffi::export]
impl Ed25519VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Ed25519PublicKey) -> Result<Self> {
        iota_crypto::ed25519::Ed25519VerifyingKey::new(&public_key.0)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        self.0.public_key().into()
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        iota_crypto::ed25519::Ed25519VerifyingKey::from_der(bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>, SdkFfiError> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize public key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        iota_crypto::ed25519::Ed25519VerifyingKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key into PEM format
    pub fn to_pem(&self) -> Result<String, SdkFfiError> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }

    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), SdkFfiError> {
        <iota_crypto::ed25519::Ed25519VerifyingKey as iota_crypto::Verifier<
            iota_types::Ed25519Signature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_simple(
        &self,
        message: &[u8],
        signature: &SimpleSignature,
    ) -> Result<(), SdkFfiError> {
        <iota_crypto::ed25519::Ed25519VerifyingKey as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_user(
        &self,
        message: &[u8],
        signature: &UserSignature,
    ) -> Result<(), SdkFfiError> {
        <iota_crypto::ed25519::Ed25519VerifyingKey as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Ed25519Verifier(iota_crypto::ed25519::Ed25519Verifier);

impl Ed25519Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_crypto::ed25519::Ed25519Verifier::new())
    }

    fn verify_simple(
        &self,
        message: &[u8],
        signature: &SimpleSignature,
    ) -> Result<(), SdkFfiError> {
        <iota_crypto::ed25519::Ed25519Verifier as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<(), SdkFfiError> {
        <iota_crypto::ed25519::Ed25519Verifier as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}
