// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::SignatureScheme;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        crypto::{Secp256k1PublicKey, Secp256k1Signature},
        signature::{SimpleSignature, UserSignature},
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1PrivateKey(iota_crypto::secp256k1::Secp256k1PrivateKey);

#[uniffi::export]
impl Secp256k1PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(
            iota_crypto::secp256k1::Secp256k1PrivateKey::new(bytes.try_into().unwrap())
                .map_err(SdkFfiError::custom)?,
        ))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> Secp256k1VerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        self.0.public_key().into()
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self(iota_crypto::secp256k1::Secp256k1PrivateKey::generate(OsRng))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        iota_crypto::secp256k1::Secp256k1PrivateKey::from_der(bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        iota_crypto::secp256k1::Secp256k1PrivateKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }

    pub fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1Signature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::Secp256k1Signature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_simple(&self, msg: &[u8]) -> Result<SimpleSignature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::SimpleSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_user(&self, msg: &[u8]) -> Result<UserSignature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::UserSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1VerifyingKey(iota_crypto::secp256k1::Secp256k1VerifyingKey);

#[uniffi::export]
impl Secp256k1VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Secp256k1PublicKey) -> Result<Self> {
        iota_crypto::secp256k1::Secp256k1VerifyingKey::new(&public_key.0)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        self.0.public_key().into()
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        iota_crypto::secp256k1::Secp256k1VerifyingKey::from_der(bytes)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.0.to_der().map_err(SdkFfiError::custom)
    }

    /// Deserialize public key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        iota_crypto::secp256k1::Secp256k1VerifyingKey::from_pem(s)
            .map(Self)
            .map_err(SdkFfiError::custom)
    }

    /// Serialize this public key into PEM
    pub fn to_pem(&self) -> Result<String> {
        self.0.to_pem().map_err(SdkFfiError::custom)
    }

    pub fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::Secp256k1Signature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1Verifier(iota_crypto::secp256k1::Secp256k1Verifier);

#[uniffi::export]
impl Secp256k1Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_crypto::secp256k1::Secp256k1Verifier::new())
    }

    fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1Verifier as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1Verifier as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}
