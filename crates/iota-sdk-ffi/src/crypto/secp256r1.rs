// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_crypto::{Signer, Verifier};
use iota_types::SignatureScheme;
use rand::rngs::OsRng;

use crate::{
    error::{Result, SdkFfiError},
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
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1PrivateKey;
        Ok(Self(Secp256r1PrivateKey::new(bytes.try_into().map_err(
            |v: Vec<u8>| {
                SdkFfiError::custom(format!("expected bytes of length 32, found {}", v.len()))
            },
        )?)))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    /// Get the public key corresponding to this private key.
    pub fn public_key(&self) -> Secp256r1PublicKey {
        self.0.public_key().into()
    }

    /// Sign a message and return a Secp256r1Signature.
    pub fn try_sign(&self, message: &[u8]) -> Result<Secp256r1Signature> {
        use iota_crypto::{Signer, secp256r1::Secp256r1PrivateKey};
        use iota_types::Secp256r1Signature;
        Ok(<Secp256r1PrivateKey as Signer<Secp256r1Signature>>::try_sign(&self.0, message)?.into())
    }

    /// Sign a message and return a SimpleSignature.
    pub fn try_sign_simple(&self, message: &[u8]) -> Result<SimpleSignature> {
        use iota_crypto::{Signer, secp256r1::Secp256r1PrivateKey};
        use iota_types::SimpleSignature;
        Ok(<Secp256r1PrivateKey as Signer<SimpleSignature>>::try_sign(&self.0, message)?.into())
    }

    /// Sign a message and return a UserSignature.
    pub fn try_sign_user(&self, message: &[u8]) -> Result<UserSignature> {
        use iota_crypto::{Signer, secp256r1::Secp256r1PrivateKey};
        use iota_types::UserSignature;
        Ok(<Secp256r1PrivateKey as Signer<UserSignature>>::try_sign(&self.0, message)?.into())
    }

    pub fn verifying_key(&self) -> Secp256r1VerifyingKey {
        self.0.verifying_key().into()
    }

    /// Generate a new random Secp256r1PrivateKey
    #[uniffi::constructor]
    pub fn generate() -> Self {
        use iota_crypto::secp256r1::Secp256r1PrivateKey;
        Self(Secp256r1PrivateKey::generate(OsRng))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: Vec<u8>) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1PrivateKey;
        Ok(Secp256r1PrivateKey::from_der(&bytes)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1PrivateKey;
        Ok(Secp256r1PrivateKey::from_pem(s)?.into())
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256r1VerifyingKey(pub iota_crypto::secp256r1::Secp256r1VerifyingKey);

#[uniffi::export]
impl Secp256r1VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Secp256r1PublicKey) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1VerifyingKey;
        Ok(Secp256r1VerifyingKey::new(public_key)?.into())
    }

    pub fn public_key(&self) -> Secp256r1PublicKey {
        self.0.public_key().into()
    }

    pub fn verify(&self, message: Vec<u8>, signature: &Secp256r1Signature) -> bool {
        self.0.verify(&message, &signature.0).is_ok()
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[uniffi::constructor]
    pub fn from_der(bytes: Vec<u8>) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1VerifyingKey;
        Ok(Secp256r1VerifyingKey::from_der(&bytes)?.into())
    }

    /// Serialize this public key as DER-encoded data.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize public key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        use iota_crypto::secp256r1::Secp256r1VerifyingKey;
        Ok(Secp256r1VerifyingKey::from_pem(s)?.into())
    }

    /// Serialize this public key into PEM.
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256r1Verifier(pub iota_crypto::secp256r1::Secp256r1Verifier);

#[uniffi::export]
impl Secp256r1Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        use iota_crypto::secp256r1::Secp256r1Verifier;
        Self(Secp256r1Verifier::new())
    }

    pub fn verify_simple(&self, message: Vec<u8>, signature: &SimpleSignature) -> Result<()> {
        use iota_crypto::{Verifier, secp256r1::Secp256r1Verifier};
        use iota_types::SimpleSignature;
        Ok(<Secp256r1Verifier as Verifier<SimpleSignature>>::verify(
            &self.0,
            &message,
            &signature.0,
        )?)
    }

    pub fn verify_user(&self, message: Vec<u8>, signature: &UserSignature) -> Result<()> {
        use iota_crypto::secp256r1::Secp256r1Verifier;
        use iota_types::UserSignature;
        Ok(<Secp256r1Verifier as Verifier<UserSignature>>::verify(
            &self.0,
            &message,
            &signature.0,
        )?)
    }
}
