// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::{Signer, Verifier};
use iota_types::SignatureScheme;

use crate::{
    crypto::{
        ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey, secp256r1::Secp256r1PrivateKey,
    },
    error::Result,
    types::{crypto::multisig::MultisigMemberPublicKey, signature::SimpleSignature},
};

#[derive(derive_more::From, uniffi::Object)]
pub struct SimpleVerifier(iota_crypto::simple::SimpleVerifier);

#[uniffi::export]
impl SimpleVerifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_crypto::simple::SimpleVerifier)
    }

    pub fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        Ok(self.0.verify(message, &signature.0)?)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct SimpleKeypair(pub iota_crypto::simple::SimpleKeypair);

#[uniffi::export]
impl SimpleKeypair {
    #[uniffi::constructor]
    pub fn from_ed25519(keypair: &Ed25519PrivateKey) -> Self {
        Self(iota_crypto::simple::SimpleKeypair::from(
            (**keypair).clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn from_secp256k1(keypair: &Secp256k1PrivateKey) -> Self {
        Self(iota_crypto::simple::SimpleKeypair::from(
            (**keypair).clone(),
        ))
    }

    #[uniffi::constructor]
    pub fn from_secp256r1(keypair: &Secp256r1PrivateKey) -> Self {
        Self(iota_crypto::simple::SimpleKeypair::from(
            (**keypair).clone(),
        ))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> SimpleVerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> MultisigMemberPublicKey {
        self.verifying_key().public_key()
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleKeypair::from_der(bytes)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleKeypair::from_pem(s)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }

    fn try_sign(&self, message: &[u8]) -> Result<SimpleSignature> {
        Ok(Signer::<iota_types::SimpleSignature>::try_sign(&self.0, message)?.into())
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct SimpleVerifyingKey(iota_crypto::simple::SimpleVerifyingKey);

#[uniffi::export]
impl SimpleVerifyingKey {
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn public_key(&self) -> MultisigMemberPublicKey {
        self.0.public_key().into()
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleVerifyingKey::from_der(bytes)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleVerifyingKey::from_pem(s)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }

    pub fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        Ok(self.0.verify(message, &signature.0)?)
    }
}
