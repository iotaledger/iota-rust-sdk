// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::{PrivateKeyExt, Signer, Verifier};
use iota_types::SignatureScheme;

use crate::{
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
    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> SimpleVerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> MultisigMemberPublicKey {
        self.verifying_key().public_key()
    }

    /// Encode a SimpleKeypair as `flag || privkey` in bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Decode a SimpleKeypair from `flag || privkey` bytes
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleKeypair::from_bytes(bytes)?.into())
    }

    /// Encode a SimpleKeypair as `flag || privkey` in Bech32 starting with
    /// "iotaprivkey" to a string. Note that the pubkey is not encoded.
    pub fn to_bech32(&self) -> Result<String> {
        Ok(self.0.to_bech32()?)
    }

    /// Decode a SimpleKeypair from `flag || privkey` in Bech32 starting with
    /// "iotaprivkey" to SimpleKeypair. The public key is computed directly from
    /// the private key bytes.
    #[uniffi::constructor]
    pub fn from_bech32(value: &str) -> Result<Self> {
        Ok(iota_crypto::simple::SimpleKeypair::from_bech32(value)?.into())
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
