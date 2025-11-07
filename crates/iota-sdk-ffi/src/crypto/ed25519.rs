// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    crypto::{FromMnemonic, ToFromBech32, ToFromBytes},
    types::SignatureScheme,
};
use rand::rngs::OsRng;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        crypto::{Ed25519PublicKey, Ed25519Signature},
        signature::{SimpleSignature, UserSignature},
    },
};

#[derive(derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct Ed25519PrivateKey(iota_sdk::crypto::ed25519::Ed25519PrivateKey);

#[uniffi::export]
impl Ed25519PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::crypto::ed25519::Ed25519PrivateKey::new(
            bytes.try_into().map_err(|v: Vec<u8>| {
                SdkFfiError::custom(format!("expected bytes of length 32, found {}", v.len()))
            })?,
        )))
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
        Self(iota_sdk::crypto::ed25519::Ed25519PrivateKey::generate(
            OsRng,
        ))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519PrivateKey::from_der(bytes)?.into())
    }

    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519PrivateKey::from_pem(s)?.into())
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }

    /// Serialize this private key to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Encode this private key as `flag || privkey` in Bech32 starting with
    /// "iotaprivkey" to a string.
    pub fn to_bech32(&self) -> Result<String> {
        Ok(self.0.to_bech32()?)
    }

    /// Decode a private key from `flag || privkey` in Bech32 starting with
    /// "iotaprivkey".
    #[uniffi::constructor]
    pub fn from_bech32(value: &str) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519PrivateKey::from_bech32(value)?.into())
    }

    /// Construct the private key from a mnemonic phrase
    #[uniffi::constructor(default(password = "", account_index = 0))]
    pub fn from_mnemonic(phrase: &str, account_index: u64, password: String) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519PrivateKey::from_mnemonic(
            phrase,
            account_index,
            password,
        )?
        .into())
    }

    /// Create an instance from a mnemonic phrase and a derivation path like
    /// `"m/44'/4218'/0'/0'/0'"`
    #[uniffi::constructor(default(password = ""))]
    pub fn from_mnemonic_with_path(phrase: &str, path: String, password: String) -> Result<Self> {
        Ok(
            iota_sdk::crypto::ed25519::Ed25519PrivateKey::from_mnemonic_with_path(
                phrase, path, password,
            )?
            .into(),
        )
    }

    pub fn try_sign(&self, message: &[u8]) -> Result<Ed25519Signature> {
        Ok(
            iota_sdk::crypto::Signer::<iota_sdk::types::Ed25519Signature>::try_sign(
                &self.0, message,
            )?
            .into(),
        )
    }

    pub fn try_sign_simple(&self, message: &[u8]) -> Result<SimpleSignature> {
        Ok(
            iota_sdk::crypto::Signer::<iota_sdk::types::SimpleSignature>::try_sign(
                &self.0, message,
            )?
            .into(),
        )
    }

    pub fn try_sign_user(&self, message: &[u8]) -> Result<UserSignature> {
        Ok(
            iota_sdk::crypto::Signer::<iota_sdk::types::UserSignature>::try_sign(&self.0, message)?
                .into(),
        )
    }

    /// Sign a transaction and return a UserSignature.
    pub fn sign_transaction(
        &self,
        transaction: &crate::types::transaction::Transaction,
    ) -> Result<UserSignature> {
        Ok(iota_sdk::crypto::IotaSigner::sign_transaction(&self.0, &transaction.0)?.into())
    }

    /// Sign a personal message and return a UserSignature.
    pub fn sign_personal_message(
        &self,
        message: &crate::types::PersonalMessage,
    ) -> Result<UserSignature> {
        Ok(iota_sdk::crypto::IotaSigner::sign_personal_message(&self.0, &message.0)?.into())
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Ed25519VerifyingKey(iota_sdk::crypto::ed25519::Ed25519VerifyingKey);

#[uniffi::export]
impl Ed25519VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Ed25519PublicKey) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519VerifyingKey::new(&public_key.0).map(Self)?)
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        self.0.public_key().into()
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[uniffi::constructor]
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519VerifyingKey::from_der(bytes)?.into())
    }

    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.to_der()?)
    }

    /// Deserialize public key from PEM.
    #[uniffi::constructor]
    pub fn from_pem(s: &str) -> Result<Self> {
        Ok(iota_sdk::crypto::ed25519::Ed25519VerifyingKey::from_pem(s)?.into())
    }

    /// Serialize this public key into PEM format
    pub fn to_pem(&self) -> Result<String> {
        Ok(self.0.to_pem()?)
    }

    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<()> {
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::Ed25519Signature,
        >::verify(&self.0, message, &signature.0)?)
    }

    pub fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::SimpleSignature,
        >::verify(&self.0, message, &signature.0)?)
    }

    pub fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        Ok(
            iota_sdk::crypto::Verifier::<iota_sdk::types::UserSignature>::verify(
                &self.0,
                message,
                &signature.0,
            )?,
        )
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Ed25519Verifier(iota_sdk::crypto::ed25519::Ed25519Verifier);

impl Ed25519Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_sdk::crypto::ed25519::Ed25519Verifier::new())
    }

    fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::SimpleSignature,
        >::verify(&self.0, message, &signature.0)?)
    }

    fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        Ok(
            iota_sdk::crypto::Verifier::<iota_sdk::types::UserSignature>::verify(
                &self.0,
                message,
                &signature.0,
            )?,
        )
    }
}
