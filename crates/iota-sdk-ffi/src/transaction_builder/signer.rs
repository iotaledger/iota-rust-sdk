// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::crypto::IotaSigner;

use crate::{
    crypto::{
        ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey, secp256r1::Secp256r1PrivateKey,
        simple::SimpleKeypair,
    },
    error::Result,
    types::{signature::UserSignature, transaction::Transaction},
};

/// Defines a type which can sign a transaction asynchronously.
///
/// This trait can be implemented downstream to enable signing when using the
/// `TransactionBuilder::execute` function.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SignerFn: Send + Sync + std::fmt::Debug {
    /// Sign a transaction and return a BCS serialized `UserSignature`.
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl SignerFn for Ed25519PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<Vec<u8>> {
        let sig = self.0.sign_transaction(&transaction.0)?;
        Ok(bcs::to_bytes(&sig)?)
    }
}

#[async_trait::async_trait]
impl SignerFn for Secp256k1PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<Vec<u8>> {
        let sig = self.0.sign_transaction(&transaction.0)?;
        Ok(bcs::to_bytes(&sig)?)
    }
}

#[async_trait::async_trait]
impl SignerFn for Secp256r1PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<Vec<u8>> {
        let sig = self.0.sign_transaction(&transaction.0)?;
        Ok(bcs::to_bytes(&sig)?)
    }
}

#[async_trait::async_trait]
impl SignerFn for SimpleKeypair {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<Vec<u8>> {
        let sig = self.0.sign_transaction(&transaction.0)?;
        Ok(bcs::to_bytes(&sig)?)
    }
}

/// An async signer implementation which wraps a `SignerFn` definition, which
/// can be used to sign a transaction with a callback.
#[derive(uniffi::Object)]
pub struct Signer(Arc<dyn SignerFn>);

#[uniffi::export(async_runtime = "tokio")]
impl Signer {
    #[uniffi::constructor]
    pub fn new(signer_fn: Arc<dyn SignerFn>) -> Self {
        Self(signer_fn)
    }

    #[uniffi::constructor]
    pub fn from_ed25519(key: Arc<Ed25519PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_secp256k1(key: Arc<Secp256k1PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_secp256r1(key: Arc<Secp256r1PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_keypair(key: Arc<SimpleKeypair>) -> Self {
        Self(key as Arc<_>)
    }

    pub async fn sign(&self, txn: Arc<Transaction>) -> Result<UserSignature> {
        let bytes = self.0.sign(txn).await?;
        let sig: iota_sdk::types::UserSignature = bcs::from_bytes(&bytes)?;
        Ok(sig.into())
    }
}

#[derive(Debug)]
pub struct SignerError(crate::error::SdkFfiError);

impl std::error::Error for SignerError {}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let crate::error::SdkFfiError::Generic(s) = &self.0;
        write!(f, "{s}")
    }
}

impl iota_sdk::transaction_builder::Signer for Signer {
    type Error = SignerError;

    async fn sign(
        &self,
        transaction: &iota_sdk::types::Transaction,
    ) -> std::result::Result<iota_sdk::types::UserSignature, Self::Error> {
        Ok(self
            .sign(Arc::new(transaction.clone().into()))
            .await
            .map_err(SignerError)?
            .0)
    }
}
