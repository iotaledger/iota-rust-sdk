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
    types::{
        crypto::move_authenticator::MoveAuthenticator, signature::UserSignature,
        transaction::Transaction,
    },
};

/// The result of an async sign call containing the `UserSignature`.
#[derive(uniffi::Record)]
pub struct TransactionSignerFnOutput {
    signature: Arc<UserSignature>,
}

/// Defines a type which can sign a transaction asynchronously.
///
/// This trait can be implemented downstream to enable signing when using the
/// `TransactionBuilder::execute` function.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait TransactionSignerFn: Send + Sync + std::fmt::Debug {
    /// Sign a transaction and return a `UserSignature`.
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput>;
}

#[async_trait::async_trait]
impl TransactionSignerFn for Ed25519PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = self.0.sign_transaction(&transaction.0)?;

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

#[async_trait::async_trait]
impl TransactionSignerFn for Secp256k1PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = self.0.sign_transaction(&transaction.0)?;

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

#[async_trait::async_trait]
impl TransactionSignerFn for Secp256r1PrivateKey {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = self.0.sign_transaction(&transaction.0)?;

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

#[async_trait::async_trait]
impl TransactionSignerFn for SimpleKeypair {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = self.0.sign_transaction(&transaction.0)?;

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

#[async_trait::async_trait]
impl TransactionSignerFn for MoveAuthenticator {
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = UserSignature::new_move_authenticator(self);

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature.into()),
        })
    }
}

/// An async signer implementation which wraps a `TransactionSignerFn`
/// definition, which can be used to sign a transaction with a callback.
#[derive(uniffi::Object)]
pub struct TransactionSigner(Arc<dyn TransactionSignerFn>);

#[uniffi::export(async_runtime = "tokio")]
impl TransactionSigner {
    #[uniffi::constructor]
    pub fn new(signer_fn: Arc<dyn TransactionSignerFn>) -> Self {
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

    #[uniffi::constructor]
    pub fn from_move_authenticator(auth: Arc<MoveAuthenticator>) -> Self {
        Self(auth as Arc<_>)
    }

    pub async fn sign(&self, txn: Arc<Transaction>) -> Result<Arc<UserSignature>> {
        Ok(self.0.sign(txn).await?.signature)
    }
}

#[derive(Debug)]
pub struct TransactionSignerError(crate::error::SdkFfiError);

impl std::error::Error for TransactionSignerError {}

impl std::fmt::Display for TransactionSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let crate::error::SdkFfiError::Generic(s) = &self.0;
        write!(f, "{s}")
    }
}

impl iota_sdk::transaction_builder::TransactionSigner for TransactionSigner {
    type Error = TransactionSignerError;

    async fn sign(
        &self,
        transaction: &iota_sdk::types::Transaction,
    ) -> std::result::Result<iota_sdk::types::UserSignature, Self::Error> {
        Ok(self
            .sign(Arc::new(transaction.clone().into()))
            .await
            .map_err(TransactionSignerError)?
            .0
            .clone())
    }
}
