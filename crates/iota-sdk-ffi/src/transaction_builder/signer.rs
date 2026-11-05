// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

// Supertrait of [`TransactionSignerFn`] that conditionally drops Send+Sync on
// wasm32, where uniffi's `wasm-unstable-single-threaded` feature doesn't
// generate them for callback handlers.
#[cfg(not(target_arch = "wasm32"))]
pub trait ThreadSafety: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> ThreadSafety for T {}
#[cfg(target_arch = "wasm32")]
pub trait ThreadSafety {}
#[cfg(target_arch = "wasm32")]
impl<T> ThreadSafety for T {}

use crate::{
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
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait TransactionSignerFn: ThreadSafety + std::fmt::Debug {
    /// Sign a transaction and return a `UserSignature`.
    async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput>;
}

#[cfg(feature = "crypto")]
mod crypto_signers {
    use iota_sdk::crypto::IotaSigner;

    use super::*;
    use crate::crypto::{
        ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey, secp256r1::Secp256r1PrivateKey,
        simple::SimpleKeypair,
    };

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl TransactionSignerFn for Ed25519PrivateKey {
        async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
            let signature = self.0.sign_transaction(&transaction.0)?;

            Ok(TransactionSignerFnOutput {
                signature: Arc::new(signature.into()),
            })
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl TransactionSignerFn for Secp256k1PrivateKey {
        async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
            let signature = self.0.sign_transaction(&transaction.0)?;

            Ok(TransactionSignerFnOutput {
                signature: Arc::new(signature.into()),
            })
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl TransactionSignerFn for Secp256r1PrivateKey {
        async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
            let signature = self.0.sign_transaction(&transaction.0)?;

            Ok(TransactionSignerFnOutput {
                signature: Arc::new(signature.into()),
            })
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl TransactionSignerFn for SimpleKeypair {
        async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
            let signature = self.0.sign_transaction(&transaction.0)?;

            Ok(TransactionSignerFnOutput {
                signature: Arc::new(signature.into()),
            })
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TransactionSignerFn for MoveAuthenticator {
    async fn sign(&self, _transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = UserSignature::new_move_authenticator(self);

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature),
        })
    }
}

/// An async signer implementation which wraps a `TransactionSignerFn`
/// definition, which can be used to sign a transaction with a callback.
#[derive(uniffi::Object)]
pub struct TransactionSigner(Inner);

enum Inner {
    Fn(Arc<dyn TransactionSignerFn>),
    /// Kept apart from `Fn` because the builder passes it the transaction's
    /// objects.
    #[cfg(feature = "ledger")]
    Ledger(Arc<crate::ledger::LedgerSigner>),
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl TransactionSigner {
    #[uniffi::constructor]
    pub fn new(signer_fn: Arc<dyn TransactionSignerFn>) -> Self {
        Self(Inner::Fn(signer_fn))
    }

    #[uniffi::constructor]
    pub fn from_move_authenticator(auth: Arc<MoveAuthenticator>) -> Self {
        Self(Inner::Fn(auth))
    }

    pub async fn sign(&self, txn: Arc<Transaction>) -> Result<Arc<UserSignature>> {
        match &self.0 {
            Inner::Fn(signer_fn) => Ok(signer_fn.sign(txn).await?.signature),
            #[cfg(feature = "ledger")]
            Inner::Ledger(signer) => Ok(Arc::new(signer.sign_transaction(&txn).await?)),
        }
    }
}

#[cfg(feature = "crypto")]
#[uniffi::export]
impl TransactionSigner {
    #[uniffi::constructor]
    pub fn from_ed25519(key: Arc<crate::crypto::ed25519::Ed25519PrivateKey>) -> Self {
        Self(Inner::Fn(key))
    }

    #[uniffi::constructor]
    pub fn from_secp256k1(key: Arc<crate::crypto::secp256k1::Secp256k1PrivateKey>) -> Self {
        Self(Inner::Fn(key))
    }

    #[uniffi::constructor]
    pub fn from_secp256r1(key: Arc<crate::crypto::secp256r1::Secp256r1PrivateKey>) -> Self {
        Self(Inner::Fn(key))
    }

    #[uniffi::constructor]
    pub fn from_keypair(key: Arc<crate::crypto::simple::SimpleKeypair>) -> Self {
        Self(Inner::Fn(key))
    }
}

#[cfg(feature = "ledger")]
#[uniffi::export]
impl TransactionSigner {
    /// Sign with a Ledger device. The transaction builder passes the signer
    /// the transaction's objects so the device shows what the transaction
    /// does; without them, or with an IOTA app older than 1.0, it blind-signs,
    /// which the app only allows when blind signing is enabled in its
    /// settings.
    #[uniffi::constructor]
    pub fn from_ledger(signer: Arc<crate::ledger::LedgerSigner>) -> Self {
        Self(Inner::Ledger(signer))
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

    #[cfg(feature = "ledger")]
    fn uses_objects(&self) -> bool {
        matches!(self.0, Inner::Ledger(_))
    }

    #[cfg(feature = "ledger")]
    async fn sign_with_objects(
        &self,
        transaction: &iota_sdk::types::Transaction,
        objects: &[iota_sdk::types::Object],
    ) -> std::result::Result<iota_sdk::types::UserSignature, Self::Error> {
        match &self.0 {
            Inner::Fn(_) => {
                iota_sdk::transaction_builder::TransactionSigner::sign(self, transaction).await
            }
            Inner::Ledger(signer) => {
                iota_sdk::transaction_builder::TransactionSigner::sign_with_objects(
                    &signer.0,
                    transaction,
                    objects,
                )
                .await
                .map_err(|e| TransactionSignerError(crate::ledger::LedgerError::from(e).into()))
            }
        }
    }
}
