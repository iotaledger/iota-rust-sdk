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
        crypto::move_authenticator::MoveAuthenticator, object::Object, signature::UserSignature,
        transaction::Transaction,
    },
};

/// The result of an async sign call containing the `UserSignature`.
#[derive(uniffi::Record)]
pub struct TransactionSignerFnOutput {
    pub(crate) signature: Arc<UserSignature>,
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

    /// Whether the signer uses the objects the transaction reads, such as a
    /// hardware wallet showing what the transaction does. When `true`, the
    /// transaction builder gathers them and calls `sign_with_objects` instead
    /// of `sign`.
    fn uses_objects(&self) -> bool;

    /// Sign a transaction given the objects it reads: its gas coins and
    /// immutable, owned or receiving inputs at the versions it references, and
    /// its shared inputs as the builder fetched them, which may change before
    /// the transaction executes. The transaction builder only calls this when
    /// `uses_objects` returns `true`, and passes no objects when it has no
    /// client to fetch them.
    async fn sign_with_objects(
        &self,
        transaction: Arc<Transaction>,
        objects: Vec<Arc<Object>>,
    ) -> Result<TransactionSignerFnOutput>;
}

/// Implements [`TransactionSignerFn`] for signers that sign the transaction
/// digest with a key and do not use the transaction's objects.
#[cfg(feature = "crypto")]
macro_rules! impl_key_signer {
    ($($signer:ty),*) => {
        $(
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        impl TransactionSignerFn for $signer {
            async fn sign(&self, transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
                let signature = iota_sdk::crypto::IotaSigner::sign_transaction(&self.0, &transaction.0)?;

                Ok(TransactionSignerFnOutput {
                    signature: Arc::new(signature.into()),
                })
            }

            fn uses_objects(&self) -> bool {
                false
            }

            async fn sign_with_objects(
                &self,
                transaction: Arc<Transaction>,
                _objects: Vec<Arc<Object>>,
            ) -> Result<TransactionSignerFnOutput> {
                self.sign(transaction).await
            }
        }
        )*
    };
}

#[cfg(feature = "crypto")]
impl_key_signer!(
    crate::crypto::ed25519::Ed25519PrivateKey,
    crate::crypto::secp256k1::Secp256k1PrivateKey,
    crate::crypto::secp256r1::Secp256r1PrivateKey,
    crate::crypto::simple::SimpleKeypair
);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl TransactionSignerFn for MoveAuthenticator {
    async fn sign(&self, _transaction: Arc<Transaction>) -> Result<TransactionSignerFnOutput> {
        let signature = UserSignature::new_move_authenticator(self);

        Ok(TransactionSignerFnOutput {
            signature: Arc::new(signature),
        })
    }

    fn uses_objects(&self) -> bool {
        false
    }

    async fn sign_with_objects(
        &self,
        transaction: Arc<Transaction>,
        _objects: Vec<Arc<Object>>,
    ) -> Result<TransactionSignerFnOutput> {
        self.sign(transaction).await
    }
}

/// An async signer implementation which wraps a `TransactionSignerFn`
/// definition, which can be used to sign a transaction with a callback.
#[derive(uniffi::Object)]
pub struct TransactionSigner(Arc<dyn TransactionSignerFn>);

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl TransactionSigner {
    #[uniffi::constructor]
    pub fn new(signer_fn: Arc<dyn TransactionSignerFn>) -> Self {
        Self(signer_fn)
    }

    #[uniffi::constructor]
    pub fn from_move_authenticator(auth: Arc<MoveAuthenticator>) -> Self {
        Self(auth as Arc<_>)
    }

    pub async fn sign(&self, txn: Arc<Transaction>) -> Result<Arc<UserSignature>> {
        Ok(self.0.sign(txn).await?.signature)
    }
}

#[cfg(feature = "crypto")]
#[uniffi::export]
impl TransactionSigner {
    #[uniffi::constructor]
    pub fn from_ed25519(key: Arc<crate::crypto::ed25519::Ed25519PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_secp256k1(key: Arc<crate::crypto::secp256k1::Secp256k1PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_secp256r1(key: Arc<crate::crypto::secp256r1::Secp256r1PrivateKey>) -> Self {
        Self(key as Arc<_>)
    }

    #[uniffi::constructor]
    pub fn from_keypair(key: Arc<crate::crypto::simple::SimpleKeypair>) -> Self {
        Self(key as Arc<_>)
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
        Self(signer as Arc<_>)
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

    fn uses_objects(&self) -> bool {
        self.0.uses_objects()
    }

    async fn sign_with_objects(
        &self,
        transaction: &iota_sdk::types::Transaction,
        objects: &[iota_sdk::types::Object],
    ) -> std::result::Result<iota_sdk::types::UserSignature, Self::Error> {
        // The builder passes the objects to every signer when any of them uses
        // them, so only convert them for a signer that does.
        if !self.0.uses_objects() {
            return iota_sdk::transaction_builder::TransactionSigner::sign(self, transaction).await;
        }
        let objects = objects
            .iter()
            .map(|object| Arc::new(object.clone().into()))
            .collect();
        Ok(self
            .0
            .sign_with_objects(Arc::new(transaction.clone().into()), objects)
            .await
            .map_err(TransactionSignerError)?
            .signature
            .0
            .clone())
    }
}
