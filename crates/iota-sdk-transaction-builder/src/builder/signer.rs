//! Defines the [`Signer`] trait, which allows users to implement any
//! type which can sign a transaction asynchronously.

use std::future::Future;

use iota_crypto::{IotaSigner, SignatureError};
use iota_types::{Transaction, UserSignature};

/// Defines a type which can sign a transaction asynchronously.
///
/// This trait can be implemented downstream to enable signing when using the
/// [`TransactionBuilder`](crate::TransactionBuilder)
/// [`execute`](crate::TransactionBuilder::execute) function.
pub trait Signer {
    /// The error that can occur during signing.
    type Error: 'static + std::error::Error + Send + Sync;

    /// Sign a transaction and return a [`UserSignature`].
    fn sign(
        &self,
        transaction: &Transaction,
    ) -> impl Future<Output = Result<UserSignature, Self::Error>>;
}

impl<T: IotaSigner> Signer for T {
    type Error = SignatureError;

    async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
        self.sign_transaction(transaction)
    }
}
