// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Defines the [`TransactionSigner`] trait, which allows users to implement any
//! type which can sign a transaction asynchronously.

use std::future::Future;

use iota_crypto::{
    IotaSigner, SignatureError, ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey,
    secp256r1::Secp256r1PrivateKey, simple::SimpleKeypair,
};
use iota_types::{Address, MoveAuthenticator, Transaction, UserSignature};

/// Defines a type which can sign a transaction asynchronously.
///
/// This trait can be implemented downstream to enable signing when using the
/// [`TransactionBuilder`](crate::TransactionBuilder)
/// [`execute`](crate::TransactionBuilder::execute) function.
pub trait TransactionSigner {
    /// The error that can occur during signing.
    type Error: 'static + std::error::Error + Send + Sync;

    /// Returns the address associated with this signer.
    fn address(&self) -> Address;

    /// Sign a transaction and return a [`UserSignature`].
    fn sign(
        &self,
        transaction: &Transaction,
    ) -> impl Future<Output = Result<UserSignature, Self::Error>>;
}

macro_rules! impl_basic_signer {
    ($($signer:ident),*) => {
        $(
        impl TransactionSigner for $signer {
            type Error = SignatureError;

            fn address(&self) -> Address {
                self.public_key().derive_address()
            }

            async fn sign(&self, transaction: &Transaction) -> Result<UserSignature, Self::Error> {
                self.sign_transaction(transaction)
            }
        }
        )*
    };
}

impl_basic_signer!(
    Ed25519PrivateKey,
    Secp256k1PrivateKey,
    Secp256r1PrivateKey,
    SimpleKeypair
);

impl TransactionSigner for MoveAuthenticator {
    type Error = SignatureError;

    fn address(&self) -> Address {
        self.address()
    }

    async fn sign(&self, _transaction: &Transaction) -> Result<UserSignature, Self::Error> {
        Ok(UserSignature::MoveAuthenticator(self.clone()))
    }
}
