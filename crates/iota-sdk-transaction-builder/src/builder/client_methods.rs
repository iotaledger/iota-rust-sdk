// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{
    Address, Digest, Object, ObjectId, SignedTransaction, Transaction, TransactionEffects, TypeTag,
    UserSignature, Version,
};

/// Determines what to wait for after executing a transaction.
///
/// Users should almost always use [`WaitForTx::Finalized`] (the default), as
/// clients may interact with the indexer and not the fullnode directly.
/// Using [`WaitForTx::IndexedOnNode`] only guarantees the transaction is
/// indexed on the fullnode (meaning you can submit transactions that reference
/// objects created by this transaction), but subsequent queries using the
/// transaction ID can still fail until the transaction is indexed on the
/// indexer.
#[derive(Default)]
pub enum WaitForTx {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer. Since the client may query the indexer, subsequent
    /// queries with this transaction ID may still fail. Prefer
    /// [`WaitForTx::Finalized`] unless you have a specific reason to use this.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    #[default]
    Finalized,
}

/// A trait which defines methods needed from the client for the Transaction
/// Builder.
pub trait ClientMethods {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;
    /// The result of a dry run.
    type DryRunResult;

    /// Fetch an object
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>>;

    /// Fetch objects
    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>>;

    /// Fetch a transaction
    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>>;

    /// Fetch transaction effects
    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>>;

    /// Get the reference gas price
    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    /// Estimate the gas budget needed for a transaction
    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    /// Dry run a transaction
    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>>;

    /// Execute a transaction
    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>>;

    /// Wait for the indexing or finalization of a transaction by its digest.
    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;
}

impl<T: ClientMethods> ClientMethods for &T {
    type Error = T::Error;
    type DryRunResult = T::DryRunResult;

    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        (*self).object(object_id, version)
    }

    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>> {
        (*self).objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        (*self).transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        (*self).transaction_effects(digest)
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).reference_gas_price(epoch)
    }

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).estimate_tx_budget(tx)
    }

    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        (*self).dry_run_tx(tx, skip_checks)
    }

    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        (*self).execute_tx(signatures, tx, wait_for)
    }

    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        (*self).wait_for_tx(digest, wait_for)
    }
}

impl<T: ClientMethods> ClientMethods for std::sync::Arc<T> {
    type Error = T::Error;
    type DryRunResult = T::DryRunResult;

    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        self.as_ref().object(object_id, version)
    }

    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>> {
        self.as_ref()
            .objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        self.as_ref().transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        self.as_ref().transaction_effects(digest)
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().reference_gas_price(epoch)
    }

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().estimate_tx_budget(tx)
    }

    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        self.as_ref().dry_run_tx(tx, skip_checks)
    }

    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        self.as_ref().execute_tx(signatures, tx, wait_for)
    }

    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        self.as_ref().wait_for_tx(digest, wait_for)
    }
}

#[cfg(feature = "test-client")]
pub(crate) mod test_client {
    //! Test utilities for the transaction builder.

    use iota_types::{
        Address, Digest, Object, ObjectId, SignedTransaction, Transaction, TransactionEffects,
        TypeTag, UserSignature, Version,
    };

    use super::{ClientMethods, WaitForTx};

    /// A test client that implements [`ClientMethods`] with stub
    /// implementations.
    ///
    /// This client is useful for testing scenarios where a real client
    /// connection is not needed. All methods return default or empty
    /// values.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TestClient;

    /// Error type for [`TestClient`].
    #[derive(Clone, Debug)]
    pub struct TestClientError(pub String);

    impl std::fmt::Display for TestClientError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestClientError: {}", self.0)
        }
    }

    impl std::error::Error for TestClientError {}

    impl ClientMethods for TestClient {
        type Error = TestClientError;
        type DryRunResult = ();

        async fn object(
            &self,
            _object_id: ObjectId,
            _version: impl Into<Option<Version>>,
        ) -> Result<Option<Object>, Self::Error> {
            Ok(None)
        }

        async fn objects(
            &self,
            _type_tag: Option<TypeTag>,
            _owner: Option<Address>,
            _object_ids: Option<Vec<ObjectId>>,
            _ascending: bool,
            _cursor: Option<String>,
            _limit: Option<usize>,
        ) -> Result<Vec<Object>, Self::Error> {
            Ok(Vec::new())
        }

        async fn transaction(
            &self,
            _digest: Digest,
        ) -> Result<Option<SignedTransaction>, Self::Error> {
            Ok(None)
        }

        async fn transaction_effects(
            &self,
            _digest: Digest,
        ) -> Result<Option<TransactionEffects>, Self::Error> {
            Ok(None)
        }

        async fn reference_gas_price(
            &self,
            _epoch: impl Into<Option<u64>>,
        ) -> Result<Option<u64>, Self::Error> {
            Ok(Some(1000))
        }

        async fn estimate_tx_budget(&self, _tx: &Transaction) -> Result<Option<u64>, Self::Error> {
            Ok(Some(50_000_000))
        }

        async fn dry_run_tx(
            &self,
            _tx: &Transaction,
            _skip_checks: bool,
        ) -> Result<Self::DryRunResult, Self::Error> {
            Ok(())
        }

        async fn execute_tx(
            &self,
            _signatures: &[UserSignature],
            _tx: &Transaction,
            _wait_for: impl Into<Option<WaitForTx>>,
        ) -> Result<TransactionEffects, Self::Error> {
            Err(TestClientError(
                "TestClient cannot execute transactions".to_string(),
            ))
        }

        async fn wait_for_tx(
            &self,
            _digest: Digest,
            _wait_for: WaitForTx,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
