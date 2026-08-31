// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use iota_types::{
    Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
    UserSignature, Version,
};

/// Determines what to wait for after executing a transaction.
///
/// Users should almost always use [`WaitForTransaction::Finalized`] (the
/// default), as clients may interact with the indexer and not the fullnode
/// directly. Using [`WaitForTransaction::IndexedOnNode`] only guarantees the
/// transaction is indexed on the fullnode (meaning you can submit transactions
/// that reference objects created by this transaction), but subsequent queries
/// using the transaction ID can still fail until the transaction is indexed on
/// the indexer.
#[derive(Default)]
#[non_exhaustive]
pub enum WaitForTransaction {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer. Since the client may query the indexer, subsequent
    /// queries with this transaction ID may still fail. Prefer
    /// [`WaitForTransaction::Finalized`] unless you have a specific reason to
    /// use this.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    #[default]
    Finalized,
}

/// One page of objects plus an optional cursor for the next page. See
/// [`TransactionBuilderLedgerClient::objects`].
#[derive(Clone, Debug)]
pub struct ObjectsPage {
    /// The objects in this page.
    pub data: Vec<Object>,
    /// Opaque continuation cursor for fetching the next page; `None` when no
    /// further pages exist. Pass it back as the `cursor` argument to
    /// [`TransactionBuilderLedgerClient::objects`] to advance.
    pub next_cursor: Option<Vec<u8>>,
}

/// Transport-neutral view of the chain's protocol configuration: a flat
/// map of attribute name to value, parsed by callers as needed.
#[derive(Clone, Debug, Default)]
pub struct ProtocolConfig {
    /// All available configuration attributes, keyed by their canonical
    /// protocol name (e.g. `"max_gas_payment_objects"`).
    pub attributes: BTreeMap<String, String>,
}

/// Base trait shared by the transaction builder client traits, carrying the
/// client's error type.
pub trait TransactionBuilderClientBase {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;
}

/// Read-only access to ledger state: everything the Transaction Builder needs
/// to resolve and build a transaction
/// ([`finish_with_budget`](crate::TransactionBuilder::finish_with_budget)).
pub trait TransactionBuilderLedgerClient: TransactionBuilderClientBase {
    /// Fetch an object
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>>;

    /// Fetch several objects at once, returning them in the order they were
    /// requested with `None` in place of any object that does not exist.
    ///
    /// The default impl calls [`object`](Self::object) once per entry, costing
    /// one round trip each. Clients whose transport can fetch a batch (such as
    /// gRPC's `GetObjects`) should override it.
    fn objects_by_id(
        &self,
        object_ids: &[(ObjectId, Option<Version>)],
    ) -> impl std::future::Future<Output = Result<Vec<Option<Object>>, Self::Error>> {
        async move {
            let mut objects = Vec::with_capacity(object_ids.len());
            for (object_id, version) in object_ids {
                objects.push(self.object(*object_id, *version).await?);
            }
            Ok(objects)
        }
    }

    /// Fetch one page of objects matching the filter, returning the page
    /// contents and a continuation cursor (when more pages exist).
    ///
    /// The cursor is opaque to callers — both GraphQL (base64-encoded
    /// JSON/BCS) and gRPC (`prost::bytes::Bytes` page token) formats fit
    /// into `Option<Vec<u8>>`. Pass `None` to start from the beginning;
    /// pass the cursor returned by a previous call to advance.
    fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>>;

    /// Fetch the chain's protocol configuration.
    ///
    /// The default impl returns a default [`ProtocolConfig`].
    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        std::future::ready(Ok(ProtocolConfig::default()))
    }

    /// Get the reference gas price
    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;
}

/// Transaction simulation: dry runs and the gas budget estimation built on
/// them ([`finish`](crate::TransactionBuilder::finish),
/// [`dry_run`](crate::TransactionBuilder::dry_run)).
pub trait TransactionBuilderSimulationClient: TransactionBuilderClientBase {
    /// The result of a dry run.
    type DryRunResult;

    /// Estimate the gas budget needed for a transaction, typically by
    /// simulating it and reading the gas cost from the result. `Ok(None)`
    /// means no estimate is available;
    /// [`finish`](crate::TransactionBuilder::finish) then fails unless a
    /// budget was set explicitly.
    fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    /// Dry run a transaction
    fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>>;
}

/// Transaction execution: submitting a transaction and tracking its result
/// ([`execute`](crate::TransactionBuilder::execute)).
pub trait TransactionBuilderExecutionClient: TransactionBuilderClientBase {
    /// Execute a transaction
    fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>>;

    /// Wait for the indexing or finalization of a transaction by its digest.
    fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;

    /// Fetch the effects of an executed transaction
    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>>;
}

/// A full transaction builder client: ledger reads, simulation, and execution.
///
/// This is a blanket alias — do not implement it directly. Implement
/// [`TransactionBuilderLedgerClient`], [`TransactionBuilderSimulationClient`],
/// and [`TransactionBuilderExecutionClient`] instead, and this trait is
/// implemented automatically.
pub trait TransactionBuilderClient:
    TransactionBuilderLedgerClient
    + TransactionBuilderSimulationClient
    + TransactionBuilderExecutionClient
{
}

impl<T> TransactionBuilderClient for T where
    T: TransactionBuilderLedgerClient
        + TransactionBuilderSimulationClient
        + TransactionBuilderExecutionClient
{
}

impl<T: TransactionBuilderClientBase> TransactionBuilderClientBase for &T {
    type Error = T::Error;
}

impl<T: TransactionBuilderLedgerClient> TransactionBuilderLedgerClient for &T {
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        (*self).object(object_id, version)
    }

    fn objects_by_id(
        &self,
        object_ids: &[(ObjectId, Option<Version>)],
    ) -> impl std::future::Future<Output = Result<Vec<Option<Object>>, Self::Error>> {
        (*self).objects_by_id(object_ids)
    }

    fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>> {
        (*self).objects(struct_tag, owner, cursor, limit)
    }

    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        (*self).protocol_config()
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).reference_gas_price(epoch)
    }
}

impl<T: TransactionBuilderSimulationClient> TransactionBuilderSimulationClient for &T {
    type DryRunResult = T::DryRunResult;

    fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).estimate_transaction_budget(transaction)
    }

    fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        (*self).dry_run_transaction(transaction, skip_checks)
    }
}

impl<T: TransactionBuilderExecutionClient> TransactionBuilderExecutionClient for &T {
    fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        (*self).execute_transaction(signatures, transaction, wait_for)
    }

    fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        (*self).wait_for_transaction(digest, wait_for)
    }

    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        (*self).transaction_effects(digest)
    }
}

impl<T: TransactionBuilderClientBase> TransactionBuilderClientBase for std::sync::Arc<T> {
    type Error = T::Error;
}

impl<T: TransactionBuilderLedgerClient> TransactionBuilderLedgerClient for std::sync::Arc<T> {
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        self.as_ref().object(object_id, version)
    }

    fn objects_by_id(
        &self,
        object_ids: &[(ObjectId, Option<Version>)],
    ) -> impl std::future::Future<Output = Result<Vec<Option<Object>>, Self::Error>> {
        self.as_ref().objects_by_id(object_ids)
    }

    fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>> {
        self.as_ref().objects(struct_tag, owner, cursor, limit)
    }

    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        self.as_ref().protocol_config()
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().reference_gas_price(epoch)
    }
}

impl<T: TransactionBuilderSimulationClient> TransactionBuilderSimulationClient
    for std::sync::Arc<T>
{
    type DryRunResult = T::DryRunResult;

    fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().estimate_transaction_budget(transaction)
    }

    fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        self.as_ref().dry_run_transaction(transaction, skip_checks)
    }
}

impl<T: TransactionBuilderExecutionClient> TransactionBuilderExecutionClient for std::sync::Arc<T> {
    fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        self.as_ref()
            .execute_transaction(signatures, transaction, wait_for)
    }

    fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        self.as_ref().wait_for_transaction(digest, wait_for)
    }

    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        self.as_ref().transaction_effects(digest)
    }
}

#[cfg(feature = "test-client")]
pub(crate) mod test_client {
    //! Test utilities for the transaction builder.

    use iota_types::{
        Address, MoveStruct, Object, ObjectData, ObjectId, Owner, StructTag, Transaction,
        TransactionDigest, TransactionEffects, UserSignature, Version,
    };

    use super::{
        TransactionBuilderClientBase, TransactionBuilderExecutionClient,
        TransactionBuilderLedgerClient, TransactionBuilderSimulationClient, WaitForTransaction,
    };
    use crate::ObjectsPage;

    /// Balance, in NANOS, of every fabricated coin. Large enough to cover any
    /// gas budget the builder might estimate in a doc test or example.
    const FABRICATED_COIN_BALANCE: u64 = 1_000_000_000_000;

    /// Build a fabricated gas coin (`0x2::coin::Coin<0x2::iota::IOTA>`) with
    /// the given id, owner and balance.
    ///
    /// The contents are the BCS layout the coin resolution code expects: the
    /// 32-byte object id followed by the little-endian `u64` balance.
    fn fabricated_coin(object_id: ObjectId, owner: Owner, balance: u64) -> Object {
        let mut contents = Vec::with_capacity(ObjectId::LENGTH + std::mem::size_of::<u64>());
        contents.extend_from_slice(object_id.as_ref());
        contents.extend_from_slice(&balance.to_le_bytes());
        let move_struct = MoveStruct::new(
            StructTag::new_gas_coin().into(),
            Version::from_u64(1),
            contents,
        )
        .expect("contents always contain a full object id");
        Object::new(
            ObjectData::Struct(move_struct),
            owner,
            TransactionDigest::ZERO,
            0,
        )
    }

    /// A test client that implements the transaction builder client traits by
    /// fabricating objects on demand.
    ///
    /// It is useful for building transactions in tests, examples, and doc tests
    /// where a live network connection is not available. Object lookups resolve
    /// to a synthesized gas coin owned by an address (shared system objects
    /// such as the system state object resolve as shared), and gas
    /// selection always finds a single funded coin. This is enough to drive
    /// [`finish`](crate::TransactionBuilder::finish) to completion, but the
    /// resulting transaction references made-up objects and cannot be executed
    /// — [`execute_transaction`](TransactionBuilderExecutionClient::execute_transaction) returns
    /// an error.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TestClient;

    /// TransactionBuilderError type for [`TestClient`].
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("TestClientError: {0}")]
    pub struct TestClientError(pub String);

    impl TransactionBuilderClientBase for TestClient {
        type Error = TestClientError;
    }

    impl TransactionBuilderLedgerClient for TestClient {
        async fn object(
            &self,
            object_id: ObjectId,
            _version: impl Into<Option<Version>>,
        ) -> Result<Option<Object>, Self::Error> {
            // System objects (e.g. the system state object used by staking) are
            // shared; everything else resolves as an address-owned coin.
            let owner = if object_id == ObjectId::SYSTEM_STATE || object_id == ObjectId::CLOCK {
                Owner::Shared(Version::from_u64(1))
            } else {
                Owner::Address(Address::ZERO)
            };
            Ok(Some(fabricated_coin(
                object_id,
                owner,
                FABRICATED_COIN_BALANCE,
            )))
        }

        async fn objects(
            &self,
            _struct_tag: Option<StructTag>,
            owner: Address,
            _cursor: Option<Vec<u8>>,
            _limit: Option<usize>,
        ) -> Result<ObjectsPage, Self::Error> {
            // A single funded gas coin owned by the requested owner is enough for
            // the builder's automatic gas selection. Its id is a fixed sentinel
            // that won't collide with the object ids used in examples.
            let gas_coin_id = ObjectId::from_bytes([0xee; ObjectId::LENGTH])
                .expect("32 bytes is a valid object id");
            let owner = Owner::Address(owner);
            Ok(ObjectsPage {
                data: vec![fabricated_coin(gas_coin_id, owner, FABRICATED_COIN_BALANCE)],
                next_cursor: None,
            })
        }

        async fn reference_gas_price(
            &self,
            _epoch: impl Into<Option<u64>>,
        ) -> Result<Option<u64>, Self::Error> {
            Ok(Some(1000))
        }
    }

    impl TransactionBuilderSimulationClient for TestClient {
        type DryRunResult = ();

        async fn estimate_transaction_budget(
            &self,
            _transaction: &Transaction,
        ) -> Result<Option<u64>, Self::Error> {
            Ok(Some(50_000_000))
        }

        async fn dry_run_transaction(
            &self,
            _transaction: &Transaction,
            _skip_checks: bool,
        ) -> Result<Self::DryRunResult, Self::Error> {
            Ok(())
        }
    }

    impl TransactionBuilderExecutionClient for TestClient {
        async fn execute_transaction(
            &self,
            _signatures: &[UserSignature],
            _transaction: &Transaction,
            _wait_for: impl Into<Option<WaitForTransaction>>,
        ) -> Result<TransactionEffects, Self::Error> {
            Err(TestClientError(
                "TestClient cannot execute transactions".to_string(),
            ))
        }

        async fn wait_for_transaction(
            &self,
            _digest: TransactionDigest,
            _wait_for: WaitForTransaction,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn transaction_effects(
            &self,
            _digest: TransactionDigest,
        ) -> Result<Option<TransactionEffects>, Self::Error> {
            Ok(None)
        }
    }

    /// A [`TestClient`] that records how the builder asked for objects, and can
    /// report chosen ids as missing.
    #[derive(Clone, Default)]
    pub struct RecordingClient {
        /// The ids of each `objects_by_id` call, in call order.
        pub batches: std::sync::Arc<std::sync::Mutex<Vec<Vec<ObjectId>>>>,
        /// The ids of each single-object `object` call, in call order.
        pub singles: std::sync::Arc<std::sync::Mutex<Vec<ObjectId>>>,
        /// Ids to report as missing instead of fabricating an object.
        pub missing: Vec<ObjectId>,
    }

    impl RecordingClient {
        /// Returns the ids of each `objects_by_id` call, in call order.
        pub fn batches(&self) -> Vec<Vec<ObjectId>> {
            self.batches.lock().unwrap().clone()
        }

        /// Returns the ids of each single-object `object` call, in call order.
        pub fn singles(&self) -> Vec<ObjectId> {
            self.singles.lock().unwrap().clone()
        }
    }

    impl TransactionBuilderClientBase for RecordingClient {
        type Error = crate::TestClientError;
    }

    impl TransactionBuilderLedgerClient for RecordingClient {
        async fn object(
            &self,
            object_id: ObjectId,
            version: impl Into<Option<Version>>,
        ) -> Result<Option<Object>, Self::Error> {
            self.singles.lock().unwrap().push(object_id);
            if self.missing.contains(&object_id) {
                return Ok(None);
            }
            crate::TestClient.object(object_id, version).await
        }

        async fn objects_by_id(
            &self,
            object_ids: &[(ObjectId, Option<Version>)],
        ) -> Result<Vec<Option<Object>>, Self::Error> {
            self.batches
                .lock()
                .unwrap()
                .push(object_ids.iter().map(|(id, _)| *id).collect());
            let mut objects = Vec::with_capacity(object_ids.len());
            for (object_id, _) in object_ids {
                objects.push(if self.missing.contains(object_id) {
                    None
                } else {
                    crate::TestClient.object(*object_id, None).await?
                });
            }
            Ok(objects)
        }

        async fn objects(
            &self,
            struct_tag: Option<StructTag>,
            owner: Address,
            cursor: Option<Vec<u8>>,
            limit: Option<usize>,
        ) -> Result<crate::ObjectsPage, Self::Error> {
            crate::TestClient
                .objects(struct_tag, owner, cursor, limit)
                .await
        }

        async fn reference_gas_price(
            &self,
            epoch: impl Into<Option<u64>>,
        ) -> Result<Option<u64>, Self::Error> {
            crate::TestClient.reference_gas_price(epoch).await
        }
    }

    impl TransactionBuilderSimulationClient for RecordingClient {
        type DryRunResult = ();

        async fn estimate_transaction_budget(
            &self,
            transaction: &Transaction,
        ) -> Result<Option<u64>, Self::Error> {
            crate::TestClient
                .estimate_transaction_budget(transaction)
                .await
        }

        async fn dry_run_transaction(
            &self,
            transaction: &Transaction,
            skip_checks: bool,
        ) -> Result<Self::DryRunResult, Self::Error> {
            crate::TestClient
                .dry_run_transaction(transaction, skip_checks)
                .await
        }
    }

    impl TransactionBuilderExecutionClient for RecordingClient {
        async fn execute_transaction(
            &self,
            signatures: &[iota_types::UserSignature],
            transaction: &Transaction,
            wait_for: impl Into<Option<WaitForTransaction>>,
        ) -> Result<TransactionEffects, Self::Error> {
            crate::TestClient
                .execute_transaction(signatures, transaction, wait_for)
                .await
        }

        async fn wait_for_transaction(
            &self,
            digest: iota_types::TransactionDigest,
            wait_for: WaitForTransaction,
        ) -> Result<(), Self::Error> {
            crate::TestClient
                .wait_for_transaction(digest, wait_for)
                .await
        }

        async fn transaction_effects(
            &self,
            digest: iota_types::TransactionDigest,
        ) -> Result<Option<TransactionEffects>, Self::Error> {
            crate::TestClient.transaction_effects(digest).await
        }
    }
}
