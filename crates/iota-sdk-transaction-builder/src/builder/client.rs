// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use iota_types::{
    Address, Object, ObjectId, SignedTransaction, StructTag, Transaction, TransactionDigest,
    TransactionEffects, UserSignature, Version,
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
#[non_exhaustive]
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

/// One page of objects plus an optional cursor for the next page. See
/// [`TransactionBuilderResolveClient::objects`].
#[derive(Clone, Debug)]
pub struct ObjectsPage {
    /// The objects in this page.
    pub data: Vec<Object>,
    /// Opaque continuation cursor for fetching the next page; `None` when no
    /// further pages exist. Pass it back as the `cursor` argument to
    /// [`TransactionBuilderResolveClient::objects`] to advance.
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

/// A trait which defines read-only methods the Transaction Builder needs to
/// resolve and build a transaction
/// ([`finish`](crate::TransactionBuilder::finish)).
pub trait TransactionBuilderResolveClient {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;

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

    /// Estimate the gas budget needed for a transaction
    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;
}

/// A trait which defines methods needed from the client for the Transaction
/// Builder, extending [`TransactionBuilderResolveClient`] with dry run and
/// execution.
pub trait TransactionBuilderClient: TransactionBuilderResolveClient {
    /// The result of a dry run.
    type DryRunResult;

    /// Fetch a transaction
    fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>>;

    /// Fetch transaction effects
    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>>;

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
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;
}

impl<T: TransactionBuilderResolveClient> TransactionBuilderResolveClient for &T {
    type Error = T::Error;

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

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).estimate_tx_budget(tx)
    }
}

impl<T: TransactionBuilderClient> TransactionBuilderClient for &T {
    type DryRunResult = T::DryRunResult;

    fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        (*self).transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        (*self).transaction_effects(digest)
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
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        (*self).wait_for_tx(digest, wait_for)
    }
}

impl<T: TransactionBuilderResolveClient> TransactionBuilderResolveClient for std::sync::Arc<T> {
    type Error = T::Error;

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

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().estimate_tx_budget(tx)
    }
}

impl<T: TransactionBuilderClient> TransactionBuilderClient for std::sync::Arc<T> {
    type DryRunResult = T::DryRunResult;

    fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        self.as_ref().transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        self.as_ref().transaction_effects(digest)
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
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        self.as_ref().wait_for_tx(digest, wait_for)
    }
}

#[cfg(feature = "test-client")]
pub(crate) mod test_client {
    //! Test utilities for the transaction builder.

    use iota_types::{
        Address, MoveStruct, Object, ObjectData, ObjectId, Owner, SignedTransaction, StructTag,
        Transaction, TransactionDigest, TransactionEffects, UserSignature, Version,
    };

    use super::{TransactionBuilderClient, TransactionBuilderResolveClient, WaitForTx};
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

    /// A test client that implements [`TransactionBuilderClient`] by
    /// fabricating objects on demand.
    ///
    /// It is useful for building transactions in tests, examples, and doc tests
    /// where a live network connection is not available. Object lookups resolve
    /// to a synthesized gas coin owned by an address (shared system objects
    /// such as the system state object resolve as shared), and gas
    /// selection always finds a single funded coin. This is enough to drive
    /// [`finish`](crate::TransactionBuilder::finish) to completion, but the
    /// resulting transaction references made-up objects and cannot be executed
    /// — [`execute_tx`](TransactionBuilderClient::execute_tx) returns an error.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TestClient;

    /// Error type for [`TestClient`].
    #[derive(Clone, Debug, thiserror::Error)]
    #[error("TestClientError: {0}")]
    pub struct TestClientError(pub String);

    impl TransactionBuilderResolveClient for TestClient {
        type Error = TestClientError;

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

        async fn estimate_tx_budget(&self, _tx: &Transaction) -> Result<Option<u64>, Self::Error> {
            Ok(Some(50_000_000))
        }
    }

    impl TransactionBuilderClient for TestClient {
        type DryRunResult = ();

        async fn transaction(
            &self,
            _digest: TransactionDigest,
        ) -> Result<Option<SignedTransaction>, Self::Error> {
            Ok(None)
        }

        async fn transaction_effects(
            &self,
            _digest: TransactionDigest,
        ) -> Result<Option<TransactionEffects>, Self::Error> {
            Ok(None)
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
            _digest: TransactionDigest,
            _wait_for: WaitForTx,
        ) -> Result<(), Self::Error> {
            Ok(())
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

    impl TransactionBuilderClient for RecordingClient {
        type Error = crate::TestClientError;
        type DryRunResult = ();

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

        async fn transaction(
            &self,
            digest: iota_types::TransactionDigest,
        ) -> Result<Option<iota_types::SignedTransaction>, Self::Error> {
            crate::TestClient.transaction(digest).await
        }

        async fn transaction_effects(
            &self,
            digest: iota_types::TransactionDigest,
        ) -> Result<Option<TransactionEffects>, Self::Error> {
            crate::TestClient.transaction_effects(digest).await
        }

        async fn reference_gas_price(
            &self,
            epoch: impl Into<Option<u64>>,
        ) -> Result<Option<u64>, Self::Error> {
            crate::TestClient.reference_gas_price(epoch).await
        }

        async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
            crate::TestClient.estimate_tx_budget(tx).await
        }

        async fn dry_run_tx(
            &self,
            tx: &Transaction,
            skip_checks: bool,
        ) -> Result<Self::DryRunResult, Self::Error> {
            crate::TestClient.dry_run_tx(tx, skip_checks).await
        }

        async fn execute_tx(
            &self,
            signatures: &[iota_types::UserSignature],
            tx: &Transaction,
            wait_for: impl Into<Option<WaitForTx>>,
        ) -> Result<TransactionEffects, Self::Error> {
            crate::TestClient.execute_tx(signatures, tx, wait_for).await
        }

        async fn wait_for_tx(
            &self,
            digest: iota_types::TransactionDigest,
            wait_for: WaitForTx,
        ) -> Result<(), Self::Error> {
            crate::TestClient.wait_for_tx(digest, wait_for).await
        }
    }
}
