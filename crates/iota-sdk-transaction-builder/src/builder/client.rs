// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub use iota_client_api::{
    Client as TransactionBuilderClientBase, ExecutionClient as TransactionBuilderExecutionClient,
    LedgerClient as TransactionBuilderLedgerClient, ObjectsPage, ProtocolConfig,
    SimulationClient as TransactionBuilderSimulationClient, WaitForTransaction,
};

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
    use crate::{
        ObjectsPage,
        builder::{BASE_TX_COST_FIXED_KEY, MAX_GAS_PAYMENT_OBJECTS_KEY},
    };

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

    /// Error type for [`TestClient`].
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

        async fn protocol_config(&self) -> Result<super::ProtocolConfig, Self::Error> {
            Ok(super::ProtocolConfig::new(
                [
                    (BASE_TX_COST_FIXED_KEY.to_owned(), "1000".to_owned()),
                    (MAX_GAS_PAYMENT_OBJECTS_KEY.to_owned(), "256".to_owned()),
                ]
                .into(),
            ))
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

        async fn protocol_config(&self) -> Result<super::ProtocolConfig, Self::Error> {
            crate::TestClient.protocol_config().await
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
