// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, sync::Arc};

use iota_types::{
    Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
    UserSignature, Version,
};

use crate::{ObjectsPage, ProtocolConfig, WaitForTransaction};

/// Base trait of the client traits, carrying the client's error type.
pub trait Client {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;
}

/// Read-only access to ledger state.
pub trait LedgerClient: Client {
    /// Fetch an object
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl Future<Output = Result<Option<Object>, Self::Error>>;

    /// Fetch several objects at once, returning them in the order they were
    /// requested with `None` in place of any object that does not exist.
    ///
    /// The default impl calls [`object`](Self::object) once per entry, costing
    /// one round trip each. Clients whose transport can fetch a batch should
    /// override it.
    fn objects_by_id(
        &self,
        object_ids: &[(ObjectId, Option<Version>)],
    ) -> impl Future<Output = Result<Vec<Option<Object>>, Self::Error>> {
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
    /// The cursor is opaque to callers, so every transport's page token fits
    /// into `Option<Vec<u8>>`. Pass `None` to start from the beginning; pass
    /// the cursor returned by a previous call to advance.
    fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl Future<Output = Result<ObjectsPage, Self::Error>>;

    /// Fetch the chain's protocol configuration.
    fn protocol_config(&self) -> impl Future<Output = Result<ProtocolConfig, Self::Error>>;

    /// Get the reference gas price
    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl Future<Output = Result<Option<u64>, Self::Error>>;
}

/// Transaction simulation: dry runs and the gas budget estimation built on
/// them.
pub trait SimulationClient: Client {
    /// The result of a dry run.
    type DryRunResult;

    /// Estimate the gas budget needed for a transaction, typically by
    /// simulating it and reading the gas cost from the result. `Ok(None)`
    /// means no estimate is available.
    fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> impl Future<Output = Result<Option<u64>, Self::Error>>;

    /// Dry run a transaction
    fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> impl Future<Output = Result<Self::DryRunResult, Self::Error>>;
}

/// Transaction execution: submitting a transaction and tracking its result.
pub trait ExecutionClient: Client {
    /// Execute a transaction
    fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> impl Future<Output = Result<TransactionEffects, Self::Error>>;

    /// Wait for the indexing or finalization of a transaction by its digest.
    fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Fetch the effects of an executed transaction
    fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> impl Future<Output = Result<Option<TransactionEffects>, Self::Error>>;
}

/// Forwards every client trait from a pointer type to its target.
macro_rules! forward_client_traits {
    ($($pointer:ty),* $(,)?) => {$(
        impl<T: Client> Client for $pointer {
            type Error = T::Error;
        }

        impl<T: LedgerClient> LedgerClient for $pointer {
            fn object(
                &self,
                object_id: ObjectId,
                version: impl Into<Option<Version>>,
            ) -> impl Future<Output = Result<Option<Object>, Self::Error>> {
                T::object(self, object_id, version)
            }

            fn objects_by_id(
                &self,
                object_ids: &[(ObjectId, Option<Version>)],
            ) -> impl Future<Output = Result<Vec<Option<Object>>, Self::Error>> {
                T::objects_by_id(self, object_ids)
            }

            fn objects(
                &self,
                struct_tag: Option<StructTag>,
                owner: Address,
                cursor: Option<Vec<u8>>,
                limit: Option<usize>,
            ) -> impl Future<Output = Result<ObjectsPage, Self::Error>> {
                T::objects(self, struct_tag, owner, cursor, limit)
            }

            fn protocol_config(&self) -> impl Future<Output = Result<ProtocolConfig, Self::Error>> {
                T::protocol_config(self)
            }

            fn reference_gas_price(
                &self,
                epoch: impl Into<Option<u64>>,
            ) -> impl Future<Output = Result<Option<u64>, Self::Error>> {
                T::reference_gas_price(self, epoch)
            }
        }

        impl<T: SimulationClient> SimulationClient for $pointer {
            type DryRunResult = T::DryRunResult;

            fn estimate_transaction_budget(
                &self,
                transaction: &Transaction,
            ) -> impl Future<Output = Result<Option<u64>, Self::Error>> {
                T::estimate_transaction_budget(self, transaction)
            }

            fn dry_run_transaction(
                &self,
                transaction: &Transaction,
                skip_checks: bool,
            ) -> impl Future<Output = Result<Self::DryRunResult, Self::Error>> {
                T::dry_run_transaction(self, transaction, skip_checks)
            }
        }

        impl<T: ExecutionClient> ExecutionClient for $pointer {
            fn execute_transaction(
                &self,
                signatures: &[UserSignature],
                transaction: &Transaction,
                wait_for: impl Into<Option<WaitForTransaction>>,
            ) -> impl Future<Output = Result<TransactionEffects, Self::Error>> {
                T::execute_transaction(self, signatures, transaction, wait_for)
            }

            fn wait_for_transaction(
                &self,
                digest: TransactionDigest,
                wait_for: WaitForTransaction,
            ) -> impl Future<Output = Result<(), Self::Error>> {
                T::wait_for_transaction(self, digest, wait_for)
            }

            fn transaction_effects(
                &self,
                digest: TransactionDigest,
            ) -> impl Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
                T::transaction_effects(self, digest)
            }
        }
    )*};
}

forward_client_traits!(&T, Arc<T>);
