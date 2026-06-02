// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`ClientMethods`] for the GraphQL [`Client`].

use iota_transaction_builder::{ClientMethods, WaitForTx};
use iota_types::{
    Address, Digest, Object, ObjectId, SignedTransaction, Transaction, TransactionEffects, TypeTag,
    UserSignature, Version,
};

use crate::{
    Client, DryRunResult,
    pagination::{Direction, PaginationFilter},
    query_types::{ObjectFilter, TransactionMetadata},
};

impl ClientMethods for Client {
    type Error = crate::error::Error;
    type DryRunResult = DryRunResult;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        self.object(object_id, version).await
    }

    async fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<Object>, Self::Error> {
        Ok(self
            .objects(
                ObjectFilter {
                    type_: type_tag.as_ref().map(ToString::to_string),
                    owner,
                    object_ids,
                },
                PaginationFilter {
                    direction: if ascending {
                        Direction::Forward
                    } else {
                        Direction::Backward
                    },
                    cursor,
                    limit: limit.map(|v| v as _),
                },
            )
            .await?
            .data)
    }

    async fn transaction(&self, digest: Digest) -> Result<Option<SignedTransaction>, Self::Error> {
        self.transaction(digest).await
    }

    async fn transaction_effects(
        &self,
        digest: Digest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        self.transaction_effects(digest).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        self.reference_gas_price(epoch).await
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        let res = self.dry_run_tx(tx, true).await?;
        Ok(res.effects.map(|e| match e {
            TransactionEffects::V1(e) => e.gas_cost_summary.gas_used(),
            _ => {
                unimplemented!("a new TransactionEffects variant was added and needs to be handled")
            }
        }))
    }

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        let Transaction::V1(tx) = &tx else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let gas_objects = tx
            .gas_payment
            .objects
            .iter()
            .map(|r| crate::query_types::ObjectRef {
                address: r.object_id,
                digest: r.digest.to_base58(),
                version: r.version.as_u64(),
            })
            .collect::<Vec<_>>();
        self.dry_run_tx_kind(
            &tx.kind,
            skip_checks,
            TransactionMetadata {
                gas_budget: (tx.gas_payment.budget > 0).then_some(tx.gas_payment.budget),
                gas_objects: (!gas_objects.is_empty()).then_some(gas_objects),
                gas_price: Some(tx.gas_payment.price),
                gas_sponsor: Some(tx.gas_payment.owner),
                sender: Some(tx.sender),
            },
        )
        .await
    }

    async fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        self.execute_tx(signatures, tx, wait_for).await
    }

    async fn wait_for_tx(&self, digest: Digest, wait_for: WaitForTx) -> Result<(), Self::Error> {
        self.wait_for_tx(digest, wait_for, None).await
    }
}
