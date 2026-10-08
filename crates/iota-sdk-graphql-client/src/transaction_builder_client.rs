// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the transaction builder client traits for the GraphQL
//! [`GraphQLClient`].

use iota_transaction_builder::{
    ObjectsPage, ProtocolConfig, TransactionBuilder, TransactionBuilderClientBase,
    TransactionBuilderExecutionClient, TransactionBuilderLedgerClient,
    TransactionBuilderSimulationClient, WaitForTransaction,
};
use iota_types::{
    Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
    UserSignature, Version,
};

use crate::{
    DryRunResult, GraphQLClient,
    pagination::{Direction, PaginationFilter},
    query_types::ObjectFilter,
};

impl GraphQLClient {
    /// Create a new [`TransactionBuilder`] with the given sender address.
    pub fn transaction_builder(&self, sender: Address) -> TransactionBuilder<&Self> {
        TransactionBuilder::new(sender).with_client(self)
    }
}

impl TransactionBuilderClientBase for GraphQLClient {
    type Error = crate::error::GraphQLError;
}

impl TransactionBuilderLedgerClient for GraphQLClient {
    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        let mut query = self.object(object_id);
        if let Some(version) = version.into() {
            query = query.version(version);
        }
        query.await
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        // GraphQL cursors are base64 ASCII, so round-tripping through
        // Vec<u8> is lossless. Caller-supplied cursors must come from a
        // prior call to this method; anything else is rejected here
        // rather than panicked on.
        let cursor = cursor.map(String::from_utf8).transpose()?;
        let page = self
            .objects()
            .filter(ObjectFilter {
                type_tag: struct_tag.map(|tag| tag.to_string()),
                owner: Some(owner),
                object_ids: None,
            })
            .pagination(PaginationFilter {
                direction: Direction::Forward,
                cursor,
                limit: limit.map(|v| v as _),
            })
            .await?;
        let (page_info, data) = page.into_parts();
        let next_cursor = page_info
            .has_next_page
            .then_some(page_info.end_cursor)
            .flatten()
            .map(String::into_bytes);
        Ok(ObjectsPage { data, next_cursor })
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        let cfg = self.protocol_config().await?;
        let attributes = cfg
            .configs
            .into_iter()
            .filter_map(|attr| attr.value.map(|v| (attr.key, v)))
            .collect();
        Ok(ProtocolConfig::new(attributes))
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        let mut query = self.reference_gas_price();
        if let Some(epoch) = epoch.into() {
            query = query.epoch_number(epoch);
        }
        query.await
    }
}

impl TransactionBuilderSimulationClient for GraphQLClient {
    type DryRunResult = DryRunResult;

    async fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> Result<Option<u64>, Self::Error> {
        let res = self
            .dry_run_transaction(transaction)
            .skip_checks(true)
            .await?;
        Ok(res.effects.map(|effects| match effects {
            TransactionEffects::V1(v1) => v1.gas_cost_summary.gas_used(),
            _ => unimplemented!(
                "a new TransactionEffects enum variant was added and needs to be handled"
            ),
        }))
    }

    async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        self.dry_run_transaction(transaction)
            .skip_checks(skip_checks)
            .await
    }
}

impl TransactionBuilderExecutionClient for GraphQLClient {
    async fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
    ) -> Result<TransactionEffects, Self::Error> {
        self.execute_transaction(signatures, transaction).await
    }

    async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<(), Self::Error> {
        self.wait_for_transaction(digest, wait_for).await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        self.transaction_effects(digest).await
    }
}
