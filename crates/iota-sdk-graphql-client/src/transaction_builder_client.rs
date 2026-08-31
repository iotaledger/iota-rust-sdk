// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the transaction builder client traits for the GraphQL
//! [`Client`].

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
    Client, DryRunResult,
    pagination::{Direction, PaginationFilter},
    query_types::ObjectFilter,
};

impl Client {
    /// Create a new [`TransactionBuilder`] with the given sender address.
    pub fn transaction_builder(&self, sender: Address) -> TransactionBuilder<&Self> {
        TransactionBuilder::new(sender).with_client(self)
    }
}

impl TransactionBuilderClientBase for Client {
    type Error = crate::error::GraphQLError;
}

impl TransactionBuilderLedgerClient for Client {
    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        self.object(object_id, version).await
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
        let cursor = cursor
            .map(String::from_utf8)
            .transpose()
            .map_err(crate::error::GraphQLError::parse)?;
        let page = self
            .objects(
                ObjectFilter {
                    type_tag: struct_tag.map(|tag| tag.to_string()),
                    owner: Some(owner),
                    object_ids: None,
                },
                PaginationFilter {
                    direction: Direction::Forward,
                    cursor,
                    limit: limit.map(|v| v as _),
                },
            )
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
        let cfg = crate::Client::protocol_config(self, None).await?;
        let attributes = cfg
            .configs
            .into_iter()
            .filter_map(|attr| attr.value.map(|v| (attr.key, v)))
            .collect();
        Ok(ProtocolConfig { attributes })
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        self.reference_gas_price(epoch).await
    }
}

impl TransactionBuilderSimulationClient for Client {
    type DryRunResult = DryRunResult;

    async fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> Result<Option<u64>, Self::Error> {
        let res = self.dry_run_transaction(transaction, true).await?;
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
        (*self).dry_run_transaction(transaction, skip_checks).await
    }
}

impl TransactionBuilderExecutionClient for Client {
    async fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> Result<TransactionEffects, Self::Error> {
        self.execute_transaction(signatures, transaction, wait_for)
            .await
    }

    async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<(), Self::Error> {
        self.wait_for_transaction(digest, wait_for, None).await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        self.transaction_effects(digest).await
    }
}
