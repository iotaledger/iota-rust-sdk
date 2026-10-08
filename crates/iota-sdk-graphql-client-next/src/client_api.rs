// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The shared client traits, so that code written against them, such as the
//! transaction builder, works with this client.

use iota_client_api::{
    Client, ExecutionClient, LedgerClient, ObjectsPage, ProtocolConfig, SimulationClient,
    WaitForTransaction,
};
use iota_types::{
    Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
    UserSignature, Version,
};

use crate::{Cursor, DryRunResult, Error, GraphQLClient, Result};

impl Client for GraphQLClient {
    type Error = Error;
}

impl LedgerClient for GraphQLClient {
    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>> {
        let request = GraphQLClient::object(self, object_id);
        match version.into() {
            Some(version) => request.version(version).await,
            None => request.await,
        }
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage> {
        let mut request = GraphQLClient::objects(self).owner(owner);
        if let Some(struct_tag) = struct_tag {
            request = request.type_filter(struct_tag);
        }
        if let Some(limit) = limit {
            request = request.first(limit.try_into().unwrap_or(u32::MAX));
        }
        if let Some(cursor) = cursor {
            let cursor = String::from_utf8(cursor)
                .map_err(|error| Error::invalid_input(format!("invalid cursor: {error}")))?;
            request = request.after(Cursor::new(cursor));
        }
        let page = request.await?;
        let next_cursor = page
            .has_next_page()
            .then(|| page.end_cursor())
            .flatten()
            .map(|cursor| cursor.as_str().as_bytes().to_vec());
        Ok(ObjectsPage {
            data: page.into_items(),
            next_cursor,
        })
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig> {
        GraphQLClient::protocol_config(self).await
    }

    async fn reference_gas_price(&self, epoch: impl Into<Option<u64>>) -> Result<Option<u64>> {
        let request = self.epoch();
        let epoch = match epoch.into() {
            Some(id) => request.id(id).await?,
            None => request.await?,
        };
        Ok(epoch.and_then(|epoch| epoch.reference_gas_price))
    }
}

impl SimulationClient for GraphQLClient {
    type DryRunResult = DryRunResult;

    async fn estimate_transaction_budget(&self, transaction: &Transaction) -> Result<Option<u64>> {
        let result = self.dry_run(transaction).skip_checks(true).await?;
        result
            .effects
            .map(|effects| match effects {
                TransactionEffects::V1(effects) => Ok(effects.gas_cost_summary.gas_used()),
                _ => Err(Error::malformed(
                    "the dry run returned effects of a version this client cannot read",
                )),
            })
            .transpose()
    }

    async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> Result<DryRunResult> {
        self.dry_run(transaction).skip_checks(skip_checks).await
    }
}

impl ExecutionClient for GraphQLClient {
    async fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> Result<TransactionEffects> {
        let effects = self.execute(transaction, signatures).await?;
        if let Some(until) = wait_for.into() {
            self.wait_for_transaction(transaction.digest())
                .until(until)
                .await?;
        }
        Ok(effects)
    }

    async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<()> {
        GraphQLClient::wait_for_transaction(self, digest)
            .until(wait_for)
            .await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>> {
        self.transaction(digest).effects().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implements_every_shared_client_trait() {
        fn assert_client<C: LedgerClient + SimulationClient + ExecutionClient>() {}
        assert_client::<GraphQLClient>();
    }
}
