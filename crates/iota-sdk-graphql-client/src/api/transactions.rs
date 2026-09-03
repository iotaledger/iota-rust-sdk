// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::time::Duration;

use base64ct::Encoding;
use cynic::{MutationBuilder, QueryBuilder};
use futures::Stream;
use iota_transaction_builder::WaitForTransaction;
use iota_types::{
    SenderSignedTransaction, SignedTransaction, Transaction, TransactionDigest, TransactionEffects,
    UserSignature,
};

use crate::{
    Client, TransactionDataEffects,
    error::{Error, Kind, Result},
    pagination::{Direction, Page, PaginationFilter},
    query_types::{
        ExecuteTransactionArgs, ExecuteTransactionQuery, TransactionBlockArgs,
        TransactionBlockCheckpointQuery, TransactionBlockEffectsQuery,
        TransactionBlockIndexedQuery, TransactionBlockQuery, TransactionBlockWithEffectsQuery,
        TransactionBlocksEffectsQuery, TransactionBlocksQuery, TransactionBlocksQueryArgs,
        TransactionBlocksWithEffectsQuery, TransactionsFilter,
    },
    streams::stream_paginated_query,
};

impl Client {
    /// Get a transaction by its digest.
    pub async fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<SignedTransaction>> {
        let operation = TransactionBlockQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions based on the provided filters.
    pub async fn transactions(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<SignedTransaction>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>> {
        let operation = TransactionBlockEffectsQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions' effects based on the provided filters.
    pub async fn transactions_effects(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionEffects>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksEffectsQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionDataEffects>> {
        let operation = TransactionBlockWithEffectsQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        match response.transaction_block.map(|tx| (tx.bcs, tx.effects)) {
            Some((Some(bcs), Some(effects))) => {
                let bcs = base64ct::Base64::decode_vec(bcs.0.as_str())?;
                let effects = base64ct::Base64::decode_vec(effects.bcs.unwrap().0.as_str())?;
                let transaction: SenderSignedTransaction = bcs::from_bytes(&bcs)?;
                let effects: TransactionEffects = bcs::from_bytes(&effects)?;

                Ok(Some(TransactionDataEffects {
                    signed_transaction: transaction.into(),
                    effects,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Get a page of transactions' data and effects based on the provided
    /// filters.
    pub async fn transactions_data_effects(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionDataEffects>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksWithEffectsQuery::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = {
            txc.nodes
                .into_iter()
                .map(|node| {
                    let (Some(bcs), Some(effects)) = (node.bcs, node.effects) else {
                        return Err(Error::empty_response_error());
                    };
                    let bcs = base64ct::Base64::decode_vec(bcs.0.as_str())?;
                    let effects =
                        base64ct::Base64::decode_vec(effects.bcs.as_ref().unwrap().0.as_str())?;
                    let transaction: SenderSignedTransaction = bcs::from_bytes(&bcs)?;
                    let effects: TransactionEffects = bcs::from_bytes(&effects)?;

                    Ok(TransactionDataEffects {
                        signed_transaction: transaction.into(),
                        effects,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        Ok(Page::new(page_info, transactions))
    }

    /// Get a stream of transactions' effects based on the (optional)
    /// transaction filter.
    pub fn transactions_effects_stream(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<TransactionEffects>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.transactions_effects(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    /// Execute a transaction.
    pub async fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> Result<TransactionEffects> {
        let wait_for = wait_for.into();
        let operation = ExecuteTransactionQuery::build(ExecuteTransactionArgs {
            signatures: signatures.iter().map(|s| s.to_base64()).collect(),
            tx_bytes: base64ct::Base64::encode_string(bcs::to_bytes(transaction).unwrap().as_ref()),
        });

        let response = self.run_query(&operation).await?;

        let result = response.execute_transaction_block;
        let bcs = base64ct::Base64::decode_vec(result.effects.bcs.0.as_str())?;
        let effects: TransactionEffects = bcs::from_bytes(&bcs)?;

        if let Some(wait_for) = wait_for {
            self.wait_for_transaction(transaction.digest(), wait_for, None)
                .await?;
        }

        Ok(effects)
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queried by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use [`Self::is_transaction_finalized`].
    pub async fn is_transaction_indexed_on_node(&self, digest: TransactionDigest) -> Result<bool> {
        let operation = TransactionBlockIndexedQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        Ok(self
            .run_query(&operation)
            .await?
            .is_transaction_indexed_on_node)
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    pub async fn is_transaction_finalized(&self, digest: TransactionDigest) -> Result<bool> {
        let operation = TransactionBlockCheckpointQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;
        if let Some(block) = response.transaction_block
            && block
                .effects
                .as_ref()
                .and_then(|e| e.checkpoint.as_ref())
                .is_some()
        {
            return Ok(true);
        }
        Ok(false)
    }

    /// Wait for the indexing or finalization of a transaction
    /// by its digest. An optional timeout can be provided, which, if
    /// exceeded, will return an error (default 60s).
    pub async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<()> {
        crate::wait::timeout(
            timeout.into().unwrap_or_else(|| Duration::from_secs(60)),
            async {
                loop {
                    if match wait_for {
                        WaitForTransaction::IndexedOnNode => self.is_transaction_indexed_on_node(digest).await?,
                        WaitForTransaction::Finalized => self.is_transaction_finalized(digest).await?,
                        _ => unimplemented!(
                            "a new WaitForTransaction enum variant was added and needs to be handled"
                        ),
                    } {
                        break Ok(());
                    }
                    crate::wait::sleep(Duration::from_millis(100)).await;
                }
            },
        )
        .await
        .map_err(|e| Error::from_error(Kind::Other, e))?
    }
}

#[cfg(test)]
mod tests {
    use crate::{PaginationFilter, query_types::TransactionsFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_transaction_effects_query() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .unwrap();
        let tx_digest = transactions.data()[0].transaction.digest();
        let effects = client.transaction_effects(tx_digest).await.unwrap();
        assert!(
            effects.is_some(),
            "Transaction effects query failed for {} network.",
            client.rpc_server(),
        );
    }

    #[tokio::test]
    async fn test_transactions_effects_query() {
        let client = test_client();
        client
            .transactions_effects(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions effects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_transactions_query() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Transactions query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !transactions.is_empty(),
            "Transactions query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_transaction_data_effects() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .unwrap();
        let digest = transactions.data()[0].transaction.digest();

        client
            .transaction_data_effects(digest)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_transactions_data_effects() {
        let client = test_client();
        let transactions = client
            .transactions(None, PaginationFilter::default())
            .await
            .unwrap();
        let digest = transactions.data()[0].transaction.digest();

        client
            .transactions_data_effects(
                TransactionsFilter::default().with_transaction_ids(vec![digest.to_string()]),
                PaginationFilter::default(),
            )
            .await
            .unwrap();
    }
}
