// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::{future::IntoFuture, time::Duration};

use base64ct::Encoding;
use cynic::{MutationBuilder, QueryBuilder};
use futures::Stream;
use iota_transaction_builder::WaitForTransaction;
use iota_types::{
    Address, SenderSignedTransaction, SignedTransaction, Transaction, TransactionDigest,
    TransactionEffects, UserSignature,
};

use crate::{
    GraphQLClient, TransactionDataEffects,
    api::define_query,
    error::{GraphQLError, GraphQLResult},
    pagination::{Direction, Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        AddressTransactionBlocksQueryFragment, AddressTransactionRelationship,
        AddressTransactionsQueryArgs, AddressTransactionsQueryFragment, ExecuteTransactionArgs,
        ExecuteTransactionQueryFragment, TransactionBlockArgs,
        TransactionBlockCheckpointQueryFragment, TransactionBlockEffectsQueryFragment,
        TransactionBlockIndexedQueryFragment, TransactionBlockQueryFragment,
        TransactionBlockWithEffectsQueryFragment, TransactionBlocksEffectsQueryFragment,
        TransactionBlocksQueryArgs, TransactionBlocksQueryFragment,
        TransactionBlocksWithEffectsQueryFragment, TransactionsFilter,
    },
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::transactions`]. Await it to send the
    /// request.
    pub struct ListTransactionsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<SignedTransaction>>;
}

impl ListTransactionsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<TransactionsFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        &self,
        pagination: &PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksQueryFragment, TransactionBlocksQueryArgs> {
        TransactionBlocksQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after.clone(),
            before: pagination.before.clone(),
            filter: self.filter.clone().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<SignedTransaction>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<GraphQLResult<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }
}

define_query! {
    /// Query for [`GraphQLClient::address_transactions`]. Await it to send the
    /// request.
    pub struct ListAddressTransactionsQuery {
        client: GraphQLClient,
        address: Address,
        relation: Option<AddressTransactionRelationship>,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<SignedTransaction>>;
}

impl ListAddressTransactionsQuery {
    /// Set how the address relates to the transactions. Defaults to the
    /// transactions it sent.
    pub fn relation(mut self, relation: impl Into<Option<AddressTransactionRelationship>>) -> Self {
        self.relation = relation.into();
        self
    }

    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<TransactionsFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        &self,
        pagination: &PaginationFilterResponse,
    ) -> cynic::Operation<AddressTransactionsQueryFragment, AddressTransactionsQueryArgs> {
        AddressTransactionsQueryFragment::build(AddressTransactionsQueryArgs {
            address: self.address,
            relation: self.relation,
            after: pagination.after.clone(),
            before: pagination.before.clone(),
            filter: self.filter.clone().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<SignedTransaction>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        let Some(AddressTransactionBlocksQueryFragment { transaction_blocks }) = response.address
        else {
            return Ok(Page::new_empty());
        };

        let transactions = transaction_blocks
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<GraphQLResult<Vec<_>>>()?;

        Ok(Page::new(transaction_blocks.page_info, transactions))
    }
}

define_query! {
    /// Query for [`GraphQLClient::transactions_effects`]. Await it to send the
    /// request.
    pub struct ListTransactionsEffectsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<TransactionEffects>>;
}

impl ListTransactionsEffectsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<TransactionsFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        &self,
        pagination: &PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksEffectsQueryFragment, TransactionBlocksQueryArgs> {
        TransactionBlocksEffectsQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after.clone(),
            before: pagination.before.clone(),
            filter: self.filter.clone().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<TransactionEffects>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = txc
            .nodes
            .into_iter()
            .map(|n| n.try_into())
            .collect::<GraphQLResult<Vec<_>>>()?;
        Ok(Page::new(page_info, transactions))
    }
}

define_query! {
    /// Query for [`GraphQLClient::transactions_data_effects`]. Await it to send the
    /// request.
    pub struct ListTransactionsDataEffectsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<TransactionDataEffects>>;
}

impl ListTransactionsDataEffectsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<TransactionsFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        &self,
        pagination: &PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksWithEffectsQueryFragment, TransactionBlocksQueryArgs>
    {
        TransactionBlocksWithEffectsQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after.clone(),
            before: pagination.before.clone(),
            filter: self.filter.clone().map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<TransactionDataEffects>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        let txc = response.transaction_blocks;
        let page_info = txc.page_info;

        let transactions = {
            txc.nodes
                .into_iter()
                .map(|node| {
                    let (Some(bcs), Some(effects)) = (node.bcs, node.effects) else {
                        return Err(GraphQLError::EmptyResponseField(
                            "transaction bcs or effects",
                        ));
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
                .collect::<GraphQLResult<Vec<_>>>()?
        };

        Ok(Page::new(page_info, transactions))
    }
}

impl GraphQLClient {
    /// Get a transaction by its digest.
    pub async fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> GraphQLResult<Option<SignedTransaction>> {
        let operation = TransactionBlockQueryFragment::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions.
    pub fn transactions(&self) -> ListTransactionsQuery {
        ListTransactionsQuery {
            client: self.clone(),
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Get a page of transactions related to the given address.
    pub fn address_transactions(&self, address: Address) -> ListAddressTransactionsQuery {
        ListAddressTransactionsQuery {
            client: self.clone(),
            address,
            relation: None,
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> GraphQLResult<Option<TransactionEffects>> {
        let operation = TransactionBlockEffectsQueryFragment::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a page of transactions' effects.
    pub fn transactions_effects(&self) -> ListTransactionsEffectsQuery {
        ListTransactionsEffectsQuery {
            client: self.clone(),
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: TransactionDigest,
    ) -> GraphQLResult<Option<TransactionDataEffects>> {
        let operation = TransactionBlockWithEffectsQueryFragment::build(TransactionBlockArgs {
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

    /// Get a page of transactions' data and effects.
    pub fn transactions_data_effects(&self) -> ListTransactionsDataEffectsQuery {
        ListTransactionsDataEffectsQuery {
            client: self.clone(),
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Get a stream of transactions' effects based on the (optional)
    /// transaction filter.
    pub fn transactions_effects_stream(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<TransactionEffects>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| {
                self.transactions_effects()
                    .filter(filter.clone())
                    .pagination(pag_filter)
                    .into_future()
            },
            streaming_direction,
        )
    }

    /// Execute a transaction.
    pub async fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> GraphQLResult<TransactionEffects> {
        let wait_for = wait_for.into();
        let operation = ExecuteTransactionQueryFragment::build(ExecuteTransactionArgs {
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
    pub async fn is_transaction_indexed_on_node(
        &self,
        digest: TransactionDigest,
    ) -> GraphQLResult<bool> {
        let operation = TransactionBlockIndexedQueryFragment::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        Ok(self
            .run_query(&operation)
            .await?
            .is_transaction_indexed_on_node)
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    pub async fn is_transaction_finalized(&self, digest: TransactionDigest) -> GraphQLResult<bool> {
        let operation = TransactionBlockCheckpointQueryFragment::build(TransactionBlockArgs {
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
    ) -> GraphQLResult<()> {
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
        .map_err(|_| GraphQLError::Timeout)?
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::Address;

    use crate::{
        query_types::{AddressTransactionRelationship, TransactionsFilter},
        test_utils::{assert_backward_page, backward_page, sent_variables, test_client},
    };

    fn sent_by_framework() -> TransactionsFilter {
        TransactionsFilter::default().with_sent_address(Address::FRAMEWORK)
    }

    #[tokio::test]
    async fn transactions_send_the_filter_and_pagination() {
        let vars = sent_variables("TransactionBlocksQueryFragment", |client| async move {
            let _ = client
                .transactions()
                .filter(sent_by_framework())
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(
            vars["filter"]["sentAddress"],
            Address::FRAMEWORK.to_string()
        );
        assert_backward_page(&vars);

        let vars = sent_variables(
            "TransactionBlocksEffectsQueryFragment",
            |client| async move {
                let _ = client
                    .transactions_effects()
                    .filter(sent_by_framework())
                    .pagination(backward_page())
                    .await;
            },
        )
        .await;
        assert_eq!(
            vars["filter"]["sentAddress"],
            Address::FRAMEWORK.to_string()
        );
        assert_backward_page(&vars);

        let vars = sent_variables(
            "TransactionBlocksWithEffectsQueryFragment",
            |client| async move {
                let _ = client
                    .transactions_data_effects()
                    .filter(sent_by_framework())
                    .pagination(backward_page())
                    .await;
            },
        )
        .await;
        assert_eq!(
            vars["filter"]["sentAddress"],
            Address::FRAMEWORK.to_string()
        );
        assert_backward_page(&vars);
    }

    #[tokio::test]
    async fn address_transactions_sends_the_address_relation_filter_and_pagination() {
        let vars = sent_variables("AddressTransactionsQueryFragment", |client| async move {
            let _ = client
                .address_transactions(Address::STD)
                .relation(AddressTransactionRelationship::Recv)
                .filter(sent_by_framework())
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["address"], Address::STD.to_string());
        assert_eq!(vars["relation"], "RECV");
        assert_eq!(
            vars["filter"]["sentAddress"],
            Address::FRAMEWORK.to_string()
        );
        assert_backward_page(&vars);
    }

    #[tokio::test]
    async fn test_transaction_effects_query() {
        let client = test_client();
        let transactions = client.transactions().await.unwrap();
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
            .transactions_effects()
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
            .transactions()
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
    async fn test_address_transactions() {
        let client = test_client();
        let transactions = client.transactions().await.unwrap();
        let sender = transactions.data()[0].transaction.as_v1().sender;

        for relation in [
            AddressTransactionRelationship::Sent,
            AddressTransactionRelationship::Recv,
            AddressTransactionRelationship::Affected,
        ] {
            let page = client
                .address_transactions(sender)
                .relation(relation)
                .await
                .map_err(|e| {
                    format!(
                        "Address transactions query with relation {relation:?} failed for {} \
                         network: Error {e}",
                        client.rpc_server()
                    )
                })
                .unwrap();

            if matches!(relation, AddressTransactionRelationship::Sent) {
                assert!(
                    page.data()
                        .iter()
                        .all(|tx| tx.transaction.as_v1().sender == sender),
                    "Sent relation returned a transaction from another sender"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_transaction_data_effects() {
        let client = test_client();
        let transactions = client.transactions().await.unwrap();
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
        let transactions = client.transactions().await.unwrap();
        let digest = transactions.data()[0].transaction.digest();

        client
            .transactions_data_effects()
            .filter(TransactionsFilter::default().with_transaction_ids([digest]))
            .await
            .unwrap();
    }
}
