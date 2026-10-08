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
    Address, SenderSignedTransaction, SignedTransaction, Transaction, TransactionDigest,
    TransactionEffects, UserSignature,
};

use crate::{
    GraphQLClient, TransactionDataEffects,
    api::define_query,
    error::{GraphQLError, GraphQLResult},
    pagination::{Page, PaginationFilter, PaginationFilterResponse},
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
    #[derive(Clone)]
    pub struct ListTransactionsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<SignedTransaction>>;
}

impl ListTransactionsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: TransactionsFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<SignedTransaction>> + Unpin {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation(
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksQueryFragment, TransactionBlocksQueryArgs> {
        TransactionBlocksQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<SignedTransaction>> {
        let Self {
            client,
            pagination,
            filter,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(filter, pagination))
            .await?;

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
    #[derive(Clone)]
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
    pub fn relation(mut self, relation: AddressTransactionRelationship) -> Self {
        self.relation = Some(relation);
        self
    }

    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: TransactionsFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<SignedTransaction>> + Unpin {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation(
        address: Address,
        relation: Option<AddressTransactionRelationship>,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<AddressTransactionsQueryFragment, AddressTransactionsQueryArgs> {
        AddressTransactionsQueryFragment::build(AddressTransactionsQueryArgs {
            address,
            relation,
            after: pagination.after,
            before: pagination.before,
            filter: filter.map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<SignedTransaction>> {
        let Self {
            client,
            pagination,
            address,
            relation,
            filter,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(address, relation, filter, pagination))
            .await?;

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
    #[derive(Clone)]
    pub struct ListTransactionsEffectsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<TransactionEffects>>;
}

impl ListTransactionsEffectsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: TransactionsFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<TransactionEffects>> + Unpin {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation(
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksEffectsQueryFragment, TransactionBlocksQueryArgs> {
        TransactionBlocksEffectsQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<TransactionEffects>> {
        let Self {
            client,
            pagination,
            filter,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(filter, pagination))
            .await?;

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
    /// Query for [`GraphQLClient::transactions_data_effects`]. Await it to
    /// send the request.
    #[derive(Clone)]
    pub struct ListTransactionsDataEffectsQuery {
        client: GraphQLClient,
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<TransactionDataEffects>>;
}

impl ListTransactionsDataEffectsQuery {
    /// Only return the transactions that match `filter`.
    pub fn filter(mut self, filter: TransactionsFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<TransactionDataEffects>> + Unpin {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation(
        filter: Option<TransactionsFilter>,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<TransactionBlocksWithEffectsQueryFragment, TransactionBlocksQueryArgs>
    {
        TransactionBlocksWithEffectsQueryFragment::build(TransactionBlocksQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.map(Into::into),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<TransactionDataEffects>> {
        let Self {
            client,
            pagination,
            filter,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(filter, pagination))
            .await?;

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
                    let bcs = crate::base64::decode(bcs.0.as_str())?;
                    let effects = crate::base64::decode(effects.bcs.as_ref().unwrap().0.as_str())?;
                    let transaction: SenderSignedTransaction =
                        bcs::from_bytes(&bcs).map_err(iota_types::BcsError::new)?;
                    let effects: TransactionEffects =
                        bcs::from_bytes(&effects).map_err(iota_types::BcsError::new)?;

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

define_query! {
    /// Query for [`GraphQLClient::execute_transaction`]. Await it to send the
    /// request.
    pub struct ExecuteTransactionQuery {
        client: GraphQLClient,
        signatures: Vec<String>,
        transaction: Transaction,
    }
    output: GraphQLResult<TransactionEffects>;
}

impl ExecuteTransactionQuery {
    async fn send(self) -> GraphQLResult<TransactionEffects> {
        let operation = ExecuteTransactionQueryFragment::build(ExecuteTransactionArgs {
            signatures: self.signatures,
            tx_bytes: base64ct::Base64::encode_string(
                bcs::to_bytes(&self.transaction).unwrap().as_ref(),
            ),
        });

        let response = self.client.run_query(&operation).await?;

        let result = response.execute_transaction_block;
        let bcs = crate::base64::decode(result.effects.bcs.0.as_str())?;
        let effects: TransactionEffects =
            bcs::from_bytes(&bcs).map_err(iota_types::BcsError::new)?;

        Ok(effects)
    }
}

define_query! {
    /// Query for [`GraphQLClient::wait_for_transaction`]. Await it to send the
    /// request.
    pub struct WaitForTransactionQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
        timeout: Option<Duration>,
    }
    output: GraphQLResult<()>;
}

impl WaitForTransactionQuery {
    /// Set how long to wait. Defaults to 60s.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    async fn send(self) -> GraphQLResult<()> {
        let client = &self.client;
        let digest = self.digest;
        crate::wait::timeout(
            self.timeout.unwrap_or_else(|| Duration::from_secs(60)),
            async {
                loop {
                    if match self.wait_for {
                        WaitForTransaction::IndexedOnNode => client.is_transaction_indexed_on_node(digest).await?,
                        WaitForTransaction::Finalized => client.is_transaction_finalized(digest).await?,
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

define_query! {
    /// Query for [`GraphQLClient::transaction`]. Await it to send the request.
    pub struct GetTransactionQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
    }
    output: GraphQLResult<Option<SignedTransaction>>;
}

impl GetTransactionQuery {
    async fn send(self) -> GraphQLResult<Option<SignedTransaction>> {
        let operation = TransactionBlockQueryFragment::build(TransactionBlockArgs {
            digest: self.digest.to_string(),
        });
        let response = self.client.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }
}

define_query! {
    /// Query for [`GraphQLClient::transaction_effects`]. Await it to send the
    /// request.
    pub struct GetTransactionEffectsQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
    }
    output: GraphQLResult<Option<TransactionEffects>>;
}

impl GetTransactionEffectsQuery {
    async fn send(self) -> GraphQLResult<Option<TransactionEffects>> {
        let operation = TransactionBlockEffectsQueryFragment::build(TransactionBlockArgs {
            digest: self.digest.to_string(),
        });
        let response = self.client.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }
}

define_query! {
    /// Query for [`GraphQLClient::transaction_data_effects`]. Await it to send
    /// the request.
    pub struct GetTransactionDataEffectsQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
    }
    output: GraphQLResult<Option<TransactionDataEffects>>;
}

impl GetTransactionDataEffectsQuery {
    async fn send(self) -> GraphQLResult<Option<TransactionDataEffects>> {
        let operation = TransactionBlockWithEffectsQueryFragment::build(TransactionBlockArgs {
            digest: self.digest.to_string(),
        });
        let response = self.client.run_query(&operation).await?;

        match response.transaction_block.map(|tx| (tx.bcs, tx.effects)) {
            Some((Some(bcs), Some(effects))) => {
                let bcs = crate::base64::decode(bcs.0.as_str())?;
                let effects = crate::base64::decode(effects.bcs.unwrap().0.as_str())?;
                let transaction: SenderSignedTransaction =
                    bcs::from_bytes(&bcs).map_err(iota_types::BcsError::new)?;
                let effects: TransactionEffects =
                    bcs::from_bytes(&effects).map_err(iota_types::BcsError::new)?;

                Ok(Some(TransactionDataEffects {
                    signed_transaction: transaction.into(),
                    effects,
                }))
            }
            _ => Ok(None),
        }
    }
}

define_query! {
    /// Query for [`GraphQLClient::is_transaction_indexed_on_node`]. Await it to
    /// send the request.
    pub struct IsTransactionIndexedOnNodeQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
    }
    output: GraphQLResult<bool>;
}

impl IsTransactionIndexedOnNodeQuery {
    async fn send(self) -> GraphQLResult<bool> {
        let operation = TransactionBlockIndexedQueryFragment::build(TransactionBlockArgs {
            digest: self.digest.to_string(),
        });
        Ok(self
            .client
            .run_query(&operation)
            .await?
            .is_transaction_indexed_on_node)
    }
}

define_query! {
    /// Query for [`GraphQLClient::is_transaction_finalized`]. Await it to send
    /// the request.
    pub struct IsTransactionFinalizedQuery {
        client: GraphQLClient,
        digest: TransactionDigest,
    }
    output: GraphQLResult<bool>;
}

impl IsTransactionFinalizedQuery {
    async fn send(self) -> GraphQLResult<bool> {
        let operation = TransactionBlockCheckpointQueryFragment::build(TransactionBlockArgs {
            digest: self.digest.to_string(),
        });
        let response = self.client.run_query(&operation).await?;
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
}

impl GraphQLClient {
    /// Get a transaction by its digest.
    pub fn transaction(&self, digest: TransactionDigest) -> GetTransactionQuery {
        GetTransactionQuery {
            client: self.clone(),
            digest,
        }
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
    pub fn transaction_effects(&self, digest: TransactionDigest) -> GetTransactionEffectsQuery {
        GetTransactionEffectsQuery {
            client: self.clone(),
            digest,
        }
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
    pub fn transaction_data_effects(
        &self,
        digest: TransactionDigest,
    ) -> GetTransactionDataEffectsQuery {
        GetTransactionDataEffectsQuery {
            client: self.clone(),
            digest,
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

    /// Execute a transaction.
    pub fn execute_transaction(
        &self,
        signatures: &[UserSignature],
        transaction: &Transaction,
    ) -> ExecuteTransactionQuery {
        ExecuteTransactionQuery {
            client: self.clone(),
            signatures: signatures.iter().map(|s| s.to_base64()).collect(),
            transaction: transaction.clone(),
        }
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queried by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use [`Self::is_transaction_finalized`].
    pub fn is_transaction_indexed_on_node(
        &self,
        digest: TransactionDigest,
    ) -> IsTransactionIndexedOnNodeQuery {
        IsTransactionIndexedOnNodeQuery {
            client: self.clone(),
            digest,
        }
    }

    /// Returns whether the transaction for the given digest has been included
    /// in a checkpoint (finalized).
    pub fn is_transaction_finalized(
        &self,
        digest: TransactionDigest,
    ) -> IsTransactionFinalizedQuery {
        IsTransactionFinalizedQuery {
            client: self.clone(),
            digest,
        }
    }

    /// Wait for the indexing or finalization of a transaction by its digest.
    /// Resolves to an error if it takes longer than the timeout, 60s unless
    /// set with [`timeout`](WaitForTransactionQuery::timeout).
    pub fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> WaitForTransactionQuery {
        WaitForTransactionQuery {
            client: self.clone(),
            digest,
            wait_for,
            timeout: None,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use base64ct::Encoding;
    use iota_types::{Address, Ed25519PublicKey, Ed25519Signature, SimpleSignature, UserSignature};

    use crate::{
        GraphQLClient, GraphQLError, WaitForTransaction,
        query_types::{AddressTransactionRelationship, TransactionsFilter},
        test_utils::{
            assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
            test_client, test_transaction,
        },
    };

    #[tokio::test]
    async fn digest_getters_send_the_digest() {
        let digest = test_transaction().digest();
        let expected = digest.to_string();
        let vars = sent_variables("TransactionBlockQueryFragment", |client| async move {
            let _ = client.transaction(digest).await;
        })
        .await;
        assert_eq!(vars["digest"], expected);

        let vars = sent_variables(
            "TransactionBlockEffectsQueryFragment",
            |client| async move {
                let _ = client.transaction_effects(digest).await;
            },
        )
        .await;
        assert_eq!(vars["digest"], expected);

        let vars = sent_variables(
            "TransactionBlockWithEffectsQueryFragment",
            |client| async move {
                let _ = client.transaction_data_effects(digest).await;
            },
        )
        .await;
        assert_eq!(vars["digest"], expected);

        let vars = sent_variables(
            "TransactionBlockIndexedQueryFragment",
            |client| async move {
                let _ = client.is_transaction_indexed_on_node(digest).await;
            },
        )
        .await;
        assert_eq!(vars["digest"], expected);

        let vars = sent_variables(
            "TransactionBlockCheckpointQueryFragment",
            |client| async move {
                let _ = client.is_transaction_finalized(digest).await;
            },
        )
        .await;
        assert_eq!(vars["digest"], expected);
    }

    #[tokio::test]
    async fn execute_transaction_sends_the_signatures_and_transaction() {
        let transaction = test_transaction();
        let signature = UserSignature::Simple(SimpleSignature::Ed25519 {
            signature: Ed25519Signature::new([1; 64]),
            public_key: Ed25519PublicKey::new([2; 32]),
        });
        let expected_signature = signature.to_base64();
        let expected_tx_bytes =
            base64ct::Base64::encode_string(&bcs::to_bytes(&transaction).unwrap());
        let vars = sent_variables("ExecuteTransactionQueryFragment", |client| async move {
            let _ = client.execute_transaction(&[signature], &transaction).await;
        })
        .await;
        assert_eq!(vars["signatures"], serde_json::json!([expected_signature]));
        assert_eq!(vars["txBytes"], expected_tx_bytes);
    }

    #[tokio::test]
    async fn wait_for_transaction_sends_the_digest_to_the_status_query() {
        let digest = test_transaction().digest();
        for (wait_for, operation) in [
            (
                WaitForTransaction::IndexedOnNode,
                "TransactionBlockIndexedQueryFragment",
            ),
            (
                WaitForTransaction::Finalized,
                "TransactionBlockCheckpointQueryFragment",
            ),
        ] {
            let vars = sent_variables(operation, |client| async move {
                let _ = client.wait_for_transaction(digest, wait_for).await;
            })
            .await;
            assert_eq!(vars["digest"], digest.to_string());
        }
    }

    #[tokio::test]
    async fn wait_for_transaction_stops_at_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            GraphQLClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            client
                .wait_for_transaction(test_transaction().digest(), WaitForTransaction::Finalized)
                .timeout(Duration::from_millis(100)),
        )
        .await
        .expect("the query's own timeout fires first");
        assert!(matches!(result, Err(GraphQLError::Timeout)));
    }

    fn sent_by_framework() -> TransactionsFilter {
        TransactionsFilter::default().with_sent_address(Address::FRAMEWORK)
    }

    #[tokio::test]
    async fn transactions_sends_the_filter_and_pagination() {
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

        let vars = sent_variables("TransactionBlocksQueryFragment", |client| async move {
            let _ = client
                .transactions()
                .filter(sent_by_framework())
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
    }

    #[tokio::test]
    async fn transactions_effects_sends_the_filter_and_pagination() {
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
            "TransactionBlocksEffectsQueryFragment",
            |client| async move {
                let _ = client
                    .transactions_effects()
                    .filter(sent_by_framework())
                    .pagination(forward_page())
                    .await;
            },
        )
        .await;
        assert_forward_page(&vars);
    }

    #[tokio::test]
    async fn transactions_data_effects_sends_the_filter_and_pagination() {
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

        let vars = sent_variables(
            "TransactionBlocksWithEffectsQueryFragment",
            |client| async move {
                let _ = client
                    .transactions_data_effects()
                    .filter(sent_by_framework())
                    .pagination(forward_page())
                    .await;
            },
        )
        .await;
        assert_forward_page(&vars);
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

        let vars = sent_variables("AddressTransactionsQueryFragment", |client| async move {
            let _ = client
                .address_transactions(Address::STD)
                .relation(AddressTransactionRelationship::Recv)
                .filter(sent_by_framework())
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
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
