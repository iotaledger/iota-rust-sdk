// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod error;
pub mod faucet;
pub mod output_types;
pub mod pagination;
pub mod query_types;
pub mod streams;

use std::{str::FromStr, time::Duration};

use base64ct::Encoding;
use cynic::{GraphQlResponse, MutationBuilder, Operation, QueryBuilder, serde};
use error::{Error, Kind};
use futures::Stream;
use iota_types::{
    Address, CheckpointSequenceNumber, CheckpointSummary, Digest, DryRunEffect, DryRunResult,
    IdentifierRef, MovePackage, Object, ObjectId, SenderSignedTransaction, SignedTransaction,
    StructTag, Transaction, TransactionEffects, TransactionKind, TypeTag, UserSignature,
    framework::Coin,
    iota_names::{NameFormat, NameRegistration, name::Name},
};
pub use output_types::*;
use query_types::{
    ActiveValidatorsArgs, ActiveValidatorsQuery, BalanceArgs, BalanceQuery, ChainIdentifierQuery,
    CheckpointArgs, CheckpointId, CheckpointQuery, CheckpointsArgs, CheckpointsQuery, CoinMetadata,
    CoinMetadataArgs, CoinMetadataQuery, DryRunArgs, DryRunQuery, DynamicFieldArgs,
    DynamicFieldConnectionArgs, DynamicFieldQuery, DynamicFieldsOwnerQuery,
    DynamicObjectFieldQuery, Epoch, EpochArgs, EpochQuery, EpochSummaryQuery, Event, EventFilter,
    EventsQuery, EventsQueryArgs, ExecuteTransactionArgs, ExecuteTransactionQuery,
    LatestPackageQuery, MoveFunction, MoveModule, MovePackageVersionFilter,
    NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs, NormalizedMoveModuleQuery,
    NormalizedMoveModuleQueryArgs, ObjectFilter, ObjectQuery, ObjectQueryArgs, ObjectsQuery,
    ObjectsQueryArgs, PackageArgs, PackageCheckpointFilter, PackageQuery, PackageVersionsArgs,
    PackageVersionsQuery, PackagesQuery, PackagesQueryArgs, ProtocolConfigQuery, ProtocolConfigs,
    ProtocolVersionArgs, ServiceConfig, ServiceConfigQuery, TransactionBlockArgs,
    TransactionBlockEffectsQuery, TransactionBlockQuery, TransactionBlocksEffectsQuery,
    TransactionBlocksQuery, TransactionBlocksQueryArgs, TransactionMetadata, TransactionsFilter,
    Validator,
};
use reqwest::Url;
use streams::stream_paginated_query;

use crate::{
    error::Result,
    pagination::{Direction, Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        CheckpointTotalTxQuery, IotaNamesAddressDefaultNameQuery,
        IotaNamesAddressRegistrationsQuery, IotaNamesDefaultNameArgs, IotaNamesDefaultNameQuery,
        IotaNamesRegistrationsArgs, IotaNamesRegistrationsQuery, ResolveIotaNamesAddressArgs,
        ResolveIotaNamesAddressQuery, TransactionBlockCheckpointQuery,
        TransactionBlockIndexedQuery, TransactionBlockWithEffectsQuery,
        TransactionBlocksWithEffectsQuery,
    },
};

const DEFAULT_ITEMS_PER_PAGE: i32 = 10;
const MAINNET_HOST: &str = "https://graphql.mainnet.iota.cafe";
const TESTNET_HOST: &str = "https://graphql.testnet.iota.cafe";
const DEVNET_HOST: &str = "https://graphql.devnet.iota.cafe";
const LOCAL_HOST: &str = "http://localhost:9125/graphql";
static USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

fn response_to_err<T>(response: GraphQlResponse<T>) -> Result<T, crate::Error> {
    match (response.data, response.errors) {
        (Some(data), None) => Ok(data),
        (None, Some(errors)) => Err(Error::graphql_error(errors)),
        _ => unreachable!(
            "Either data or errors must be present in a GraphQL response, but not both"
        ),
    }
}

/// Determines what to wait for after executing a transaction.
pub enum WaitForTx {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions, and that the transaction itself is indexed on the node.
    Indexed,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    Finalized,
}

/// The GraphQL client for interacting with the IOTA blockchain.
/// By default, it uses the `reqwest` crate as the HTTP client.
#[derive(Debug, Clone)]
pub struct Client {
    /// The URL of the GraphQL server.
    rpc: Url,
    /// The reqwest client.
    inner: reqwest::Client,
    service_config: std::sync::OnceLock<ServiceConfig>,
}

impl Client {
    /// Return the URL for the GraphQL server.
    fn rpc_server(&self) -> &Url {
        &self.rpc
    }

    /// Set the server address for the GraphQL GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub fn set_rpc_server(&mut self, server: &str) -> Result<()> {
        let rpc = reqwest::Url::parse(server)?;
        self.rpc = rpc;
        Ok(())
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<&ServiceConfig> {
        // If the value is already initialized, return it
        if let Some(service_config) = self.service_config.get() {
            return Ok(service_config);
        }

        // Otherwise, fetch and initialize it
        let operation = ServiceConfigQuery::build(());
        let response = self.run_query(&operation).await?;

        let service_config = self
            .service_config
            .get_or_init(move || response.service_config);

        Ok(service_config)
    }

    /// Get the list of coins for the specified address as a stream.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    pub fn coins_stream(
        &self,
        address: Address,
        coin_type: impl Into<Option<StructTag>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Coin>> + '_ {
        let coin_type = coin_type.into();
        stream_paginated_query(
            move |filter| self.coins(address, coin_type.clone(), filter),
            streaming_direction,
        )
    }

    /// Get the list of gas coins for the specified address as a stream.
    pub fn gas_coins_stream(
        &self,
        address: Address,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Coin>> + '_ {
        stream_paginated_query(
            move |filter| self.gas_coins(address, filter),
            streaming_direction,
        )
    }

    /// Get a stream of [`CheckpointSummary`]. Note that this will fetch all
    /// checkpoints which may trigger a lot of requests.
    pub fn checkpoints_stream(
        &self,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<CheckpointSummary>> + '_ {
        stream_paginated_query(move |filter| self.checkpoints(filter), streaming_direction)
    }

    /// Get a stream of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    pub fn dynamic_fields_stream(
        &self,
        address: Address,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<DynamicFieldOutput>> + '_ {
        stream_paginated_query(
            move |filter| self.dynamic_fields(address, filter),
            streaming_direction,
        )
    }

    /// Internal method for getting the epoch summary that is called in a few
    /// other APIs for convenience.
    async fn epoch_summary(&self, epoch: Option<u64>) -> Result<EpochSummaryQuery> {
        let operation = EpochSummaryQuery::build(EpochArgs { id: epoch });
        self.run_query(&operation).await
    }

    /// Return a stream of events based on the (optional) event filter.
    pub fn events_stream(
        &self,
        filter: impl Into<Option<EventFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Event>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.events(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    /// Return a stream of objects based on the (optional) object filter.
    pub fn objects_stream(
        &self,
        filter: impl Into<Option<ObjectFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Object>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.objects(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    // ===========================================================================
    // Dry Run API
    // ===========================================================================

    /// Dry run a [`Transaction`] and return the transaction effects and dry
    /// run error (if any).
    ///
    /// The `skip_checks` flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks.
    pub async fn dry_run_tx(&self, tx: &Transaction, skip_checks: bool) -> Result<DryRunResult> {
        let tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&tx)?);
        self.dry_run(tx_bytes, skip_checks, None).await
    }

    /// Dry run a [`TransactionKind`] and return the transaction effects and dry
    /// run error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    ///
    /// `tx_meta` is the transaction metadata.
    pub async fn dry_run_tx_kind(
        &self,
        tx_kind: &TransactionKind,
        skip_checks: bool,
        tx_meta: TransactionMetadata,
    ) -> Result<DryRunResult> {
        let tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&tx_kind)?);
        self.dry_run(tx_bytes, skip_checks, Some(tx_meta)).await
    }

    /// Internal implementation of the dry run API.
    async fn dry_run(
        &self,
        tx_bytes: String,
        skip_checks: bool,
        tx_meta: impl Into<Option<TransactionMetadata>>,
    ) -> Result<DryRunResult> {
        let operation = DryRunQuery::build(DryRunArgs {
            tx_bytes,
            skip_checks,
            tx_meta: tx_meta.into(),
        });
        let response = self.run_query(&operation).await?;

        // Convert DryRunEffect to DryRunEffect
        let results = response
            .dry_run_transaction_block
            .results
            .iter()
            .flatten()
            .map(DryRunEffect::try_from)
            .collect::<Result<Vec<_>>>()?;

        let txn_block = &response.dry_run_transaction_block.transaction;

        let effects = txn_block
            .as_ref()
            .and_then(|tx| tx.effects.as_ref())
            .and_then(|tx| tx.bcs.as_ref())
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<TransactionEffects>(&bcs))
            .transpose()?;

        // Extract transaction
        let transaction = txn_block
            .as_ref()
            .and_then(|tx| tx.bcs.as_ref())
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<SignedTransaction>(&bcs))
            .transpose()?;

        Ok(DryRunResult {
            error: response.dry_run_transaction_block.error,
            results,
            transaction,
            effects,
        })
    }

    /// Get a stream of transactions based on the (optional) transaction filter.
    pub fn transactions_stream(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<SignedTransaction>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.transactions(filter.clone(), pag_filter),
            streaming_direction,
        )
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

    /// Run a query on the GraphQL server and return the response.
    /// This method returns [`cynic::GraphQlResponse`]  over the query type `T`,
    /// and it is intended to be used with custom queries.
    pub async fn run_query<T, V>(&self, operation: &Operation<T, V>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        V: serde::Serialize,
    {
        response_to_err(
            self.inner
                .post(self.rpc_server().clone())
                .json(&operation)
                .send()
                .await?
                .json::<GraphQlResponse<T>>()
                .await?,
        )
    }

    /// Run a JSON query on the GraphQL server and return the response.
    /// This method expects a JSON map holding the GraphQL query string and
    /// matching GraphQL variables. It returns a [`cynic::GraphQlResponse`]
    /// wrapping a [`serde_json::Value`]. In general, it is recommended to use
    /// [`run_query`](`Self::run_query`) which guarantees valid GraphQL
    /// query syntax and returns a proper response type.
    pub async fn run_query_from_json(
        &self,
        json: serde_json::Map<String, serde_json::Value>,
    ) -> Result<GraphQlResponse<serde_json::Value>> {
        let res = self
            .inner
            .post(self.rpc_server().clone())
            .json(&json)
            .send()
            .await?
            .json::<GraphQlResponse<serde_json::Value>>()
            .await?;
        Ok(res)
    }

    // ===========================================================================
    // Balance API
    // ===========================================================================

    /// Get the balance of all the coins owned by address for the provided coin
    /// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
    /// if not provided.
    pub async fn balance(
        &self,
        address: Address,
        coin_type: impl Into<Option<String>>,
    ) -> Result<Option<u64>> {
        let operation = BalanceQuery::build(BalanceArgs {
            address,
            coin_type: coin_type.into(),
        });
        let response = self.run_query(&operation).await?;

        let total_balance = response
            .owner
            .and_then(|o| o.balance.and_then(|b| b.total_balance))
            .map(|x| x.0.parse::<u64>())
            .transpose()?;
        Ok(total_balance)
    }

    // ===========================================================================
    // Client Misc API
    // ===========================================================================

    /// Create a new GraphQL client with the provided server address.
    pub fn new(server: &str) -> Result<Self> {
        let rpc = reqwest::Url::parse(server)?;

        let client = Client {
            rpc,
            inner: reqwest::Client::builder().user_agent(USER_AGENT).build()?,
            service_config: Default::default(),
        };
        Ok(client)
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    pub fn new_mainnet() -> Self {
        Self::new(MAINNET_HOST).expect("Invalid mainnet URL")
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    pub fn new_testnet() -> Self {
        Self::new(TESTNET_HOST).expect("Invalid testnet URL")
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    pub fn new_devnet() -> Self {
        Self::new(DEVNET_HOST).expect("Invalid devnet URL")
    }

    /// Create a new GraphQL client connected to a `localnet` GraphQL server:
    /// {DEFAULT_LOCAL_HOST}.
    pub fn new_localnet() -> Self {
        Self::new(LOCAL_HOST).expect("Invalid localhost URL")
    }

    /// Get the chain identifier.
    pub async fn chain_id(&self) -> Result<String> {
        let operation = ChainIdentifierQuery::build(());
        let response = self.run_query(&operation).await?;

        Ok(response.chain_identifier)
    }

    /// Handle pagination filters and return the appropriate values. If limit is
    /// omitted, it will use the max page size from the service config.
    pub async fn pagination_filter(
        &self,
        pagination_filter: PaginationFilter,
    ) -> PaginationFilterResponse {
        let limit = pagination_filter
            .limit
            .unwrap_or(self.max_page_size().await.unwrap_or(DEFAULT_ITEMS_PER_PAGE));

        let (after, before, first, last) = match pagination_filter.direction {
            Direction::Forward => (pagination_filter.cursor, None, Some(limit), None),
            Direction::Backward => (None, pagination_filter.cursor, None, Some(limit)),
        };
        PaginationFilterResponse {
            after,
            before,
            first,
            last,
        }
    }

    /// Lazily fetch the max page size
    pub async fn max_page_size(&self) -> Result<i32> {
        self.service_config().await.map(|cfg| cfg.max_page_size)
    }

    // ===========================================================================
    // Network info API
    // ===========================================================================

    /// Get the reference gas price for the provided epoch or the last known one
    /// if no epoch is provided.
    ///
    /// This will return `Ok(None)` if the epoch requested is not available in
    /// the GraphQL service (e.g., due to pruning).
    pub async fn reference_gas_price(&self, epoch: impl Into<Option<u64>>) -> Result<Option<u64>> {
        let operation = EpochSummaryQuery::build(EpochArgs { id: epoch.into() });
        let response = self.run_query(&operation).await?;

        response
            .epoch
            .and_then(|e| e.reference_gas_price)
            .map(|x| x.try_into())
            .transpose()
    }

    /// Get the protocol configuration.
    pub async fn protocol_config(
        &self,
        version: impl Into<Option<u64>>,
    ) -> Result<ProtocolConfigs> {
        let operation = ProtocolConfigQuery::build(ProtocolVersionArgs { id: version.into() });
        let response = self.run_query(&operation).await?;
        Ok(response.protocol_config)
    }

    /// Get the list of active validators for the provided epoch, including
    /// related metadata. If no epoch is provided, it will return the active
    /// validators for the current epoch.
    pub async fn active_validators(
        &self,
        epoch: impl Into<Option<u64>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Validator>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = ActiveValidatorsQuery::build(ActiveValidatorsArgs {
            id: epoch.into(),
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
        });
        let response = self.run_query(&operation).await?;

        if let Some(validators) = response.epoch.and_then(|v| v.validator_set) {
            let page_info = validators.active_validators.page_info;
            let nodes = validators
                .active_validators
                .nodes
                .into_iter()
                .collect::<Vec<_>>();
            Ok(Page::new(page_info, nodes))
        } else {
            Ok(Page::new_empty())
        }
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint digest.
    pub async fn total_transaction_blocks_by_digest(&self, digest: Digest) -> Result<Option<u64>> {
        self.internal_total_transaction_blocks(Some(digest.to_string()), None)
            .await
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint sequence number.
    pub async fn total_transaction_blocks_by_seq_num(&self, seq_num: u64) -> Result<Option<u64>> {
        self.internal_total_transaction_blocks(None, Some(seq_num))
            .await
    }

    /// The total number of transaction blocks in the network by the end of the
    /// last known checkpoint.
    pub async fn total_transaction_blocks(&self) -> Result<Option<u64>> {
        self.internal_total_transaction_blocks(None, None).await
    }

    /// Internal function to get the total number of transaction blocks based on
    /// the provided checkpoint digest or sequence number.
    async fn internal_total_transaction_blocks(
        &self,
        digest: Option<String>,
        seq_num: Option<u64>,
    ) -> Result<Option<u64>> {
        if digest.is_some() && seq_num.is_some() {
            return Err(Error::from_error(
                Kind::Other,
                "Conflicting arguments: either digest or seq_num can be provided, but not both.",
            ));
        }

        let operation = CheckpointTotalTxQuery::build(CheckpointArgs {
            id: CheckpointId {
                digest,
                sequence_number: seq_num,
            },
        });
        let response = self.run_query(&operation).await?;

        Ok(response
            .checkpoint
            .and_then(|c| c.network_total_transactions))
    }

    // ===========================================================================
    // Coin API
    // ===========================================================================

    /// Get the list of coins for the specified address.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    pub async fn coins(
        &self,
        owner: Address,
        coin_type: impl Into<Option<StructTag>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Coin>> {
        let filter = ObjectFilter {
            type_: Some(
                coin_type
                    .into()
                    .map(StructTag::new_coin)
                    .unwrap_or_else(|| StructTag {
                        address: Address::FRAMEWORK,
                        module: IdentifierRef::const_new("coin").into(),
                        name: IdentifierRef::const_new("Coin").into(),
                        type_params: Default::default(),
                    })
                    .to_string(),
            ),
            owner: Some(owner),
            object_ids: None,
        };
        let response = self.objects(filter, pagination_filter).await?;

        Ok(Page::new(
            response.page_info,
            response
                .data
                .iter()
                .flat_map(Coin::try_from_object)
                .collect::<Vec<_>>(),
        ))
    }

    /// Get the list of gas coins for the specified address.
    pub async fn gas_coins(
        &self,
        owner: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Coin>> {
        self.coins(owner, StructTag::new_iota_coin_type(), pagination_filter)
            .await
    }

    /// Get the coin metadata for the coin type.
    pub async fn coin_metadata(&self, coin_type: &str) -> Result<Option<CoinMetadata>> {
        let operation = CoinMetadataQuery::build(CoinMetadataArgs { coin_type });
        let response = self.run_query(&operation).await?;

        Ok(response.coin_metadata)
    }

    /// Get total supply for the coin type.
    pub async fn total_supply(&self, coin_type: &str) -> Result<Option<u64>> {
        let coin_metadata = self.coin_metadata(coin_type).await?;

        coin_metadata
            .and_then(|c| c.supply)
            .map(|c| c.try_into())
            .transpose()
    }

    // ===========================================================================
    // Checkpoints API
    // ===========================================================================

    /// Get the [`CheckpointSummary`] for a given checkpoint digest or
    /// checkpoint id. If none is provided, it will use the last known
    /// checkpoint id.
    pub async fn checkpoint(
        &self,
        digest: impl Into<Option<Digest>>,
        seq_num: impl Into<Option<u64>>,
    ) -> Result<Option<CheckpointSummary>> {
        let digest = digest.into();
        let seq_num = seq_num.into();
        if digest.is_some() && seq_num.is_some() {
            return Err(Error::from_error(
                Kind::Other,
                "either digest or seq_num must be provided",
            ));
        }

        let operation = CheckpointQuery::build(CheckpointArgs {
            id: CheckpointId {
                digest: digest.map(|d| d.to_string()),
                sequence_number: seq_num,
            },
        });
        let response = self.run_query(&operation).await?;

        response.checkpoint.map(|c| c.try_into()).transpose()
    }

    /// Get a page of [`CheckpointSummary`] for the provided parameters.
    pub async fn checkpoints(
        &self,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<CheckpointSummary>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = CheckpointsQuery::build(CheckpointsArgs {
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
        });
        let response = self.run_query(&operation).await?;

        let cc = response.checkpoints;
        let page_info = cc.page_info;
        let nodes = cc
            .nodes
            .into_iter()
            .map(|c| c.try_into())
            .collect::<Result<Vec<CheckpointSummary>, _>>()?;

        Ok(Page::new(page_info, nodes))
    }

    /// Return the sequence number of the latest checkpoint that has been
    /// executed.
    pub async fn latest_checkpoint_sequence_number(
        &self,
    ) -> Result<Option<CheckpointSequenceNumber>> {
        Ok(self
            .checkpoint(None, None)
            .await?
            .map(|c| c.sequence_number))
    }

    // ===========================================================================
    // Epoch API
    // ===========================================================================

    /// Return the epoch information for the provided epoch. If no epoch is
    /// provided, it will return the last known epoch.
    pub async fn epoch(&self, epoch: impl Into<Option<u64>>) -> Result<Option<Epoch>> {
        let operation = EpochQuery::build(EpochArgs { id: epoch.into() });
        let response = self.run_query(&operation).await?;

        Ok(response.epoch)
    }

    /// Return the number of checkpoints in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    pub async fn epoch_total_checkpoints(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>> {
        let response = self.epoch_summary(epoch.into()).await?;

        Ok(response.epoch.and_then(|e| e.total_checkpoints))
    }

    /// Return the number of transaction blocks in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    pub async fn epoch_total_transaction_blocks(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>> {
        let response = self.epoch_summary(epoch.into()).await?;

        Ok(response.epoch.and_then(|e| e.total_transactions))
    }

    // ===========================================================================
    // Events API
    // ===========================================================================

    /// Return a page of events based on the (optional) event filter.
    pub async fn events(
        &self,
        filter: impl Into<Option<EventFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Event>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = EventsQuery::build(EventsQueryArgs {
            filter: filter.into(),
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
        });

        let response = self.run_query(&operation).await?;

        let ec = response.events;
        let page_info = ec.page_info;

        let events = ec.nodes;

        Ok(Page::new(page_info, events))
    }

    // ===========================================================================
    // Objects API
    // ===========================================================================

    /// Return an object based on the provided [`Address`].
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<Object>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into(),
        });

        let response = self.run_query(&operation).await?;

        let obj = response.object;
        let bcs = obj
            .and_then(|o| o.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?;

        let object = bcs
            .map(|b| bcs::from_bytes::<iota_types::Object>(&b))
            .transpose()?;

        Ok(object)
    }

    /// Return a page of objects based on the provided parameters.
    ///
    /// Use this function together with the [`ObjectFilter::owner`] to get the
    /// objects owned by an address.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let filter = ObjectFilter {
    ///     type_: None,
    ///     owner: Some(Address::from_str("test").unwrap().into()),
    ///     object_ids: None,
    /// };
    ///
    /// let owned_objects = client.objects(None, None, Some(filter), None, None).await;
    /// ```
    pub async fn objects(
        &self,
        filter: impl Into<Option<ObjectFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Object>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;
        let operation = ObjectsQuery::build(ObjectsQueryArgs {
            after,
            before,
            filter: filter.into(),
            first,
            last,
        });

        let response = self.run_query(&operation).await?;

        let oc = response.objects;
        let page_info = oc.page_info;
        let bcs = oc
            .nodes
            .iter()
            .map(|o| &o.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let objects = bcs
            .iter()
            .map(|b| bcs::from_bytes::<iota_types::Object>(b))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, objects))
    }

    /// Return the object's bcs content [`Vec<u8>`] based on the provided
    /// [`Address`].
    pub async fn object_bcs(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: None,
        });

        let response = self.run_query(&operation).await.unwrap();

        Ok(response
            .object
            .and_then(|o| {
                o.bcs
                    .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            })
            .transpose()?)
    }

    /// Return the BCS of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn move_object_contents_bcs(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<Vec<u8>>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into(),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.bcs.0.as_str()))
            .transpose()?)
    }

    // ===========================================================================
    // Package API
    // ===========================================================================

    /// The package corresponding to the given address (at the optionally given
    /// version). When no version is given, the package is loaded directly
    /// from the address given. Otherwise, the address is translated before
    /// loading to point to the package whose original ID matches
    /// the package at address, but whose version is version. For non-system
    /// packages, this might result in a different address than address
    /// because different versions of a package, introduced by upgrades,
    /// exist at distinct addresses.
    ///
    /// Note that this interpretation of version is different from a historical
    /// object read (the interpretation of version for the object query).
    pub async fn package(
        &self,
        address: Address,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<MovePackage>> {
        let operation = PackageQuery::build(PackageArgs {
            address,
            version: version.into(),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|x| x.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Object>(&bcs))
            .transpose()?
            .map(|obj| obj.data.into_package()))
    }

    /// Fetch all versions of package at address (packages that share this
    /// package's original ID), optionally bounding the versions exclusively
    /// from below with afterVersion, or from above with beforeVersion.
    pub async fn package_versions(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
        after_version: impl Into<Option<u64>>,
        before_version: impl Into<Option<u64>>,
    ) -> Result<Page<MovePackage>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;
        let operation = PackageVersionsQuery::build(PackageVersionsArgs {
            address,
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
            filter: Some(MovePackageVersionFilter {
                after_version: after_version.into(),
                before_version: before_version.into(),
            }),
        });

        let response = self.run_query(&operation).await?;

        let pc = response.package_versions;
        let page_info = pc.page_info;
        let bcs = pc
            .nodes
            .iter()
            .map(|p| &p.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let packages = bcs
            .iter()
            .map(|b| Ok(bcs::from_bytes::<Object>(b)?.data.into_package()))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, packages))
    }

    /// Fetch the latest version of the package at address.
    /// This corresponds to the package with the highest version that shares its
    /// original ID with the package at address.
    pub async fn package_latest(&self, address: Address) -> Result<Option<MovePackage>> {
        let operation = LatestPackageQuery::build(PackageArgs {
            address,
            version: None,
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .latest_package
            .and_then(|x| x.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(&bcs.0))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Object>(&bcs))
            .transpose()?
            .map(|obj| obj.data.into_package()))
    }

    /// The Move packages that exist in the network, optionally filtered to be
    /// strictly before beforeCheckpoint and/or strictly after
    /// afterCheckpoint.
    ///
    /// This query returns all versions of a given user package that appear
    /// between the specified checkpoints, but only records the latest
    /// versions of system packages.
    pub async fn packages(
        &self,
        pagination_filter: PaginationFilter,
        after_checkpoint: impl Into<Option<u64>>,
        before_checkpoint: impl Into<Option<u64>>,
    ) -> Result<Page<MovePackage>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = PackagesQuery::build(PackagesQueryArgs {
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
            filter: Some(PackageCheckpointFilter {
                after_checkpoint: after_checkpoint.into(),
                before_checkpoint: before_checkpoint.into(),
            }),
        });

        let response = self.run_query(&operation).await?;

        let pc = response.packages;
        let page_info = pc.page_info;
        let bcs = pc
            .nodes
            .iter()
            .map(|p| &p.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let packages = bcs
            .iter()
            .map(|b| Ok(bcs::from_bytes::<Object>(b)?.data.into_package()))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, packages))
    }

    // ===========================================================================
    // Transaction API
    // ===========================================================================

    /// Get a transaction by its digest.
    pub async fn transaction(&self, digest: Digest) -> Result<Option<SignedTransaction>> {
        let operation = TransactionBlockQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(&self, digest: Digest) -> Result<Option<TransactionEffects>> {
        let operation = TransactionBlockEffectsQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;

        response
            .transaction_block
            .map(TryInto::try_into)
            .transpose()
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: Digest,
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
                    tx: transaction.0,
                    effects,
                }))
            }
            _ => Ok(None),
        }
    }

    /// Get a page of transactions based on the provided filters.
    pub async fn transactions(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<SignedTransaction>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksQuery::build(TransactionBlocksQueryArgs {
            after,
            before,
            filter: filter.into(),
            first,
            last,
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

    /// Get a page of transactions' effects based on the provided filters.
    pub async fn transactions_effects(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionEffects>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksEffectsQuery::build(TransactionBlocksQueryArgs {
            after,
            before,
            filter: filter.into(),
            first,
            last,
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

    /// Get a page of transactions' data and effects based on the provided
    /// filters.
    pub async fn transactions_data_effects(
        &self,
        filter: impl Into<Option<TransactionsFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<TransactionDataEffects>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;

        let operation = TransactionBlocksWithEffectsQuery::build(TransactionBlocksQueryArgs {
            after,
            before,
            filter: filter.into(),
            first,
            last,
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
                        tx: transaction.0,
                        effects,
                    })
                })
                .collect::<Result<Vec<_>>>()?
        };

        Ok(Page::new(page_info, transactions))
    }

    /// Execute a transaction.
    pub async fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects> {
        let wait_for = wait_for.into();
        let operation = ExecuteTransactionQuery::build(ExecuteTransactionArgs {
            signatures: signatures.iter().map(|s| s.to_base64()).collect(),
            tx_bytes: base64ct::Base64::encode_string(bcs::to_bytes(tx).unwrap().as_ref()),
        });

        let response = self.run_query(&operation).await?;

        let result = response.execute_transaction_block;
        let bcs = base64ct::Base64::decode_vec(result.effects.bcs.0.as_str())?;
        let effects: TransactionEffects = bcs::from_bytes(&bcs)?;

        if let Some(wait_for) = wait_for {
            self.wait_for_tx(tx.digest(), wait_for, None).await?;
        }

        Ok(effects)
    }

    /// Returns whether the transaction for the given digest has been indexed
    /// on the node. This means that it can be queries by its digest and its
    /// effects will be usable for subsequent transactions. To check for
    /// full finalization, use [`Self::is_tx_finalized`].
    pub async fn is_tx_indexed_on_node(&self, digest: Digest) -> Result<bool> {
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
    pub async fn is_tx_finalized(&self, digest: Digest) -> Result<bool> {
        let operation = TransactionBlockCheckpointQuery::build(TransactionBlockArgs {
            digest: digest.to_string(),
        });
        let response = self.run_query(&operation).await?;
        if let Some(block) = response.transaction_block {
            if block
                .effects
                .as_ref()
                .and_then(|e| e.checkpoint.as_ref())
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Wait for the indexing or finalization of a transaction
    /// by its digest. An optional timeout can be provided, which, if
    /// exceeded, will return an error (default 60s).
    pub async fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<()> {
        tokio::time::timeout(
            timeout.into().unwrap_or_else(|| Duration::from_secs(60)),
            async {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    if match wait_for {
                        WaitForTx::Indexed => self.is_tx_indexed_on_node(digest).await?,
                        WaitForTx::Finalized => self.is_tx_finalized(digest).await?,
                    } {
                        break Ok(());
                    }
                }
            },
        )
        .await
        .map_err(|e| Error::from_error(Kind::Other, e))?
    }

    // ===========================================================================
    // Normalized Move Package API
    // ===========================================================================
    /// Return the normalized Move function data for the provided package,
    /// module, and function.
    pub async fn normalized_move_function(
        &self,
        package: Address,
        module: &str,
        function: &str,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<MoveFunction>> {
        let operation = NormalizedMoveFunctionQuery::build(NormalizedMoveFunctionQueryArgs {
            address: package,
            module,
            function,
            version: version.into(),
        });
        let response = self.run_query(&operation).await?;

        Ok(response
            .package
            .and_then(|p| p.module)
            .and_then(|m| m.function))
    }

    /// Return the contents' JSON of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn move_object_contents(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<serde_json::Value>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into(),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .and_then(|mv| mv.json))
    }

    /// Return the normalized Move module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep pagination
    // options?
    #[allow(clippy::too_many_arguments)]
    pub async fn normalized_move_module(
        &self,
        package: Address,
        module: &str,
        version: impl Into<Option<u64>>,
        pagination_filter_enums: PaginationFilter,
        pagination_filter_friends: PaginationFilter,
        pagination_filter_functions: PaginationFilter,
        pagination_filter_structs: PaginationFilter,
    ) -> Result<Option<MoveModule>> {
        let enums = self.pagination_filter(pagination_filter_enums).await;
        let friends = self.pagination_filter(pagination_filter_friends).await;
        let functions = self.pagination_filter(pagination_filter_functions).await;
        let structs = self.pagination_filter(pagination_filter_structs).await;
        let operation = NormalizedMoveModuleQuery::build(NormalizedMoveModuleQueryArgs {
            package,
            module,
            version: version.into(),
            after_enums: enums.after.as_deref(),
            after_functions: functions.after.as_deref(),
            after_structs: structs.after.as_deref(),
            after_friends: friends.after.as_deref(),
            before_enums: enums.after.as_deref(),
            before_functions: functions.before.as_deref(),
            before_structs: structs.before.as_deref(),
            before_friends: friends.before.as_deref(),
            first_enums: enums.first,
            first_functions: functions.first,
            first_structs: structs.first,
            first_friends: friends.first,
            last_enums: enums.last,
            last_functions: functions.last,
            last_structs: structs.last,
            last_friends: friends.last,
        });
        let response = self.run_query(&operation).await?;

        Ok(response.package.and_then(|p| p.module))
    }

    // ===========================================================================
    // Dynamic Field(s) API
    // ===========================================================================

    /// Access a dynamic field on an object using its name. Names are arbitrary
    /// Move values whose type have copy, drop, and store, and are specified
    /// using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument can be either a [`BcsName`] for passing raw bcs
    /// bytes or a type that implements Serialize.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    ///
    /// # Example
    /// ```rust,ignore
    /// 
    /// let client = iota_graphql_client::Client::new_devnet();
    /// let address = ObjectId::system().into();
    /// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
    ///
    /// # alternatively, pass in the bcs bytes
    /// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
    /// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
    /// ```
    pub async fn dynamic_field(
        &self,
        address: Address,
        type_: TypeTag,
        name: impl Into<NameValue>,
    ) -> Result<Option<DynamicFieldOutput>> {
        let bcs = name.into().0;
        let operation = DynamicFieldQuery::build(DynamicFieldArgs {
            address,
            name: crate::query_types::DynamicFieldName {
                type_: type_.to_string(),
                bcs: crate::query_types::Base64(base64ct::Base64::encode_string(&bcs)),
            },
        });

        let response = self.run_query(&operation).await?;

        let result = response
            .owner
            .and_then(|o| o.dynamic_field)
            .map(|df| df.try_into())
            .transpose()?;

        Ok(result)
    }

    /// Access a dynamic object field on an object using its name. Names are
    /// arbitrary Move values whose type have copy, drop, and store, and are
    /// specified using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument can be either a [`BcsName`] for passing raw bcs
    /// bytes or a type that implements Serialize.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    pub async fn dynamic_object_field(
        &self,
        address: Address,
        type_: TypeTag,
        name: impl Into<NameValue>,
    ) -> Result<Option<DynamicFieldOutput>> {
        let bcs = name.into().0;
        let operation = DynamicObjectFieldQuery::build(DynamicFieldArgs {
            address,
            name: crate::query_types::DynamicFieldName {
                type_: type_.to_string(),
                bcs: crate::query_types::Base64(base64ct::Base64::encode_string(&bcs)),
            },
        });

        let response = self.run_query(&operation).await?;

        let result: Option<DynamicFieldOutput> = response
            .owner
            .and_then(|o| o.dynamic_object_field)
            .map(|df| df.try_into())
            .transpose()?;
        Ok(result)
    }

    /// Get a page of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    ///
    /// This returns [`Page`] of [`DynamicFieldOutput`]s.
    pub async fn dynamic_fields(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<DynamicFieldOutput>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;
        let operation = DynamicFieldsOwnerQuery::build(DynamicFieldConnectionArgs {
            address,
            after: after.as_deref(),
            before: before.as_deref(),
            first,
            last,
        });
        let response = self.run_query(&operation).await?;

        let DynamicFieldsOwnerQuery { owner: Some(dfs) } = response else {
            return Ok(Page::new_empty());
        };

        Ok(Page::new(
            dfs.dynamic_fields.page_info,
            dfs.dynamic_fields
                .nodes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    /// Return the resolved address for the given name.
    pub async fn iota_names_lookup(&self, name: &str) -> Result<Option<Address>> {
        let operation = ResolveIotaNamesAddressQuery::build(ResolveIotaNamesAddressArgs {
            name: name.to_owned(),
        });
        let response = self.run_query(&operation).await?;

        let ResolveIotaNamesAddressQuery {
            resolve_iota_names_address: Some(address),
        } = response
        else {
            return Ok(None);
        };

        Ok(Some(address.address))
    }

    /// Find all registration NFTs for the given address.
    pub async fn iota_names_registrations(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<NameRegistration>> {
        let PaginationFilterResponse {
            after,
            before,
            first,
            last,
        } = self.pagination_filter(pagination_filter).await;
        let operation = IotaNamesAddressRegistrationsQuery::build(IotaNamesRegistrationsArgs {
            address,
            after,
            before,
            first,
            last,
        });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressRegistrationsQuery {
            address:
                Some(IotaNamesRegistrationsQuery {
                    iota_names_registrations,
                }),
        } = response
        else {
            return Ok(Page::new_empty());
        };

        Ok(Page::new(
            iota_names_registrations.page_info,
            iota_names_registrations
                .nodes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    /// Get the default name pointing to this address, if one exists.
    pub async fn iota_names_default_name(
        &self,
        address: Address,
        format: impl Into<Option<NameFormat>>,
    ) -> Result<Option<Name>> {
        let operation = IotaNamesAddressDefaultNameQuery::build(IotaNamesDefaultNameArgs {
            address,
            format: format.into().map(Into::into),
        });
        let response = self.run_query(&operation).await?;

        let IotaNamesAddressDefaultNameQuery {
            address:
                Some(IotaNamesDefaultNameQuery {
                    iota_names_default_name: Some(name),
                }),
        } = response
        else {
            return Ok(None);
        };

        Ok(Some(Name::from_str(&name).map_err(|_| {
            Error::from_error(Kind::Parse, format!("invalid name: {name}"))
        })?))
    }
}

// This function is used in tests to create a new client instance for the local
// server.
#[cfg(test)]
mod tests {
    use base64ct::Encoding;
    use futures::StreamExt;
    use iota_types::{Address, Digest, Ed25519PublicKey, ObjectId, TypeTag};
    use tokio::time;

    use crate::{
        BcsName, Client, DEVNET_HOST, Direction, LOCAL_HOST, MAINNET_HOST, PaginationFilter,
        TESTNET_HOST, faucet::FaucetClient, query_types::TransactionsFilter,
    };

    const NUM_COINS_FROM_FAUCET: usize = 5;

    fn test_client() -> Client {
        let network = std::env::var("NETWORK").unwrap_or_else(|_| "local".to_string());
        match network.as_str() {
            "mainnet" => Client::new_mainnet(),
            "testnet" => Client::new_testnet(),
            "devnet" => Client::new_devnet(),
            "local" => Client::new_localnet(),
            _ => Client::new(&network).expect("Invalid network URL: {network}"),
        }
    }

    #[test]
    fn test_rpc_server() {
        let mut client = Client::new_mainnet();
        assert_eq!(client.rpc_server(), &MAINNET_HOST.parse().unwrap());
        client.set_rpc_server(TESTNET_HOST).unwrap();
        assert_eq!(client.rpc_server(), &TESTNET_HOST.parse().unwrap());
        client.set_rpc_server(DEVNET_HOST).unwrap();
        assert_eq!(client.rpc_server(), &DEVNET_HOST.parse().unwrap());
        client.set_rpc_server(LOCAL_HOST).unwrap();
        assert_eq!(client.rpc_server(), &LOCAL_HOST.parse().unwrap());

        assert!(client.set_rpc_server("localhost:9125/graphql").is_ok());
        assert!(client.set_rpc_server("9125/graphql").is_err());
    }

    #[tokio::test]
    async fn test_balance_query() {
        let client = test_client();
        client
            .balance(Address::STD_LIB, None)
            .await
            .map_err(|e| {
                format!(
                    "Balance query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_chain_id() {
        let client = test_client();
        let chain_id = client.chain_id().await;
        assert!(chain_id.is_ok());
    }

    #[tokio::test]
    async fn test_reference_gas_price_query() {
        let client = test_client();
        client
            .reference_gas_price(None)
            .await
            .map_err(|e| {
                format!(
                    "Reference gas price query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_protocol_config_query() {
        let client = test_client();
        client
            .protocol_config(None)
            .await
            .map_err(|e| {
                format!(
                    "Protocol config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        // test specific version
        let pc = client
            .protocol_config(Some(50))
            .await
            .map_err(|e| {
                format!(
                    "Protocol config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert_eq!(
            pc.protocol_version,
            50,
            "Protocol version query mismatch for {} network. Expected: 50, received: {}",
            client.rpc_server(),
            pc.protocol_version
        );
    }

    #[tokio::test]
    async fn test_service_config_query() {
        let client = test_client();
        client
            .service_config()
            .await
            .map_err(|e| {
                format!(
                    "Service config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_active_validators() {
        let client = test_client();
        let av = client
            .active_validators(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Active validators query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !av.is_empty(),
            "Active validators query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_coin_metadata_query() {
        let client = test_client();
        client
            .coin_metadata("0x2::iota::IOTA")
            .await
            .map_err(|e| {
                format!(
                    "Coin metadata query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_checkpoint_query() {
        let client = test_client();
        client
            .checkpoint(None, None)
            .await
            .map_err(|e| {
                format!(
                    "Checkpoint query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn test_checkpoints_query() {
        let client = test_client();
        let cs = client
            .checkpoints(PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Checkpoints query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !cs.is_empty(),
            "Checkpoints query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_latest_checkpoint_sequence_number_query() {
        let client = test_client();
        client
            .latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                format!(
                    "Latest checkpoint sequence number query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_query() {
        let client = test_client();
        client
            .epoch(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_total_checkpoints_query() {
        let client = test_client();
        client
            .epoch_total_checkpoints(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch total checkpoints query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_total_transaction_blocks_query() {
        let client = test_client();
        client
            .epoch_total_transaction_blocks(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch total transaction blocks query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_epoch_summary_query() {
        let client = test_client();
        client
            .epoch_summary(None)
            .await
            .map_err(|e| {
                format!(
                    "Epoch summary query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_events_query() {
        let client = test_client();
        let events = client
            .events(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Events query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !events.is_empty(),
            "Events query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_objects_query() {
        let client = test_client();
        let objects = client
            .objects(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Objects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !objects.is_empty(),
            "Objects query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_object_query() {
        let client = test_client();
        client
            .object(ObjectId::SYSTEM, None)
            .await
            .map_err(|e| {
                format!(
                    "Object query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_object_bcs_query() {
        let client = test_client();
        client
            .object_bcs(ObjectId::SYSTEM)
            .await
            .map_err(|e| {
                format!(
                    "Object bcs query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_coins_query() {
        let client = test_client();
        client
            .coins(Address::STD_LIB, None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Coins query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_coins_stream() {
        let client = test_client();
        let faucet = match client.rpc_server().as_str() {
            LOCAL_HOST => FaucetClient::new_localnet(),
            TESTNET_HOST => FaucetClient::new_testnet(),
            DEVNET_HOST => FaucetClient::new_devnet(),
            _ => return,
        };
        let key = Ed25519PublicKey::generate(rand::thread_rng());
        let address = key.derive_address();
        faucet.request_and_wait(address).await.unwrap();

        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY: time::Duration = time::Duration::from_secs(1);

        let mut num_coins = 0;
        for attempt in 0..MAX_RETRIES {
            let mut stream = client.coins_stream(address, None, Direction::default());

            while let Some(result) = stream.next().await {
                match result {
                    Ok(_) => num_coins += 1,
                    Err(_) => {
                        if attempt < MAX_RETRIES - 1 {
                            time::sleep(RETRY_DELAY).await;
                            num_coins = 0;
                            break;
                        }
                    }
                }
            }
        }

        assert!(num_coins >= NUM_COINS_FROM_FAUCET);
    }

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
    async fn test_total_supply() {
        let client = test_client();
        client
            .total_supply("0x2::iota::IOTA")
            .await
            .map_err(|e| {
                format!(
                    "Total supply query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    // This needs the tx builder to be able to be tested properly
    #[tokio::test]
    async fn test_dry_run() {
        let client = Client::new_testnet();
        let tx_bytes = "AAACAAgAypo7AAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgABAQAAAQEDAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACg9WqbvnpQmublI1+/dnonzEvhVPHnGEX++ianEHLIZmoiqRAAAAAAAgmrviNLnSJMjhRUZ8il2SFFjZ60cdJWv9v3M7pTsTQaA0FjZwX1JlYTftfc/+nF7J1QTfVacG+5wc2teKJoJHBDf/BgAAAAAAIOFdV7nQyvw+7AJpDmJFifAa4SqrI5qqXqAq1IKZsSxKVTI1Cd7yJVFzIqi4nnPX1ShmHEJWweFl5BId7OSkHXViNQ0AAAAAACA4U7t1jiQwTs87xenAvOkQWAAMWbElg0Exz1annhowtXPQJaMX5mcenWnm/aFAXhUM2rGsvqqa2zM2OOQyEKqbNP8GAAAAAAAg7pHVs4Z58mP71Y53cDuY3X/TbTgfmBHkDWe16J+kBOqhnfl+yRNiYZ3fpWvyc4rB2u+a2qjUGqcw7yFnlhJAj1w00w8AAAAAIDEjW30S0iN4lnDXpigCjEmOA0tUYKf339ZayYUU9PG6s1wmB/dndlMUdTZGe5MOz1baxXMESHbVd5L7XTObgECAQpEAAAAAACBCkCOAwD6Dl2DkdXj/eFRBTsNPWg3XYATTPxeThLuhzrTmcYf4XqT8ceMAoKbQBjtzyaTv+xb0K0MzHfvJR1NFgUKRAAAAAAAgxUVPvQUU/R1jcC2+AxZ7uC3ls+09G7xAk0xusdBSUkXPNNWDsV8xzw6ipjnf5pk9W3R9P0RD6iORRe+0JKaLtmE1DQAAAAAAIPhsUoriBlzhLc4SHds72JTbjeI37VhyjlFVtQurLY+26e+jqKb2TsdARpYEvxPl31WAelj2RMuUyK8S5NeluEWjKpEAAAAAACCR/0nc3l5UIXpl6I6SEpWABP/vJewHhZ5iMDpIDXdMqf0VCu+y2k/TZIpRFMDRiBO0oUW+L8+06uAi3pZkwpbFNf8GAAAAAAAgyIfExjdHxdt7+eiOLRh4N4/iSMZCrHf2t5iYI+Kl8ysAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgDAAAAAAAA4G88AAAAAAAA";

        client
            .dry_run(tx_bytes.to_string(), false, None)
            .await
            .map_err(|e| {
                format!(
                    "Dry run failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_dynamic_field_query() {
        let client = test_client();
        let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
        client
            .dynamic_field(ObjectId::SYSTEM.into(), TypeTag::U64, BcsName(bcs))
            .await
            .map_err(|e| {
                format!(
                    "Dynamic field query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        client
            .dynamic_field(ObjectId::SYSTEM.into(), TypeTag::U64, 2u64)
            .await
            .map_err(|e| {
                format!(
                    "Dynamic field query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_dynamic_fields_query() {
        let client = test_client();
        client
            .dynamic_fields(ObjectId::SYSTEM.into(), PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Dynamic fields query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_total_transaction_blocks() {
        let client = test_client();
        let total_transaction_blocks = client
            .total_transaction_blocks()
            .await
            .map_err(|e| {
                format!(
                    "Total transaction blocks query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
        assert!(total_transaction_blocks > 0);

        let chckp_id = client
            .latest_checkpoint_sequence_number()
            .await
            .map_err(|e| {
                format!(
                    "Latest checkpoint sequence number query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
        let total_transaction_blocks_by_seq_num = client
            .total_transaction_blocks_by_seq_num(chckp_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            total_transaction_blocks_by_seq_num >= total_transaction_blocks,
            "expected at least {total_transaction_blocks} transaction blocks, found {total_transaction_blocks_by_seq_num}"
        );

        let chckp = client
            .checkpoint(None, Some(chckp_id))
            .await
            .unwrap()
            .unwrap();

        let digest = chckp.content_digest;
        let total_transaction_blocks_by_digest = client
            .total_transaction_blocks_by_digest(digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            total_transaction_blocks_by_seq_num,
            total_transaction_blocks_by_digest
        );
    }

    #[tokio::test]
    async fn test_package() {
        let client = test_client();
        client
            .package(Address::FRAMEWORK, None)
            .await
            .map_err(|e| {
                format!(
                    "Package query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_latest_package_query() {
        let client = test_client();
        client
            .package_latest(Address::FRAMEWORK)
            .await
            .map_err(|e| {
                format!(
                    "Latest package query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_packages_query() {
        let client = test_client();
        let packages = client
            .packages(PaginationFilter::default(), None, None)
            .await
            .map_err(|e| {
                format!(
                    "Packages query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !packages.is_empty(),
            "Packages query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_transaction_data_effects() {
        let client = Client::new_devnet();

        client
            .transaction_data_effects(
                Digest::from_base58("Agug2GETToZj4Ncw3RJn2KgDUEpVQKG1WaTZVcLcqYnf").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_transactions_data_effects() {
        let client = Client::new_devnet();

        client
            .transactions_data_effects(
                TransactionsFilter {
                    transaction_ids: Some(vec![
                        "Agug2GETToZj4Ncw3RJn2KgDUEpVQKG1WaTZVcLcqYnf".to_string(),
                    ]),
                    ..Default::default()
                },
                PaginationFilter::default(),
            )
            .await
            .unwrap();
    }
}
