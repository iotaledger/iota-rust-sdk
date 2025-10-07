// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use iota_graphql_client::{
    pagination::PaginationFilter,
    query_types::{ObjectKey, ProtocolConfigs, ServiceConfig},
};
use iota_types::{CheckpointSequenceNumber, def_is};
use tokio::sync::RwLock;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        address::Address,
        checkpoint::CheckpointSummary,
        digest::Digest,
        graphql::{
            CoinMetadata, DryRunResult, DynamicFieldOutput, Epoch, EventFilter, MoveFunction,
            MoveModule, ObjectFilter, TransactionDataEffects, TransactionMetadata,
            TransactionsFilter,
        },
        object::{MovePackage, Object, ObjectId},
        signature::UserSignature,
        transaction::{SignedTransaction, Transaction, TransactionEffects, TransactionKind},
        type_tag::TypeTag,
    },
    uniffi_helpers::{
        CheckpointSummaryPage, CoinPage, DynamicFieldOutputPage, EpochPage, EventPage,
        MovePackagePage, ObjectPage, SignedTransactionPage, TransactionDataEffectsPage,
        TransactionEffectsPage, ValidatorPage,
    },
};

/// The GraphQL client for interacting with the IOTA blockchain.
#[derive(uniffi::Object)]
pub struct GraphQLClient(RwLock<iota_graphql_client::Client>);

impl GraphQLClient {
    pub fn inner(&self) -> &RwLock<iota_graphql_client::Client> {
        &self.0
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    // ===========================================================================
    // Client Misc API
    // ===========================================================================

    /// Create a new GraphQL client with the provided server address.
    #[uniffi::constructor]
    pub fn new(server: String) -> Result<Self> {
        Ok(Self(RwLock::new(iota_graphql_client::Client::new(
            &server,
        )?)))
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    #[uniffi::constructor]
    pub fn new_mainnet() -> Self {
        Self(RwLock::new(iota_graphql_client::Client::new_mainnet()))
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    #[uniffi::constructor]
    pub fn new_testnet() -> Self {
        Self(RwLock::new(iota_graphql_client::Client::new_testnet()))
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    #[uniffi::constructor]
    pub fn new_devnet() -> Self {
        Self(RwLock::new(iota_graphql_client::Client::new_devnet()))
    }

    /// Create a new GraphQL client connected to the `localhost` GraphQL server:
    /// {DEFAULT_LOCAL_HOST}.
    #[uniffi::constructor]
    pub fn new_localnet() -> Self {
        Self(RwLock::new(iota_graphql_client::Client::new_localnet()))
    }

    /// Get the chain identifier.
    pub async fn chain_id(&self) -> Result<String> {
        Ok(self.0.read().await.chain_id().await?)
    }

    /// Lazily fetch the max page size
    pub async fn max_page_size(&self) -> Result<i32> {
        Ok(self.0.read().await.max_page_size().await?)
    }

    // ===========================================================================
    // Network info API
    // ===========================================================================

    /// Get the reference gas price for the provided epoch or the last known one
    /// if no epoch is provided.
    ///
    /// This will return `Ok(None)` if the epoch requested is not available in
    /// the GraphQL service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn reference_gas_price(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self.0.read().await.reference_gas_price(epoch).await?)
    }

    /// Get the protocol configuration.
    #[uniffi::method(default(version = None))]
    pub async fn protocol_config(&self, version: Option<u64>) -> Result<Option<ProtocolConfigs>> {
        Ok(self.0.read().await.protocol_config(version).await?)
    }

    /// Get the list of active validators for the provided epoch, including
    /// related metadata. If no epoch is provided, it will return the active
    /// validators for the current epoch.
    #[uniffi::method(default(epoch = None, pagination_filter = None))]
    pub async fn active_validators(
        &self,
        epoch: Option<u64>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<ValidatorPage> {
        Ok(self
            .0
            .read()
            .await
            .active_validators(epoch, pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint digest.
    pub async fn total_transaction_blocks_by_digest(&self, digest: &Digest) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .total_transaction_blocks_by_digest(**digest)
            .await?)
    }

    /// The total number of transaction blocks in the network by the end of the
    /// provided checkpoint sequence number.
    pub async fn total_transaction_blocks_by_seq_num(&self, seq_num: u64) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .total_transaction_blocks_by_seq_num(seq_num)
            .await?)
    }

    /// The total number of transaction blocks in the network by the end of the
    /// last known checkpoint.
    pub async fn total_transaction_blocks(&self) -> Result<Option<u64>> {
        Ok(self.0.read().await.total_transaction_blocks().await?)
    }

    // ===========================================================================
    // Coin API
    // ===========================================================================

    /// Get the list of coins for the specified address.
    ///
    /// If `coin_type` is not provided, it will default to `0x2::coin::Coin`,
    /// which will return all coins. For IOTA coin, pass in the coin type:
    /// `0x2::coin::Coin<0x2::iota::IOTA>`.
    #[uniffi::method(default(pagination_filter = None, coin_type = None))]
    pub async fn coins(
        &self,
        owner: &Address,
        pagination_filter: Option<PaginationFilter>,
        coin_type: Option<String>,
    ) -> Result<CoinPage> {
        Ok(self
            .0
            .read()
            .await
            .coins(**owner, coin_type, pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// Get the coin metadata for the coin type.
    pub async fn coin_metadata(&self, coin_type: &str) -> Result<Option<CoinMetadata>> {
        Ok(self
            .0
            .read()
            .await
            .coin_metadata(coin_type)
            .await?
            .map(Into::into))
    }

    /// Get total supply for the coin type.
    pub async fn total_supply(&self, coin_type: &str) -> Result<Option<u64>> {
        Ok(self.0.read().await.total_supply(coin_type).await?)
    }

    // ===========================================================================
    // Checkpoints API
    // ===========================================================================

    /// Get the [`CheckpointSummary`] for a given checkpoint digest or
    /// checkpoint id. If none is provided, it will use the last known
    /// checkpoint id.
    #[uniffi::method(default(digest = None, seq_num = None))]
    pub async fn checkpoint(
        &self,
        digest: Option<Arc<Digest>>,
        seq_num: Option<u64>,
    ) -> Result<Option<Arc<CheckpointSummary>>> {
        Ok(self
            .0
            .read()
            .await
            .checkpoint(digest.map(|d| **d), seq_num)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Get a page of [`CheckpointSummary`] for the provided parameters.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn checkpoints(
        &self,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<CheckpointSummaryPage> {
        Ok(self
            .0
            .read()
            .await
            .checkpoints(pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// Return the sequence number of the latest checkpoint that has been
    /// executed.
    pub async fn latest_checkpoint_sequence_number(
        &self,
    ) -> Result<Option<CheckpointSequenceNumber>> {
        Ok(self
            .0
            .read()
            .await
            .latest_checkpoint_sequence_number()
            .await?)
    }

    // ===========================================================================
    // Epoch API
    // ===========================================================================

    /// Return the epoch information for the provided epoch. If no epoch is
    /// provided, it will return the last known epoch.
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch(&self, epoch: Option<u64>) -> Result<Option<Epoch>> {
        Ok(self.0.read().await.epoch(epoch).await?.map(Into::into))
    }

    /// Return the number of checkpoints in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_checkpoints(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self.0.read().await.epoch_total_checkpoints(epoch).await?)
    }

    /// Return the number of transaction blocks in this epoch. This will return
    /// `Ok(None)` if the epoch requested is not available in the GraphQL
    /// service (e.g., due to pruning).
    #[uniffi::method(default(epoch = None))]
    pub async fn epoch_total_transaction_blocks(&self, epoch: Option<u64>) -> Result<Option<u64>> {
        Ok(self
            .0
            .read()
            .await
            .epoch_total_transaction_blocks(epoch)
            .await?)
    }

    // ===========================================================================
    // Events API
    // ===========================================================================

    /// Return a page of tuple (event, transaction digest) based on the
    /// (optional) event filter.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn events(
        &self,
        filter: Option<EventFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<EventPage> {
        Ok(self
            .0
            .read()
            .await
            .events(
                filter.map(|f| f.into()),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    // ===========================================================================
    // Objects API
    // ===========================================================================

    /// Return an object based on the provided [`Address`].
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn object(
        &self,
        object_id: &ObjectId,
        version: Option<u64>,
    ) -> Result<Option<Arc<Object>>> {
        Ok(self
            .0
            .read()
            .await
            .object(**object_id, version)
            .await?
            .map(Into::into)
            .map(Arc::new))
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
    ///     type_tag: None,
    ///     owner: Some(Address::from_str("test").unwrap().into()),
    ///     object_ids: None,
    /// };
    ///
    /// let owned_objects = client.objects(None, None, Some(filter), None, None).await;
    /// ```
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn objects(
        &self,
        filter: Option<ObjectFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<ObjectPage> {
        Ok(self
            .0
            .read()
            .await
            .objects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Return the object's bcs content [`Vec<u8>`] based on the provided
    /// [`Address`].
    pub async fn object_bcs(&self, object_id: &ObjectId) -> Result<Option<Vec<u8>>> {
        Ok(self.0.read().await.object_bcs(**object_id).await?)
    }

    /// Return the BCS of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn move_object_contents_bcs(
        &self,
        object_id: &ObjectId,
        version: Option<u64>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .read()
            .await
            .move_object_contents_bcs(**object_id, version)
            .await?)
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
    #[uniffi::method(default(version = None))]
    pub async fn package(
        &self,
        address: &Address,
        version: Option<u64>,
    ) -> Result<Option<Arc<MovePackage>>> {
        Ok(self
            .0
            .read()
            .await
            .package(**address, version)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Fetch all versions of package at address (packages that share this
    /// package's original ID), optionally bounding the versions exclusively
    /// from below with afterVersion, or from above with beforeVersion.
    #[uniffi::method(default(pagination_filter = None, after_version = None, before_version = None))]
    pub async fn package_versions(
        &self,
        address: &Address,
        after_version: Option<u64>,
        before_version: Option<u64>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<MovePackagePage> {
        Ok(self
            .0
            .read()
            .await
            .package_versions(
                **address,
                pagination_filter.unwrap_or_default(),
                after_version,
                before_version,
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Fetch the latest version of the package at address.
    /// This corresponds to the package with the highest version that shares its
    /// original ID with the package at address.
    pub async fn package_latest(&self, address: &Address) -> Result<Option<Arc<MovePackage>>> {
        Ok(self
            .0
            .read()
            .await
            .package_latest(**address)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// The Move packages that exist in the network, optionally filtered to be
    /// strictly before beforeCheckpoint and/or strictly after
    /// afterCheckpoint.
    ///
    /// This query returns all versions of a given user package that appear
    /// between the specified checkpoints, but only records the latest
    /// versions of system packages.
    #[uniffi::method(default(pagination_filter = None, after_checkpoint = None, before_checkpoint = None))]
    pub async fn packages(
        &self,
        after_checkpoint: Option<u64>,
        before_checkpoint: Option<u64>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<MovePackagePage> {
        Ok(self
            .0
            .read()
            .await
            .packages(
                pagination_filter.unwrap_or_default(),
                after_checkpoint,
                before_checkpoint,
            )
            .await?
            .map(Into::into)
            .into())
    }

    // ===========================================================================
    // Transaction API
    // ===========================================================================

    /// Get a transaction by its digest.
    pub async fn transaction(&self, digest: &Digest) -> Result<Option<SignedTransaction>> {
        Ok(self
            .0
            .read()
            .await
            .transaction(**digest)
            .await?
            .map(Into::into))
    }

    /// Get a transaction's effects by its digest.
    pub async fn transaction_effects(
        &self,
        digest: &Digest,
    ) -> Result<Option<Arc<TransactionEffects>>> {
        Ok(self
            .0
            .read()
            .await
            .transaction_effects(**digest)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Get a transaction's data and effects by its digest.
    pub async fn transaction_data_effects(
        &self,
        digest: &Digest,
    ) -> Result<Option<TransactionDataEffects>> {
        Ok(self
            .0
            .read()
            .await
            .transaction_data_effects(**digest)
            .await?
            .map(Into::into))
    }

    /// Get a page of transactions based on the provided filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions(
        &self,
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<SignedTransactionPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions' effects based on the provided filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions_effects(
        &self,
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_effects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Get a page of transactions' data and effects based on the provided
    /// filters.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn transactions_data_effects(
        &self,
        filter: Option<TransactionsFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<TransactionDataEffectsPage> {
        Ok(self
            .0
            .read()
            .await
            .transactions_data_effects(
                filter.map(Into::into),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }

    /// Execute a transaction.
    pub async fn execute_tx(
        &self,
        signatures: Vec<Arc<UserSignature>>,
        tx: &Transaction,
    ) -> Result<Option<Arc<TransactionEffects>>> {
        Ok(self
            .0
            .read()
            .await
            .execute_tx(
                &signatures
                    .into_iter()
                    .map(|s| s.0.clone())
                    .collect::<Vec<_>>(),
                &tx.clone().into(),
            )
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    // ===========================================================================
    // Normalized Move Package API
    // ===========================================================================
    /// Return the normalized Move function data for the provided package,
    /// module, and function.
    #[uniffi::method(default(version = None))]
    pub async fn normalized_move_function(
        &self,
        package: &Address,
        module: &str,
        function: &str,
        version: Option<u64>,
    ) -> Result<Option<Arc<MoveFunction>>> {
        Ok(self
            .0
            .read()
            .await
            .normalized_move_function(**package, module, function, version)
            .await?
            .map(Into::into)
            .map(Arc::new))
    }

    /// Return the contents' JSON of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    #[uniffi::method(default(version = None))]
    pub async fn move_object_contents(
        &self,
        object_id: &ObjectId,
        version: Option<u64>,
    ) -> Result<Option<serde_json::Value>> {
        Ok(self
            .0
            .read()
            .await
            .move_object_contents(**object_id, version)
            .await?)
    }

    /// Return the normalized Move module data for the provided module.
    // TODO: do we want to self paginate everything and return all the data, or keep pagination
    // options?
    #[allow(clippy::too_many_arguments)]
    #[uniffi::method(default(
        version = None,
        pagination_filter_enums = None,
        pagination_filter_friends = None,
        pagination_filter_functions = None,
        pagination_filter_structs = None,
    ))]
    pub async fn normalized_move_module(
        &self,
        package: &Address,
        module: &str,
        version: Option<u64>,
        pagination_filter_enums: Option<PaginationFilter>,
        pagination_filter_friends: Option<PaginationFilter>,
        pagination_filter_functions: Option<PaginationFilter>,
        pagination_filter_structs: Option<PaginationFilter>,
    ) -> Result<Option<MoveModule>> {
        Ok(self
            .0
            .read()
            .await
            .normalized_move_module(
                **package,
                module,
                version,
                pagination_filter_enums.unwrap_or_default(),
                pagination_filter_friends.unwrap_or_default(),
                pagination_filter_functions.unwrap_or_default(),
                pagination_filter_structs.unwrap_or_default(),
            )
            .await?
            .map(Into::into))
    }

    // ===========================================================================
    // Dynamic Field(s) API
    // ===========================================================================

    /// Access a dynamic field on an object using its name. Names are arbitrary
    /// Move values whose type have copy, drop, and store, and are specified
    /// using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument is a json serialized type.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    ///
    /// # Example
    /// ```rust,ignore
    /// 
    /// let client = iota_graphql_client::Client::new_devnet();
    /// let address = Address::from_str("0x5").unwrap();
    /// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
    ///
    /// # alternatively, pass in the bcs bytes
    /// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
    /// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
    /// ```
    pub async fn dynamic_field(
        &self,
        address: &Address,
        type_tag: &TypeTag,
        name: serde_json::Value,
    ) -> Result<Option<DynamicFieldOutput>> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_field(**address, type_tag.0.clone(), name)
            .await?
            .map(Into::into))
    }

    /// Access a dynamic object field on an object using its name. Names are
    /// arbitrary Move values whose type have copy, drop, and store, and are
    /// specified using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument is a json serialized type.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    pub async fn dynamic_object_field(
        &self,
        address: &Address,
        type_tag: &TypeTag,
        name: serde_json::Value,
    ) -> Result<Option<DynamicFieldOutput>> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_object_field(**address, type_tag.0.clone(), name)
            .await?
            .map(Into::into))
    }

    /// Get a page of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    ///
    /// This returns [`Page`] of [`DynamicFieldOutput`]s.
    #[uniffi::method(default(pagination_filter = None))]
    pub async fn dynamic_fields(
        &self,
        address: &Address,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<DynamicFieldOutputPage> {
        Ok(self
            .0
            .read()
            .await
            .dynamic_fields(**address, pagination_filter.unwrap_or_default())
            .await?
            .map(Into::into)
            .into())
    }

    /// Set the server address for the GraphQL GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub async fn set_rpc_server(&self, server: String) -> Result<()> {
        Ok(self.0.write().await.set_rpc_server(&server)?)
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<ServiceConfig> {
        Ok(self.0.read().await.service_config().await?.clone())
    }

    // ===========================================================================
    // Dry Run API
    // ===========================================================================

    /// Dry run a [`Transaction`] and return the transaction effects and dry run
    /// error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    #[uniffi::method(default(skip_checks = None))]
    pub async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: Option<bool>,
    ) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_tx(&tx.clone().into(), skip_checks.unwrap_or(false))
            .await?
            .into())
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
    #[uniffi::method(default(skip_checks = None))]
    pub async fn dry_run_tx_kind(
        &self,
        tx_kind: &TransactionKind,
        tx_meta: TransactionMetadata,
        skip_checks: Option<bool>,
    ) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_tx_kind(&tx_kind.0, skip_checks.unwrap_or(false), tx_meta.into())
            .await?
            .into())
    }

    /// Run a query.
    pub async fn run_query(&self, query: Query) -> Result<serde_json::Value> {
        self.0
            .read()
            .await
            .run_query_from_json(
                serde_json::to_value(query)?
                    .as_object()
                    .ok_or_else(|| SdkFfiError::custom("invalid json; must be a map"))?
                    .clone(),
            )
            .await?
            .data
            .ok_or_else(|| SdkFfiError::custom("query yielded no data"))
    }

    // ===========================================================================
    // Balance API
    // ===========================================================================

    /// Get the balance of all the coins owned by address for the provided coin
    /// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
    /// if not provided.
    #[uniffi::method(default(coin_type = None))]
    pub async fn balance(
        &self,
        address: &Address,
        coin_type: Option<String>,
    ) -> Result<Option<u64>> {
        Ok(self.0.read().await.balance(**address, coin_type).await?)
    }
}

#[derive(Debug, uniffi::Record, serde::Serialize)]
pub struct Query {
    pub query: String,
    #[uniffi(default = None)]
    #[serde(default)]
    pub variables: Option<serde_json::Value>,
}
