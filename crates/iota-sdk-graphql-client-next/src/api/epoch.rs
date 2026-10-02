// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cynic::{Operation, QueryBuilder};
use iota_client_api::ProtocolConfig;

use crate::{
    GraphQLClient, Query, Request, Result, ServerVersion,
    wire::{DateTime, Num, schema},
};

/// An epoch's summary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Epoch {
    /// The epoch's number, counting from 0.
    pub epoch_id: u64,
    /// The protocol version the epoch runs.
    pub protocol_version: u64,
    /// The minimum gas price a quorum of validators sign transactions for.
    pub reference_gas_price: Option<u64>,
    /// When the epoch started, as an ISO 8601 timestamp.
    pub start_timestamp: String,
    /// When the epoch ended, as an ISO 8601 timestamp, if it has.
    pub end_timestamp: Option<String>,
    /// The number of checkpoints in the epoch.
    pub total_checkpoints: Option<u64>,
    /// The number of transactions in the epoch.
    pub total_transactions: Option<u64>,
    /// The gas fees paid in the epoch, in NANOS.
    pub total_gas_fees: Option<u64>,
    /// The stake rewards paid in the epoch, in NANOS.
    pub total_stake_rewards: Option<u64>,
    /// The version of the system state object, which changes whenever the
    /// system state does.
    pub system_state_version: Option<u64>,
}

/// Query for [`GraphQLClient::epoch`].
#[derive(Clone, Debug)]
pub struct GetEpoch {
    id: Option<u64>,
}

impl Query for GetEpoch {
    type Output = Option<Epoch>;
    type Data = EpochQuery;
    type Variables = EpochVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<EpochQuery, EpochVariables>> {
        Ok(EpochQuery::build(EpochVariables { id: self.id }))
    }

    fn decode(self, data: EpochQuery) -> Result<Option<Epoch>> {
        Ok(data.epoch.map(|epoch| Epoch {
            epoch_id: epoch.epoch_id,
            protocol_version: epoch.protocol_configs.protocol_version,
            reference_gas_price: epoch.reference_gas_price.map(Num::into_inner),
            start_timestamp: epoch.start_timestamp.0,
            end_timestamp: epoch.end_timestamp.map(|timestamp| timestamp.0),
            total_checkpoints: epoch.total_checkpoints,
            total_transactions: epoch.total_transactions,
            total_gas_fees: epoch.total_gas_fees.map(Num::into_inner),
            total_stake_rewards: epoch.total_stake_rewards.map(Num::into_inner),
            system_state_version: epoch.system_state_version,
        }))
    }
}

impl Request<GetEpoch> {
    /// Fetch the epoch with this number instead of the current one.
    pub fn id(self, id: u64) -> Self {
        self.map(|_| GetEpoch { id: Some(id) })
    }
}

/// Query for [`GraphQLClient::protocol_config`].
#[derive(Clone, Debug)]
pub struct GetProtocolConfig {
    version: Option<u64>,
}

impl Query for GetProtocolConfig {
    type Output = ProtocolConfig;
    type Data = ProtocolConfigQuery;
    type Variables = ProtocolConfigVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<ProtocolConfigQuery, ProtocolConfigVariables>> {
        Ok(ProtocolConfigQuery::build(ProtocolConfigVariables {
            version: self.version,
        }))
    }

    fn decode(self, data: ProtocolConfigQuery) -> Result<ProtocolConfig> {
        let config = data.protocol_config;
        let attributes = config
            .configs
            .into_iter()
            .filter_map(|attribute| Some((attribute.key, attribute.value?)))
            .collect();
        let feature_flags = config
            .feature_flags
            .into_iter()
            .map(|flag| (flag.key, flag.value))
            .collect();
        Ok(ProtocolConfig::new(attributes)
            .with_protocol_version(config.protocol_version)
            .with_feature_flags(feature_flags))
    }
}

impl Request<GetProtocolConfig> {
    /// Fetch the configuration of this protocol version instead of the
    /// current one.
    pub fn version(self, version: u64) -> Self {
        self.map(|_| GetProtocolConfig {
            version: Some(version),
        })
    }
}

impl GraphQLClient {
    /// The current epoch, or the one set with
    /// [`id`](Request::<GetEpoch>::id). Resolves to `None` if the server has
    /// no data for it (e.g., after pruning).
    pub fn epoch(&self) -> Request<GetEpoch> {
        Request::new(self, GetEpoch { id: None })
    }

    /// The configuration of the current protocol version, or the one set with
    /// [`version`](Request::<GetProtocolConfig>::version).
    pub fn protocol_config(&self) -> Request<GetProtocolConfig> {
        Request::new(self, GetProtocolConfig { version: None })
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct EpochVariables {
    pub(crate) id: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EpochVariables")]
pub struct EpochQuery {
    #[arguments(id: $id)]
    pub(crate) epoch: Option<EpochNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Epoch")]
pub(crate) struct EpochNode {
    pub(crate) epoch_id: u64,
    pub(crate) protocol_configs: ProtocolVersionNode,
    pub(crate) reference_gas_price: Option<Num<u64>>,
    pub(crate) start_timestamp: DateTime,
    pub(crate) end_timestamp: Option<DateTime>,
    pub(crate) total_checkpoints: Option<u64>,
    pub(crate) total_transactions: Option<u64>,
    pub(crate) total_gas_fees: Option<Num<u64>>,
    pub(crate) total_stake_rewards: Option<Num<u64>>,
    pub(crate) system_state_version: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ProtocolConfigs")]
pub(crate) struct ProtocolVersionNode {
    pub(crate) protocol_version: u64,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ProtocolConfigVariables {
    pub(crate) version: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "ProtocolConfigVariables"
)]
pub struct ProtocolConfigQuery {
    #[arguments(protocolVersion: $version)]
    pub(crate) protocol_config: ProtocolConfigsNode,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ProtocolConfigs")]
pub(crate) struct ProtocolConfigsNode {
    pub(crate) protocol_version: u64,
    pub(crate) feature_flags: Vec<FeatureFlagNode>,
    pub(crate) configs: Vec<AttributeNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ProtocolConfigFeatureFlag")]
pub(crate) struct FeatureFlagNode {
    pub(crate) key: String,
    pub(crate) value: bool,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ProtocolConfigAttr")]
pub(crate) struct AttributeNode {
    pub(crate) key: String,
    pub(crate) value: Option<String>,
}
