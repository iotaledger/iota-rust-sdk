// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;
use iota_types::CheckpointSummary;

use crate::{
    error,
    query_types::{Base64, PageInfo, schema},
};

// ===========================================================================
// Checkpoint Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "CheckpointArgs")]
pub struct CheckpointQuery {
    #[arguments(id: $id)]
    pub checkpoint: Option<Checkpoint>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "CheckpointArgs")]
pub struct CheckpointTotalTxQuery {
    #[arguments(id: $id)]
    pub checkpoint: Option<CheckpointTotalTx>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Checkpoint")]
pub struct CheckpointTotalTx {
    pub network_total_transactions: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "CheckpointsArgs")]
pub struct CheckpointsQuery {
    pub checkpoints: CheckpointConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "CheckpointConnection")]
pub struct CheckpointConnection {
    pub nodes: Vec<Checkpoint>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct CheckpointsArgs<'a> {
    pub first: Option<i32>,
    pub after: Option<&'a str>,
    pub last: Option<i32>,
    pub before: Option<&'a str>,
}

// ===========================================================================
// Checkpoint Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct CheckpointArgs {
    pub id: CheckpointId,
}

#[derive(cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "CheckpointId")]
pub struct CheckpointId {
    pub digest: Option<String>,
    pub sequence_number: Option<u64>,
}
// ===========================================================================
// Checkpoint Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Checkpoint")]
pub struct Checkpoint {
    /// BCS serialization of the `CheckpointSummary`, Base64-encoded.
    pub bcs: Base64,
}

impl TryInto<CheckpointSummary> for Checkpoint {
    type Error = error::Error;

    fn try_into(self) -> Result<CheckpointSummary, Self::Error> {
        let bytes = base64ct::Base64::decode_vec(&self.bcs.0)?;
        Ok(bcs::from_bytes::<CheckpointSummary>(&bytes)?)
    }
}
