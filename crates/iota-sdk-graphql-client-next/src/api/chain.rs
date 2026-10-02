// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cynic::{Operation, QueryBuilder};

use crate::{GraphQLClient, Query, Request, Result, ServerVersion, wire::schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query")]
pub struct ChainIdentifierQuery {
    pub(crate) chain_identifier: String,
}

/// Query for [`GraphQLClient::chain_id`].
#[derive(Clone, Debug)]
pub struct GetChainId(());

impl Query for GetChainId {
    type Output = String;
    type Data = ChainIdentifierQuery;
    type Variables = ();

    fn operation(&self, _: Option<&ServerVersion>) -> Result<Operation<ChainIdentifierQuery>> {
        Ok(ChainIdentifierQuery::build(()))
    }

    fn decode(self, data: ChainIdentifierQuery) -> Result<String> {
        Ok(data.chain_identifier)
    }
}

impl GraphQLClient {
    /// The network's chain identifier: the first four bytes of its genesis
    /// checkpoint digest, in hex.
    pub fn chain_id(&self) -> Request<GetChainId> {
        Request::new(self, GetChainId(()))
    }
}
