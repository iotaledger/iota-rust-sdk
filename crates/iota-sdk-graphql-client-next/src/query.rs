// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::future::IntoFuture;

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    GraphQLClient, Result, ServerVersion,
    transport::{BoxFuture, MaybeSend},
};

/// A GraphQL operation and how to turn its response into a result.
///
/// Every query of this crate implements it, and so can a query written
/// elsewhere, with its own [`cynic`] fragments: [`GraphQLClient::send`] sends
/// it with the client's transport, timeout, retries and error handling.
///
/// ```rust,ignore
/// #[derive(cynic::QueryFragment, Debug)]
/// #[cynic(schema = "rpc", graphql_type = "Query")]
/// struct ReferenceGasPrice {
///     epoch: Option<Epoch>,
/// }
///
/// struct GetReferenceGasPrice;
///
/// impl Query for GetReferenceGasPrice {
///     type Output = Option<String>;
///     type Data = ReferenceGasPrice;
///     type Variables = ();
///
///     fn operation(&self, _: Option<&ServerVersion>) -> Result<cynic::Operation<ReferenceGasPrice>> {
///         Ok(ReferenceGasPrice::build(()))
///     }
///
///     fn decode(self, data: ReferenceGasPrice) -> Result<Option<String>> {
///         Ok(data.epoch.and_then(|epoch| epoch.reference_gas_price))
///     }
/// }
///
/// let price = client.send(GetReferenceGasPrice).await?;
/// ```
pub trait Query {
    /// What the query resolves to.
    type Output;
    /// The response's `data`.
    type Data: DeserializeOwned;
    /// The operation's variables.
    type Variables: Serialize;

    /// Whether [`operation`](Self::operation) needs the server's version. If
    /// so, and no response has been received yet, the client sends a request
    /// to learn it first.
    const NEEDS_SERVER_VERSION: bool = false;

    /// The operation to send, given the server's version when known.
    fn operation(
        &self,
        server_version: Option<&ServerVersion>,
    ) -> Result<cynic::Operation<Self::Data, Self::Variables>>;

    /// Turn the response's `data` into the result.
    fn decode(self, data: Self::Data) -> Result<Self::Output>;
}

/// A query bound to the client that sends it when awaited.
///
/// The client's query methods return one, and its methods set the query's
/// optional inputs:
///
/// ```rust,ignore
/// let object = client.object(object_id).version(version).await?;
/// ```
#[derive(Clone, Debug)]
#[must_use = "a request is only sent when awaited"]
pub struct Request<Q> {
    client: GraphQLClient,
    query: Q,
}

impl<Q> Request<Q> {
    pub(crate) fn new(client: &GraphQLClient, query: Q) -> Self {
        Self {
            client: client.clone(),
            query,
        }
    }

    pub(crate) fn map<P>(self, f: impl FnOnce(Q) -> P) -> Request<P> {
        Request {
            client: self.client,
            query: f(self.query),
        }
    }

    pub(crate) fn query(&self) -> &Q {
        &self.query
    }
}

impl<Q> IntoFuture for Request<Q>
where
    Q: Query + MaybeSend + 'static,
    Q::Variables: MaybeSend + Sync,
{
    type Output = Result<Q::Output>;
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.client.send(self.query).await })
    }
}
