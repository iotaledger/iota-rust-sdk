// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for health check queries.

use iota_grpc_types::v1::ledger_service::{
    GetHealthRequest, GetHealthResponse, ledger_service_client::LedgerServiceClient,
};

use crate::{
    GrpcClient, InterceptedChannel,
    api::{GrpcResult, MetadataEnvelope, define_query},
};

define_query! {
    /// Request for [`GrpcClient::health`]. Await it to send the request.
    pub struct GetHealthQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        threshold_ms: Option<u64>,
    }
    output: GrpcResult<MetadataEnvelope<GetHealthResponse>>;
}

impl GetHealthQuery {
    /// Consider the node healthy only if the latest executed checkpoint
    /// timestamp is within `threshold_ms` milliseconds of the current system
    /// time. If `None`, the server applies its default threshold (5 seconds).
    pub fn threshold_ms(mut self, threshold_ms: impl Into<Option<u64>>) -> Self {
        self.threshold_ms = threshold_ms.into();
        self
    }

    async fn send(mut self) -> GrpcResult<MetadataEnvelope<GetHealthResponse>> {
        let mut request = GetHealthRequest::default();
        if let Some(ms) = self.threshold_ms {
            request = request.with_threshold_ms(ms);
        }

        let response = self.service_client.get_health(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}

impl GrpcClient {
    /// Check the health of the node.
    ///
    /// Returns a [`MetadataEnvelope`]`<`[`GetHealthResponse`]`>` with the
    /// latest checkpoint sequence number and an estimated validator latency
    /// field (reserved for future use).
    ///
    /// If the node's latest checkpoint is stale (beyond the threshold), the
    /// server returns an `UNAVAILABLE` error. Set the threshold with
    /// [`threshold_ms`](GetHealthQuery::threshold_ms).
    pub fn health(&self) -> GetHealthQuery {
        GetHealthQuery {
            service_client: self.ledger_service_client(),
            threshold_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::GrpcClient;

    #[tokio::test]
    async fn threshold_ms_defaults_to_the_server_threshold() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.health();
        assert_eq!(query.threshold_ms, None);

        let query = query.threshold_ms(2_000);
        assert_eq!(query.threshold_ms, Some(2_000));
    }
}
