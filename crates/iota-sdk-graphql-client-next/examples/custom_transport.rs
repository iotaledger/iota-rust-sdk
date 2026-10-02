// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A transport that logs every request the client sends, wrapped around the
//! built-in one.

use std::time::Instant;

use eyre::Result;
use iota_sdk_graphql_client_next::{
    GraphQLClient, TransportError,
    transport::{BoxFuture, HttpRequest, HttpResponse, ReqwestTransport, Transport},
};

#[derive(Debug)]
struct Logging<T> {
    inner: T,
}

impl<T: Transport> Transport for Logging<T> {
    fn post(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let operation = serde_json::from_slice::<serde_json::Value>(&request.body)
                .ok()
                .and_then(|body| body["operationName"].as_str().map(str::to_owned))
                .unwrap_or_default();
            let start = Instant::now();
            let response = self.inner.post(request).await;
            match &response {
                Ok(response) => println!(
                    "[{operation}] HTTP {} in {:?}, {} bytes",
                    response.status(),
                    start.elapsed(),
                    response.body().len()
                ),
                Err(error) => println!("[{operation}] failed after {:?}: {error}", start.elapsed()),
            }
            response
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let transport = Logging {
        inner: ReqwestTransport::new(reqwest::Client::new()),
    };
    let client = GraphQLClient::builder("https://graphql.testnet.iota.cafe")
        .transport(transport)
        .build()?;

    println!("Chain ID: {}", client.chain_id().await?);
    let events = client.events().last(5).await?;
    println!("{} events", events.len());

    Ok(())
}
