// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{PoisonError, RwLock};

use crate::error::Result;

/// The tokio runtime that backs the gRPC channels.
///
/// Creating a tonic channel spawns background tasks, which requires a running
/// tokio runtime. The uniffi constructors are synchronous and run outside of
/// the uniffi tokio runtime, so the channels are backed by this dedicated
/// runtime instead.
fn tokio_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("iota-sdk-ffi-grpc")
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    })
}

/// The gRPC client for interacting with the IOTA blockchain.
#[derive(uniffi::Object)]
pub struct GrpcClient(RwLock<iota_sdk::grpc_client::Client>);

impl GrpcClient {
    /// A handle on the current client configuration.
    pub(crate) fn client(&self) -> iota_sdk::grpc_client::Client {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn update(
        &self,
        f: impl FnOnce(iota_sdk::grpc_client::Client) -> iota_sdk::grpc_client::Client,
    ) {
        let mut client = self.0.write().unwrap_or_else(PoisonError::into_inner);
        *client = f(client.clone());
    }
}

#[uniffi::export]
impl GrpcClient {
    /// Create a new gRPC client with the provided server URI.
    #[uniffi::constructor]
    pub fn new(uri: String) -> Result<Self> {
        let _guard = tokio_runtime().enter();
        Ok(Self(RwLock::new(iota_sdk::grpc_client::Client::new(
            uri.as_str(),
        )?)))
    }

    /// Create a new gRPC client connected to the `mainnet` gRPC server.
    #[uniffi::constructor]
    pub fn new_mainnet() -> Result<Self> {
        let _guard = tokio_runtime().enter();
        Ok(Self(RwLock::new(
            iota_sdk::grpc_client::Client::new_mainnet()?,
        )))
    }

    /// Create a new gRPC client connected to the `testnet` gRPC server.
    #[uniffi::constructor]
    pub fn new_testnet() -> Result<Self> {
        let _guard = tokio_runtime().enter();
        Ok(Self(RwLock::new(
            iota_sdk::grpc_client::Client::new_testnet()?,
        )))
    }

    /// Create a new gRPC client connected to the `devnet` gRPC server.
    #[uniffi::constructor]
    pub fn new_devnet() -> Result<Self> {
        let _guard = tokio_runtime().enter();
        Ok(Self(RwLock::new(
            iota_sdk::grpc_client::Client::new_devnet()?,
        )))
    }

    /// Create a new gRPC client connected to a `localnet` gRPC server:
    /// <http://localhost:50051>.
    #[uniffi::constructor]
    pub fn new_localnet() -> Result<Self> {
        let _guard = tokio_runtime().enter();
        Ok(Self(RwLock::new(
            iota_sdk::grpc_client::Client::new_localnet()?,
        )))
    }

    /// Set a basic auth `Authorization` header that is sent with every
    /// request.
    pub fn set_basic_auth(&self, username: String, password: Option<String>) {
        self.update(|client| {
            let mut headers = client.headers().clone();
            headers.basic_auth(username, password);
            client.with_headers(headers)
        });
    }

    /// Set a bearer auth `Authorization` header that is sent with every
    /// request.
    pub fn set_bearer_auth(&self, token: String) -> Result<()> {
        let mut headers = self.client().headers().clone();
        headers.bearer_auth(token)?;
        self.update(|client| client.with_headers(headers));
        Ok(())
    }

    /// Set the maximum size in bytes that a response message can be.
    pub fn set_max_decoding_message_size(&self, limit: u64) {
        self.update(|client| {
            client.with_max_decoding_message_size(usize::try_from(limit).unwrap_or(usize::MAX))
        });
    }
}
