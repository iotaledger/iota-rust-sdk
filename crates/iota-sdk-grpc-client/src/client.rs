// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use iota_grpc_types::v1::{
    ledger_service::ledger_service_client::LedgerServiceClient,
    move_package_service::move_package_service_client::MovePackageServiceClient,
    state_service::state_service_client::StateServiceClient,
    transaction_execution_service::transaction_execution_service_client::TransactionExecutionServiceClient,
};
#[cfg(not(target_arch = "wasm32"))]
use tonic::codec::CompressionEncoding;

use crate::{api::Result, interceptors::HeadersInterceptor};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub(crate) const MAINNET_HOST: &str = "https://grpc.mainnet.iota.cafe:443";
pub(crate) const TESTNET_HOST: &str = "https://grpc.testnet.iota.cafe:443";
pub(crate) const DEVNET_HOST: &str = "https://grpc.devnet.iota.cafe:443";
pub(crate) const LOCAL_HOST: &str = "http://localhost:9000";

/// Underlying gRPC transport.
///
/// Native builds use tonic's HTTP/2 [`tonic::transport::Channel`]. On wasm32
/// the client speaks gRPC-Web over the browser `fetch` API, the only transport
/// a browser can offer; this requires the server to expose gRPC-Web.
#[cfg(not(target_arch = "wasm32"))]
pub type GrpcChannel = tonic::transport::Channel;
#[cfg(target_arch = "wasm32")]
pub type GrpcChannel = tonic_web_wasm_client::Client;

pub type InterceptedChannel =
    tonic::service::interceptor::InterceptedService<GrpcChannel, HeadersInterceptor>;

/// gRPC client factory for IOTA gRPC operations.
#[derive(Clone)]
pub struct Client {
    /// Target URI of the gRPC server
    uri: http::Uri,
    /// Shared gRPC channel for all service clients
    channel: GrpcChannel,
    /// Headers interceptor for adding custom headers to requests
    headers: HeadersInterceptor,
    /// Maximum decoding message size for responses
    max_decoding_message_size: Option<usize>,
}

impl Client {
    /// Create a new Client instance for the given gRPC server URI.
    pub fn new<T>(uri: T) -> Result<Self>
    where
        T: TryInto<http::Uri>,
        T::Error: Into<BoxError>,
    {
        let uri = uri
            .try_into()
            .map_err(Into::into)
            .map_err(tonic::Status::from_error)?;

        #[cfg(not(target_arch = "wasm32"))]
        let channel = {
            let endpoint = tonic::transport::Endpoint::from(uri.clone());

            #[cfg(all(
                feature = "tls-ring",
                any(feature = "tls-native-roots", feature = "tls-webpki-roots")
            ))]
            let endpoint = if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                endpoint
                    .tls_config(
                        tonic::transport::channel::ClientTlsConfig::new().with_enabled_roots(),
                    )
                    .map_err(Into::into)
                    .map_err(tonic::Status::from_error)?
            } else {
                endpoint
            };

            #[cfg(not(all(
                feature = "tls-ring",
                any(feature = "tls-native-roots", feature = "tls-webpki-roots")
            )))]
            if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                return Err(tonic::Status::failed_precondition(
                    "HTTPS requires the `tls-ring` feature and either `tls-native-roots` or `tls-webpki-roots` to be enabled",
                )
                .into());
            }

            endpoint
                .connect_timeout(Duration::from_secs(5))
                .http2_keep_alive_interval(Duration::from_secs(5))
                .connect_lazy()
        };

        // The browser handles TLS and connection management; gRPC-Web only needs
        // the target URL.
        #[cfg(target_arch = "wasm32")]
        let channel = tonic_web_wasm_client::Client::new(uri.to_string());

        Ok(Self {
            uri,
            channel,
            headers: Default::default(),
            max_decoding_message_size: None,
        })
    }

    /// Create a new client connected to the `mainnet` gRPC server:
    /// <https://grpc.mainnet.iota.cafe:443>.
    pub fn new_mainnet() -> Result<Self> {
        Self::new(MAINNET_HOST)
    }

    /// Create a new client connected to the `testnet` gRPC server:
    /// <https://grpc.testnet.iota.cafe:443>.
    pub fn new_testnet() -> Result<Self> {
        Self::new(TESTNET_HOST)
    }

    /// Create a new client connected to the `devnet` gRPC server:
    /// <https://grpc.devnet.iota.cafe:443>.
    pub fn new_devnet() -> Result<Self> {
        Self::new(DEVNET_HOST)
    }

    /// Create a new client connected to a `localnet` gRPC server:
    /// <http://localhost:9000>.
    pub fn new_localnet() -> Result<Self> {
        Self::new(LOCAL_HOST)
    }

    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    /// Get a reference to the underlying channel.
    ///
    /// This can be useful for creating additional service clients that aren't
    /// yet integrated into Client.
    pub fn channel(&self) -> &GrpcChannel {
        &self.channel
    }

    pub fn headers(&self) -> &HeadersInterceptor {
        &self.headers
    }

    pub fn max_decoding_message_size(&self) -> Option<usize> {
        self.max_decoding_message_size
    }

    pub fn with_headers(mut self, headers: HeadersInterceptor) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_max_decoding_message_size(mut self, limit: usize) -> Self {
        self.max_decoding_message_size = Some(limit);
        self
    }

    /// Get a ledger service client.
    pub fn ledger_service_client(&self) -> LedgerServiceClient<InterceptedChannel> {
        self.configure_client(LedgerServiceClient::with_interceptor(
            self.channel.clone(),
            self.headers.clone(),
        ))
    }

    /// Get a transaction execution service client.
    pub fn execution_service_client(
        &self,
    ) -> TransactionExecutionServiceClient<InterceptedChannel> {
        self.configure_client(TransactionExecutionServiceClient::with_interceptor(
            self.channel.clone(),
            self.headers.clone(),
        ))
    }

    /// Get a state service client.
    pub fn state_service_client(&self) -> StateServiceClient<InterceptedChannel> {
        self.configure_client(StateServiceClient::with_interceptor(
            self.channel.clone(),
            self.headers.clone(),
        ))
    }

    /// Get a move package service client.
    pub fn move_package_service_client(&self) -> MovePackageServiceClient<InterceptedChannel> {
        self.configure_client(MovePackageServiceClient::with_interceptor(
            self.channel.clone(),
            self.headers.clone(),
        ))
    }

    /// Apply common client configuration (compression, message size limits).
    fn configure_client<C: GrpcClientConfig>(&self, client: C) -> C {
        // zstd pulls a C dependency that does not build for wasm32, and gRPC-Web
        // responses are not compressed, so only negotiate compression natively.
        #[cfg(not(target_arch = "wasm32"))]
        let client = client.accept_compressed(CompressionEncoding::Zstd);
        if let Some(limit) = self.max_decoding_message_size {
            client.max_decoding_message_size(limit)
        } else {
            client
        }
    }
}

/// Trait for common gRPC client configuration methods.
///
/// This trait abstracts over the common configuration methods shared by
/// tonic-generated service clients, allowing `configure_client` to work
/// generically.
trait GrpcClientConfig: Sized {
    #[cfg(not(target_arch = "wasm32"))]
    fn accept_compressed(self, encoding: CompressionEncoding) -> Self;
    fn max_decoding_message_size(self, limit: usize) -> Self;
}

/// Implement `GrpcClientConfig` for tonic-generated service clients.
macro_rules! impl_grpc_client_config {
    ($($client:ty),* $(,)?) => {
        $(
            impl GrpcClientConfig for $client {
                #[cfg(not(target_arch = "wasm32"))]
                fn accept_compressed(self, encoding: CompressionEncoding) -> Self {
                    self.accept_compressed(encoding)
                }
                fn max_decoding_message_size(self, limit: usize) -> Self {
                    self.max_decoding_message_size(limit)
                }
            }
        )*
    };
}

impl_grpc_client_config!(
    LedgerServiceClient<InterceptedChannel>,
    TransactionExecutionServiceClient<InterceptedChannel>,
    StateServiceClient<InterceptedChannel>,
    MovePackageServiceClient<InterceptedChannel>,
);

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "tls-ring"))]
    #[test]
    fn https_without_tls_ring_returns_failed_precondition() {
        use super::Client;

        let status = match Client::new("https://example.com") {
            Err(crate::api::Error::Grpc(status)) => status,
            Err(other) => panic!("expected Error::Grpc, got: {other:?}"),
            Ok(_) => panic!("new should fail without tls-ring"),
        };

        assert_eq!(
            status.code(),
            tonic::Code::FailedPrecondition,
            "status: {status:?}"
        );
        assert!(
            status.message().contains("tls-ring"),
            "error should mention `tls-ring` feature, got: {}",
            status.message()
        );
    }
}
