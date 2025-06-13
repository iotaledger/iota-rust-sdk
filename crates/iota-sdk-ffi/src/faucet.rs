// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::faucet::{BatchSendStatus, FaucetReceipt};
use iota_types::Address;

use crate::error::{BindingsSdkError, Result};

#[derive(uniffi::Object)]
pub struct FaucetClient(iota_graphql_client::faucet::FaucetClient);

#[uniffi::export(async_runtime = "tokio")]
impl FaucetClient {
    /// Construct a new `FaucetClient` with the given faucet service URL. This
    /// [`FaucetClient`] expects that the service provides two endpoints:
    /// /v1/gas and /v1/status. As such, do not provide the request
    /// endpoint, just the top level service endpoint.
    ///
    /// - /v1/gas is used to request gas
    /// - /v1/status/taks-uuid is used to check the status of the request
    #[uniffi::constructor]
    pub fn new(faucet_url: String) -> Self {
        Self(iota_graphql_client::faucet::FaucetClient::new(&faucet_url))
    }

    /// Set to local faucet.
    #[uniffi::constructor]
    pub fn local() -> Self {
        Self(iota_graphql_client::faucet::FaucetClient::local())
    }

    /// Set to devnet faucet.
    #[uniffi::constructor]
    pub fn devnet() -> Self {
        Self(iota_graphql_client::faucet::FaucetClient::devnet())
    }

    /// Set to testnet faucet.
    #[uniffi::constructor]
    pub fn testnet() -> Self {
        Self(iota_graphql_client::faucet::FaucetClient::testnet())
    }

    /// Request gas from the faucet. Note that this will return the UUID of the
    /// request and not wait until the token is received. Use
    /// `request_and_wait` to wait for the token.
    pub async fn request(&self, address: Address) -> Result<Option<String>> {
        Ok(self
            .0
            .request(address)
            .await
            .map_err(BindingsSdkError::custom)?)
    }

    /// Request gas from the faucet and wait until the request is completed and
    /// token is transferred. Returns `FaucetReceipt` if the request is
    /// successful, which contains the list of tokens transferred, and the
    /// transaction digest.
    ///
    /// Note that the faucet is heavily rate-limited, so calling repeatedly the
    /// faucet would likely result in a 429 code or 502 code.
    pub async fn request_and_wait(&self, address: Address) -> Result<Option<FaucetReceipt>> {
        Ok(self
            .0
            .request_and_wait(address)
            .await
            .map_err(BindingsSdkError::custom)?)
    }

    /// Check the faucet request status.
    ///
    /// Possible statuses are defined in: [`BatchSendStatusType`]
    pub async fn request_status(&self, id: String) -> Result<Option<BatchSendStatus>> {
        Ok(self
            .0
            .request_status(id)
            .await
            .map_err(BindingsSdkError::custom)?)
    }
}
