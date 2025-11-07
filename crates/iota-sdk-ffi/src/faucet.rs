// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::{Result, SdkFfiError},
    types::{address::Address, digest::Digest, object::ObjectId},
};

#[derive(uniffi::Object)]
pub struct FaucetClient(iota_sdk::graphql_client::faucet::FaucetClient);

#[uniffi::export(async_runtime = "tokio")]
impl FaucetClient {
    /// Construct a new `FaucetClient` with the given faucet service URL. This
    /// `FaucetClient` expects that the service provides two endpoints:
    /// /v1/gas and /v1/status. As such, do not provide the request
    /// endpoint, just the top level service endpoint.
    ///
    /// - /v1/gas is used to request gas
    /// - /v1/status/taks-uuid is used to check the status of the request
    #[uniffi::constructor]
    pub fn new(faucet_url: String) -> Self {
        Self(iota_sdk::graphql_client::faucet::FaucetClient::new(
            &faucet_url,
        ))
    }

    /// Create a new Faucet client connected to the `testnet` faucet.
    #[uniffi::constructor]
    pub fn new_testnet() -> Self {
        Self(iota_sdk::graphql_client::faucet::FaucetClient::new_testnet())
    }

    /// Create a new Faucet client connected to the `devnet` faucet.
    #[uniffi::constructor]
    pub fn new_devnet() -> Self {
        Self(iota_sdk::graphql_client::faucet::FaucetClient::new_devnet())
    }

    /// Create a new Faucet client connected to a `localnet` faucet.
    #[uniffi::constructor]
    pub fn new_localnet() -> Self {
        Self(iota_sdk::graphql_client::faucet::FaucetClient::new_localnet())
    }

    /// Request gas from the faucet. Note that this will return the UUID of the
    /// request and not wait until the token is received. Use
    /// `request_and_wait` to wait for the token.
    pub async fn request(&self, address: &Address) -> Result<Option<String>> {
        self.0.request(**address).await.map_err(SdkFfiError::custom)
    }

    /// Request gas from the faucet and wait until the request is completed and
    /// token is transferred. Returns `FaucetReceipt` if the request is
    /// successful, which contains the list of tokens transferred, and the
    /// transaction digest.
    ///
    /// Note that the faucet is heavily rate-limited, so calling repeatedly the
    /// faucet would likely result in a 429 code or 502 code.
    pub async fn request_and_wait(&self, address: &Address) -> Result<Option<FaucetReceipt>> {
        Ok(self
            .0
            .request_and_wait(**address)
            .await
            .map_err(SdkFfiError::custom)?
            .map(Into::into))
    }

    /// Check the faucet request status.
    ///
    /// Possible statuses are defined in: `BatchSendStatusType`
    pub async fn request_status(&self, id: String) -> Result<Option<BatchSendStatus>> {
        Ok(self
            .0
            .request_status(id)
            .await
            .map_err(SdkFfiError::custom)?
            .map(Into::into))
    }
}

#[derive(uniffi::Enum)]
pub enum BatchSendStatusType {
    InProgress,
    Succeeded,
    Discarded,
}

impl From<iota_sdk::graphql_client::faucet::BatchSendStatusType> for BatchSendStatusType {
    fn from(value: iota_sdk::graphql_client::faucet::BatchSendStatusType) -> Self {
        match value {
            iota_sdk::graphql_client::faucet::BatchSendStatusType::InProgress => Self::InProgress,
            iota_sdk::graphql_client::faucet::BatchSendStatusType::Succeeded => Self::Succeeded,
            iota_sdk::graphql_client::faucet::BatchSendStatusType::Discarded => Self::Discarded,
        }
    }
}

impl From<BatchSendStatusType> for iota_sdk::graphql_client::faucet::BatchSendStatusType {
    fn from(value: BatchSendStatusType) -> Self {
        match value {
            BatchSendStatusType::InProgress => Self::InProgress,
            BatchSendStatusType::Succeeded => Self::Succeeded,
            BatchSendStatusType::Discarded => Self::Discarded,
        }
    }
}

#[derive(uniffi::Record)]
pub struct CoinInfo {
    pub amount: u64,
    pub id: Arc<ObjectId>,
    pub transfer_tx_digest: Arc<Digest>,
}

impl From<iota_sdk::graphql_client::faucet::CoinInfo> for CoinInfo {
    fn from(value: iota_sdk::graphql_client::faucet::CoinInfo) -> Self {
        Self {
            amount: value.amount,
            id: Arc::new(value.id.into()),
            transfer_tx_digest: Arc::new(value.transfer_tx_digest.into()),
        }
    }
}

impl From<CoinInfo> for iota_sdk::graphql_client::faucet::CoinInfo {
    fn from(value: CoinInfo) -> Self {
        Self {
            amount: value.amount,
            id: value.id.0,
            transfer_tx_digest: value.transfer_tx_digest.0,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FaucetReceipt {
    pub sent: Vec<CoinInfo>,
}

impl From<iota_sdk::graphql_client::faucet::FaucetReceipt> for FaucetReceipt {
    fn from(value: iota_sdk::graphql_client::faucet::FaucetReceipt) -> Self {
        Self {
            sent: value.sent.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<FaucetReceipt> for iota_sdk::graphql_client::faucet::FaucetReceipt {
    fn from(value: FaucetReceipt) -> Self {
        Self {
            sent: value.sent.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct BatchSendStatus {
    pub status: BatchSendStatusType,
    pub transferred_gas_objects: Option<FaucetReceipt>,
}

impl From<iota_sdk::graphql_client::faucet::BatchSendStatus> for BatchSendStatus {
    fn from(value: iota_sdk::graphql_client::faucet::BatchSendStatus) -> Self {
        Self {
            status: value.status.into(),
            transferred_gas_objects: value.transferred_gas_objects.map(Into::into),
        }
    }
}

impl From<BatchSendStatus> for iota_sdk::graphql_client::faucet::BatchSendStatus {
    fn from(value: BatchSendStatus) -> Self {
        Self {
            status: value.status.into(),
            transferred_gas_objects: value.transferred_gas_objects.map(Into::into),
        }
    }
}
