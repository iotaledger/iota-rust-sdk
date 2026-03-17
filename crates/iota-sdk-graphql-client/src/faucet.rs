// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use iota_types::{Address, Digest, ObjectId};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info};

use crate::WaitForTx;

pub const FAUCET_DEVNET_HOST: &str = "https://faucet.devnet.iota.cafe";
pub const FAUCET_TESTNET_HOST: &str = "https://faucet.testnet.iota.cafe";
pub const FAUCET_LOCAL_HOST: &str = "http://localhost:9123";

const FAUCET_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const FAUCET_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(thiserror::Error, Debug)]
pub enum FaucetError {
    #[error("Cannot fetch request status due to a bad gateway.")]
    BadGateway,
    #[error("Faucet request was unsuccessful: {0}")]
    Request(String),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Faucet request was unsuccessful with status code {0}")]
    StatusCode(StatusCode),
    #[error("Faucet request timed out")]
    TimedOut,
    #[error(
        "Faucet service received too many requests from this IP address. Please try again later."
    )]
    TooManyRequests,
    #[error("Faucet service is currently overloaded or unavailable. Please try again later.")]
    Unavailable,
}

pub struct FaucetClient {
    faucet_url: Url,
    inner: reqwest::Client,
}

#[derive(serde::Deserialize)]
struct FaucetResponse {
    task: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchStatusFaucetResponse {
    pub status: Option<BatchSendStatus>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum BatchSendStatusType {
    InProgress,
    Succeeded,
    Discarded,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchSendStatus {
    pub status: BatchSendStatusType,
    pub transferred_gas_objects: Option<FaucetReceipt>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FaucetReceipt {
    pub sent: Vec<CoinInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CoinInfo {
    pub amount: u64,
    pub id: ObjectId,
    pub transfer_tx_digest: Digest,
}

impl FaucetClient {
    /// Construct a new `FaucetClient` with the given faucet service URL. This
    /// [`FaucetClient`] expects that the service provides two endpoints:
    /// /v1/gas and /v1/status. As such, do not provide the request
    /// endpoint, just the top level service endpoint.
    ///
    /// - /v1/gas is used to request gas
    /// - /v1/status/task-uuid is used to check the status of the request
    pub fn new(faucet_url: &str) -> Self {
        let inner = reqwest::Client::new();
        let faucet_url = Url::parse(faucet_url).expect("Invalid faucet URL");
        FaucetClient { faucet_url, inner }
    }

    /// Create a new Faucet client connected to the `testnet` faucet.
    pub fn new_testnet() -> Self {
        Self::new(FAUCET_TESTNET_HOST)
    }

    /// Create a new Faucet client connected to the `devnet` faucet.
    pub fn new_devnet() -> Self {
        Self::new(FAUCET_DEVNET_HOST)
    }

    /// Create a new Faucet client connected to a `localnet` faucet.
    pub fn new_localnet() -> Self {
        Self::new(FAUCET_LOCAL_HOST)
    }

    /// Request gas from the faucet. Note that this will return the UUID of the
    /// request and not wait until the token is received. Use
    /// `request_and_wait` to wait for the token.
    pub async fn request(&self, address: Address) -> Result<Option<String>, FaucetError> {
        self.request_impl(address).await
    }

    /// Internal implementation of a faucet request. It returns the task Uuid as
    /// a String.
    async fn request_impl(&self, address: Address) -> Result<Option<String>, FaucetError> {
        let address = address.to_string();
        let json_body = json![{
            "FixedAmountRequest": {
                "recipient": &address
            }
        }];
        let url = format!("{}v1/gas", self.faucet_url);
        info!(
            "Requesting gas from faucet for address {} : {}",
            address, url
        );
        let resp = self
            .inner
            .post(url)
            .header("content-type", "application/json")
            .json(&json_body)
            .send()
            .await?;
        match resp.status() {
            StatusCode::ACCEPTED | StatusCode::CREATED => {
                let faucet_resp: FaucetResponse = resp.json().await?;

                if let Some(err) = faucet_resp.error {
                    error!("Faucet request was unsuccessful: {err}");
                    Err(FaucetError::Request(err))
                } else {
                    info!("Request successful: {:?}", faucet_resp.task);
                    Ok(faucet_resp.task)
                }
            }
            StatusCode::TOO_MANY_REQUESTS => {
                error!("Faucet service received too many requests from this IP address.");
                Err(FaucetError::TooManyRequests)
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                error!("Faucet service is currently overloaded or unavailable.");
                Err(FaucetError::Unavailable)
            }
            status_code => {
                error!("Faucet request was unsuccessful: {status_code}");
                Err(FaucetError::StatusCode(status_code))
            }
        }
    }

    /// Request gas from the faucet and wait until the request is completed and
    /// token is transferred. Returns `FaucetReceipt` if the request is
    /// successful, which contains the list of tokens transferred, and the
    /// transaction digest.
    ///
    /// Note that the faucet is heavily rate-limited, so calling repeatedly the
    /// faucet would likely result in a 429 code or 502 code.
    ///
    /// If you intend to use the transferred tokens with the graphql client,
    /// consider using `request_and_wait_for_finalized` instead to ensure
    /// the tokens are available in the indexer.
    pub async fn request_and_wait(
        &self,
        address: Address,
    ) -> Result<Option<FaucetReceipt>, FaucetError> {
        let request_id = self.request(address).await?;

        if let Some(request_id) = request_id {
            let status_response = tokio::time::timeout(FAUCET_REQUEST_TIMEOUT, async {
                let mut interval = tokio::time::interval(FAUCET_POLL_INTERVAL);
                loop {
                    interval.tick().await;
                    info!("Polling faucet request status: {request_id}");
                    let status_response = self.request_status(request_id.clone()).await?;

                    if let Some(status_response) = status_response {
                        match status_response.status {
                            BatchSendStatusType::Succeeded => {
                                info!("Faucet request {request_id} succeeded");
                                break Ok::<_, FaucetError>(status_response);
                            }
                            BatchSendStatusType::Discarded => {
                                break Ok(BatchSendStatus {
                                    status: BatchSendStatusType::Discarded,
                                    transferred_gas_objects: None,
                                });
                            }
                            BatchSendStatusType::InProgress => {
                                continue;
                            }
                        }
                    }
                }
            })
            .await
            .map_err(|_| {
                error!(
                    "Faucet request {request_id} timed out. Timeout set to {} seconds",
                    FAUCET_REQUEST_TIMEOUT.as_secs()
                );
                FaucetError::TimedOut
            })??;
            Ok(status_response.transferred_gas_objects)
        } else {
            Ok(None)
        }
    }

    /// Request gas from the faucet and wait until the request is completed and
    /// token is transferred and finalized on the ledger. Returns
    /// `FaucetReceipt` if the request is successful, which contains the
    /// list of tokens transferred, and the transaction digest.
    ///
    /// This is a convenience method that combines `request_and_wait` and
    /// waiting for the funding transactions to be finalized using the provided
    /// GraphQL `Client`.
    pub async fn request_and_wait_for_finalized(
        &self,
        address: Address,
        client: &crate::Client,
    ) -> Result<Option<FaucetReceipt>, crate::error::Error> {
        let Some(receipt) = self
            .request_and_wait(address)
            .await
            .map_err(|e| crate::error::Error::from_error(crate::error::Kind::Other, e))?
        else {
            return Ok(None);
        };

        // Wait for the funding transactions to be finalized
        let tx_digests = receipt
            .sent
            .iter()
            .map(|coin| coin.transfer_tx_digest)
            .collect::<HashSet<_>>();
        for digest in tx_digests {
            client
                .wait_for_tx(digest, WaitForTx::Finalized, None)
                .await?;
        }

        Ok(Some(receipt))
    }

    /// Check the faucet request status.
    ///
    /// Possible statuses are defined in [`BatchSendStatusType`].
    pub async fn request_status(&self, id: String) -> Result<Option<BatchSendStatus>, FaucetError> {
        let status_url = format!("{}v1/status/{}", self.faucet_url, id);
        info!("Checking status of faucet request: {status_url}");
        let response = self.inner.get(&status_url).send().await?;

        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(FaucetError::TooManyRequests);
        } else if response.status() == StatusCode::BAD_GATEWAY {
            return Err(FaucetError::BadGateway);
        }

        let json = response.json::<BatchStatusFaucetResponse>().await?;

        Ok(json.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constructor tests ---

    #[test]
    fn new_testnet_client() {
        let client = FaucetClient::new_testnet();
        assert_eq!(client.faucet_url.as_str(), "https://faucet.testnet.iota.cafe/");
    }

    #[test]
    fn new_devnet_client() {
        let client = FaucetClient::new_devnet();
        assert_eq!(client.faucet_url.as_str(), "https://faucet.devnet.iota.cafe/");
    }

    #[test]
    fn new_localnet_client() {
        let client = FaucetClient::new_localnet();
        assert_eq!(client.faucet_url.as_str(), "http://localhost:9123/");
    }

    #[test]
    fn new_custom_url() {
        let client = FaucetClient::new("http://my-faucet.example.com:5000");
        assert_eq!(
            client.faucet_url.as_str(),
            "http://my-faucet.example.com:5000/"
        );
    }

    #[test]
    #[should_panic(expected = "Invalid faucet URL")]
    fn new_invalid_url_panics() {
        FaucetClient::new("not a valid url !@#$");
    }

    // --- Constants tests ---

    #[test]
    fn faucet_host_constants() {
        assert_eq!(FAUCET_DEVNET_HOST, "https://faucet.devnet.iota.cafe");
        assert_eq!(FAUCET_TESTNET_HOST, "https://faucet.testnet.iota.cafe");
        assert_eq!(FAUCET_LOCAL_HOST, "http://localhost:9123");
    }

    #[test]
    fn faucet_timeout_constant() {
        assert_eq!(FAUCET_REQUEST_TIMEOUT, Duration::from_secs(120));
    }

    #[test]
    fn faucet_poll_interval_constant() {
        assert_eq!(FAUCET_POLL_INTERVAL, Duration::from_secs(2));
    }

    // --- FaucetError Display tests ---

    #[test]
    fn faucet_error_display_bad_gateway() {
        let err = FaucetError::BadGateway;
        assert_eq!(
            err.to_string(),
            "Cannot fetch request status due to a bad gateway."
        );
    }

    #[test]
    fn faucet_error_display_request() {
        let err = FaucetError::Request("out of funds".to_string());
        assert!(err.to_string().contains("out of funds"));
    }

    #[test]
    fn faucet_error_display_too_many_requests() {
        let err = FaucetError::TooManyRequests;
        assert!(err.to_string().contains("too many requests"));
    }

    #[test]
    fn faucet_error_display_unavailable() {
        let err = FaucetError::Unavailable;
        assert!(err.to_string().contains("overloaded or unavailable"));
    }

    #[test]
    fn faucet_error_display_timed_out() {
        let err = FaucetError::TimedOut;
        assert_eq!(err.to_string(), "Faucet request timed out");
    }

    #[test]
    fn faucet_error_display_status_code() {
        let err = FaucetError::StatusCode(StatusCode::INTERNAL_SERVER_ERROR);
        assert!(err.to_string().contains("500"));
    }

    // --- BatchSendStatusType tests ---

    #[test]
    fn batch_send_status_type_serde_roundtrip() {
        let status = BatchSendStatusType::Succeeded;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"SUCCEEDED\"");
        let parsed: BatchSendStatusType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, BatchSendStatusType::Succeeded);
    }

    #[test]
    fn batch_send_status_type_in_progress_serde() {
        let json = "\"INPROGRESS\"";
        let parsed: BatchSendStatusType = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, BatchSendStatusType::InProgress);
    }

    #[test]
    fn batch_send_status_type_discarded_serde() {
        let json = "\"DISCARDED\"";
        let parsed: BatchSendStatusType = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, BatchSendStatusType::Discarded);
    }

    // --- FaucetResponse deserialization tests ---

    #[test]
    fn faucet_response_with_task() {
        let json = r#"{"task": "abc-123", "error": null}"#;
        let resp: FaucetResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.task, Some("abc-123".to_string()));
        assert!(resp.error.is_none());
    }

    #[test]
    fn faucet_response_with_error() {
        let json = r#"{"task": null, "error": "rate limited"}"#;
        let resp: FaucetResponse = serde_json::from_str(json).unwrap();
        assert!(resp.task.is_none());
        assert_eq!(resp.error, Some("rate limited".to_string()));
    }

    // --- BatchStatusFaucetResponse tests ---

    #[test]
    fn batch_status_response_deserialization() {
        let json = r#"{"status": {"status": "SUCCEEDED", "transferredGasObjects": null}, "error": null}"#;
        let resp: BatchStatusFaucetResponse = serde_json::from_str(json).unwrap();
        let status = resp.status.unwrap();
        assert_eq!(status.status, BatchSendStatusType::Succeeded);
        assert!(status.transferred_gas_objects.is_none());
    }

    #[test]
    fn batch_status_response_with_error() {
        let json = r#"{"status": null, "error": "something failed"}"#;
        let resp: BatchStatusFaucetResponse = serde_json::from_str(json).unwrap();
        assert!(resp.status.is_none());
        assert_eq!(resp.error, Some("something failed".to_string()));
    }
}
