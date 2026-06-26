// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use iota_types::{Address, ObjectId, TransactionDigest};
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

#[derive(Debug, thiserror::Error)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchStatusFaucetResponse {
    pub status: Option<BatchSendStatus>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum BatchSendStatusType {
    InProgress,
    Succeeded,
    Discarded,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchSendStatus {
    pub status: BatchSendStatusType,
    pub transferred_gas_objects: Option<FaucetReceipt>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FaucetReceipt {
    pub sent: Vec<CoinInfo>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoinInfo {
    pub amount: u64,
    pub id: ObjectId,
    pub transfer_tx_digest: TransactionDigest,
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
            let status_response = crate::wait::timeout(FAUCET_REQUEST_TIMEOUT, async {
                loop {
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
                            // Still pending — fall through to the poll interval and retry.
                            BatchSendStatusType::InProgress => {}
                        }
                    }

                    crate::wait::sleep(FAUCET_POLL_INTERVAL).await;
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
    /// Possible statuses are defined in: [`BatchSendStatusType`]
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
