// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, time::Duration};

use iota_types::{Address, ObjectId, TransactionDigest};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info};

use crate::WaitForTransaction;

pub const FAUCET_LOCAL_HOST: &str = "http://localhost:9123";

const FAUCET_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const FAUCET_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FaucetError {
    #[error("Cannot fetch request status due to a bad gateway.")]
    BadGateway,
    #[error("Faucet request {0} was discarded")]
    Discarded(String),
    #[error("Invalid faucet request id `{0}`: expected a UUID")]
    InvalidRequestId(String),
    #[error("Invalid faucet URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Faucet request was unsuccessful: {0}")]
    Request(String),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Faucet request was unsuccessful with status code {0}")]
    StatusCode(StatusCode),
    #[error("Faucet request timed out")]
    TimedOut,
    #[deprecated(note = "no longer returned; an `https` request without TLS fails with `Reqwest`")]
    #[error(
        "Faucet URL scheme `{0}` needs TLS: enable the `tls-ring` or `tls-aws-lc` feature, or pass \
         your own client to `new_with_reqwest_client`"
    )]
    TlsUnavailable(String),
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
    ///
    /// The HTTP client is built for you, trusting the platform store plus the
    /// bundled Mozilla roots. Use [`Self::new_with_reqwest_client`] to supply
    /// your own.
    pub fn new(faucet_url: &str) -> Result<Self, FaucetError> {
        Self::new_with_reqwest_client(
            faucet_url,
            crate::tls::default_http_client_builder().build()?,
        )
    }

    /// Construct a new `FaucetClient` that issues its requests through the
    /// supplied [`reqwest::Client`].
    ///
    /// This is the way to choose your own trust anchors or TLS backend.
    ///
    /// Note that on a build with `tls-ring` or `tls-aws-lc`, `reqwest` has no
    /// crypto provider to fall back on, so building a `reqwest::Client` panics
    /// unless one has been installed for the process. See the crate README.
    pub fn new_with_reqwest_client(
        faucet_url: &str,
        client: reqwest::Client,
    ) -> Result<Self, FaucetError> {
        let mut faucet_url = Url::parse(faucet_url)?;
        if !faucet_url.path().ends_with('/') {
            let path = format!("{}/", faucet_url.path());
            faucet_url.set_path(&path);
        }
        Ok(FaucetClient {
            faucet_url,
            inner: client,
        })
    }

    /// Create a new Faucet client connected to a `localnet` faucet.
    pub fn new_localnet() -> Self {
        Self::new(FAUCET_LOCAL_HOST).expect("cannot build localnet faucet client")
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
        let url = self.faucet_url.join("v1/gas")?;
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
    /// transaction digest. Returns [`FaucetError::Discarded`] if the faucet
    /// discards the request.
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
                                error!("Faucet request {request_id} was discarded");
                                break Err(FaucetError::Discarded(request_id.clone()));
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
    /// list of tokens transferred, and the transaction digest. Returns
    /// [`FaucetError::Discarded`] if the faucet discards the request.
    ///
    /// This is a convenience method that combines `request_and_wait` and
    /// waiting for the funding transactions to be finalized using the provided
    /// GraphQL `GraphQLClient`.
    pub async fn request_and_wait_for_finalized(
        &self,
        address: Address,
        client: &crate::GraphQLClient,
    ) -> Result<Option<FaucetReceipt>, crate::error::GraphQLError> {
        let Some(receipt) = self.request_and_wait(address).await? else {
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
                .wait_for_transaction(digest, WaitForTransaction::Finalized)
                .await?;
        }

        Ok(Some(receipt))
    }

    /// Check the faucet request status.
    ///
    /// Possible statuses are defined in: [`BatchSendStatusType`]
    ///
    /// Returns [`FaucetError::InvalidRequestId`] without sending a request if
    /// `id` is empty or contains anything other than ASCII letters, digits,
    /// `-`, `{`, `}` and `:`, which covers the UUID forms the faucet accepts.
    /// A reply that carries the faucet's error message and no status returns
    /// [`FaucetError::Request`] with that message, and any other unsuccessful
    /// HTTP status returns an error.
    pub async fn request_status(&self, id: String) -> Result<Option<BatchSendStatus>, FaucetError> {
        let status_url = self.status_url(&id)?;
        info!("Checking status of faucet request: {status_url}");
        let response = self.inner.get(status_url).send().await?;

        let status_code = response.status();
        match status_code {
            StatusCode::TOO_MANY_REQUESTS => return Err(FaucetError::TooManyRequests),
            StatusCode::BAD_GATEWAY => return Err(FaucetError::BadGateway),
            StatusCode::SERVICE_UNAVAILABLE => return Err(FaucetError::Unavailable),
            _ => {}
        }

        if !status_code.is_success() {
            let error = response
                .json::<BatchStatusFaucetResponse>()
                .await
                .ok()
                .and_then(|json| json.error);
            error!("Faucet status request was unsuccessful: {status_code}");
            return Err(error.map_or(FaucetError::StatusCode(status_code), FaucetError::Request));
        }

        let json = response.json::<BatchStatusFaucetResponse>().await?;
        match json {
            BatchStatusFaucetResponse {
                status: None,
                error: Some(error),
            } => {
                error!("Faucet status request was unsuccessful: {error}");
                Err(FaucetError::Request(error))
            }
            json => Ok(json.status),
        }
    }

    fn status_url(&self, id: &str) -> Result<Url, FaucetError> {
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'{' | b'}' | b':'))
        {
            return Err(FaucetError::InvalidRequestId(id.to_owned()));
        }
        Ok(self.faucet_url.join(&format!("v1/status/{id}"))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gas_url(base: &str) -> String {
        FaucetClient::new(base)
            .unwrap()
            .faucet_url
            .join("v1/gas")
            .unwrap()
            .to_string()
    }

    #[test]
    fn endpoints_keep_the_base_path() {
        assert_eq!(gas_url("http://host:9123"), "http://host:9123/v1/gas");
        assert_eq!(gas_url("http://host:9123/"), "http://host:9123/v1/gas");
        assert_eq!(gas_url("https://host/faucet"), "https://host/faucet/v1/gas");
        assert_eq!(
            gas_url("https://host/faucet/"),
            "https://host/faucet/v1/gas"
        );
    }

    /// Answer one `request_status` call with `status_line` and `body`.
    #[cfg(not(target_arch = "wasm32"))]
    async fn status_reply(
        status_line: &str,
        body: &str,
    ) -> Result<Option<BatchSendStatus>, FaucetError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client =
            FaucetClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut chunk = [0; 4096];
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "connection closed before the request headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        };
        let (_, result) = tokio::join!(
            server,
            client.request_status("11111111-2222-3333-4444-555555555555".to_owned())
        );
        result
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn request_status_reports_the_faucet_error() {
        let body = r#"{"status":null,"error":"task not found"}"#;
        for status_line in ["500 Internal Server Error", "201 Created"] {
            assert!(
                matches!(
                    status_reply(status_line, body).await,
                    Err(FaucetError::Request(error)) if error == "task not found"
                ),
                "{status_line}"
            );
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn request_status_rejects_an_unsuccessful_status() {
        assert!(matches!(
            status_reply("404 Not Found", "not json").await,
            Err(FaucetError::StatusCode(StatusCode::NOT_FOUND))
        ));
        assert!(matches!(
            status_reply("503 Service Unavailable", "").await,
            Err(FaucetError::Unavailable)
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn request_status_returns_the_status() {
        let status = status_reply("201 Created", r#"{"status":{"status":"INPROGRESS"}}"#)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.status, BatchSendStatusType::InProgress);
    }

    #[test]
    fn status_url_takes_the_id_as_one_segment() {
        let client = FaucetClient::new("https://host/faucet").unwrap();
        assert_eq!(
            client
                .status_url("11111111-2222-3333-4444-555555555555")
                .unwrap()
                .as_str(),
            "https://host/faucet/v1/status/11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            client
                .status_url("{11111111-2222-3333-4444-555555555555}")
                .unwrap()
                .as_str(),
            "https://host/faucet/v1/status/%7B11111111-2222-3333-4444-555555555555%7D"
        );
        assert_eq!(
            client
                .status_url("urn:uuid:11111111-2222-3333-4444-555555555555")
                .unwrap()
                .as_str(),
            "https://host/faucet/v1/status/urn:uuid:11111111-2222-3333-4444-555555555555"
        );
        for id in [
            "",
            ".",
            "..",
            "../../graphql",
            "x?y=1",
            "x#frag",
            "a\nb",
            "a/b",
            "a%2Fb",
        ] {
            assert!(
                matches!(client.status_url(id), Err(FaucetError::InvalidRequestId(_))),
                "{id:?} was accepted"
            );
        }
    }
}
