// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A [`GasSponsor`] implementation for the IOTA gas station.

use std::{str::FromStr, sync::OnceLock, time::Duration};

use base64ct::Encoding;
use iota_types::{
    Address, ObjectDigest, ObjectId, ObjectReference, Transaction, TransactionDigest,
    UserSignature, Version,
};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};

use crate::builder::gas_sponsor::{GasSponsor, SponsoredGas};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
enum VersionParsingErrorKind {
    #[error("failed to parse {} version into a number", idx_to_segment_name(*segment_idx))]
    InvalidVersionSegment {
        segment_idx: usize,
        source: std::num::ParseIntError,
    },
    #[error(
        "invalid amount of version segments. A valid SemVer has exactly three: \"<major>.<minor>.<patch>\""
    )]
    InvalidNumberOfSegments,
    #[error("an empty string cannot be a valid SemVer")]
    Empty,
}

/// Parsing a [GasStationVersion] out of a string failed.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse a valid SemVer out of `{input}`")]
pub struct VersionParsingError {
    /// The input string.
    input: String,
    #[source]
    kind: VersionParsingErrorKind,
}

fn idx_to_segment_name(idx: usize) -> &'static str {
    assert!(idx < 3);

    ["major", "minor", "patch"][idx]
}

/// Errors returned by the [`GasStation`] sponsor.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GasStationError {
    /// A request path could not be joined onto the configured base URL.
    #[error(transparent)]
    InvalidUrl(<Url as FromStr>::Err),
    /// A request to the gas station could not be completed.
    #[error("request to gas station `{gas_station_url}` failed: {source}")]
    Request {
        /// The underlying transport error.
        source: reqwest::Error,
        /// The URL that was requested.
        gas_station_url: Url,
    },
    /// The gas station answered with something unusable.
    #[
        error("invalid gas station response from {gas_station_url}{}",
        .message.as_deref().map(|msg| format!(": {msg}")).unwrap_or_default())
    ]
    Response {
        /// The error the gas station reported, when it reported one.
        message: Option<String>,
        /// The URL that was requested.
        gas_station_url: Url,
    },
    /// The gas station is too old for this client.
    #[error(
        "invalid gas-station version: got version `{version}`, but at least version `{min_required_version}` is required"
    )]
    UnsupportedVersion {
        /// The minimum IOTA gas-station version needed for this operation.
        min_required_version: GasStationVersion,
        /// The actual IOTA gas-station's version.
        version: GasStationVersion,
    },
    /// The version the gas station reported could not be parsed.
    #[error(transparent)]
    VersionParsing(VersionParsingError),
    /// The transaction could not be serialized for the gas station.
    #[error("BCS serialization error: {0}")]
    Bcs(bcs::Error),
}

/// The IOTA gas station, sponsoring transactions over its HTTP API.
///
/// A station is configured once and reused for any number of transactions;
/// build one with [`GasStation::builder`].
///
/// # Example
///
/// ```no_run
/// # use std::time::Duration;
/// use iota_sdk_transaction_builder::GasStation;
/// use reqwest::header::{AUTHORIZATION, HeaderValue};
///
/// # fn main() -> eyre::Result<()> {
/// let station = GasStation::builder("http://0.0.0.0:9527".parse()?)
///     .header(AUTHORIZATION, HeaderValue::from_static("Bearer token"))
///     .reservation_duration(Duration::from_secs(60))
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct GasStation {
    url: Url,
    http_client: reqwest::Client,
    headers: HeaderMap<HeaderValue>,
    reservation_duration: Duration,
    /// The version check result, kept so the station is probed once rather
    /// than once per reservation. Racing callers may both probe, which is
    /// harmless.
    checked_version: OnceLock<GasStationVersion>,
}

impl GasStation {
    /// Start configuring a gas station reachable at `url`.
    pub fn builder(url: Url) -> GasStationBuilder {
        GasStationBuilder {
            url,
            http_client: None,
            headers: HeaderMap::default(),
            reservation_duration: DEFAULT_RESERVATION_DURATION,
        }
    }

    /// A gas station at `url` with no headers and a default HTTP client.
    pub fn new(url: Url) -> Self {
        Self::builder(url).build()
    }

    /// The URL this station is reached at.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The HTTP client this station sends its requests with.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

/// Duration of the gas allocation when the caller sets none.
const DEFAULT_RESERVATION_DURATION: Duration = Duration::from_secs(60);

/// Configures a [`GasStation`].
#[derive(Clone, Debug)]
pub struct GasStationBuilder {
    url: Url,
    http_client: Option<reqwest::Client>,
    headers: HeaderMap<HeaderValue>,
    reservation_duration: Duration,
}

impl GasStationBuilder {
    /// Send requests with this HTTP client instead of a default one.
    ///
    /// Set this to control timeouts, proxies, TLS roots or connection pooling;
    /// without it the station builds a [`reqwest::Client`] with reqwest's own
    /// defaults.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Add a header sent with every request to the gas station.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Add headers sent with every request to the gas station.
    pub fn headers(mut self, headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>) -> Self {
        for (name, value) in headers {
            self.headers.append(name, value);
        }
        self
    }

    /// How long the station should hold the gas it reserves. Defaults to 60
    /// seconds.
    pub fn reservation_duration(mut self, duration: Duration) -> Self {
        self.reservation_duration = duration;
        self
    }

    /// Build the gas station.
    pub fn build(self) -> GasStation {
        let Self {
            url,
            http_client,
            mut headers,
            reservation_duration,
        } = self;
        headers
            .entry(reqwest::header::CONTENT_TYPE)
            .or_insert_with(|| HeaderValue::from_static("application/json"));

        GasStation {
            url,
            http_client: http_client.unwrap_or_default(),
            headers,
            reservation_duration,
            checked_version: OnceLock::new(),
        }
    }
}

/// The version of an IOTA gas station.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GasStationVersion {
    version_core: [u8; 3],
    // Suffix without leading '-'.
    suffix: Option<String>,
}

impl GasStationVersion {
    const MIN: Self = Self::new(0, 3, 0);

    const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            version_core: [major, minor, patch],
            suffix: None,
        }
    }
}

impl PartialOrd for GasStationVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GasStationVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version_core.cmp(&other.version_core)
    }
}

impl std::fmt::Display for GasStationVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.version_core;
        write!(f, "{}.{}.{}", v[0], v[1], v[2])?;
        if let Some(suffix) = self.suffix.as_deref() {
            write!(f, "-{suffix}")?;
        }

        Ok(())
    }
}

impl FromStr for GasStationVersion {
    type Err = VersionParsingError;

    // Disable this lint as looping over a range allows for checking that we have at
    // least 3 segments.
    #[allow(clippy::needless_range_loop)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(VersionParsingError {
                input: String::default(),
                kind: VersionParsingErrorKind::Empty,
            });
        }

        let (version_core_str, maybe_suffix) = if let Some((version, suffix)) = s.split_once('-') {
            (version, Some(suffix))
        } else {
            (s, None)
        };

        let mut segments = version_core_str.split('.');
        let mut version_core = [0; 3];
        for i in 0..3 {
            let segment = segments.next().ok_or_else(|| VersionParsingError {
                input: s.to_owned(),
                kind: VersionParsingErrorKind::InvalidNumberOfSegments,
            })?;
            let parsed_segment = segment.parse().map_err(|parse_int_e| VersionParsingError {
                input: s.to_owned(),
                kind: VersionParsingErrorKind::InvalidVersionSegment {
                    segment_idx: i,
                    source: parse_int_e,
                },
            })?;
            version_core[i] = parsed_segment;
        }
        // Check if there would be more segments than 3.
        if segments.next().is_some() {
            return Err(VersionParsingError {
                input: s.to_owned(),
                kind: VersionParsingErrorKind::InvalidNumberOfSegments,
            });
        }

        Ok(Self {
            version_core,
            suffix: maybe_suffix.map(String::from),
        })
    }
}

#[derive(Debug, Serialize)]
struct ReserveGasRequest {
    gas_budget: u64,
    reserve_duration_secs: u64,
}

#[derive(Debug, Deserialize)]
struct ReserveGasResponse {
    result: Option<GasReservation>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GasReservation {
    pub sponsor_address: Address,
    pub reservation_id: u64,
    pub gas_coins: Vec<GasObjectRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GasObjectRef {
    /// The object id of this object.
    pub object_id: ObjectId,
    /// The version of this object.
    #[serde(deserialize_with = "deserialize_readable_u64")]
    pub version: u64,
    /// The digest of this object.
    pub digest: ObjectDigest,
}

fn deserialize_readable_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrString {
        Num(i64),
        String(String),
    }

    match NumOrString::deserialize(deserializer)? {
        NumOrString::Num(num) => num
            .try_into()
            .map_err(|e: std::num::TryFromIntError| serde::de::Error::custom(e.to_string())),
        NumOrString::String(s) => s
            .parse()
            .map_err(|e: std::num::ParseIntError| serde::de::Error::custom(e.to_string())),
    }
}

#[derive(Debug, Serialize)]
struct ExecuteTxRequest {
    reservation_id: u64,
    tx_bytes: String,
    user_sig: String,
    request_type: String,
}

#[derive(Debug, Deserialize)]
struct ExecuteTxResponse {
    effects: Option<serde_json::Value>,
    error: Option<String>,
}

impl GasStation {
    fn endpoint(&self, kind: GasStationRequestKind) -> Result<Url, GasStationError> {
        self.url
            .join(kind.as_path())
            .map_err(GasStationError::InvalidUrl)
    }

    async fn gas_station_version(&self) -> Result<GasStationVersion, GasStationError> {
        let url = self.endpoint(GasStationRequestKind::Version)?;
        let response = self
            .http_client
            .request(reqwest::Method::GET, url.clone())
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?;

        // A string in the format <PKG VERSION>-<GIT REVISION>.
        let mut version_info = String::from_utf8(
            response
                .bytes()
                .await
                .map_err(|_| GasStationError::Response {
                    message: None,
                    gas_station_url: url.clone(),
                })?
                .to_vec(),
        )
        .map_err(|_| GasStationError::Response {
            message: None,
            gas_station_url: url.clone(),
        })?;

        // We only care about the version.
        // Using `rfind` instead of `find` because the pkg's version might have a suffix
        // like "-alpha".
        let separator_idx = version_info
            .rfind('-')
            .ok_or_else(|| GasStationError::Response {
                message: None,
                gas_station_url: url,
            })?;
        version_info.truncate(separator_idx);

        let version = version_info
            .parse()
            .map_err(GasStationError::VersionParsing)?;

        Ok(version)
    }

    /// Check that the station is new enough, probing it only the first time.
    async fn check_version(&self) -> Result<(), GasStationError> {
        if self.checked_version.get().is_some() {
            return Ok(());
        }

        let version = self.gas_station_version().await?;
        if version < GasStationVersion::MIN {
            return Err(GasStationError::UnsupportedVersion {
                min_required_version: GasStationVersion::MIN,
                version,
            });
        }
        let _ = self.checked_version.set(version);

        Ok(())
    }

    async fn reserve(&self, gas_budget: u64) -> Result<GasReservation, GasStationError> {
        self.check_version().await?;

        let url = self.endpoint(GasStationRequestKind::ReserveGas)?;
        let response = self
            .http_client
            .request(reqwest::Method::POST, url.clone())
            .json(&ReserveGasRequest {
                gas_budget,
                reserve_duration_secs: self.reservation_duration.as_secs(),
            })
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?;

        let res: ReserveGasResponse =
            response
                .json()
                .await
                .map_err(|e| GasStationError::Request {
                    source: e,
                    gas_station_url: url.clone(),
                })?;

        res.result.ok_or(GasStationError::Response {
            message: res.error,
            gas_station_url: url,
        })
    }

    /// Execute a transaction against a reservation and return the gas
    /// station's own JSON effects.
    ///
    /// The station reports effects in a JSON-RPC shape that cannot be turned
    /// back into [`TransactionEffects`](iota_types::TransactionEffects); use
    /// this when that JSON is what you want, and
    /// [`execute_with_gas_sponsor`](crate::TransactionBuilder::execute_with_gas_sponsor)
    /// when you want typed effects.
    pub async fn execute_reserved_json(
        &self,
        reservation_id: u64,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<serde_json::Value, GasStationError> {
        let url = self.endpoint(GasStationRequestKind::ExecuteTx)?;

        let tx_bytes = base64ct::Base64::encode_string(
            &bcs::to_bytes(transaction).map_err(GasStationError::Bcs)?,
        );

        let response = self
            .http_client
            .request(reqwest::Method::POST, url.clone())
            .headers(self.headers.clone())
            .json(&ExecuteTxRequest {
                reservation_id,
                tx_bytes,
                user_sig: signature.to_base64(),
                request_type: "waitForLocalExecution".to_owned(),
            })
            .send()
            .await
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| GasStationError::Request {
                source: e,
                gas_station_url: url.clone(),
            })?;

        let res: ExecuteTxResponse =
            response
                .json()
                .await
                .map_err(|e| GasStationError::Request {
                    source: e,
                    gas_station_url: url.clone(),
                })?;

        res.effects.ok_or(GasStationError::Response {
            message: res.error,
            gas_station_url: url,
        })
    }
}

impl GasSponsor for GasStation {
    type Error = GasStationError;
    type Reservation = u64;

    async fn reserve_gas(
        &self,
        transaction: &Transaction,
    ) -> Result<(Self::Reservation, SponsoredGas), Self::Error> {
        let Transaction::V1(v1) = transaction else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let GasReservation {
            sponsor_address,
            reservation_id,
            gas_coins,
        } = self.reserve(v1.gas_payment.budget).await?;

        let gas = SponsoredGas {
            owner: sponsor_address,
            objects: gas_coins
                .into_iter()
                .map(|obj_ref| ObjectReference {
                    object_id: obj_ref.object_id,
                    version: Version::from_u64(obj_ref.version),
                    digest: obj_ref.digest,
                })
                .collect(),
        };

        Ok((reservation_id, gas))
    }

    async fn execute_reserved(
        &self,
        reservation: Self::Reservation,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<TransactionDigest, Self::Error> {
        let effects = self
            .execute_reserved_json(reservation, transaction, signature)
            .await?;

        TransactionDigest::deserialize(&effects["transactionDigest"]).map_err(|e| {
            GasStationError::Response {
                message: Some(e.to_string()),
                gas_station_url: self.url.clone(),
            }
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum GasStationRequestKind {
    #[non_exhaustive]
    ReserveGas,
    #[non_exhaustive]
    ExecuteTx,
    Version,
}

impl GasStationRequestKind {
    const fn as_path(&self) -> &str {
        match self {
            Self::ReserveGas => "/v1/reserve_gas",
            Self::ExecuteTx => "/v1/execute_tx",
            Self::Version => "/version",
        }
    }
}
