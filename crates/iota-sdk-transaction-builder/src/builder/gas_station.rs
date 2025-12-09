// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, time::Duration};

use base64ct::Encoding;
use iota_crypto::{IotaSigner, simple::SimpleKeypair};
use iota_types::{Address, Digest, ObjectId, ObjectReference, Transaction, Version};
use reqwest::{
    Url,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

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

/// Parsing a [Version] out of a string failed.
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

/// Data to configure gas station sponsorship.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct GasStationData {
    /// The gas station URL.
    url: Url,
    /// Duration of the gas allocation. Default value: `60` seconds.
    gas_reservation_duration: Duration,
    /// Headers to be included in all requests to the gas station.
    headers: HeaderMap<HeaderValue>,
}

impl GasStationData {
    pub fn new(url: Url) -> Self {
        Self {
            url,
            gas_reservation_duration: Duration::from_secs(60),
            headers: Default::default(),
        }
    }

    pub fn set_gas_reservation_duration(&mut self, duration: Duration) {
        self.gas_reservation_duration = duration;
    }

    pub fn add_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers.append(name, value);
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
    pub version: Version,
    /// The digest of this object.
    pub digest: Digest,
}

fn deserialize_readable_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Version, D::Error> {
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

impl GasStationData {
    async fn gas_station_version(
        &self,
        client: &reqwest::Client,
    ) -> Result<GasStationVersion, Error> {
        let url = self
            .url
            .join(GasStationRequestKind::Version.as_path())
            .map_err(Error::InvalidUrl)?;
        let response = client
            .request(reqwest::Method::GET, url.clone())
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?;

        // A string in the format <PKG VERSION>-<GIT REVISION>.
        let mut version_info = String::from_utf8(
            response
                .bytes()
                .await
                .map_err(|_| Error::GasStationResponse {
                    message: None,
                    gas_station_url: url.clone(),
                })?
                .to_vec(),
        )
        .map_err(|_| Error::GasStationResponse {
            message: None,
            gas_station_url: url.clone(),
        })?;

        // We only care about the version.
        // Using `rfind` instead of `find` because the pkg's version might have a suffix
        // like "-alpha".
        let separator_idx = version_info
            .rfind('-')
            .ok_or_else(|| Error::GasStationResponse {
                message: None,
                gas_station_url: url,
            })?;
        version_info.truncate(separator_idx);

        let version = version_info.parse().map_err(Error::VersionParsing)?;

        Ok(version)
    }

    async fn reserve_gas(
        &mut self,
        gas_budget: u64,
        client: &reqwest::Client,
    ) -> Result<GasReservation, Error> {
        self.headers
            .entry(reqwest::header::CONTENT_TYPE)
            .or_insert_with(|| HeaderValue::from_static("application/json"));

        let version = self.gas_station_version(client).await?;
        if version < GasStationVersion::MIN {
            return Err(Error::InvalidGasStationVersion {
                min_required_version: GasStationVersion::MIN,
                version,
            });
        }

        let url = self
            .url
            .join(GasStationRequestKind::ReserveGas.as_path())
            .map_err(Error::InvalidUrl)?;

        let response = client
            .request(reqwest::Method::POST, url.clone())
            .json(&ReserveGasRequest {
                gas_budget,
                reserve_duration_secs: self.gas_reservation_duration.as_secs(),
            })
            .headers(self.headers.clone())
            .send()
            .await
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?;

        let res: ReserveGasResponse =
            response
                .json()
                .await
                .map_err(|e| Error::GasStationRequest {
                    source: e,
                    gas_station_url: url.clone(),
                })?;

        let Some(gas_reservation) = res.result else {
            return Err(Error::GasStationResponse {
                message: res.error,
                gas_station_url: url.clone(),
            });
        };

        Ok(gas_reservation)
    }

    pub(crate) async fn execute_txn(
        self,
        txn: &mut Transaction,
        keypair: &SimpleKeypair,
    ) -> Result<Digest, Error> {
        let url = self
            .url
            .join(GasStationRequestKind::ExecuteTx.as_path())
            .map_err(Error::InvalidUrl)?;
        let effects = self.execute_txn_inner(&url, txn, keypair).await?;

        Digest::deserialize(&effects["transactionDigest"]).map_err(|e| Error::GasStationResponse {
            message: Some(e.to_string()),
            gas_station_url: url,
        })
    }

    pub(crate) async fn execute_txn_json(
        self,
        txn: &mut Transaction,
        keypair: &SimpleKeypair,
    ) -> Result<serde_json::Value, Error> {
        let url = self
            .url
            .join(GasStationRequestKind::ExecuteTx.as_path())
            .map_err(Error::InvalidUrl)?;
        self.execute_txn_inner(&url, txn, keypair).await
    }

    async fn execute_txn_inner(
        mut self,
        url: &Url,
        txn: &mut Transaction,
        keypair: &SimpleKeypair,
    ) -> Result<serde_json::Value, Error> {
        let client = reqwest::Client::new();
        let reservation_id = match txn {
            Transaction::V1(ref mut inner_txn) => {
                let reservation = self
                    .reserve_gas(inner_txn.gas_payment.budget, &client)
                    .await?;
                let GasReservation {
                    sponsor_address,
                    reservation_id,
                    gas_coins,
                } = reservation;
                inner_txn.gas_payment.owner = sponsor_address;
                let objects: Vec<_> = gas_coins
                    .into_iter()
                    .map(|obj_ref| ObjectReference {
                        object_id: obj_ref.object_id,
                        version: obj_ref.version as _,
                        digest: obj_ref.digest,
                    })
                    .collect();
                inner_txn.gas_payment.objects = objects;
                reservation_id
            }
        };

        let tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&txn).map_err(Error::Bcs)?);

        let user_sig = keypair
            .sign_transaction(txn)
            .map_err(Error::Signature)?
            .to_base64();

        let response = client
            .request(reqwest::Method::POST, url.clone())
            .headers(self.headers)
            .json(&ExecuteTxRequest {
                reservation_id,
                tx_bytes,
                user_sig,
                request_type: "waitForLocalExecution".to_owned(),
            })
            .send()
            .await
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?
            .error_for_status()
            .map_err(|e| Error::GasStationRequest {
                source: e,
                gas_station_url: url.clone(),
            })?;

        let res: ExecuteTxResponse =
            response
                .json()
                .await
                .map_err(|e| Error::GasStationRequest {
                    source: e,
                    gas_station_url: url.clone(),
                })?;

        let Some(effects) = res.effects else {
            return Err(Error::GasStationResponse {
                message: res.error,
                gas_station_url: url.clone(),
            });
        };

        Ok(effects)
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
