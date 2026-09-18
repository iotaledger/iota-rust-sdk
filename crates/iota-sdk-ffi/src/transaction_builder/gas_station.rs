// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::error::{Result, SdkFfiError};

/// The IOTA gas station, sponsoring transactions over its HTTP API.
///
/// Build one and pass it to a transaction builder's `execute_with_gas_sponsor`.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct GasStation(pub(crate) iota_sdk::transaction_builder::GasStation);

#[uniffi::export]
impl GasStation {
    /// Create a gas station reachable at `url`.
    ///
    /// `reservation_duration` is how long the station holds the gas it
    /// reserves, defaulting to 60 seconds. `headers` are sent with every
    /// request, typically to carry an authorization token.
    #[uniffi::constructor(default(reservation_duration = None, headers = None))]
    pub fn new(
        url: String,
        reservation_duration: Option<Duration>,
        headers: Option<HashMap<String, Vec<String>>>,
    ) -> Result<Arc<Self>> {
        let mut builder = iota_sdk::transaction_builder::GasStation::builder(
            url.parse().map_err(SdkFfiError::new)?,
        );

        if let Some(duration) = reservation_duration {
            builder = builder.reservation_duration(duration);
        }
        for (name, values) in headers.into_iter().flatten() {
            let name: iota_sdk::transaction_builder::HeaderName =
                name.parse().map_err(SdkFfiError::new)?;
            for value in values {
                builder = builder.header(name.clone(), value.parse().map_err(SdkFfiError::new)?);
            }
        }

        Ok(Arc::new(Self(builder.build())))
    }

    /// The URL this station is reached at.
    pub fn url(&self) -> String {
        self.0.url().to_string()
    }
}
