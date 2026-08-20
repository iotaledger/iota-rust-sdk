// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

#[derive(derive_more::Deref, derive_more::From, uniffi::Object)]
pub struct Version(iota_sdk::types::Version);

#[uniffi::export]
impl Version {
    /// Create a new Version from a u64 value
    #[uniffi::constructor]
    pub const fn from_u64(value: u64) -> Self {
        Self(iota_sdk::types::Version::from_u64(value))
    }

    /// Get the underlying u64 value of this version
    pub const fn as_u64(&self) -> u64 {
        self.0.as_u64()
    }

    /// Returns a special version used for congested shared objects:
    /// `Version::MIN_CONGESTED + suggested_gas_price`,
    /// where `suggested_gas_price` is embedded into a congested version
    /// to facilitate a gas price feedback mechanism for transactions
    /// canceled due to shared object congestion.
    #[uniffi::constructor]
    pub fn new_congested_with_suggested_gas_price(suggested_gas_price: u64) -> Result<Self> {
        Ok(Self(
            iota_sdk::types::Version::new_congested_with_suggested_gas_price(suggested_gas_price)?,
        ))
    }

    /// Check if this version is congested, i.e., the corresponding
    /// object is the reason for transaction cancelation.
    pub fn is_congested(&self) -> bool {
        self.0.is_congested()
    }

    /// Returns the `suggested_gas_price` embedded in this congested shared
    /// object version. The `suggested_gas_price` here is used for a
    /// gas price feedback mechanism for transactions canceled due to
    /// shared object congestion.
    pub fn get_congested_version_suggested_gas_price(&self) -> Result<u64> {
        Ok(self.0.get_congested_version_suggested_gas_price()?)
    }

    /// Returns a new version that is greater than all versions
    /// in `inputs`, assuming this operation will not overflow.
    #[uniffi::constructor]
    pub fn lamport_increment(inputs: Vec<Arc<Self>>) -> Result<Self> {
        Ok(Self(iota_sdk::types::Version::lamport_increment(
            inputs.into_iter().map(|v| v.0),
        )?))
    }

    /// Checks if this version is canceled, i.e., the corresponding
    /// object appears in a canceled transaction.
    pub fn is_canceled(&self) -> bool {
        self.0.is_canceled()
    }

    /// Checks if this version is valid, i.e., the corresponding
    /// object does not appear in a canceled transaction.
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }

    /// An inclusive lower limit on a valid version.
    ///
    /// A valid version means an object, which this version
    /// is assigned to, does not appear in a canceled transaction.
    #[uniffi::constructor]
    pub fn min_valid_incl() -> Self {
        Self(iota_sdk::types::Version::MIN_VALID_INCL)
    }

    /// An exclusive upper limit on a valid version: versions
    /// strictly smaller than this limit are valid versions.
    ///
    /// A valid version means an object, which this version
    /// is assigned to, does not appear in a canceled transaction.
    /// Versions larger than this value are "special" and
    /// assigned to objects that appear in canceled transactions.
    #[uniffi::constructor]
    pub fn max_valid_excl() -> Self {
        Self(iota_sdk::types::Version::MAX_VALID_EXCL)
    }

    /// Special version that is assigned to objects which are accessed
    /// immutably in a canceled transaction.
    #[uniffi::constructor]
    pub fn canceled_read() -> Self {
        Self(iota_sdk::types::Version::CANCELED_READ)
    }

    /// Special version that was assigned to congested objects which
    /// cause transaction cancelations. Note that this special version
    /// was only used prior to the introduction of a gas price feedback
    /// mechanism, but it is kept for backward compatibility.
    #[uniffi::constructor]
    pub fn congested_prior_to_gas_price_feedback() -> Self {
        Self(iota_sdk::types::Version::CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK)
    }

    #[uniffi::constructor]
    pub fn randomness_unavailable() -> Self {
        Self(iota_sdk::types::Version::RANDOMNESS_UNAVAILABLE)
    }

    /// Returns the next version, or an error if overflow occurs.
    pub fn next(&self) -> Result<Self> {
        Ok(Self(self.0.next()?))
    }

    /// Returns the previous version, or an error if underflow occurs.
    pub fn previous(&self) -> Result<Self> {
        Ok(Self(self.0.previous()?))
    }
}
