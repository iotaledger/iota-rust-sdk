// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

#[derive(uniffi::Object, derive_more::From, derive_more::Deref)]
pub struct Version(iota_sdk::types::Version);

#[uniffi::export]
impl Version {
    #[uniffi::constructor]
    pub const fn new(value: u64) -> Self {
        Self(iota_sdk::types::Version(value))
    }

    /// Get the underlying u64 value of this version
    pub const fn value(&self) -> u64 {
        self.0.0
    }

    /// Returns a special sequence number used for congested shared objects:
    /// `Version::MIN_CONGESTED + suggested_gas_price`,
    /// where `suggested_gas_price` is embedded into a congested sequence
    /// number to facilitate a gas price feedback mechanism for transactions
    /// cancelled due to shared object congestion.
    #[uniffi::constructor]
    pub fn new_congested_with_suggested_gas_price(suggested_gas_price: u64) -> Result<Self> {
        Ok(Self(
            iota_sdk::types::Version::new_congested_with_suggested_gas_price(suggested_gas_price)?,
        ))
    }

    /// Check if this sequence number is congested, i.e., the corresponding
    /// object is the reason for transaction cancellation.
    pub fn is_congested(&self) -> bool {
        self.0.is_congested()
    }

    /// Returns the `suggested_gas_price` embedded in this congested shared
    /// object sequence number. The `suggested_gas_price` here is used for a
    /// gas price feedback mechanism for transactions cancelled due to
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

    /// Checks if this version is cancelled, i.e., the corresponding
    /// object appears in a cancelled transaction.
    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }

    /// Checks if this version is valid, i.e., the corresponding
    /// object does not appear in a cancelled transaction.
    pub fn is_valid(&self) -> bool {
        self.0.is_valid()
    }

    /// An inclusive lower limit on a valid sequence number.
    ///
    /// A valid sequence number means an object, which this sequence number
    /// is assigned to, does not appear in a cancelled transaction.
    #[uniffi::constructor]
    pub fn min_valid_incl() -> Self {
        Self(iota_sdk::types::Version::MIN_VALID_INCL)
    }

    /// An exclusive upper limit on a valid sequence number: sequence numbers
    /// strictly smaller than this limit are valid sequence numbers.
    ///
    /// A valid sequence number means an object, which this sequence number
    /// is assigned to, does not appear in a cancelled transaction.
    /// Sequence numbers larger than this value are "special" and
    /// assigned to objects that appear in cancelled transactions.
    #[uniffi::constructor]
    pub fn max_valid_excl() -> Self {
        Self(iota_sdk::types::Version::MAX_VALID_EXCL)
    }

    /// Special sequence number that is assigned to objects which are accessed
    /// immutably in a cancelled transaction.
    #[uniffi::constructor]
    pub fn cancelled_read() -> Self {
        Self(iota_sdk::types::Version::CANCELLED_READ)
    }

    /// Special sequence number that was assigned to congested objects which
    /// cause transaction cancellations. Note that this special sequence
    /// number was only used prior to the introduction of a gas price feedback
    /// mechanism, but it is kept for backward compatibility.
    #[uniffi::constructor]
    pub fn congested_prior_to_gas_price_feedback() -> Self {
        Self(iota_sdk::types::Version::CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK)
    }

    #[uniffi::constructor]
    pub fn randomness_unavailable() -> Self {
        Self(iota_sdk::types::Version::RANDOMNESS_UNAVAILABLE)
    }

    /// In the gas price feedback mechanism, sequence numbers >=
    /// `Version::MAX_VALID_EXCL` +
    /// `CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK` are assigned to
    /// objects that cause transactions cancellations due to congestion.
    ///
    /// Sequence numbers larger than `Version::MAX_VALID_EXCL` but
    /// smaller than `Version::MAX_VALID_EXCL` +
    /// `CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK` are
    /// intended for other transaction cancellation reasons.
    ///
    /// There unlikely will be more than 1000 non-congestion cancellation
    /// reasons, but this offset can be increased if needed, as long as
    /// (`Version::MIN_CONGESTED.value()` + maximum gas price) does not
    /// overflow `u64::MAX`.
    #[uniffi::constructor]
    pub fn congested_base_offset_for_gas_price_feedback() -> Self {
        Self(iota_sdk::types::Version::CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK)
    }

    /// Minimum congested sequence number used in the gas price feedback
    /// mechanism. A congested sequence number is assigned to objects that
    /// cause transaction cancellations.
    #[uniffi::constructor]
    pub fn min_congested_for_gas_price_feedback() -> Self {
        Self(iota_sdk::types::Version::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK)
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
