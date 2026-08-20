// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Sub, SubAssign};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VersionError {
    #[error("cannot increment Version: maximum valid Version has already been reached")]
    InvalidIncrement,
    #[error("cannot decrement Version: minimum valid Version has already been reached")]
    InvalidDecrement,
    #[error("Version arithmetic resulted in an overflow")]
    Overflow,
    #[error("not a version used for congested shared objects in the gas price feedback mechanism")]
    InvalidCongestedVersion,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Display,
    derive_more::Div,
    derive_more::DivAssign,
    derive_more::From,
    derive_more::FromStr,
    derive_more::Mul,
    derive_more::MulAssign,
    derive_more::Rem,
    derive_more::RemAssign,
    derive_more::Sub,
    derive_more::SubAssign,
    derive_more::Sum,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(transparent)
)]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[repr(transparent)]
pub struct Version(
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))] u64,
);

impl Version {
    /// An inclusive lower limit on a valid version.
    ///
    /// A valid version means an object, which this version
    /// is assigned to, does not appear in a canceled transaction.
    pub const MIN_VALID_INCL: Self = Self(u64::MIN);

    /// The initial shared version for shared system objects.
    pub const INITIAL_SHARED_VERSION: Self = Self(1);

    /// An exclusive upper limit on a valid version: versions
    /// strictly smaller than this limit are valid versions.
    ///
    /// A valid version means an object, which this version
    /// is assigned to, does not appear in a canceled transaction.
    /// Versions larger than this value are "special" and
    /// assigned to objects that appear in canceled transactions.
    pub const MAX_VALID_EXCL: Self = Self(0x7fff_ffff_ffff_ffff);

    /// Special version that is assigned to objects which are accessed
    /// immutably in a canceled transaction.
    pub const CANCELED_READ: Self = Self(Self::MAX_VALID_EXCL.0 + 1);

    /// Special version that was assigned to congested objects which
    /// cause transaction cancelations. Note that this special version
    /// was only used prior to the introduction of a gas price feedback
    /// mechanism, but it is kept for backward compatibility.
    pub const CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK: Self = Self(Self::MAX_VALID_EXCL.0 + 2);

    pub const RANDOMNESS_UNAVAILABLE: Self = Self(Self::MAX_VALID_EXCL.0 + 3);

    // NOTE: if you want to add new Version constants used for cancelation
    // reasons different than those used for cancelations due to shared object
    // congestion, please make sure their offset is less than
    // CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK

    /// In the gas price feedback mechanism, versions >=
    /// `Version::MAX_VALID_EXCL` +
    /// `CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK` are assigned to
    /// objects that cause transactions cancelations due to congestion.
    ///
    /// Versions larger than `Version::MAX_VALID_EXCL` but
    /// smaller than `Version::MAX_VALID_EXCL` +
    /// `CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK` are
    /// intended for other transaction cancelation reasons.
    ///
    /// There unlikely will be more than 1000 non-congestion cancelation
    /// reasons, but this offset can be increased if needed, as long as
    /// (`Version::MIN_CONGESTED.value()` + maximum gas price) does not
    /// overflow `u64::MAX`.
    const CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK: Self = Self(1_000);

    /// Minimum congested version used in the gas price feedback
    /// mechanism. A congested version is assigned to objects that
    /// cause transaction cancelations.
    const MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK: Self =
        Self(Self::MAX_VALID_EXCL.0 + Self::CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK.0);

    pub const OBJECT_START: Self = Self(1);

    /// Create a new Version from a u64 value
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Get the underlying u64 value of this version
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the next version, or an error if overflow occurs.
    pub fn next(mut self) -> Result<Self, VersionError> {
        if !self.is_valid() {
            return Err(VersionError::InvalidIncrement);
        }
        self.0 += 1;
        Ok(self)
    }

    /// Increments this version by one, or returns an error if overflow occurs.
    pub fn increment(&mut self) -> Result<(), VersionError> {
        *self = self.next()?;
        Ok(())
    }

    /// Returns the previous version, or an error if underflow occurs.
    pub fn previous(mut self) -> Result<Self, VersionError> {
        if self == Self::MIN_VALID_INCL {
            return Err(VersionError::InvalidDecrement);
        }
        self.0 -= 1;
        Ok(self)
    }

    /// Decrements this version by one, or returns an error if underflow occurs.
    pub fn decrement(&mut self) -> Result<(), VersionError> {
        *self = self.previous()?;
        Ok(())
    }

    /// Returns a special version used for congested shared objects:
    /// `Version::MIN_CONGESTED + suggested_gas_price`,
    /// where `suggested_gas_price` is embedded into a congested version
    /// to facilitate a gas price feedback mechanism for transactions
    /// canceled due to shared object congestion.
    pub fn new_congested_with_suggested_gas_price(
        suggested_gas_price: u64,
    ) -> Result<Self, VersionError> {
        let (version, overflows) = Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK
            .0
            .overflowing_add(suggested_gas_price);
        if overflows {
            return Err(VersionError::Overflow);
        }

        Ok(Self(version))
    }

    /// Check if this version is congested, i.e., the corresponding
    /// object is the reason for transaction cancelation.
    pub fn is_congested(&self) -> bool {
        *self == Self::CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK
            || *self >= Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK
    }

    /// Returns the `suggested_gas_price` embedded in this congested shared
    /// object version. The `suggested_gas_price` here is used for a
    /// gas price feedback mechanism for transactions canceled due to
    /// shared object congestion.
    pub fn get_congested_version_suggested_gas_price(&self) -> Result<u64, VersionError> {
        if *self < Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK {
            return Err(VersionError::InvalidCongestedVersion);
        }

        Ok(self.0 - Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK.0)
    }

    /// Returns a new version that is greater than all versions
    /// in `inputs`, assuming this operation will not overflow.
    pub fn lamport_increment(inputs: impl IntoIterator<Item = Self>) -> Result<Self, VersionError> {
        let max_input = inputs.into_iter().max().unwrap_or_default();
        max_input.next()
    }

    /// Checks if this version is canceled, i.e., the corresponding
    /// object appears in a canceled transaction.
    pub fn is_canceled(&self) -> bool {
        *self == Self::CANCELED_READ || *self == Self::RANDOMNESS_UNAVAILABLE || self.is_congested()
    }

    /// Checks if this version is valid, i.e., the corresponding
    /// object does not appear in a canceled transaction.
    pub fn is_valid(&self) -> bool {
        *self < Self::MAX_VALID_EXCL
    }
}

impl Add<u64> for Version {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<u64> for Version {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Sub<u64> for Version {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl SubAssign<u64> for Version {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl TryFrom<i64> for Version {
    type Error = <u64 as TryFrom<i64>>::Error;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
    }
}

impl PartialEq<u64> for Version {
    fn eq(&self, other: &u64) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<Version> for u64 {
    fn eq(&self, other: &Version) -> bool {
        self.eq(&other.0)
    }
}

impl PartialOrd<u64> for Version {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<Version> for u64 {
    fn partial_cmp(&self, other: &Version) -> Option<std::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}
