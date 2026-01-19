// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, AddAssign, Sub, SubAssign};

#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Hash,
    Default,
    derive_more::Display,
    derive_more::FromStr,
    derive_more::From,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Sub,
    derive_more::SubAssign,
    derive_more::Mul,
    derive_more::MulAssign,
    derive_more::Div,
    derive_more::DivAssign,
    derive_more::Sum,
    derive_more::Rem,
    derive_more::RemAssign,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[repr(transparent)]
pub struct Version(pub u64);

impl Version {
    /// An inclusive lower limit on a valid sequence number.
    ///
    /// A valid sequence number means an object, which this sequence number
    /// is assigned to, does not appear in a cancelled transaction.
    pub const MIN_VALID_INCL: Self = Self(u64::MIN);

    /// An exclusive upper limit on a valid sequence number: sequence numbers
    /// strictly smaller than this limit are valid sequence numbers.
    ///
    /// A valid sequence number means an object, which this sequence number
    /// is assigned to, does not appear in a cancelled transaction.
    /// Sequence numbers larger than this value are "special" and
    /// assigned to objects that appear in cancelled transactions.
    pub const MAX_VALID_EXCL: Self = Self(0x7fff_ffff_ffff_ffff);

    /// Special sequence number that is assigned to objects which are accessed
    /// immutably in a cancelled transaction.
    pub const CANCELLED_READ: Self = Self(Self::MAX_VALID_EXCL.0 + 1);

    /// Special sequence number that was assigned to congested objects which
    /// cause transaction cancellations. Note that this special sequence
    /// number was only used prior to the introduction of a gas price feedback
    /// mechanism, but it is kept for backward compatibility.
    pub const CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK: Self = Self(Self::MAX_VALID_EXCL.0 + 2);

    pub const RANDOMNESS_UNAVAILABLE: Self = Self(Self::MAX_VALID_EXCL.0 + 3);

    // NOTE: if you want to add new Version constants used for cancellation
    // reasons different than those used for cancellations due to shared object
    // congestion, please make sure their offset is less than
    // CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK

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
    pub const CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK: Self = Self(1_000);

    /// Minimum congested sequence number used in the gas price feedback
    /// mechanism. A congested sequence number is assigned to objects that
    /// cause transaction cancellations.
    pub const MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK: Self =
        Self(Self::MAX_VALID_EXCL.0 + Self::CONGESTED_BASE_OFFSET_FOR_GAS_PRICE_FEEDBACK.0);

    /// Get the underlying u64 value of this version
    pub const fn value(&self) -> u64 {
        self.0
    }

    pub fn increment(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    pub fn decrement(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Returns a special sequence number used for congested shared objects:
    /// `Version::MIN_CONGESTED + suggested_gas_price`,
    /// where `suggested_gas_price` is embedded into a congested sequence
    /// number to facilitate a gas price feedback mechanism for transactions
    /// cancelled due to shared object congestion.
    pub fn new_congested_with_suggested_gas_price(suggested_gas_price: u64) -> Self {
        let (version, overflows) = Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK
            .0
            .overflowing_add(suggested_gas_price);
        debug_assert!(
            !overflows,
            "the calculated version for a congested shared objects overflows"
        );

        Self(version)
    }

    /// Check if this sequence number is congested, i.e., the corresponding
    /// object is the reason for transaction cancellation.
    pub fn is_congested(&self) -> bool {
        *self == Self::CONGESTED_PRIOR_TO_GAS_PRICE_FEEDBACK
            || *self >= Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK
    }

    /// Returns the `suggested_gas_price` embedded in this congested shared
    /// object sequence number. The `suggested_gas_price` here is used for a
    /// gas price feedback mechanism for transactions cancelled due to
    /// shared object congestion.
    pub fn get_congested_version_suggested_gas_price(&self) -> u64 {
        assert!(
            *self >= Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK,
            "this is not a version used for congested shared objects in the gas price feedback \
                mechanism"
        );

        self.0 - Self::MIN_CONGESTED_FOR_GAS_PRICE_FEEDBACK.0
    }

    /// Returns a new version that is greater than all versions
    /// in `inputs`, assuming this operation will not overflow.
    pub fn lamport_increment(inputs: impl IntoIterator<Item = Self>) -> Self {
        let max_input = inputs.into_iter().fold(Self::default(), core::cmp::max);

        assert!(
            max_input.is_valid(),
            "cannot increment a version: \
                maximum valid version has already been reached"
        );

        max_input + 1
    }

    /// Checks if this version is cancelled, i.e., the corresponding
    /// object appears in a cancelled transaction.
    pub fn is_cancelled(&self) -> bool {
        *self == Self::CANCELLED_READ
            || *self == Self::RANDOMNESS_UNAVAILABLE
            || self.is_congested()
    }

    /// Checks if this version is valid, i.e., the corresponding
    /// object does not appear in a cancelled transaction.
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
