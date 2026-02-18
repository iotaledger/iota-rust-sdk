// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Round number of generated randomness.
#[derive(
    Clone,
    Copy,
    Hash,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    derive_more::From,
    derive_more::Display,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Sub,
    derive_more::SubAssign,
)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[repr(transparent)]
pub struct RandomnessRound(
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    u64,
);

impl RandomnessRound {
    pub fn new(round: u64) -> Self {
        Self(round)
    }

    pub fn value(&self) -> u64 {
        self.0
    }

    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }

    pub fn checked_sub(self, rhs: u64) -> Option<Self> {
        self.0.checked_sub(rhs).map(Self)
    }

    /// Returns the message to be signed for a randomness round.
    pub fn signature_message(&self) -> Vec<u8> {
        "random_beacon round "
            .as_bytes()
            .iter()
            .cloned()
            .chain(bcs::to_bytes(&self.0).expect("serialization should not fail"))
            .collect()
    }
}

impl std::ops::Add<u64> for RandomnessRound {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::Sub<u64> for RandomnessRound {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::AddAssign<u64> for RandomnessRound {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl std::ops::SubAssign<u64> for RandomnessRound {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}
