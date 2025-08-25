// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::crypto::Bls12381PublicKey;

/// A member of a Validator Committee
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-committee-member = bls-public-key
///                              u64 ; stake
/// ```
#[derive(uniffi::Record)]
pub struct ValidatorCommitteeMember {
    pub public_key: Arc<Bls12381PublicKey>,
    pub stake: u64,
}

impl From<iota_types::ValidatorCommitteeMember> for ValidatorCommitteeMember {
    fn from(value: iota_types::ValidatorCommitteeMember) -> Self {
        Self {
            public_key: Arc::new(value.public_key.into()),
            stake: value.stake,
        }
    }
}

impl From<ValidatorCommitteeMember> for iota_types::ValidatorCommitteeMember {
    fn from(value: ValidatorCommitteeMember) -> Self {
        Self {
            public_key: **value.public_key,
            stake: value.stake,
        }
    }
}
