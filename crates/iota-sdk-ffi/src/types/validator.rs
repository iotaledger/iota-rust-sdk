// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    export_iota_object_types_bcs_conversion, export_iota_types_bcs_conversion,
    types::{
        checkpoint::EpochId,
        crypto::{Bls12381PublicKey, Bls12381Signature},
        signature,
    },
};

/// The Validator Set for a particular epoch.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-committee = u64 ; epoch
///                       (vector validator-committee-member)
/// ```
#[derive(uniffi::Record)]
pub struct ValidatorCommittee {
    pub epoch: EpochId,
    pub members: Vec<ValidatorCommitteeMember>,
}

impl From<iota_types::ValidatorCommittee> for ValidatorCommittee {
    fn from(value: iota_types::ValidatorCommittee) -> Self {
        Self {
            epoch: value.epoch,
            members: value.members.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ValidatorCommittee> for iota_types::ValidatorCommittee {
    fn from(value: ValidatorCommittee) -> Self {
        Self {
            epoch: value.epoch,
            members: value.members.into_iter().map(Into::into).collect(),
        }
    }
}

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
#[derive(Clone, uniffi::Record)]
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

/// A signature from a Validator
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-signature = u64               ; epoch
///                       bls-public-key
///                       bls-signature
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorSignature(pub iota_types::ValidatorSignature);

#[uniffi::export]
impl ValidatorSignature {
    #[uniffi::constructor]
    pub fn new(
        epoch: EpochId,
        public_key: &Bls12381PublicKey,
        signature: &Bls12381Signature,
    ) -> Self {
        Self(iota_types::ValidatorSignature {
            epoch,
            public_key: **public_key,
            signature: **signature,
        })
    }

    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key.into()
    }

    pub fn signature(&self) -> Bls12381Signature {
        self.0.signature.into()
    }
}

/// An aggregated signature from multiple Validators.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-aggregated-signature = u64               ; epoch
///                                  bls-signature
///                                  roaring-bitmap
/// roaring-bitmap = bytes  ; where the contents of the bytes are valid
///                         ; according to the serialized spec for
///                         ; roaring bitmaps
/// ```
///
/// See [here](https://github.com/RoaringBitmap/RoaringFormatSpec) for the specification for the
/// serialized format of RoaringBitmaps.
#[derive(derive_more::From, uniffi::Object)]
pub struct ValidatorAggregatedSignature(pub iota_types::ValidatorAggregatedSignature);

#[uniffi::export]
impl ValidatorAggregatedSignature {
    #[uniffi::constructor]
    pub fn new(epoch: EpochId, signature: &Bls12381Signature, bitmap_bytes: &[u8]) -> Result<Self> {
        Ok(Self(iota_types::ValidatorAggregatedSignature {
            epoch,
            signature: **signature,
            bitmap: roaring::RoaringBitmap::deserialize_from(bitmap_bytes)?,
        }))
    }

    pub fn epoch(&self) -> EpochId {
        self.0.epoch
    }

    pub fn signature(&self) -> Bls12381Signature {
        self.0.signature.into()
    }

    pub fn bitmap_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.0.bitmap.serialize_into(&mut bytes)?;
        Ok(bytes)
    }
}

export_iota_types_bcs_conversion!(ValidatorCommittee, ValidatorCommitteeMember);
export_iota_object_types_bcs_conversion!(ValidatorSignature, ValidatorAggregatedSignature);
