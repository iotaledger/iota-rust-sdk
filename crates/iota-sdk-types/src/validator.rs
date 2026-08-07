// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Bls12381PublicKey, Bls12381Signature};
use crate::checkpoint::{EpochId, StakeUnit};

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
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ValidatorCommittee {
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub epoch: EpochId,
    pub members: Vec<ValidatorCommitteeMember>,
}

impl crate::TreeDisplay for ValidatorCommittee {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Validator Committee")?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.children("Members", &self.members, true)
    }
}

/// A member of a Validator Committee
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-committee-member = bls12381-public-key
///                              u64 ; stake
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ValidatorCommitteeMember {
    #[cfg_attr(feature = "serde", serde(with = "ValidatorPublicKeySerialization"))]
    pub public_key: Bls12381PublicKey,
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub stake: StakeUnit,
}

impl crate::TreeDisplay for ValidatorCommitteeMember {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Validator Committee Member")?;
        w.leaf("Public Key", &self.public_key, false)?;
        w.leaf("Stake", &self.stake, true)
    }
}

/// An aggregated signature from multiple Validators.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-aggregated-signature = u64                  ; epoch
///                                  bls12381-signature   ; signature
///                                  bytes                ; bitmap — contents of the bytes are
///                                                       ; valid according to the serialized
///                                                       ; spec for roaring bitmaps
/// ```
///
/// See [here](https://github.com/RoaringBitmap/RoaringFormatSpec) for the specification for the
/// serialized format of RoaringBitmaps.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ValidatorAggregatedSignature {
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
    pub epoch: EpochId,
    pub signature: Bls12381Signature,
    #[cfg_attr(feature = "serde", serde(with = "RoaringBitMapSerialization"))]
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Just(roaring::RoaringBitmap::default()))
    )]
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "bytes"))]
    pub bitmap: roaring::RoaringBitmap,
}

impl crate::TreeDisplay for ValidatorAggregatedSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Validator Aggregated Signature")?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.leaf("Signature", &self.signature, false)?;
        w.leaf("Bitmap", &format!("{:?}", self.bitmap), true)
    }
}

#[cfg(feature = "serde")]
type RoaringBitMapSerialization = ::serde_with::As<
    ::serde_with::IfIsHumanReadable<
        crate::_serde::Base64RoaringBitmap,
        crate::_serde::BinaryRoaringBitmap,
    >,
>;

// Similar to Digest...unfortunately validator's public key material is
// serialized with the length (96) prefixed
#[cfg(feature = "serde")]
type ValidatorPublicKeySerialization = ::serde_with::As<
    ::serde_with::IfIsHumanReadable<::serde_with::DisplayFromStr, BinaryValidatorPublicKey>,
>;

#[cfg(feature = "serde")]
struct BinaryValidatorPublicKey;

#[cfg(feature = "serde")]
impl serde_with::SerializeAs<Bls12381PublicKey> for BinaryValidatorPublicKey {
    fn serialize_as<S>(source: &Bls12381PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ::serde_with::Bytes::serialize_as(source.inner(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde_with::DeserializeAs<'de, Bls12381PublicKey> for BinaryValidatorPublicKey {
    fn deserialize_as<D>(deserializer: D) -> Result<Bls12381PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; Bls12381PublicKey::LENGTH] =
            ::serde_with::Bytes::deserialize_as(deserializer)?;
        Ok(Bls12381PublicKey::new(bytes))
    }
}

/// A signature from a Validator
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// validator-signature = u64                  ; epoch
///                       bls12381-public-key
///                       bls12381-signature
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ValidatorSignature {
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub epoch: EpochId,
    #[cfg_attr(feature = "serde", serde(with = "ValidatorPublicKeySerialization"))]
    pub public_key: Bls12381PublicKey,
    pub signature: Bls12381Signature,
}

impl crate::TreeDisplay for ValidatorSignature {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Validator Signature")?;
        w.leaf("Epoch", &self.epoch, false)?;
        w.leaf("Public Key", &self.public_key, false)?;
        w.leaf("Signature", &self.signature, true)
    }
}

crate::impl_tree_display!(
    ValidatorCommittee,
    ValidatorCommitteeMember,
    ValidatorAggregatedSignature,
    ValidatorSignature
);

#[cfg(all(test, feature = "serde"))]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn aggregated_signature_fixture() {
        use base64ct::{Base64, Encoding};

        const FIXTURE: &str = "CgAAAAAAAACZrBcXiqa0ttztfwrBxKzQRzIRnZhbmsQV7tqNXwiZQrRC+dVDbdua1Ety9uy2pCUSOjAAAAEAAAAAAAAAEAAAAAAA";
        let bcs = Base64::decode_vec(FIXTURE).unwrap();

        let signature: ValidatorAggregatedSignature = bcs::from_bytes(&bcs).unwrap();
        let bytes = bcs::to_bytes(&signature).unwrap();
        assert_eq!(bcs, bytes);
    }
}
