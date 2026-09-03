// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use blst::min_sig::{AggregatePublicKey, AggregateSignature, Signature};
use iota_types::{
    Bls12381PublicKey, Bls12381Signature, CheckpointSequenceNumber, CheckpointSummary, EpochId,
    SignedCheckpointSummary, ValidatorAggregatedSignature, ValidatorCommittee, ValidatorSignature,
};
use signature::{Error as SignatureError, Verifier};

use crate::bls12381::{Bls12381VerifyingKey, BlstError};

#[derive(Debug)]
struct ExtendedValidatorCommittee {
    committee: ValidatorCommittee,
    verifying_keys: Vec<Bls12381VerifyingKey>,
    public_key_to_index: HashMap<Bls12381PublicKey, usize>,
    total_weight: u64,
    quorum_threshold: u64,
}

struct MemberInfo<'a> {
    verifying_key: &'a Bls12381VerifyingKey,
    weight: u64,
    index: usize,
}

impl ExtendedValidatorCommittee {
    fn new(committee: ValidatorCommittee) -> Result<Self, SignatureError> {
        let total_weight = committee
            .validate()
            .and_then(|()| committee.total_stake())
            .map_err(|e| SignatureError::from_source(format!("invalid committee: {e}")))?;

        let mut public_key_to_index = HashMap::new();
        let mut verifying_keys = Vec::new();

        for (idx, member) in committee.members.iter().enumerate() {
            assert_eq!(idx, verifying_keys.len());
            verifying_keys.push(Bls12381VerifyingKey::new(&member.public_key)?);
            public_key_to_index.insert(member.public_key, idx);
        }

        // 2f+1 of the total stake, which `validate` has established is nonzero.
        let quorum_threshold = ((total_weight - 1) / 3) * 2 + 1;

        Ok(Self {
            committee,
            verifying_keys,
            public_key_to_index,
            total_weight,
            quorum_threshold,
        })
    }

    fn committee(&self) -> &ValidatorCommittee {
        &self.committee
    }

    #[allow(unused)]
    fn total_weight(&self) -> u64 {
        self.total_weight
    }

    #[allow(unused)]
    fn quorum_threshold(&self) -> u64 {
        self.quorum_threshold
    }

    fn verifying_key(
        &self,
        public_key: &Bls12381PublicKey,
    ) -> Result<&Bls12381VerifyingKey, SignatureError> {
        self.public_key_to_index
            .get(public_key)
            .and_then(|idx| self.verifying_keys.get(*idx))
            .ok_or_else(|| {
                SignatureError::from_source(format!(
                    "signature from public_key {public_key} does not belong to this committee",
                ))
            })
    }

    fn member(&self, public_key: &Bls12381PublicKey) -> Result<MemberInfo<'_>, SignatureError> {
        self.public_key_to_index
            .get(public_key)
            .ok_or_else(|| {
                SignatureError::from_source(format!(
                    "signature from public_key {public_key} does not belong to this committee",
                ))
            })
            .and_then(|idx| self.member_by_idx(*idx))
    }

    fn member_by_idx(&self, idx: usize) -> Result<MemberInfo<'_>, SignatureError> {
        let verifying_key = self.verifying_keys.get(idx).ok_or_else(|| {
            SignatureError::from_source(format!(
                "index {idx} out of bounds; committee has {} members",
                self.committee().members.len(),
            ))
        })?;
        let weight = self
            .committee()
            .members
            .get(idx)
            .ok_or_else(|| {
                SignatureError::from_source(format!(
                    "index {idx} out of bounds; committee has {} members",
                    self.committee().members.len(),
                ))
            })?
            .stake;

        Ok(MemberInfo {
            verifying_key,
            weight,
            index: idx,
        })
    }
}

#[derive(Debug)]
pub struct ValidatorCommitteeSignatureVerifier {
    committee: ExtendedValidatorCommittee,
}

impl ValidatorCommitteeSignatureVerifier {
    pub fn new(committee: ValidatorCommittee) -> Result<Self, SignatureError> {
        ExtendedValidatorCommittee::new(committee).map(|committee| Self { committee })
    }

    pub fn committee(&self) -> &ValidatorCommittee {
        self.committee.committee()
    }

    pub fn verify_checkpoint_summary(
        &self,
        summary: &CheckpointSummary,
        signature: &ValidatorAggregatedSignature,
    ) -> Result<(), SignatureError> {
        let message = summary.signing_message();
        self.verify(&message, signature)
    }
}

impl Verifier<ValidatorSignature> for ValidatorCommitteeSignatureVerifier {
    fn verify(&self, message: &[u8], signature: &ValidatorSignature) -> Result<(), SignatureError> {
        if signature.epoch != self.committee().epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch,
                self.committee().epoch
            )));
        }

        let verifying_key = self.committee.verifying_key(&signature.public_key)?;
        verifying_key.verify(message, &signature.signature)
    }
}

impl Verifier<ValidatorAggregatedSignature> for ValidatorCommitteeSignatureVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &ValidatorAggregatedSignature,
    ) -> Result<(), SignatureError> {
        if signature.epoch != self.committee().epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch,
                self.committee().epoch
            )));
        }

        let mut signed_weight = 0;
        let mut bitmap = signature.bitmap.iter();

        let mut aggregated_public_key = {
            let idx = bitmap.next().ok_or_else(|| {
                SignatureError::from_source("signature bitmap must have at least one entry")
            })?;

            let member = self.committee.member_by_idx(idx as usize)?;

            signed_weight += member.weight;
            AggregatePublicKey::from_public_key(&member.verifying_key.0)
        };

        for idx in bitmap {
            let member = self.committee.member_by_idx(idx as usize)?;

            signed_weight += member.weight;
            aggregated_public_key
                .add_public_key(&member.verifying_key.0, false) // Keys are already verified
                .map_err(BlstError)
                .map_err(SignatureError::from_source)?;
        }

        Bls12381VerifyingKey(aggregated_public_key.to_public_key())
            .verify(message, &signature.signature)?;

        if signed_weight >= self.committee.quorum_threshold {
            Ok(())
        } else {
            Err(SignatureError::from_source(format!(
                "insufficient signing weight {}; quorum threshold is {}",
                signed_weight, self.committee.quorum_threshold,
            )))
        }
    }
}

/// An error returned while walking the committee chain with
/// [`CommitteeChainVerifier`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommitteeChainError {
    /// The summary is for a different epoch than the one the verifier expects.
    #[error("checkpoint epoch {actual} does not match the expected epoch {expected}")]
    WrongEpoch { expected: EpochId, actual: EpochId },
    /// The summary is not the closing checkpoint of its epoch, so it elects no
    /// next committee.
    #[error(
        "checkpoint {sequence_number} is not the closing checkpoint of epoch {epoch} (no end-of-epoch data)"
    )]
    NotEndOfEpoch {
        sequence_number: CheckpointSequenceNumber,
        epoch: EpochId,
    },
    /// The summary's signatures did not verify under the current committee.
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
    /// The committee elected by the summary's end-of-epoch data cannot be used
    /// to verify the next epoch.
    #[error("invalid next epoch committee: {0}")]
    NextCommittee(#[source] SignatureError),
    /// The epoch counter would overflow past the last epoch.
    #[error("epoch number overflow")]
    EpochOverflow,
}

/// Verifies the committee chain: the sequence of committees linked by each
/// epoch's certified closing checkpoint, whose end-of-epoch data elects the
/// committee of the next epoch.
///
/// Starting from a trusted committee (typically the genesis committee, the
/// operator's trust root), feed it each epoch's closing
/// [`SignedCheckpointSummary`] in epoch order via [`Self::verify_epoch_close`];
/// every summary a consumer obtains this way is committee-verified, with no
/// trust in whatever transport delivered it.
///
/// The walk is transport-agnostic by design — callers drive their own loop (an
/// in-memory list, a remote-store stream, files on disk) and feed summaries in;
/// this type only holds the verification state.
#[derive(Debug)]
pub struct CommitteeChainVerifier {
    verifier: ValidatorCommitteeSignatureVerifier,
}

impl CommitteeChainVerifier {
    /// Start the walk at a trusted committee — the trust root for everything
    /// verified after it.
    pub fn new(trusted_committee: ValidatorCommittee) -> Result<Self, SignatureError> {
        ValidatorCommitteeSignatureVerifier::new(trusted_committee)
            .map(|verifier| Self { verifier })
    }

    /// The epoch whose closing checkpoint must be fed next.
    pub fn epoch(&self) -> EpochId {
        self.verifier.committee().epoch
    }

    /// The committee of [`Self::epoch`] (trusted root or chain-verified).
    pub fn committee(&self) -> &ValidatorCommittee {
        self.verifier.committee()
    }

    /// Verify `summary` as the certified closing checkpoint of [`Self::epoch`]
    /// and advance to the committee it elects for the next epoch.
    ///
    /// Errors leave the verifier unchanged, e.g. if the summary is for a
    /// different epoch, its signatures don't verify under the current
    /// committee, it is not a close-of-epoch checkpoint (no end-of-epoch data),
    /// or the committee it elects is not well-formed.
    pub fn verify_epoch_close(
        &mut self,
        summary: &SignedCheckpointSummary,
    ) -> Result<(), CommitteeChainError> {
        let SignedCheckpointSummary {
            checkpoint,
            signature,
        } = summary;
        let expected_epoch = self.verifier.committee().epoch;

        // The structural checks run before the (expensive) signature
        // verification. They can only ever reject; nothing from the summary is
        // trusted until the signatures verify.
        if checkpoint.epoch != expected_epoch {
            return Err(CommitteeChainError::WrongEpoch {
                expected: expected_epoch,
                actual: checkpoint.epoch,
            });
        }

        let Some(end_of_epoch_data) = &checkpoint.end_of_epoch_data else {
            return Err(CommitteeChainError::NotEndOfEpoch {
                sequence_number: checkpoint.sequence_number,
                epoch: expected_epoch,
            });
        };

        self.verifier
            .verify_checkpoint_summary(checkpoint, signature)?;

        // Signatures verified; the elected committee is now trusted.
        let next_committee = ValidatorCommittee {
            epoch: expected_epoch
                .checked_add(1)
                .ok_or(CommitteeChainError::EpochOverflow)?,
            members: end_of_epoch_data.next_epoch_committee.clone(),
        };
        self.verifier = ValidatorCommitteeSignatureVerifier::new(next_committee)
            .map_err(CommitteeChainError::NextCommittee)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct ValidatorCommitteeSignatureAggregator {
    verifier: ValidatorCommitteeSignatureVerifier,
    signatures: std::collections::BTreeMap<usize, ValidatorSignature>,
    signed_weight: u64,
    message: Vec<u8>,
}

impl ValidatorCommitteeSignatureAggregator {
    pub fn new_checkpoint_summary(
        committee: ValidatorCommittee,
        summary: &CheckpointSummary,
    ) -> Result<Self, SignatureError> {
        let verifier = ValidatorCommitteeSignatureVerifier::new(committee)?;
        let message = summary.signing_message();

        Ok(Self {
            verifier,
            signatures: Default::default(),
            signed_weight: 0,
            message,
        })
    }

    pub fn committee(&self) -> &ValidatorCommittee {
        self.verifier.committee()
    }

    pub fn add_signature(&mut self, signature: ValidatorSignature) -> Result<(), SignatureError> {
        use std::collections::btree_map::Entry;

        if signature.epoch != self.verifier.committee().epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch,
                self.committee().epoch
            )));
        }

        let member = self.verifier.committee.member(&signature.public_key)?;

        member
            .verifying_key
            .verify(&self.message, &signature.signature)?;

        match self.signatures.entry(member.index) {
            Entry::Vacant(v) => {
                v.insert(signature);
            }
            Entry::Occupied(_) => {
                return Err(SignatureError::from_source(
                    "duplicate signature from same committee member",
                ));
            }
        }

        self.signed_weight += member.weight;

        Ok(())
    }

    pub fn finish(&self) -> Result<ValidatorAggregatedSignature, SignatureError> {
        if self.signed_weight < self.verifier.committee.quorum_threshold {
            return Err(SignatureError::from_source(format!(
                "signature weight of {} is insufficient to reach quorum threshold of {}",
                self.signed_weight, self.verifier.committee.quorum_threshold
            )));
        }

        let mut iter = self.signatures.iter();
        let (member_idx, signature) = iter.next().ok_or_else(|| {
            SignatureError::from_source("signature map must have at least one entry")
        })?;

        let mut bitmap = roaring::RoaringBitmap::new();
        bitmap.insert(*member_idx as u32);
        let agg_sig = AggregateSignature::from_signature(
            &Signature::from_bytes(signature.signature.bytes())
                .expect("signature was already verified"),
        );

        let (agg_sig, bitmap) = iter.fold(
            (agg_sig, bitmap),
            |(mut agg_sig, mut bitmap), (member_idx, signature)| {
                bitmap.insert(*member_idx as u32);
                agg_sig
                    .add_signature(
                        &Signature::from_bytes(signature.signature.bytes())
                            .expect("signature was already verified"),
                        false,
                    )
                    .expect("signature was already verified");
                (agg_sig, bitmap)
            },
        );

        let aggregated_signature = ValidatorAggregatedSignature {
            epoch: self.verifier.committee().epoch,
            signature: Bls12381Signature::new(agg_sig.to_signature().to_bytes()),
            bitmap,
        };

        // Double check that the aggregated sig still verifies
        self.verifier.verify(&self.message, &aggregated_signature)?;

        Ok(aggregated_signature)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::{EndOfEpochData, ValidatorCommitteeMember};
    use test_strategy::proptest;

    use super::*;
    use crate::bls12381::Bls12381PrivateKey;

    #[proptest]
    fn basic_aggregation(private_keys: [Bls12381PrivateKey; 4], summary: CheckpointSummary) {
        let committee = ValidatorCommittee {
            epoch: summary.epoch,
            members: private_keys
                .iter()
                .map(|key| ValidatorCommitteeMember {
                    public_key: key.public_key(),
                    stake: 1,
                })
                .collect(),
        };

        let mut aggregator =
            ValidatorCommitteeSignatureAggregator::new_checkpoint_summary(committee, &summary)
                .unwrap();

        // Aggregating with no sigs fails
        aggregator.finish().unwrap_err();

        aggregator
            .add_signature(private_keys[0].sign_checkpoint_summary(&summary))
            .unwrap();

        // Aggregating with a sig from the same committee member more than once fails
        aggregator
            .add_signature(private_keys[0].sign_checkpoint_summary(&summary))
            .unwrap_err();

        // Aggregating with insufficient weight fails
        aggregator.finish().unwrap_err();

        aggregator
            .add_signature(private_keys[1].sign_checkpoint_summary(&summary))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign_checkpoint_summary(&summary))
            .unwrap();

        // Aggregating with sufficient weight succeeds and verifies
        let signature = aggregator.finish().unwrap();
        aggregator
            .verifier
            .verify_checkpoint_summary(&summary, &signature)
            .unwrap();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(private_keys[3].sign_checkpoint_summary(&summary))
            .unwrap();
        let signature = aggregator.finish().unwrap();
        aggregator
            .verifier
            .verify_checkpoint_summary(&summary, &signature)
            .unwrap();
    }

    fn committee(keys: &[Bls12381PrivateKey], epoch: EpochId) -> ValidatorCommittee {
        ValidatorCommittee {
            epoch,
            members: keys
                .iter()
                .map(|key| ValidatorCommitteeMember {
                    public_key: key.public_key(),
                    stake: 1,
                })
                .collect(),
        }
    }

    /// Turn `checkpoint` into a summary certified by every key in `keys`, which
    /// must be `committee`'s members.
    fn certify(
        keys: &[Bls12381PrivateKey],
        committee: ValidatorCommittee,
        checkpoint: CheckpointSummary,
    ) -> SignedCheckpointSummary {
        let mut aggregator =
            ValidatorCommitteeSignatureAggregator::new_checkpoint_summary(committee, &checkpoint)
                .unwrap();
        for key in keys {
            aggregator
                .add_signature(key.sign_checkpoint_summary(&checkpoint))
                .unwrap();
        }
        SignedCheckpointSummary {
            checkpoint,
            signature: aggregator.finish().unwrap(),
        }
    }

    /// Make `summary` the closing checkpoint of `epoch`, electing `next` as the
    /// next epoch's committee.
    fn close_epoch(
        mut summary: CheckpointSummary,
        epoch: EpochId,
        next: &ValidatorCommittee,
    ) -> CheckpointSummary {
        summary.epoch = epoch;
        summary.end_of_epoch_data = Some(EndOfEpochData {
            next_epoch_committee: next.members.clone(),
            next_epoch_protocol_version: 1,
            epoch_commitments: Vec::new(),
            epoch_supply_change: 0,
        });
        summary
    }

    #[proptest]
    fn committee_chain_walk(
        keys0: [Bls12381PrivateKey; 4],
        keys1: [Bls12381PrivateKey; 4],
        keys2: [Bls12381PrivateKey; 4],
        summary0: CheckpointSummary,
        summary1: CheckpointSummary,
    ) {
        let committee0 = committee(&keys0, 0);
        let committee1 = committee(&keys1, 1);
        let committee2 = committee(&keys2, 2);

        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();
        assert_eq!(verifier.epoch(), 0);
        assert_eq!(verifier.committee(), &committee0);

        // Closing epoch 0 elects the epoch 1 committee and advances the walk.
        let signed0 = certify(&keys0, committee0, close_epoch(summary0, 0, &committee1));
        verifier.verify_epoch_close(&signed0).unwrap();
        assert_eq!(verifier.epoch(), 1);
        assert_eq!(verifier.committee(), &committee1);

        // The newly-elected committee verifies the next epoch's close.
        let signed1 = certify(&keys1, committee1, close_epoch(summary1, 1, &committee2));
        verifier.verify_epoch_close(&signed1).unwrap();
        assert_eq!(verifier.epoch(), 2);
        assert_eq!(verifier.committee(), &committee2);
    }

    #[proptest]
    fn wrong_epoch_is_rejected(keys: [Bls12381PrivateKey; 4], summary: CheckpointSummary) {
        let committee0 = committee(&keys, 0);
        let next = committee(&keys, 1);

        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();

        // A summary for epoch 1 while the verifier is still at epoch 0.
        let signed = certify(&keys, committee(&keys, 1), close_epoch(summary, 1, &next));
        let err = verifier.verify_epoch_close(&signed).unwrap_err();
        assert!(matches!(
            err,
            CommitteeChainError::WrongEpoch {
                expected: 0,
                actual: 1
            }
        ));
        // The verifier is left unchanged.
        assert_eq!(verifier.committee(), &committee0);
    }

    #[proptest]
    fn non_closing_checkpoint_is_rejected(
        keys: [Bls12381PrivateKey; 4],
        mut summary: CheckpointSummary,
    ) {
        let committee0 = committee(&keys, 0);
        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();

        summary.epoch = 0;
        summary.end_of_epoch_data = None;
        let signed = certify(&keys, committee0.clone(), summary);
        let err = verifier.verify_epoch_close(&signed).unwrap_err();
        assert!(matches!(
            err,
            CommitteeChainError::NotEndOfEpoch { epoch: 0, .. }
        ));
        assert_eq!(verifier.committee(), &committee0);
    }

    #[proptest]
    fn committee_without_stake_is_rejected(key: Bls12381PrivateKey) {
        ValidatorCommitteeSignatureVerifier::new(ValidatorCommittee {
            epoch: 0,
            members: Vec::new(),
        })
        .unwrap_err();

        ValidatorCommitteeSignatureVerifier::new(ValidatorCommittee {
            epoch: 0,
            members: vec![ValidatorCommitteeMember {
                public_key: key.public_key(),
                stake: 0,
            }],
        })
        .unwrap_err();
    }

    /// A committee whose stake sums past `u64::MAX` wraps to a low total, and
    /// so to a quorum threshold a single member can meet.
    #[proptest]
    fn committee_with_overflowing_stake_is_rejected(
        key1: Bls12381PrivateKey,
        key2: Bls12381PrivateKey,
    ) {
        ValidatorCommitteeSignatureVerifier::new(ValidatorCommittee {
            epoch: 0,
            members: vec![
                ValidatorCommitteeMember {
                    public_key: key1.public_key(),
                    stake: u64::MAX,
                },
                ValidatorCommitteeMember {
                    public_key: key2.public_key(),
                    stake: 2,
                },
            ],
        })
        .unwrap_err();
    }

    #[proptest]
    fn quorum_threshold_matches_the_protocol_constant(keys: [Bls12381PrivateKey; 2]) {
        let verifier = ValidatorCommitteeSignatureVerifier::new(ValidatorCommittee {
            epoch: 0,
            members: vec![
                ValidatorCommitteeMember {
                    public_key: keys[0].public_key(),
                    stake: 6_000,
                },
                ValidatorCommitteeMember {
                    public_key: keys[1].public_key(),
                    stake: 4_000,
                },
            ],
        })
        .unwrap();

        assert_eq!(verifier.committee.total_weight, 10_000);
        assert_eq!(verifier.committee.quorum_threshold, 6_667);
    }

    #[proptest]
    fn electing_a_committee_without_stake_is_rejected(
        keys: [Bls12381PrivateKey; 4],
        summary: CheckpointSummary,
    ) {
        let committee0 = committee(&keys, 0);
        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();

        let empty = ValidatorCommittee {
            epoch: 1,
            members: Vec::new(),
        };
        let signed = certify(&keys, committee0.clone(), close_epoch(summary, 0, &empty));
        let err = verifier.verify_epoch_close(&signed).unwrap_err();
        assert!(matches!(err, CommitteeChainError::NextCommittee(_)));
        // The walk stays on the last committee it could verify.
        assert_eq!(verifier.epoch(), 0);
        assert_eq!(verifier.committee(), &committee0);
    }

    #[proptest]
    fn bad_signature_is_rejected(
        keys: [Bls12381PrivateKey; 4],
        wrong_keys: [Bls12381PrivateKey; 4],
        summary: CheckpointSummary,
    ) {
        let committee0 = committee(&keys, 0);
        let next = committee(&keys, 1);
        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();

        // Certified by a committee the verifier doesn't trust.
        let signed = certify(
            &wrong_keys,
            committee(&wrong_keys, 0),
            close_epoch(summary, 0, &next),
        );
        let err = verifier.verify_epoch_close(&signed).unwrap_err();
        assert!(matches!(err, CommitteeChainError::Signature(_)));
        assert_eq!(verifier.committee(), &committee0);
    }

    /// A closing checkpoint certified by a stake minority fails on weight, not
    /// on the signature: one member's signature verifies, the quorum does not.
    /// `certify` cannot build this case, since `finish` refuses it.
    #[proptest]
    fn under_quorum_certification_is_rejected(
        keys: [Bls12381PrivateKey; 4],
        summary: CheckpointSummary,
    ) {
        let committee0 = committee(&keys, 0);
        let next = committee(&keys, 1);
        let mut verifier = CommitteeChainVerifier::new(committee0.clone()).unwrap();

        let checkpoint = close_epoch(summary, 0, &next);
        // One of four equal stakes: weight 1 against a threshold of 3.
        let lone = keys[0].sign_checkpoint_summary(&checkpoint);
        let mut bitmap = roaring::RoaringBitmap::new();
        bitmap.insert(0);
        let signed = SignedCheckpointSummary {
            checkpoint,
            signature: ValidatorAggregatedSignature {
                epoch: lone.epoch,
                signature: lone.signature,
                bitmap,
            },
        };

        let err = verifier.verify_epoch_close(&signed).unwrap_err();
        // `Signature` is also how a bad signature is reported, so the message
        // is what separates the two.
        assert!(matches!(err, CommitteeChainError::Signature(_)), "{err}");
        assert!(
            err.to_string().contains("insufficient signing weight"),
            "{err}"
        );
        assert_eq!(verifier.committee(), &committee0);
    }
}
