// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use test_strategy::proptest;

use crate::*;

macro_rules! serialization_test {
    ($type:ident) => {
        paste::item! {
            #[cfg_attr(target_arch = "wasm32", proptest(cases = 50))]
            #[cfg_attr(not(target_arch = "wasm32"), proptest)]
            #[allow(non_snake_case)]
            fn [< test_roundtrip_ $type >] (instance: $type) {
                assert_roundtrip(&instance);
            }

            #[proptest]
            #[allow(non_snake_case)]
            fn [< fuzz_deserialization_ $type >] (
                #[strategy(proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..=2048))]
                bytes: Vec<u8>,
            ) {
                let _: Result<$type, _> = bcs::from_bytes(&bytes);
            }
        }
    };
}

fn assert_roundtrip<T>(instance: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    // println!("{instance:?}");
    let bcs_bytes = bcs::to_bytes(instance).unwrap();
    let deser_from_bcs_bytes = bcs::from_bytes::<T>(&bcs_bytes).unwrap();
    assert_eq!(instance, &deser_from_bcs_bytes);

    let json = serde_json::to_string(instance).unwrap();
    let deser_from_json = serde_json::from_str::<T>(&json).unwrap();
    assert_eq!(instance, &deser_from_json);
}

serialization_test!(Address);
serialization_test!(CheckpointCommitment);
serialization_test!(CheckpointContents);
serialization_test!(CheckpointContentsV1);
serialization_test!(CheckpointData);
serialization_test!(CheckpointSequenceNumber);
serialization_test!(CheckpointSummary);
serialization_test!(CheckpointTimestamp);
serialization_test!(CheckpointTransaction);
serialization_test!(CheckpointTransactionInfo);
serialization_test!(EndOfEpochData);
serialization_test!(SignedCheckpointSummary);
serialization_test!(Bls12381PublicKey);
serialization_test!(Bls12381Signature);
serialization_test!(Ed25519PublicKey);
serialization_test!(Ed25519Signature);
serialization_test!(MultisigAggregatedSignature);
serialization_test!(MultisigCommittee);
serialization_test!(MultisigMember);
serialization_test!(PublicKey);
serialization_test!(MultisigMemberSignature);
serialization_test!(Secp256k1PublicKey);
serialization_test!(Secp256k1Signature);
serialization_test!(Secp256r1PublicKey);
serialization_test!(Secp256r1Signature);
serialization_test!(SimpleSignature);
serialization_test!(UserSignature);
serialization_test!(ValidatorAggregatedSignature);
serialization_test!(ValidatorCommittee);
serialization_test!(ValidatorCommitteeMember);
serialization_test!(ValidatorSignature);
serialization_test!(PasskeyAuthenticator);
serialization_test!(PasskeyPublicKey);
serialization_test!(MoveAuthenticator);
serialization_test!(MoveAuthenticatorV1);
serialization_test!(RandomnessRound);
serialization_test!(Digest);
serialization_test!(CheckpointDigest);
serialization_test!(CheckpointContentsDigest);
serialization_test!(CertificateDigest);
serialization_test!(SenderSignedDataDigest);
serialization_test!(TransactionDigest);
serialization_test!(TransactionEffectsDigest);
serialization_test!(TransactionEventsDigest);
serialization_test!(EffectsAuxDataDigest);
serialization_test!(ObjectDigest);
serialization_test!(ConsensusCommitDigest);
serialization_test!(MisbehaviorReportDigest);
serialization_test!(MoveAuthenticatorDigest);
serialization_test!(ChangedObject);
serialization_test!(IdOperation);
serialization_test!(ObjectIn);
serialization_test!(ObjectOut);
serialization_test!(TransactionEffects);
serialization_test!(TransactionEffectsV1);
serialization_test!(UnchangedSharedKind);
serialization_test!(UnchangedSharedObject);
serialization_test!(Event);
serialization_test!(TransactionEvents);
serialization_test!(CommandArgumentError);
serialization_test!(ExecutionError);
serialization_test!(ExecutionStatus);
serialization_test!(MoveLocation);
serialization_test!(PackageUpgradeError);
serialization_test!(TypeArgumentError);
serialization_test!(GasCostSummary);
serialization_test!(GenesisObject);
serialization_test!(MovePackage);
serialization_test!(MoveObjectType);
serialization_test!(MoveStruct);
serialization_test!(Object);
serialization_test!(ObjectData);
serialization_test!(ObjectReference);
serialization_test!(SharedObjectReference);
serialization_test!(Owner);
serialization_test!(TypeOrigin);
serialization_test!(UpgradeInfo);
serialization_test!(ObjectId);
serialization_test!(Argument);
serialization_test!(ChangeEpoch);
serialization_test!(ChangeEpochV2);
serialization_test!(ChangeEpochV3);
serialization_test!(ChangeEpochV4);
serialization_test!(Command);
serialization_test!(ConsensusCommitPrologueV1);
serialization_test!(CancelledTransaction);
serialization_test!(ConsensusDeterminedVersionAssignments);
serialization_test!(VersionAssignment);
serialization_test!(DenyRuleSet);
serialization_test!(EndOfEpochTransactionKind);
serialization_test!(GasPayment);
serialization_test!(GenesisTransaction);
serialization_test!(Input);
serialization_test!(MakeMoveVector);
serialization_test!(MergeCoins);
serialization_test!(MoveCall);
serialization_test!(ProgrammableTransaction);
serialization_test!(Publish);
serialization_test!(RandomnessStateUpdate);
serialization_test!(SignedTransaction);
serialization_test!(SenderSignedTransaction);
serialization_test!(SplitCoins);
serialization_test!(SystemPackage);
serialization_test!(Transaction);
serialization_test!(TransactionV1);
serialization_test!(TransactionDenyRulesUpdate);
serialization_test!(TransactionExpiration);
serialization_test!(TransactionKind);
serialization_test!(TransferObjects);
serialization_test!(Upgrade);
serialization_test!(Identifier);
serialization_test!(StructTag);
serialization_test!(TypeTag);
serialization_test!(Version);
