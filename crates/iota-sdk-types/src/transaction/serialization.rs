// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

use super::Argument;
use crate::{Identifier, ObjectId, ObjectReference};

mod transaction_kind {
    use super::*;
    use crate::transaction::{
        ConsensusCommitPrologueV1, EndOfEpochTransactionKind, GenesisTransaction,
        ProgrammableTransaction, RandomnessStateUpdate, TransactionKind,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[serde(rename = "TransactionKind")]
    enum ReadableTransactionKindRef<'a> {
        Programmable(&'a ProgrammableTransaction),
        Genesis(&'a GenesisTransaction),
        ConsensusCommitPrologueV1(&'a ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1Deprecated,
        EndOfEpoch {
            commands: &'a Vec<EndOfEpochTransactionKind>,
        },
        RandomnessStateUpdate(&'a RandomnessStateUpdate),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[serde(rename = "TransactionKind")]
    enum ReadableTransactionKind {
        Programmable(ProgrammableTransaction),
        Genesis(GenesisTransaction),
        ConsensusCommitPrologueV1(ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1Deprecated,
        EndOfEpoch {
            commands: Vec<EndOfEpochTransactionKind>,
        },
        RandomnessStateUpdate(RandomnessStateUpdate),
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "TransactionKind")]
    enum BinaryTransactionKindRef<'a> {
        Programmable(&'a ProgrammableTransaction),
        Genesis(&'a GenesisTransaction),
        ConsensusCommitPrologueV1(&'a ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1Deprecated,
        EndOfEpoch(&'a Vec<EndOfEpochTransactionKind>),
        RandomnessStateUpdate(&'a RandomnessStateUpdate),
    }
    #[derive(serde::Deserialize)]
    #[serde(rename = "TransactionKind")]
    enum BinaryTransactionKind {
        Programmable(ProgrammableTransaction),
        Genesis(GenesisTransaction),
        ConsensusCommitPrologueV1(ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1Deprecated,
        EndOfEpoch(Vec<EndOfEpochTransactionKind>),
        RandomnessStateUpdate(RandomnessStateUpdate),
    }

    impl Serialize for TransactionKind {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    Self::Programmable(k) => ReadableTransactionKindRef::Programmable(k),
                    Self::Genesis(k) => ReadableTransactionKindRef::Genesis(k),
                    Self::ConsensusCommitPrologueV1(k) => {
                        ReadableTransactionKindRef::ConsensusCommitPrologueV1(k)
                    }
                    Self::AuthenticatorStateUpdateV1Deprecated => {
                        ReadableTransactionKindRef::AuthenticatorStateUpdateV1Deprecated
                    }
                    Self::EndOfEpoch(commands) => {
                        ReadableTransactionKindRef::EndOfEpoch { commands }
                    }
                    Self::RandomnessStateUpdate(k) => {
                        ReadableTransactionKindRef::RandomnessStateUpdate(k)
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    Self::Programmable(k) => BinaryTransactionKindRef::Programmable(k),
                    Self::Genesis(k) => BinaryTransactionKindRef::Genesis(k),
                    Self::ConsensusCommitPrologueV1(k) => {
                        BinaryTransactionKindRef::ConsensusCommitPrologueV1(k)
                    }
                    Self::AuthenticatorStateUpdateV1Deprecated => {
                        BinaryTransactionKindRef::AuthenticatorStateUpdateV1Deprecated
                    }
                    Self::EndOfEpoch(k) => BinaryTransactionKindRef::EndOfEpoch(k),
                    Self::RandomnessStateUpdate(k) => {
                        BinaryTransactionKindRef::RandomnessStateUpdate(k)
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TransactionKind {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableTransactionKind::deserialize(deserializer).map(|readable| match readable {
                    ReadableTransactionKind::Programmable(k) => Self::Programmable(k),
                    ReadableTransactionKind::Genesis(k) => Self::Genesis(k),
                    ReadableTransactionKind::ConsensusCommitPrologueV1(k) => {
                        Self::ConsensusCommitPrologueV1(k)
                    }
                    ReadableTransactionKind::AuthenticatorStateUpdateV1Deprecated => {
                        Self::AuthenticatorStateUpdateV1Deprecated
                    }
                    ReadableTransactionKind::EndOfEpoch { commands } => Self::EndOfEpoch(commands),
                    ReadableTransactionKind::RandomnessStateUpdate(k) => {
                        Self::RandomnessStateUpdate(k)
                    }
                })
            } else {
                BinaryTransactionKind::deserialize(deserializer).map(|binary| match binary {
                    BinaryTransactionKind::Programmable(k) => Self::Programmable(k),
                    BinaryTransactionKind::Genesis(k) => Self::Genesis(k),
                    BinaryTransactionKind::ConsensusCommitPrologueV1(k) => {
                        Self::ConsensusCommitPrologueV1(k)
                    }
                    BinaryTransactionKind::AuthenticatorStateUpdateV1Deprecated => {
                        Self::AuthenticatorStateUpdateV1Deprecated
                    }
                    BinaryTransactionKind::EndOfEpoch(k) => Self::EndOfEpoch(k),
                    BinaryTransactionKind::RandomnessStateUpdate(k) => {
                        Self::RandomnessStateUpdate(k)
                    }
                })
            }
        }
    }
}

mod version_assignments {
    use super::*;
    use crate::transaction::{
        CancelledTransaction, ConsensusDeterminedVersionAssignments, VersionAssignment,
    };

    #[derive(serde::Serialize)]
    #[serde(rename = "ConsensusDeterminedVersionAssignments")]
    enum ConsensusDeterminedVersionAssignmentsRef<'a> {
        CancelledTransactions(&'a Vec<CancelledTransaction>),
    }

    /// Uses an enum to allow for future expansion of the
    /// ConsensusDeterminedVersionAssignments.
    #[derive(serde::Deserialize)]
    #[serde(rename = "ConsensusDeterminedVersionAssignments")]
    enum ConsensusDeterminedVersionAssignmentsOwned {
        CancelledTransactions(Vec<CancelledTransaction>),
    }

    impl Serialize for ConsensusDeterminedVersionAssignments {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::CancelledTransactions {
                    cancelled_transactions,
                } => ConsensusDeterminedVersionAssignmentsRef::CancelledTransactions(
                    cancelled_transactions,
                ),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ConsensusDeterminedVersionAssignments {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            ConsensusDeterminedVersionAssignmentsOwned::deserialize(deserializer).map(|owned| {
                match owned {
                    ConsensusDeterminedVersionAssignmentsOwned::CancelledTransactions(
                        cancelled_transactions,
                    ) => Self::CancelledTransactions {
                        cancelled_transactions,
                    },
                }
            })
        }
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "VersionAssignment")]
    struct BinaryVersionAssignmentRef<'a>(&'a ObjectId, &'a crate::Version);

    #[derive(serde::Deserialize)]
    #[serde(rename = "VersionAssignment")]
    struct BinaryVersionAssignment(ObjectId, crate::Version);

    impl Serialize for VersionAssignment {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                use serde::ser::SerializeTuple;
                let mut tuple = serializer.serialize_tuple(2)?;
                tuple.serialize_element(&self.object_id)?;
                tuple.serialize_element(&self.version)?;
                tuple.end()
            } else {
                let binary = BinaryVersionAssignmentRef(&self.object_id, &self.version);
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for VersionAssignment {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let (object_id, version): (ObjectId, u64) = Deserialize::deserialize(deserializer)?;
                Ok(VersionAssignment {
                    object_id,
                    version: version.into(),
                })
            } else {
                BinaryVersionAssignment::deserialize(deserializer).map(|b| VersionAssignment {
                    object_id: b.0,
                    version: b.1,
                })
            }
        }
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "CancelledTransaction")]
    struct BinaryCancelledTransactionRef<'a>(&'a crate::Digest, &'a Vec<VersionAssignment>);

    #[derive(serde::Deserialize)]
    #[serde(rename = "CancelledTransaction")]
    struct BinaryCancelledTransaction(crate::Digest, Vec<VersionAssignment>);

    impl Serialize for CancelledTransaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                use serde::ser::SerializeTuple;
                let mut tuple = serializer.serialize_tuple(2)?;
                tuple.serialize_element(&self.digest)?;
                tuple.serialize_element(&self.version_assignments)?;
                tuple.end()
            } else {
                let binary = BinaryCancelledTransactionRef(&self.digest, &self.version_assignments);
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for CancelledTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let (digest, version_assignments): (crate::Digest, Vec<VersionAssignment>) =
                    Deserialize::deserialize(deserializer)?;
                Ok(CancelledTransaction {
                    digest,
                    version_assignments,
                })
            } else {
                BinaryCancelledTransaction::deserialize(deserializer).map(|b| {
                    CancelledTransaction {
                        digest: b.0,
                        version_assignments: b.1,
                    }
                })
            }
        }
    }
}

mod input_argument {
    use super::*;
    use crate::{
        Version,
        transaction::{Input, SharedObjectReference},
    };

    #[derive(serde::Deserialize, serde::Serialize)]
    struct PureInput {
        #[serde(with = "::serde_with::As::<crate::_serde::Base64Encoded>")]
        value: Vec<u8>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    #[serde(rename = "Input")]
    enum ReadableInput {
        /// A move value serialized as BCS.
        ///
        /// For normal operations this is required to be a move primitive type
        /// and not contain structs or objects.
        Pure(PureInput),
        /// A move object that is either immutable or address owned
        ImmutableOrOwned(ObjectReference),
        /// A move object whose owner is "Shared"
        Shared {
            object_id: ObjectId,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            initial_shared_version: Version,
            mutable: bool,
        },
        /// A move object that is attempted to be received in this transaction.
        Receiving(ObjectReference),
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    enum CallArg {
        Pure(#[serde(with = "::serde_with::As::<::serde_with::Bytes>")] Vec<u8>),
        Object(ObjectArg),
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    enum ObjectArg {
        ImmutableOrOwned(ObjectReference),
        Shared {
            object_id: ObjectId,
            initial_shared_version: Version,
            mutable: bool,
        },
        Receiving(ObjectReference),
    }

    impl Serialize for Input {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    Input::Pure(value) => ReadableInput::Pure(PureInput { value }),
                    Input::ImmutableOrOwned(object_ref) => {
                        ReadableInput::ImmutableOrOwned(object_ref)
                    }
                    Input::Shared(SharedObjectReference {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }) => ReadableInput::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    },
                    Input::Receiving(object_ref) => ReadableInput::Receiving(object_ref),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    Input::Pure(value) => CallArg::Pure(value),
                    Input::ImmutableOrOwned(object_ref) => {
                        CallArg::Object(ObjectArg::ImmutableOrOwned(object_ref))
                    }
                    Input::Shared(SharedObjectReference {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }) => CallArg::Object(ObjectArg::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }),
                    Input::Receiving(object_ref) => {
                        CallArg::Object(ObjectArg::Receiving(object_ref))
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Input {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableInput::deserialize(deserializer).map(|readable| match readable {
                    ReadableInput::Pure(PureInput { value }) => Input::Pure(value),
                    ReadableInput::ImmutableOrOwned(object_ref) => {
                        Input::ImmutableOrOwned(object_ref)
                    }
                    ReadableInput::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    } => Input::Shared(SharedObjectReference {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }),
                    ReadableInput::Receiving(object_ref) => Input::Receiving(object_ref),
                })
            } else {
                CallArg::deserialize(deserializer).map(|binary| match binary {
                    CallArg::Pure(value) => Input::Pure(value),
                    CallArg::Object(ObjectArg::ImmutableOrOwned(object_ref)) => {
                        Input::ImmutableOrOwned(object_ref)
                    }
                    CallArg::Object(ObjectArg::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }) => Input::Shared(SharedObjectReference {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }),
                    CallArg::Object(ObjectArg::Receiving(object_ref)) => {
                        Input::Receiving(object_ref)
                    }
                })
            }
        }
    }
}

mod argument {
    use super::*;

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "Argument")]
    enum ReadableArgument {
        /// # Gas
        Gas,
        /// # Input
        Input(u16),
        /// # Result
        Result(u16),
        /// # NestedResult
        NestedResult(u16, u16),
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "Argument")]
    enum BinaryArgument {
        Gas,
        Input(u16),
        Result(u16),
        NestedResult(u16, u16),
    }

    impl Serialize for Argument {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match *self {
                    Argument::Gas => ReadableArgument::Gas,
                    Argument::Input(input) => ReadableArgument::Input(input),
                    Argument::Result(result) => ReadableArgument::Result(result),
                    Argument::NestedResult(result, subresult) => {
                        ReadableArgument::NestedResult(result, subresult)
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match *self {
                    Argument::Gas => BinaryArgument::Gas,
                    Argument::Input(input) => BinaryArgument::Input(input),
                    Argument::Result(result) => BinaryArgument::Result(result),
                    Argument::NestedResult(result, subresult) => {
                        BinaryArgument::NestedResult(result, subresult)
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Argument {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableArgument::deserialize(deserializer).map(|readable| match readable {
                    ReadableArgument::Gas => Argument::Gas,
                    ReadableArgument::Input(input) => Argument::Input(input),
                    ReadableArgument::Result(result) => Argument::Result(result),
                    ReadableArgument::NestedResult(result, subresult) => {
                        Argument::NestedResult(result, subresult)
                    }
                })
            } else {
                BinaryArgument::deserialize(deserializer).map(|binary| match binary {
                    BinaryArgument::Gas => Argument::Gas,
                    BinaryArgument::Input(input) => Argument::Input(input),
                    BinaryArgument::Result(result) => Argument::Result(result),
                    BinaryArgument::NestedResult(result, subresult) => {
                        Argument::NestedResult(result, subresult)
                    }
                })
            }
        }
    }
}

pub(crate) use signed_transaction::SignedTransactionWithIntentMessage;

mod signed_transaction {
    use serde::ser::SerializeSeq;

    use super::*;
    use crate::{
        Intent, UserSignature,
        transaction::{SignedTransaction, Transaction},
    };

    pub(crate) struct SignedTransactionWithIntentMessage;

    #[derive(serde::Serialize)]
    #[serde(rename = "SignedTransaction")]
    struct BinarySignedTransactionWithIntentMessageRef<'a> {
        intent: &'a Intent,
        transaction: &'a Transaction,
        signatures: &'a Vec<UserSignature>,
    }

    #[derive(serde::Deserialize)]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "intent-signed-transaction")
    )]
    #[serde(rename = "SignedTransaction")]
    struct BinarySignedTransactionWithIntentMessage {
        intent: Intent,
        transaction: Transaction,
        signatures: Vec<UserSignature>,
    }

    impl SerializeAs<SignedTransaction> for SignedTransactionWithIntentMessage {
        fn serialize_as<S>(
            transaction: &SignedTransaction,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                transaction.serialize(serializer)
            } else {
                let SignedTransaction {
                    transaction,
                    signatures,
                } = transaction;
                let intent = Intent {
                    scope: crate::IntentScope::TransactionData,
                    version: crate::IntentVersion::V0,
                    app_id: crate::IntentAppId::Iota,
                };
                let binary = BinarySignedTransactionWithIntentMessageRef {
                    intent: &intent,
                    transaction,
                    signatures,
                };

                let mut s = serializer.serialize_seq(Some(1))?;
                s.serialize_element(&binary)?;
                s.end()
            }
        }
    }

    impl<'de> DeserializeAs<'de, SignedTransaction> for SignedTransactionWithIntentMessage {
        fn deserialize_as<D>(deserializer: D) -> Result<SignedTransaction, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                SignedTransaction::deserialize(deserializer)
            } else {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = SignedTransaction;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("expected a sequence with length 1")
                    }

                    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::SeqAccess<'de>,
                    {
                        if seq.size_hint().is_some_and(|size| size != 1) {
                            return Err(serde::de::Error::custom(
                                "expected a sequence with length 1",
                            ));
                        }

                        let BinarySignedTransactionWithIntentMessage {
                            intent:
                                Intent {
                                    scope: crate::IntentScope::TransactionData,
                                    version: crate::IntentVersion::V0,
                                    app_id: crate::IntentAppId::Iota,
                                },
                            transaction,
                            signatures,
                        } = seq.next_element()?.ok_or_else(|| {
                            serde::de::Error::custom("expected a sequence with length 1")
                        })?
                        else {
                            return Err(serde::de::Error::custom("invalid intent"));
                        };
                        Ok(SignedTransaction {
                            transaction,
                            signatures,
                        })
                    }
                }

                deserializer.deserialize_seq(V)
            }
        }
    }
}

/// Deserialize an `Identifier` without validating that it is a valid Move
/// identifier. This is used for deserializing the module in `MoveCall`
/// commands, where BCS bytes could contain invalid identifiers but we still
/// want to be able to deserialize them and let the move VM handle the
/// validation.
pub(super) fn deserialize_ident_unchecked<'de, D>(d: D) -> Result<Identifier, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if d.is_human_readable() {
        serde::Deserialize::deserialize(d)
    } else {
        let s: String = serde::Deserialize::deserialize(d)?;
        Ok(Identifier::new_unchecked(s))
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::{
        Digest, ObjectId, ObjectReference, Version,
        transaction::{Argument, Input, SharedObjectReference, Transaction},
    };

    #[test]
    fn argument() {
        let test_cases = [
            (Argument::Gas, serde_json::json!("Gas")),
            (Argument::Input(1), serde_json::json!({"Input": 1})),
            (Argument::Result(2), serde_json::json!({"Result": 2})),
            (
                Argument::NestedResult(3, 4),
                serde_json::json!({"NestedResult": [3, 4]}),
            ),
        ];

        for (case, expected) in test_cases {
            let actual = serde_json::to_value(case).unwrap();
            assert_eq!(actual, expected);
            println!("{actual}");

            let deser = serde_json::from_value(expected).unwrap();
            assert_eq!(case, deser);
        }
    }

    #[test]
    fn input_argument() {
        let test_cases = [
            (
                Input::Pure(vec![1, 2, 3, 4]),
                serde_json::json!({
                  "pure": {
                    "value": "AQIDBA=="
                  }
                }),
            ),
            (
                Input::ImmutableOrOwned(ObjectReference::new(
                    ObjectId::ZERO,
                    Version::from_u64(1),
                    Digest::ZERO,
                )),
                serde_json::json!({
                  "immutable_or_owned": [
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    1,
                    "11111111111111111111111111111111"
                  ]
                }),
            ),
            (
                Input::Shared(SharedObjectReference {
                    object_id: ObjectId::ZERO,
                    initial_shared_version: Version::from_u64(1),
                    mutable: true,
                }),
                serde_json::json!({
                  "shared": {
                    "object_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "initial_shared_version": "1",
                    "mutable": true
                  }
                }),
            ),
            (
                Input::Receiving(ObjectReference::new(
                    ObjectId::ZERO,
                    Version::from_u64(1),
                    Digest::ZERO,
                )),
                serde_json::json!({
                  "receiving": [
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    1,
                    "11111111111111111111111111111111"
                  ]
                }),
            ),
        ];

        for (case, expected) in test_cases {
            let actual = serde_json::to_value(&case).unwrap();
            assert_eq!(actual, expected);
            println!("{actual}");

            let deser = serde_json::from_value(expected).unwrap();
            assert_eq!(case, deser);
        }
    }

    #[test]
    fn transaction_fixtures() {
        // Look in the fixtures folder to see how to update them
        const GENESIS_TRANSACTION: &str = include_str!("fixtures/genesis");
        const CONSENSUS_PROLOGUE: &str = include_str!("fixtures/consensus-commit-prologue-v1");
        const EPOCH_CHANGE: &str = include_str!("fixtures/change-epoch-v2");
        const PTB: &str = include_str!("fixtures/ptb");

        for fixture in [GENESIS_TRANSACTION, CONSENSUS_PROLOGUE, EPOCH_CHANGE, PTB] {
            let fixture = Base64::decode_vec(fixture.trim()).unwrap();
            let tx: Transaction = bcs::from_bytes(&fixture).unwrap();
            assert_eq!(bcs::to_bytes(&tx).unwrap(), fixture);

            let json = serde_json::to_string_pretty(&tx).unwrap();
            println!("{json}");
            assert_eq!(tx, serde_json::from_str(&json).unwrap());
        }
    }
}
