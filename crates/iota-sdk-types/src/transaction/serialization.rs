// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

use super::Argument;
use crate::{ObjectId, ObjectReference};

mod transaction_kind {
    use super::*;
    use crate::transaction::{
        AuthenticatorStateUpdateV1, ConsensusCommitPrologueV1, EndOfEpochTransactionKind,
        GenesisTransaction, ProgrammableTransaction, RandomnessStateUpdate, TransactionKind,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableTransactionKindRef<'a> {
        ProgrammableTransaction(&'a ProgrammableTransaction),
        Genesis(&'a GenesisTransaction),
        ConsensusCommitPrologueV1(&'a ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1(&'a AuthenticatorStateUpdateV1),
        EndOfEpoch {
            commands: &'a Vec<EndOfEpochTransactionKind>,
        },
        RandomnessStateUpdate(&'a RandomnessStateUpdate),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    #[serde(rename = "TransactionKind")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableTransactionKind {
        ProgrammableTransaction(ProgrammableTransaction),
        Genesis(GenesisTransaction),
        ConsensusCommitPrologueV1(ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1(AuthenticatorStateUpdateV1),
        EndOfEpoch {
            commands: Vec<EndOfEpochTransactionKind>,
        },
        RandomnessStateUpdate(RandomnessStateUpdate),
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for TransactionKind {
        fn schema_name() -> String {
            ReadableTransactionKind::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ReadableTransactionKind::json_schema(gen)
        }
    }

    #[derive(serde::Serialize)]
    enum BinaryTransactionKindRef<'a> {
        ProgrammableTransaction(&'a ProgrammableTransaction),
        Genesis(&'a GenesisTransaction),
        ConsensusCommitPrologueV1(&'a ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1(&'a AuthenticatorStateUpdateV1),
        EndOfEpoch(&'a Vec<EndOfEpochTransactionKind>),
        RandomnessStateUpdate(&'a RandomnessStateUpdate),
    }
    #[derive(serde::Deserialize)]
    enum BinaryTransactionKind {
        ProgrammableTransaction(ProgrammableTransaction),
        Genesis(GenesisTransaction),
        ConsensusCommitPrologueV1(ConsensusCommitPrologueV1),
        AuthenticatorStateUpdateV1(AuthenticatorStateUpdateV1),
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
                    Self::ProgrammableTransaction(k) => {
                        ReadableTransactionKindRef::ProgrammableTransaction(k)
                    }
                    Self::Genesis(k) => ReadableTransactionKindRef::Genesis(k),
                    Self::ConsensusCommitPrologueV1(k) => {
                        ReadableTransactionKindRef::ConsensusCommitPrologueV1(k)
                    }
                    Self::AuthenticatorStateUpdateV1(k) => {
                        ReadableTransactionKindRef::AuthenticatorStateUpdateV1(k)
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
                    Self::ProgrammableTransaction(k) => {
                        BinaryTransactionKindRef::ProgrammableTransaction(k)
                    }
                    Self::Genesis(k) => BinaryTransactionKindRef::Genesis(k),
                    Self::ConsensusCommitPrologueV1(k) => {
                        BinaryTransactionKindRef::ConsensusCommitPrologueV1(k)
                    }
                    Self::AuthenticatorStateUpdateV1(k) => {
                        BinaryTransactionKindRef::AuthenticatorStateUpdateV1(k)
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
                    ReadableTransactionKind::ProgrammableTransaction(k) => {
                        Self::ProgrammableTransaction(k)
                    }
                    ReadableTransactionKind::Genesis(k) => Self::Genesis(k),
                    ReadableTransactionKind::ConsensusCommitPrologueV1(k) => {
                        Self::ConsensusCommitPrologueV1(k)
                    }
                    ReadableTransactionKind::AuthenticatorStateUpdateV1(k) => {
                        Self::AuthenticatorStateUpdateV1(k)
                    }
                    ReadableTransactionKind::EndOfEpoch { commands } => Self::EndOfEpoch(commands),
                    ReadableTransactionKind::RandomnessStateUpdate(k) => {
                        Self::RandomnessStateUpdate(k)
                    }
                })
            } else {
                BinaryTransactionKind::deserialize(deserializer).map(|binary| match binary {
                    BinaryTransactionKind::ProgrammableTransaction(k) => {
                        Self::ProgrammableTransaction(k)
                    }
                    BinaryTransactionKind::Genesis(k) => Self::Genesis(k),
                    BinaryTransactionKind::ConsensusCommitPrologueV1(k) => {
                        Self::ConsensusCommitPrologueV1(k)
                    }
                    BinaryTransactionKind::AuthenticatorStateUpdateV1(k) => {
                        Self::AuthenticatorStateUpdateV1(k)
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

mod end_of_epoch {
    use super::*;
    use crate::transaction::{
        AuthenticatorStateExpire, ChangeEpoch, ChangeEpochV2, ChangeEpochV3,
        EndOfEpochTransactionKind,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableEndOfEpochTransactionKindRef<'a> {
        ChangeEpoch(&'a ChangeEpoch),
        ChangeEpochV2(&'a ChangeEpochV2),
        ChangeEpochV3(&'a ChangeEpochV3),
        AuthenticatorStateCreate,
        AuthenticatorStateExpire(&'a AuthenticatorStateExpire),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableEndOfEpochTransactionKind {
        ChangeEpoch(ChangeEpoch),
        ChangeEpochV2(ChangeEpochV2),
        ChangeEpochV3(ChangeEpochV3),
        AuthenticatorStateCreate,
        AuthenticatorStateExpire(AuthenticatorStateExpire),
    }

    #[derive(serde::Serialize)]
    enum BinaryEndOfEpochTransactionKindRef<'a> {
        ChangeEpoch(&'a ChangeEpoch),
        ChangeEpochV2(&'a ChangeEpochV2),
        ChangeEpochV3(&'a ChangeEpochV3),
        AuthenticatorStateCreate,
        AuthenticatorStateExpire(&'a AuthenticatorStateExpire),
    }

    #[derive(serde::Deserialize)]
    enum BinaryEndOfEpochTransactionKind {
        ChangeEpoch(ChangeEpoch),
        ChangeEpochV2(ChangeEpochV2),
        ChangeEpochV3(ChangeEpochV3),
        AuthenticatorStateCreate,
        AuthenticatorStateExpire(AuthenticatorStateExpire),
    }

    impl Serialize for EndOfEpochTransactionKind {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    Self::ChangeEpoch(k) => ReadableEndOfEpochTransactionKindRef::ChangeEpoch(k),
                    Self::ChangeEpochV2(k) => {
                        ReadableEndOfEpochTransactionKindRef::ChangeEpochV2(k)
                    }
                    Self::ChangeEpochV3(k) => {
                        ReadableEndOfEpochTransactionKindRef::ChangeEpochV3(k)
                    }
                    Self::AuthenticatorStateCreate => {
                        ReadableEndOfEpochTransactionKindRef::AuthenticatorStateCreate
                    }
                    Self::AuthenticatorStateExpire(k) => {
                        ReadableEndOfEpochTransactionKindRef::AuthenticatorStateExpire(k)
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    Self::ChangeEpoch(k) => BinaryEndOfEpochTransactionKindRef::ChangeEpoch(k),
                    Self::ChangeEpochV2(k) => BinaryEndOfEpochTransactionKindRef::ChangeEpochV2(k),
                    Self::ChangeEpochV3(k) => BinaryEndOfEpochTransactionKindRef::ChangeEpochV3(k),

                    Self::AuthenticatorStateCreate => {
                        BinaryEndOfEpochTransactionKindRef::AuthenticatorStateCreate
                    }
                    Self::AuthenticatorStateExpire(k) => {
                        BinaryEndOfEpochTransactionKindRef::AuthenticatorStateExpire(k)
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for EndOfEpochTransactionKind {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableEndOfEpochTransactionKind::deserialize(deserializer).map(|readable| {
                    match readable {
                        ReadableEndOfEpochTransactionKind::ChangeEpoch(k) => Self::ChangeEpoch(k),
                        ReadableEndOfEpochTransactionKind::ChangeEpochV2(k) => {
                            Self::ChangeEpochV2(k)
                        }
                        ReadableEndOfEpochTransactionKind::ChangeEpochV3(k) => {
                            Self::ChangeEpochV3(k)
                        }
                        ReadableEndOfEpochTransactionKind::AuthenticatorStateCreate => {
                            Self::AuthenticatorStateCreate
                        }
                        ReadableEndOfEpochTransactionKind::AuthenticatorStateExpire(k) => {
                            Self::AuthenticatorStateExpire(k)
                        }
                    }
                })
            } else {
                BinaryEndOfEpochTransactionKind::deserialize(deserializer).map(
                    |binary| match binary {
                        BinaryEndOfEpochTransactionKind::ChangeEpoch(k) => Self::ChangeEpoch(k),
                        BinaryEndOfEpochTransactionKind::ChangeEpochV2(k) => Self::ChangeEpochV2(k),
                        BinaryEndOfEpochTransactionKind::ChangeEpochV3(k) => Self::ChangeEpochV3(k),

                        BinaryEndOfEpochTransactionKind::AuthenticatorStateCreate => {
                            Self::AuthenticatorStateCreate
                        }
                        BinaryEndOfEpochTransactionKind::AuthenticatorStateExpire(k) => {
                            Self::AuthenticatorStateExpire(k)
                        }
                    },
                )
            }
        }
    }
}

mod version_assignments {
    use super::*;
    use crate::transaction::{CancelledTransaction, ConsensusDeterminedVersionAssignments};

    #[derive(serde::Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableConsensusDeterminedVersionAssignmentsRef<'a> {
        CancelledTransactions {
            cancelled_transactions: &'a Vec<CancelledTransaction>,
        },
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableConsensusDeterminedVersionAssignments {
        CancelledTransactions {
            cancelled_transactions: Vec<CancelledTransaction>,
        },
    }

    #[derive(serde::Serialize)]
    enum BinaryConsensusDeterminedVersionAssignmentsRef<'a> {
        CancelledTransactions {
            cancelled_transactions: &'a Vec<CancelledTransaction>,
        },
    }

    #[derive(serde::Deserialize)]
    enum BinaryConsensusDeterminedVersionAssignments {
        CancelledTransactions {
            cancelled_transactions: Vec<CancelledTransaction>,
        },
    }

    impl Serialize for ConsensusDeterminedVersionAssignments {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    Self::CancelledTransactions {
                        cancelled_transactions,
                    } => ReadableConsensusDeterminedVersionAssignmentsRef::CancelledTransactions {
                        cancelled_transactions,
                    },
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    Self::CancelledTransactions {
                        cancelled_transactions,
                    } => BinaryConsensusDeterminedVersionAssignmentsRef::CancelledTransactions {
                        cancelled_transactions,
                    },
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ConsensusDeterminedVersionAssignments {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableConsensusDeterminedVersionAssignments::deserialize(deserializer).map(
                    |readable| match readable {
                        ReadableConsensusDeterminedVersionAssignments::CancelledTransactions {
                            cancelled_transactions,
                        } => Self::CancelledTransactions {
                            cancelled_transactions,
                        },
                    },
                )
            } else {
                BinaryConsensusDeterminedVersionAssignments::deserialize(deserializer).map(
                    |binary| match binary {
                        BinaryConsensusDeterminedVersionAssignments::CancelledTransactions {
                            cancelled_transactions,
                        } => Self::CancelledTransactions {
                            cancelled_transactions,
                        },
                    },
                )
            }
        }
    }
}

mod input_argument {
    use super::*;
    use crate::transaction::Input;

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum ReadableInput {
        Pure {
            #[serde(with = "::serde_with::As::<crate::_serde::Base64Encoded>")]
            value: Vec<u8>,
        },
        ImmutableOrOwned(ObjectReference),
        Shared {
            object_id: ObjectId,
            #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
            initial_shared_version: u64,
            mutable: bool,
        },
        Receiving(ObjectReference),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum CallArg {
        Pure(#[serde(with = "::serde_with::As::<::serde_with::Bytes>")] Vec<u8>),
        Object(ObjectArg),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum ObjectArg {
        ImmutableOrOwned(ObjectReference),
        Shared {
            object_id: ObjectId,
            initial_shared_version: u64,
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
                    Input::Pure { value } => ReadableInput::Pure { value },
                    Input::ImmutableOrOwned(object_ref) => {
                        ReadableInput::ImmutableOrOwned(object_ref)
                    }
                    Input::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    } => ReadableInput::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    },
                    Input::Receiving(object_ref) => ReadableInput::Receiving(object_ref),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    Input::Pure { value } => CallArg::Pure(value),
                    Input::ImmutableOrOwned(object_ref) => {
                        CallArg::Object(ObjectArg::ImmutableOrOwned(object_ref))
                    }
                    Input::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    } => CallArg::Object(ObjectArg::Shared {
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
                    ReadableInput::Pure { value } => Input::Pure { value },
                    ReadableInput::ImmutableOrOwned(object_ref) => {
                        Input::ImmutableOrOwned(object_ref)
                    }
                    ReadableInput::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    } => Input::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    },
                    ReadableInput::Receiving(object_ref) => Input::Receiving(object_ref),
                })
            } else {
                CallArg::deserialize(deserializer).map(|binary| match binary {
                    CallArg::Pure(value) => Input::Pure { value },
                    CallArg::Object(ObjectArg::ImmutableOrOwned(object_ref)) => {
                        Input::ImmutableOrOwned(object_ref)
                    }
                    CallArg::Object(ObjectArg::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    }) => Input::Shared {
                        object_id,
                        initial_shared_version,
                        mutable,
                    },
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

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename = "Argument", untagged, rename_all = "lowercase")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum ReadableArgument {
        /// # Gas
        Gas(Gas),
        /// # Input
        Input { input: u16 },
        /// # Result
        Result { result: u16 },
        /// # NestedResult
        NestedResult { result: (u16, u16) },
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Gas {
        Gas,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for Gas {
        fn schema_name() -> std::string::String {
            "GasArgument".to_owned()
        }

        fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            schemars::schema::Schema::Object(schemars::schema::SchemaObject {
                instance_type: Some(schemars::schema::InstanceType::String.into()),
                enum_values: Some(vec!["gas".into()]),
                ..Default::default()
            })
        }

        fn is_referenceable() -> bool {
            false
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for Argument {
        fn schema_name() -> String {
            ReadableArgument::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            ReadableArgument::json_schema(gen)
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
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
                    Argument::Gas => ReadableArgument::Gas(Gas::Gas),
                    Argument::Input(input) => ReadableArgument::Input { input },
                    Argument::Result(result) => ReadableArgument::Result { result },
                    Argument::NestedResult(result, subresult) => ReadableArgument::NestedResult {
                        result: (result, subresult),
                    },
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
                    ReadableArgument::Gas(_) => Argument::Gas,
                    ReadableArgument::Input { input } => Argument::Input(input),
                    ReadableArgument::Result { result } => Argument::Result(result),
                    ReadableArgument::NestedResult {
                        result: (result, subresult),
                    } => Argument::NestedResult(result, subresult),
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

mod command {
    use super::*;
    use crate::transaction::{
        Command, MakeMoveVector, MergeCoins, MoveCall, Publish, SplitCoins, TransferObjects,
        Upgrade,
    };

    #[derive(serde::Serialize)]
    #[serde(tag = "command", rename_all = "snake_case")]
    enum ReadableCommandRef<'a> {
        MoveCall(&'a MoveCall),
        TransferObjects(&'a TransferObjects),
        SplitCoins(&'a SplitCoins),
        MergeCoins(&'a MergeCoins),
        Publish(&'a Publish),
        MakeMoveVector(&'a MakeMoveVector),
        Upgrade(&'a Upgrade),
    }

    #[derive(serde::Deserialize)]
    #[serde(tag = "command", rename_all = "snake_case")]
    enum ReadableCommand {
        MoveCall(MoveCall),
        TransferObjects(TransferObjects),
        SplitCoins(SplitCoins),
        MergeCoins(MergeCoins),
        Publish(Publish),
        MakeMoveVector(MakeMoveVector),
        Upgrade(Upgrade),
    }

    #[derive(serde::Serialize)]
    enum BinaryCommandRef<'a> {
        MoveCall(&'a MoveCall),
        TransferObjects(&'a TransferObjects),
        SplitCoins(&'a SplitCoins),
        MergeCoins(&'a MergeCoins),
        Publish(&'a Publish),
        MakeMoveVector(&'a MakeMoveVector),
        Upgrade(&'a Upgrade),
    }

    #[derive(serde::Deserialize)]
    enum BinaryCommand {
        MoveCall(MoveCall),
        TransferObjects(TransferObjects),
        SplitCoins(SplitCoins),
        MergeCoins(MergeCoins),
        Publish(Publish),
        MakeMoveVector(MakeMoveVector),
        Upgrade(Upgrade),
    }

    impl Serialize for Command {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self {
                    Command::MoveCall(c) => ReadableCommandRef::MoveCall(c),
                    Command::TransferObjects(c) => ReadableCommandRef::TransferObjects(c),
                    Command::SplitCoins(c) => ReadableCommandRef::SplitCoins(c),
                    Command::MergeCoins(c) => ReadableCommandRef::MergeCoins(c),
                    Command::Publish(c) => ReadableCommandRef::Publish(c),
                    Command::MakeMoveVector(c) => ReadableCommandRef::MakeMoveVector(c),
                    Command::Upgrade(c) => ReadableCommandRef::Upgrade(c),
                };
                readable.serialize(serializer)
            } else {
                let binary = match self {
                    Command::MoveCall(c) => BinaryCommandRef::MoveCall(c),
                    Command::TransferObjects(c) => BinaryCommandRef::TransferObjects(c),
                    Command::SplitCoins(c) => BinaryCommandRef::SplitCoins(c),
                    Command::MergeCoins(c) => BinaryCommandRef::MergeCoins(c),
                    Command::Publish(c) => BinaryCommandRef::Publish(c),
                    Command::MakeMoveVector(c) => BinaryCommandRef::MakeMoveVector(c),
                    Command::Upgrade(c) => BinaryCommandRef::Upgrade(c),
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Command {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableCommand::deserialize(deserializer).map(|readable| match readable {
                    ReadableCommand::MoveCall(c) => Command::MoveCall(c),
                    ReadableCommand::TransferObjects(c) => Command::TransferObjects(c),
                    ReadableCommand::SplitCoins(c) => Command::SplitCoins(c),
                    ReadableCommand::MergeCoins(c) => Command::MergeCoins(c),
                    ReadableCommand::Publish(c) => Command::Publish(c),
                    ReadableCommand::MakeMoveVector(c) => Command::MakeMoveVector(c),
                    ReadableCommand::Upgrade(c) => Command::Upgrade(c),
                })
            } else {
                BinaryCommand::deserialize(deserializer).map(|binary| match binary {
                    BinaryCommand::MoveCall(c) => Command::MoveCall(c),
                    BinaryCommand::TransferObjects(c) => Command::TransferObjects(c),
                    BinaryCommand::SplitCoins(c) => Command::SplitCoins(c),
                    BinaryCommand::MergeCoins(c) => Command::MergeCoins(c),
                    BinaryCommand::Publish(c) => Command::Publish(c),
                    BinaryCommand::MakeMoveVector(c) => Command::MakeMoveVector(c),
                    BinaryCommand::Upgrade(c) => Command::Upgrade(c),
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
        UserSignature,
        transaction::{SignedTransaction, Transaction},
    };

    /// Intents are defined as:
    ///
    /// ```
    /// struct Intent {
    ///     scope: IntentScope,
    ///     version: IntentVersion,
    ///     app_id: IntendAppId,
    /// }
    ///
    /// enum IntentScope {
    ///     TransactionData = 0,         // Used for a user signature on a transaction data.
    ///     TransactionEffects = 1,      // Used for an authority signature on transaction effects.
    ///     CheckpointSummary = 2,       // Used for an authority signature on a checkpoint summary.
    ///     PersonalMessage = 3,         // Used for a user signature on a personal message.
    ///     SenderSignedTransaction = 4, // Used for an authority signature on a user signed transaction.
    ///     ProofOfPossession = 5,       /* Used as a signature representing an authority's proof of
    ///                                   * possession of its authority key. */
    ///     BridgeEventDeprecated = 6, /* Deprecated. Should not be reused. Introduced for bridge
    ///                                 * purposes but was never included in messages. */
    ///     ConsensusBlock = 7, // Used for consensus authority signature on block's digest.
    ///     DiscoveryPeers = 8, // Used for reporting peer addresses in discovery
    ///     AuthorityCapabilities = 9, // Used for authority capabilities from non-committee authorities.
    /// }
    ///
    /// enum IntentVersion {
    ///     V0 = 0,
    /// }
    ///
    /// enum IntendAppId {
    ///     Iota = 0,
    ///     Consensus = 1,
    /// }
    /// ```
    struct IntentMessageWrappedTransaction;

    impl SerializeAs<Transaction> for IntentMessageWrappedTransaction {
        fn serialize_as<S>(transaction: &Transaction, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            use serde::ser::SerializeTuple;

            let mut s = serializer.serialize_tuple(4)?;
            s.serialize_element(&0u8)?;
            s.serialize_element(&0u8)?;
            s.serialize_element(&0u8)?;
            s.serialize_element(transaction)?;
            s.end()
        }
    }

    impl<'de> DeserializeAs<'de, Transaction> for IntentMessageWrappedTransaction {
        fn deserialize_as<D>(deserializer: D) -> Result<Transaction, D::Error>
        where
            D: Deserializer<'de>,
        {
            let (scope, version, app, transaction): (u8, u8, u8, Transaction) =
                Deserialize::deserialize(deserializer)?;
            match (scope, version, app) {
                (0, 0, 0) => {}
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "invalid intent message ({scope}, {version}, {app})"
                    )));
                }
            }

            Ok(transaction)
        }
    }

    pub(crate) struct SignedTransactionWithIntentMessage;

    #[derive(serde::Serialize)]
    struct BinarySignedTransactionWithIntentMessageRef<'a> {
        #[serde(with = "::serde_with::As::<IntentMessageWrappedTransaction>")]
        transaction: &'a Transaction,
        signatures: &'a Vec<UserSignature>,
    }

    #[derive(serde::Deserialize)]
    struct BinarySignedTransactionWithIntentMessage {
        #[serde(with = "::serde_with::As::<IntentMessageWrappedTransaction>")]
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
                let binary = BinarySignedTransactionWithIntentMessageRef {
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
                            transaction,
                            signatures,
                        } = seq.next_element()?.ok_or_else(|| {
                            serde::de::Error::custom("expected a sequence with length 1")
                        })?;
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

mod transaction_expiration {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{EpochId, TransactionExpiration};

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename = "TransactionExpiration")]
    #[serde(rename_all = "lowercase")]
    enum ReadableTransactionExpiration {
        /// Validators wont sign a transaction unless the expiration Epoch
        /// is greater than or equal to the current epoch
        Epoch(
            #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))] EpochId,
        ),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum BinaryTransactionExpiration {
        /// The transaction has no expiration
        None,
        /// Validators wont sign a transaction unless the expiration Epoch
        /// is greater than or equal to the current epoch
        Epoch(EpochId),
    }

    impl Serialize for TransactionExpiration {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                match *self {
                    Self::None => None,
                    Self::Epoch(epoch) => Some(ReadableTransactionExpiration::Epoch(epoch)),
                }
                .serialize(serializer)
            } else {
                match *self {
                    Self::None => BinaryTransactionExpiration::None,
                    Self::Epoch(epoch) => BinaryTransactionExpiration::Epoch(epoch),
                }
                .serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for TransactionExpiration {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                Option::<ReadableTransactionExpiration>::deserialize(deserializer).map(|readable| {
                    match readable {
                        None => Self::None,
                        Some(ReadableTransactionExpiration::Epoch(epoch)) => Self::Epoch(epoch),
                    }
                })
            } else {
                BinaryTransactionExpiration::deserialize(deserializer).map(|binary| match binary {
                    BinaryTransactionExpiration::None => Self::None,
                    BinaryTransactionExpiration::Epoch(epoch) => Self::Epoch(epoch),
                })
            }
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for TransactionExpiration {
        fn schema_name() -> String {
            "TransactionExpiration".into()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            use schemars::{
                Map, Set,
                schema::{
                    InstanceType, ObjectValidation, Schema, SchemaObject, SubschemaValidation,
                },
            };
            let mut object = SchemaObject {
                instance_type: Some(InstanceType::Object.into()),
                object: Some(Box::new(ObjectValidation {
                    properties: {
                        let mut props = Map::new();
                        props.insert(
                            "epoch".to_owned(),
                            gen.subschema_for::<crate::_schemars::U64>(),
                        );
                        props
                    },
                    required: {
                        let mut required = Set::new();
                        required.insert("epoch".to_owned());
                        required
                    },
                    // Externally tagged variants must prohibit additional
                    // properties irrespective of the disposition of
                    // `deny_unknown_fields`. If additional properties were allowed
                    // one could easily construct an object that validated against
                    // multiple variants since here it's the properties rather than
                    // the values of a property that distinguish between variants.
                    additional_properties: Some(Box::new(false.into())),
                    ..Default::default()
                })),
                ..Default::default()
            };
            object.metadata().description = Some("Validators wont sign a transaction unless the expiration Epoch is greater than or equal to the current epoch".to_owned());
            let schema = Schema::Object(object);
            Schema::Object(SchemaObject {
                subschemas: Some(Box::new(SubschemaValidation {
                    one_of: Some(vec![
                        schema,
                        Schema::Object(SchemaObject {
                            instance_type: Some(InstanceType::Null.into()),
                            ..SchemaObject::default()
                        }),
                    ]),
                    ..Default::default()
                })),
                ..Default::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::{
        Digest, ObjectId, ObjectReference,
        transaction::{Argument, Input, Transaction},
    };

    #[test]
    fn argument() {
        let test_cases = [
            (Argument::Gas, serde_json::json!("gas")),
            (Argument::Input(1), serde_json::json!({"input": 1})),
            (Argument::Result(2), serde_json::json!({"result": 2})),
            (
                Argument::NestedResult(3, 4),
                serde_json::json!({"result": [3, 4]}),
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
                Input::Pure {
                    value: vec![1, 2, 3, 4],
                },
                serde_json::json!({
                  "type": "pure",
                  "value": "AQIDBA=="
                }),
            ),
            (
                Input::ImmutableOrOwned(ObjectReference::new(ObjectId::ZERO, 1, Digest::ZERO)),
                serde_json::json!({
                  "type": "immutable_or_owned",
                  "object_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "version": "1",
                  "digest": "11111111111111111111111111111111"
                }),
            ),
            (
                Input::Shared {
                    object_id: ObjectId::ZERO,
                    initial_shared_version: 1,
                    mutable: true,
                },
                serde_json::json!({
                  "type": "shared",
                  "object_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "initial_shared_version": "1",
                  "mutable": true
                }),
            ),
            (
                Input::Receiving(ObjectReference::new(ObjectId::ZERO, 1, Digest::ZERO)),
                serde_json::json!({
                  "type": "receiving",
                  "object_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "version": "1",
                  "digest": "11111111111111111111111111111111"
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
