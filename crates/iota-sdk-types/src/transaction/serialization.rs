// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

mod transaction {
    use super::*;
    use crate::{
        Address,
        transaction::{GasPayment, Transaction, TransactionExpiration, TransactionKind},
    };

    #[derive(serde_derive::Serialize)]
    #[serde(rename = "Transaction")]
    enum TransactionDataRef<'a> {
        V1(TransactionV1Ref<'a>),
    }

    #[derive(serde_derive::Deserialize)]
    #[serde(rename = "Transaction")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    enum TransactionData {
        V1(TransactionV1),
    }

    #[derive(serde_derive::Serialize)]
    #[serde(rename = "TransactionV1")]
    struct TransactionV1Ref<'a> {
        kind: &'a TransactionKind,
        sender: &'a Address,
        gas_payment: &'a GasPayment,
        expiration: &'a TransactionExpiration,
    }

    #[derive(serde_derive::Deserialize)]
    #[serde(rename = "TransactionV1")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct TransactionV1 {
        kind: TransactionKind,
        sender: Address,
        gas_payment: GasPayment,
        expiration: TransactionExpiration,
    }

    impl Serialize for Transaction {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let transaction = TransactionV1Ref {
                kind: &self.kind,
                sender: &self.sender,
                gas_payment: &self.gas_payment,
                expiration: &self.expiration,
            };

            TransactionDataRef::V1(transaction).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let TransactionData::V1(TransactionV1 {
                kind,
                sender,
                gas_payment,
                expiration,
            }) = Deserialize::deserialize(deserializer)?;

            Ok(Transaction {
                kind,
                sender,
                gas_payment,
                expiration,
            })
        }
    }
}

mod input_argument {
    use super::*;
    use crate::{ObjectId, ObjectReference, transaction::Input};

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    enum CallArg {
        Pure(#[serde(with = "::serde_with::As::<::serde_with::Bytes>")] Vec<u8>),
        Object(ObjectArg),
    }

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
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
                Input::Receiving(object_ref) => CallArg::Object(ObjectArg::Receiving(object_ref)),
            };
            binary.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Input {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
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
                CallArg::Object(ObjectArg::Receiving(object_ref)) => Input::Receiving(object_ref),
            })
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
    ///     app_id: AppId,
    /// }
    ///
    /// enum IntentVersion {
    ///     V0 = 0,
    /// }
    ///
    /// enum AppId {
    ///     Iota = 0,
    ///     Narwhal = 1,
    ///     Consensus = 2,
    /// }
    ///
    /// enum IntentScope {
    ///     TransactionData = 0,         // Used for a user signature on a transaction data.
    ///     TransactionEffects = 1,      // Used for an authority signature on transaction effects.
    ///     CheckpointSummary = 2,       // Used for an authority signature on a checkpoint summary.
    ///     PersonalMessage = 3,         // Used for a user signature on a personal message.
    ///     SenderSignedTransaction = 4, // Used for an authority signature on a user signed transaction.
    ///     ProofOfPossession = 5, // Used as a signature representing an authority's proof of possession of its authority protocol key.
    ///     BridgeEventDeprecated = 6, // Deprecated. Should not be reused. Introduced for bridge purposes but was never included in messages.
    ///     ConsensusBlock = 7,    // Used for consensus authority signature on block's digest
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

    #[derive(serde_derive::Serialize)]
    struct BinarySignedTransactionWithIntentMessageRef<'a> {
        #[serde(with = "::serde_with::As::<IntentMessageWrappedTransaction>")]
        transaction: &'a Transaction,
        signatures: &'a Vec<UserSignature>,
    }

    #[derive(serde_derive::Deserialize)]
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
    #[cfg(feature = "schemars")]
    use crate::TransactionExpiration;

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
                    // the values of a property that distingish between variants.
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
mod test {
    use base64ct::{Base64, Encoding};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use crate::transaction::Transaction;

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
