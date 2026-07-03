// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};

use crate::{Identifier, ObjectId, ObjectReference};

mod input_argument {
    use super::*;
    use crate::{
        Version,
        transaction::{Input, SharedObjectReference},
    };

    // Mirrors the default derived serialization of `Input`; the manual impl
    // only exists to keep the BCS form as the `CallArg`/`ObjectArg` protocol
    // encoding below.
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "Input")]
    enum ReadableInput {
        /// A move value serialized as BCS.
        ///
        /// For normal operations this is required to be a move primitive type
        /// and not contain structs or objects.
        Pure(#[serde(with = "crate::_serde::ReadableBase64Encoded")] Vec<u8>),
        /// A move object that is either immutable or address owned
        ImmutableOrOwned(ObjectReference),
        /// A move object whose owner is "Shared"
        Shared(SharedObjectReference),
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
                    Input::Pure(value) => ReadableInput::Pure(value),
                    Input::ImmutableOrOwned(object_ref) => {
                        ReadableInput::ImmutableOrOwned(object_ref)
                    }
                    Input::Shared(shared) => ReadableInput::Shared(shared),
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
                    ReadableInput::Pure(value) => Input::Pure(value),
                    ReadableInput::ImmutableOrOwned(object_ref) => {
                        Input::ImmutableOrOwned(object_ref)
                    }
                    ReadableInput::Shared(shared) => Input::Shared(shared),
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
        ObjectDigest, ObjectId, ObjectReference, Version,
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
        let object_ref = serde_json::json!({
            "object_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "version": "1",
            "digest": "11111111111111111111111111111111"
        });
        let test_cases = [
            (
                Input::Pure(vec![1, 2, 3, 4]),
                serde_json::json!({ "Pure": "AQIDBA==" }),
            ),
            (
                Input::ImmutableOrOwned(ObjectReference::new(
                    ObjectId::ZERO,
                    Version::from_u64(1),
                    ObjectDigest::ZERO,
                )),
                serde_json::json!({ "ImmutableOrOwned": object_ref }),
            ),
            (
                Input::Shared(SharedObjectReference {
                    object_id: ObjectId::ZERO,
                    initial_shared_version: Version::from_u64(1),
                    mutable: true,
                }),
                serde_json::json!({
                  "Shared": {
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
                    ObjectDigest::ZERO,
                )),
                serde_json::json!({ "Receiving": object_ref }),
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
