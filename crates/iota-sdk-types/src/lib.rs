// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core type definitions for the IOTA blockchain.
//!
//! [IOTA] is a next-generation smart contract platform with high throughput,
//! low latency, and an asset-oriented programming model powered by the Move
//! programming language. This crate provides type definitions for working with
//! the data that makes up the IOTA blockchain.
//!
//! [IOTA]: https://iota.org
//!
//! # BCS
//!
//! [BCS] is the serialization format used to represent the state of the
//! blockchain and is used extensively throughout the IOTA ecosystem. In
//! particular the BCS format is leveraged because it _"guarantees canonical
//! serialization, meaning that for any given data type, there is a one-to-one
//! correspondence between in-memory values and valid byte representations."_
//! One benefit of this property is to allow different entities in the ecosystem
//! to all agree on how a particular type should be interpreted and more
//! importantly define a deterministic representation for hashing and signing.
//!
//! This library strives to guarantee that the types defined are fully
//! BCS-compatible with the data that the network produces. The one caveat to
//! this would be that as the IOTA protocol evolves, new type variants are added
//! and older versions of this library may not support those newly
//! added variants. The expectation is that the most recent release of this
//! library will support new variants and types as they are released to IOTA's
//! `testnet` network.
//!
//! See the documentation for the various types defined by this crate for an
//! example of their BCS serialized representation. In addition to the format
//! itself, some types have an extra layer of verification and may impose
//! additional restrictions on valid byte representations above and beyond those
//! already provided by BCS. In these instances the documentation for those
//! types will clearly specify these additional restrictions.
//!
//! [BCS]: https://docs.rs/bcs
//!
//! # Feature flags
//!
//! This library uses a set of [feature flags] to reduce the number of
//! dependencies and amount of compiled code. By default, no features are
//! enabled which allows one to enable a subset specifically for their use case.
//! Below is a list of the available feature flags.
//!
//! - `schemars`: Enables JSON schema generation using the [schemars] library.
//! - `serde`: Enables support for serializing and deserializing types to/from
//!   BCS utilizing [serde] library.
//! - `rand`: Enables support for generating random instances of a number of
//!   types via the [rand] library.
//! - `hash`: Enables support for hashing, which is required for deriving
//!   addresses and calculating digests for various types.
//! - `proptest`: Enables support for the [proptest] library by providing
//!   implementations of [proptest::arbitrary::Arbitrary] for many types.
//!
//! [feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
//! [serde]: https://docs.rs/serde
//! [rand]: https://docs.rs/rand
//! [proptest]: https://docs.rs/proptest
//! [schemars]: https://docs.rs/schemars
//! [proptest::arbitrary::Arbitrary]: https://docs.rs/proptest/latest/proptest/arbitrary/trait.Arbitrary.html

#![cfg_attr(doc_cfg, feature(doc_cfg))]

#[cfg(feature = "hash")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hash")))]
pub mod hash;

mod address;
mod checkpoint;
mod crypto;
mod digest;
mod effects;
mod events;
mod execution_status;
pub mod framework;
mod gas;
mod object;
mod object_id;
mod transaction;
mod type_tag;
mod u256;

pub use address::{Address, AddressParseError};
pub use checkpoint::{
    CheckpointCommitment, CheckpointContents, CheckpointData, CheckpointSequenceNumber,
    CheckpointSummary, CheckpointTimestamp, CheckpointTransaction, CheckpointTransactionInfo,
    EndOfEpochData, EpochId, ProtocolVersion, SignedCheckpointSummary, StakeUnit,
};
pub use crypto::{
    Bls12381PublicKey, Bls12381Signature, Bn254FieldElement, CircomG1, CircomG2, Claim,
    Ed25519PublicKey, Ed25519Signature, Intent, IntentAppId, IntentScope, IntentVersion, Jwk,
    JwkId, MultisigAggregatedSignature, MultisigCommittee, MultisigMember, MultisigMemberPublicKey,
    MultisigMemberSignature, PasskeyAuthenticator, PasskeyPublicKey, Secp256k1PublicKey,
    Secp256k1Signature, Secp256r1PublicKey, Secp256r1Signature, SignatureScheme, SimpleSignature,
    UserSignature, ValidatorAggregatedSignature, ValidatorCommittee, ValidatorCommitteeMember,
    ValidatorSignature, ZkLoginAuthenticator, ZkLoginInputs, ZkLoginProof, ZkLoginPublicIdentifier,
};
pub use digest::{
    CheckpointContentsDigest, CheckpointDigest, ConsensusCommitDigest, Digest, DigestParseError,
    EffectsAuxiliaryDataDigest, ObjectDigest, SigningDigest, TransactionDigest,
    TransactionEffectsDigest, TransactionEventsDigest,
};
pub use effects::{
    ChangedObject, IdOperation, ObjectIn, ObjectOut, TransactionEffects, TransactionEffectsV1,
    UnchangedSharedKind, UnchangedSharedObject,
};
pub use events::{BalanceChange, Event, TransactionEvents};
pub use execution_status::{
    CommandArgumentError, ExecutionError, ExecutionStatus, MoveLocation, PackageUpgradeError,
    TypeArgumentError,
};
pub use gas::GasCostSummary;
pub use object::{
    GenesisObject, MovePackage, MoveStruct, Object, ObjectData, ObjectReference, ObjectType, Owner,
    TypeOrigin, UpgradeInfo, Version,
};
pub use object_id::ObjectId;
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub(crate) use transaction::SignedTransactionWithIntentMessage;
pub use transaction::{
    ActiveJwk, Argument, AuthenticatorStateExpire, AuthenticatorStateUpdateV1,
    CancelledTransaction, ChangeEpoch, Command, ConsensusCommitPrologueV1,
    ConsensusDeterminedVersionAssignments, EndOfEpochTransactionKind, GasPayment,
    GenesisTransaction, Input, MakeMoveVector, MergeCoins, MoveCall, ProgrammableTransaction,
    Publish, RandomnessStateUpdate, SignedTransaction, SplitCoins, SystemPackage, Transaction,
    TransactionExpiration, TransactionKind, TransferObjects, Upgrade, VersionAssignment,
};
pub use type_tag::{Identifier, StructTag, TypeParseError, TypeTag};

#[cfg(test)]
mod serialization_proptests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonalMessage<'a>(pub std::borrow::Cow<'a, [u8]>);

#[cfg(feature = "serde")]
mod _serde {
    use std::borrow::Cow;

    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs, SerializeAs};

    pub(crate) type ReadableDisplay =
        ::serde_with::As<::serde_with::IfIsHumanReadable<::serde_with::DisplayFromStr>>;

    pub(crate) type OptionReadableDisplay =
        ::serde_with::As<Option<::serde_with::IfIsHumanReadable<::serde_with::DisplayFromStr>>>;

    pub(crate) type ReadableBase64Encoded =
        ::serde_with::As<::serde_with::IfIsHumanReadable<Base64Encoded, ::serde_with::Bytes>>;

    pub(crate) struct Base64Encoded;

    impl<T: AsRef<[u8]>> SerializeAs<T> for Base64Encoded {
        fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = source.as_ref();
            let b64 = Base64::encode_string(bytes);
            b64.serialize(serializer)
        }
    }

    impl<'de, T: TryFrom<Vec<u8>>> DeserializeAs<'de, T> for Base64Encoded {
        fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            let length = bytes.len();
            T::try_from(bytes).map_err(|_| {
                serde::de::Error::custom(format_args!(
                    "Can't convert a Byte Vector of length {length} to the output type."
                ))
            })
        }
    }

    /// Serializes a bitmap according to the roaring bitmap on-disk standard.
    /// <https://github.com/RoaringBitmap/RoaringFormatSpec>
    pub(crate) struct BinaryRoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            Bytes::serialize_as(&bytes, serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub(crate) struct Base64RoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            let b64 = Base64::encode_string(&bytes);
            b64.serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub(crate) use super::SignedTransactionWithIntentMessage;
}

#[cfg(feature = "schemars")]
mod _schemars {
    use schemars::{
        JsonSchema,
        schema::{InstanceType, Metadata, SchemaObject},
    };

    pub(crate) struct U64;

    impl JsonSchema for U64 {
        fn schema_name() -> String {
            "u64".to_owned()
        }

        fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            SchemaObject {
                metadata: Some(Box::new(Metadata {
                    description: Some("Radix-10 encoded 64-bit unsigned integer".to_owned()),
                    ..Default::default()
                })),
                instance_type: Some(InstanceType::String.into()),
                format: Some("u64".to_owned()),
                ..Default::default()
            }
            .into()
        }

        fn is_referenceable() -> bool {
            false
        }
    }

    pub(crate) struct I128;

    impl JsonSchema for I128 {
        fn schema_name() -> String {
            "i128".to_owned()
        }

        fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            SchemaObject {
                metadata: Some(Box::new(Metadata {
                    description: Some("Radix-10 encoded 128-bit signed integer".to_owned()),
                    ..Default::default()
                })),
                instance_type: Some(InstanceType::String.into()),
                format: Some("i128".to_owned()),
                ..Default::default()
            }
            .into()
        }

        fn is_referenceable() -> bool {
            false
        }
    }

    pub(crate) struct U256;

    impl JsonSchema for U256 {
        fn schema_name() -> String {
            "u256".to_owned()
        }

        fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            SchemaObject {
                metadata: Some(Box::new(Metadata {
                    description: Some("Radix-10 encoded 256-bit unsigned integer".to_owned()),
                    ..Default::default()
                })),
                instance_type: Some(InstanceType::String.into()),
                format: Some("u256".to_owned()),
                ..Default::default()
            }
            .into()
        }

        fn is_referenceable() -> bool {
            false
        }
    }

    pub(crate) struct Base64;

    impl JsonSchema for Base64 {
        fn schema_name() -> String {
            "Base64".to_owned()
        }

        fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            SchemaObject {
                metadata: Some(Box::new(Metadata {
                    description: Some("Base64 encoded data".to_owned()),
                    ..Default::default()
                })),
                instance_type: Some(InstanceType::String.into()),
                format: Some("base64".to_owned()),
                ..Default::default()
            }
            .into()
        }

        fn is_referenceable() -> bool {
            false
        }
    }

    pub(crate) struct Base58;

    impl JsonSchema for Base58 {
        fn schema_name() -> String {
            "Base58".to_owned()
        }

        fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            SchemaObject {
                metadata: Some(Box::new(Metadata {
                    description: Some("Base58 encoded data".to_owned()),
                    ..Default::default()
                })),
                instance_type: Some(InstanceType::String.into()),
                format: Some("base58".to_owned()),
                ..Default::default()
            }
            .into()
        }

        fn is_referenceable() -> bool {
            false
        }
    }
}
