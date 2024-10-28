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
    ActiveJwk, Argument, AuthenticatorStateExpire, AuthenticatorStateUpdate, CancelledTransaction,
    ChangeEpoch, Command, ConsensusCommitPrologue, ConsensusDeterminedVersionAssignments,
    EndOfEpochTransactionKind, GasPayment, GenesisTransaction, Input, MakeMoveVector, MergeCoins,
    MoveCall, ProgrammableTransaction, Publish, RandomnessStateUpdate, SignedTransaction,
    SplitCoins, SystemPackage, Transaction, TransactionExpiration, TransactionKind,
    TransferObjects, Upgrade, VersionAssignment,
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
