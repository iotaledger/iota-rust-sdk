// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "serde")]
use std::str::FromStr;

pub const INTENT_PREFIX_LENGTH: usize = 3;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum IntentError {
    #[error("invalid bytes for Intent")]
    Bytes,
    #[error("invalid hex string for Intent")]
    Hex,
    #[error("invalid Scope for Intent")]
    Scope,
    #[error("invalid Version for Intent")]
    Version,
    #[error("invalid AppId for Intent")]
    AppId,
}

/// A Signing Intent
///
/// An intent is a compact struct that serves as the domain separator for a
/// message that a signature commits to. It consists of three parts:
///     1. [enum IntentScope] (what the type of the message is)
///     2. [enum IntentVersion]
///     3. [enum IntentAppId] (what application the signature refers to).
///
/// The serialization of an Intent is a 3-byte array where each field is
/// represented by a byte and it is prepended onto a message before it is signed
/// in IOTA.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// intent = intent-scope intent-version intent-app-id
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct Intent {
    pub scope: IntentScope,
    pub version: IntentVersion,
    pub app_id: IntentAppId,
}

impl Intent {
    pub fn new(scope: IntentScope, version: IntentVersion, app_id: IntentAppId) -> Self {
        Self {
            scope,
            version,
            app_id,
        }
    }

    pub fn scope(self) -> IntentScope {
        self.scope
    }

    pub fn version(self) -> IntentVersion {
        self.version
    }

    pub fn app_id(self) -> IntentAppId {
        self.app_id
    }

    pub fn iota_app(scope: IntentScope) -> Self {
        Self {
            scope,
            version: IntentVersion::V0,
            app_id: IntentAppId::Iota,
        }
    }

    pub const fn iota_transaction() -> Self {
        Self {
            scope: IntentScope::TransactionData,
            version: IntentVersion::V0,
            app_id: IntentAppId::Iota,
        }
    }

    pub const fn personal_message() -> Self {
        Self {
            scope: IntentScope::PersonalMessage,
            version: IntentVersion::V0,
            app_id: IntentAppId::Iota,
        }
    }

    pub const fn consensus_app(scope: IntentScope) -> Self {
        Self {
            scope,
            version: IntentVersion::V0,
            app_id: IntentAppId::Consensus,
        }
    }

    pub fn to_bytes(self) -> [u8; INTENT_PREFIX_LENGTH] {
        [self.scope as u8, self.version as u8, self.app_id as u8]
    }

    #[cfg(feature = "serde")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IntentError> {
        if bytes.len() != INTENT_PREFIX_LENGTH {
            return Err(IntentError::Bytes);
        }
        Ok(Self {
            scope: bytes[0].try_into()?,
            version: bytes[1].try_into()?,
            app_id: bytes[2].try_into()?,
        })
    }
}

#[cfg(feature = "serde")]
impl FromStr for Intent {
    type Err = IntentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> =
            hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| IntentError::Hex)?;
        Self::from_bytes(bytes.as_slice())
    }
}

/// Byte signifying the scope of an [`Intent`]
///
/// This enum specifies the intent scope. Two intents for different scopes
/// should never collide, so no signature provided for one intent scope can be
/// used for another, even when the serialized data itself may be the same.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// intent-scope = u8
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
#[non_exhaustive]
pub enum IntentScope {
    TransactionData = 0,         // Used for a user signature on a transaction data.
    TransactionEffects = 1,      // Used for an authority signature on transaction effects.
    CheckpointSummary = 2,       // Used for an authority signature on a checkpoint summary.
    PersonalMessage = 3,         // Used for a user signature on a personal message.
    SenderSignedTransaction = 4, // Used for an authority signature on a user signed transaction.
    ProofOfPossession = 5,       /* Used as a signature representing an authority's proof of
                                  * possession of its authority key. */
    BridgeEventDeprecated = 6, /* Deprecated. Should not be reused. Introduced for bridge
                                * purposes but was never included in messages. */
    ConsensusBlock = 7, // Used for consensus authority signature on block's digest.
    DiscoveryPeers = 8, // Used for reporting peer addresses in discovery
    AuthorityCapabilities = 9, // Used for authority capabilities from non-committee authorities.
}

impl IntentScope {
    crate::def_is!(
        TransactionData,
        TransactionEffects,
        CheckpointSummary,
        PersonalMessage,
        SenderSignedTransaction,
        ProofOfPossession,
        BridgeEventDeprecated,
        ConsensusBlock,
        DiscoveryPeers,
        AuthorityCapabilities,
    );
}

#[cfg(feature = "serde")]
impl TryFrom<u8> for IntentScope {
    type Error = IntentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| IntentError::Scope)
    }
}

/// Byte signifying the version of an [`Intent`]
///
/// The version here is to distinguish between signing different versions of the
/// struct or enum. Serialized output between two different versions of the same
/// struct/enum might accidentally (or maliciously on purpose) match.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// intent-version = u8
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
#[non_exhaustive]
pub enum IntentVersion {
    V0 = 0,
}

impl IntentVersion {
    crate::def_is!(V0);
}

#[cfg(feature = "serde")]
impl TryFrom<u8> for IntentVersion {
    type Error = IntentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| IntentError::Version)
    }
}

/// Byte signifying the application id of an [`Intent`]
///
/// This enum specifies the application ID. Two intents in two different
/// applications (i.e., IOTA, Ethereum etc) should never collide, so
/// that even when a signing key is reused, nobody can take a signature
/// designated for app_1 and present it as a valid signature for an (any) intent
/// in app_2.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// intent-app-id = u8
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
#[non_exhaustive]
pub enum IntentAppId {
    Iota = 0,
    Consensus = 1,
}

impl IntentAppId {
    crate::def_is!(Iota, Consensus);
}

#[cfg(feature = "serde")]
impl TryFrom<u8> for IntentAppId {
    type Error = IntentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        bcs::from_bytes(&[value]).map_err(|_| IntentError::AppId)
    }
}

/// Intent Message is a wrapper around a message with its intent. The message
/// can be any type that implements [trait Serialize]. *ALL* signatures in IOTA
/// must commit to the intent message, not the message itself. This guarantees
/// any intent message signed in the system cannot collide with another since
/// they are domain separated by intent.
///
/// The serialization of an IntentMessage is compact: it only prepends three
/// bytes to the message itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IntentMessage<T> {
    pub intent: Intent,
    pub value: T,
}

impl<T> IntentMessage<T> {
    pub fn new(intent: Intent, value: T) -> Self {
        Self { intent, value }
    }
}

/// A 1-byte domain separator for hashing Object ID in IOTA. It starts from
/// 0xf0 to ensure no hashing collision for any ObjectID vs IotaAddress which is
/// derived as the hash of `flag || pubkey`. See
/// `iota_types::crypto::SignatureScheme::flag()`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde_repr::Serialize_repr, serde_repr::Deserialize_repr)
)]
#[repr(u8)]
#[non_exhaustive]
pub enum HashingIntentScope {
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
}

/// A personal message that wraps around a byte array.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PersonalMessage<'a>(pub std::borrow::Cow<'a, [u8]>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iota_transaction_intent() {
        let intent = Intent::iota_transaction();
        assert_eq!(intent.scope(), IntentScope::TransactionData);
        assert_eq!(intent.version(), IntentVersion::V0);
        assert_eq!(intent.app_id(), IntentAppId::Iota);
    }

    #[test]
    fn personal_message_intent() {
        let intent = Intent::personal_message();
        assert_eq!(intent.scope(), IntentScope::PersonalMessage);
        assert_eq!(intent.version(), IntentVersion::V0);
        assert_eq!(intent.app_id(), IntentAppId::Iota);
    }

    #[test]
    fn iota_app_intent() {
        let intent = Intent::iota_app(IntentScope::CheckpointSummary);
        assert_eq!(intent.scope(), IntentScope::CheckpointSummary);
        assert_eq!(intent.version(), IntentVersion::V0);
        assert_eq!(intent.app_id(), IntentAppId::Iota);
    }

    #[test]
    fn consensus_app_intent() {
        let intent = Intent::consensus_app(IntentScope::ConsensusBlock);
        assert_eq!(intent.scope(), IntentScope::ConsensusBlock);
        assert_eq!(intent.version(), IntentVersion::V0);
        assert_eq!(intent.app_id(), IntentAppId::Consensus);
    }

    #[test]
    fn intent_new_and_accessors() {
        let intent = Intent::new(
            IntentScope::ProofOfPossession,
            IntentVersion::V0,
            IntentAppId::Consensus,
        );
        assert_eq!(intent.scope(), IntentScope::ProofOfPossession);
        assert_eq!(intent.version(), IntentVersion::V0);
        assert_eq!(intent.app_id(), IntentAppId::Consensus);
    }

    #[test]
    fn to_bytes_iota_transaction() {
        let intent = Intent::iota_transaction();
        assert_eq!(intent.to_bytes(), [0, 0, 0]);
    }

    #[test]
    fn to_bytes_personal_message() {
        let intent = Intent::personal_message();
        assert_eq!(intent.to_bytes(), [3, 0, 0]);
    }

    #[test]
    fn to_bytes_consensus_block() {
        let intent = Intent::consensus_app(IntentScope::ConsensusBlock);
        assert_eq!(intent.to_bytes(), [7, 0, 1]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_roundtrip_iota_transaction() {
        let intent = Intent::iota_transaction();
        let bytes = intent.to_bytes();
        let parsed = Intent::from_bytes(&bytes).unwrap();
        assert_eq!(intent, parsed);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_roundtrip_personal_message() {
        let intent = Intent::personal_message();
        let bytes = intent.to_bytes();
        let parsed = Intent::from_bytes(&bytes).unwrap();
        assert_eq!(intent, parsed);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_roundtrip_consensus() {
        let intent = Intent::consensus_app(IntentScope::ConsensusBlock);
        let bytes = intent.to_bytes();
        let parsed = Intent::from_bytes(&bytes).unwrap();
        assert_eq!(intent, parsed);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_too_short() {
        assert!(Intent::from_bytes(&[0, 0]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_too_long() {
        assert!(Intent::from_bytes(&[0, 0, 0, 0]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_empty() {
        assert!(Intent::from_bytes(&[]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_invalid_scope() {
        assert!(Intent::from_bytes(&[255, 0, 0]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_invalid_version() {
        assert!(Intent::from_bytes(&[0, 255, 0]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_bytes_error_invalid_app_id() {
        assert!(Intent::from_bytes(&[0, 0, 255]).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_str_with_0x_prefix() {
        let intent: Intent = "0x000000".parse().unwrap();
        assert_eq!(intent, Intent::iota_transaction());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_str_without_prefix() {
        let intent: Intent = "030000".parse().unwrap();
        assert_eq!(intent, Intent::personal_message());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_str_invalid_hex() {
        assert!("0xZZZZZZ".parse::<Intent>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_str_wrong_length() {
        assert!("0x00".parse::<Intent>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_str_empty() {
        assert!("".parse::<Intent>().is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_scope_valid() {
        assert_eq!(
            IntentScope::try_from(0u8).unwrap(),
            IntentScope::TransactionData
        );
        assert_eq!(
            IntentScope::try_from(3u8).unwrap(),
            IntentScope::PersonalMessage
        );
        assert_eq!(
            IntentScope::try_from(9u8).unwrap(),
            IntentScope::AuthorityCapabilities
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_scope_invalid() {
        assert!(IntentScope::try_from(10u8).is_err());
        assert!(IntentScope::try_from(255u8).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_version_valid() {
        assert_eq!(IntentVersion::try_from(0u8).unwrap(), IntentVersion::V0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_version_invalid() {
        assert!(IntentVersion::try_from(1u8).is_err());
        assert!(IntentVersion::try_from(255u8).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_app_id_valid() {
        assert_eq!(IntentAppId::try_from(0u8).unwrap(), IntentAppId::Iota);
        assert_eq!(IntentAppId::try_from(1u8).unwrap(), IntentAppId::Consensus);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn try_from_u8_intent_app_id_invalid() {
        assert!(IntentAppId::try_from(2u8).is_err());
        assert!(IntentAppId::try_from(255u8).is_err());
    }

    #[test]
    fn intent_scope_is_accessors() {
        assert!(IntentScope::TransactionData.is_transaction_data());
        assert!(!IntentScope::TransactionData.is_personal_message());
        assert!(IntentScope::PersonalMessage.is_personal_message());
        assert!(IntentScope::ConsensusBlock.is_consensus_block());
    }

    #[test]
    fn intent_version_is_accessor() {
        assert!(IntentVersion::V0.is_v0());
    }

    #[test]
    fn intent_app_id_is_accessors() {
        assert!(IntentAppId::Iota.is_iota());
        assert!(!IntentAppId::Iota.is_consensus());
        assert!(IntentAppId::Consensus.is_consensus());
    }
}
