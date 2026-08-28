// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

/// Intent errors.
#[derive(Clone, Debug, derive_more::Display, uniffi::Enum)]
pub enum IntentError {
    /// Invalid bytes for Intent
    #[display("invalid bytes for Intent")]
    Bytes,
    /// Invalid hex string for Intent
    #[display("invalid hex string for Intent")]
    Hex,
    /// Invalid Scope for Intent
    #[display("invalid Scope for Intent")]
    Scope,
    /// Invalid Version for Intent
    #[display("invalid Version for Intent")]
    Version,
    /// Invalid AppId for Intent
    #[display("invalid AppId for Intent")]
    AppId,
}

impl From<iota_sdk::types::IntentError> for IntentError {
    fn from(value: iota_sdk::types::IntentError) -> Self {
        match value {
            iota_sdk::types::IntentError::Bytes => Self::Bytes,
            iota_sdk::types::IntentError::Hex => Self::Hex,
            iota_sdk::types::IntentError::Scope => Self::Scope,
            iota_sdk::types::IntentError::Version => Self::Version,
            iota_sdk::types::IntentError::AppId => Self::AppId,
            _ => unimplemented!("a new IntentError variant was added and needs to be handled"),
        }
    }
}

impl From<IntentError> for iota_sdk::types::IntentError {
    fn from(value: IntentError) -> Self {
        match value {
            IntentError::Bytes => Self::Bytes,
            IntentError::Hex => Self::Hex,
            IntentError::Scope => Self::Scope,
            IntentError::Version => Self::Version,
            IntentError::AppId => Self::AppId,
        }
    }
}

/// Byte signifying the scope of an Intent
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
#[derive(Clone, Debug, uniffi::Enum)]
pub enum IntentScope {
    /// Used for a user signature on a transaction data.
    TransactionData = 0,
    /// Used for an authority signature on transaction effects.
    TransactionEffects = 1,
    /// Used for an authority signature on a checkpoint summary.
    CheckpointSummary = 2,
    /// Used for a user signature on a personal message.
    PersonalMessage = 3,
    /// Used for an authority signature on a user signed transaction.
    SenderSignedTransaction = 4,
    /// Used as a signature representing an authority's proof of possession of
    /// its authority key.
    ProofOfPossession = 5,
    /// Deprecated. Should not be reused. Introduced for bridge purposes but was
    /// never included in messages.
    BridgeEventDeprecated = 6,
    /// Used for consensus authority signature on block's digest.
    ConsensusBlock = 7,
    /// Used for reporting peer addresses in discovery
    DiscoveryPeers = 8,
    /// Used for authority capabilities from non-committee authorities.
    AuthorityCapabilities = 9,
}

impl From<iota_sdk::types::IntentScope> for IntentScope {
    fn from(value: iota_sdk::types::IntentScope) -> Self {
        match value {
            iota_sdk::types::IntentScope::TransactionData => Self::TransactionData,
            iota_sdk::types::IntentScope::TransactionEffects => Self::TransactionEffects,
            iota_sdk::types::IntentScope::CheckpointSummary => Self::CheckpointSummary,
            iota_sdk::types::IntentScope::PersonalMessage => Self::PersonalMessage,
            iota_sdk::types::IntentScope::SenderSignedTransaction => Self::SenderSignedTransaction,
            iota_sdk::types::IntentScope::ProofOfPossession => Self::ProofOfPossession,
            iota_sdk::types::IntentScope::BridgeEventDeprecated => Self::BridgeEventDeprecated,
            iota_sdk::types::IntentScope::ConsensusBlock => Self::ConsensusBlock,
            iota_sdk::types::IntentScope::DiscoveryPeers => Self::DiscoveryPeers,
            iota_sdk::types::IntentScope::AuthorityCapabilities => Self::AuthorityCapabilities,
            _ => unimplemented!("a new IntentScope variant was added and needs to be handled"),
        }
    }
}

impl From<IntentScope> for iota_sdk::types::IntentScope {
    fn from(value: IntentScope) -> Self {
        match value {
            IntentScope::TransactionData => Self::TransactionData,
            IntentScope::TransactionEffects => Self::TransactionEffects,
            IntentScope::CheckpointSummary => Self::CheckpointSummary,
            IntentScope::PersonalMessage => Self::PersonalMessage,
            IntentScope::SenderSignedTransaction => Self::SenderSignedTransaction,
            IntentScope::ProofOfPossession => Self::ProofOfPossession,
            IntentScope::BridgeEventDeprecated => Self::BridgeEventDeprecated,
            IntentScope::ConsensusBlock => Self::ConsensusBlock,
            IntentScope::DiscoveryPeers => Self::DiscoveryPeers,
            IntentScope::AuthorityCapabilities => Self::AuthorityCapabilities,
        }
    }
}

/// Byte signifying the version of an Intent
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
#[derive(Clone, Debug, uniffi::Enum)]
pub enum IntentVersion {
    V0 = 0,
}

impl From<iota_sdk::types::IntentVersion> for IntentVersion {
    fn from(value: iota_sdk::types::IntentVersion) -> Self {
        match value {
            iota_sdk::types::IntentVersion::V0 => Self::V0,
            _ => unimplemented!("a new IntentVersion variant was added and needs to be handled"),
        }
    }
}

impl From<IntentVersion> for iota_sdk::types::IntentVersion {
    fn from(value: IntentVersion) -> Self {
        match value {
            IntentVersion::V0 => Self::V0,
        }
    }
}

/// Byte signifying the application id of an Intent
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
#[derive(Clone, Debug, uniffi::Enum)]
pub enum IntentAppId {
    Iota = 0,
    Consensus = 1,
}

impl From<iota_sdk::types::IntentAppId> for IntentAppId {
    fn from(value: iota_sdk::types::IntentAppId) -> Self {
        match value {
            iota_sdk::types::IntentAppId::Iota => Self::Iota,
            iota_sdk::types::IntentAppId::Consensus => Self::Consensus,
            _ => unimplemented!("a new IntentAppId variant was added and needs to be handled"),
        }
    }
}

impl From<IntentAppId> for iota_sdk::types::IntentAppId {
    fn from(value: IntentAppId) -> Self {
        match value {
            IntentAppId::Iota => Self::Iota,
            IntentAppId::Consensus => Self::Consensus,
        }
    }
}

/// A Signing Intent
///
/// An intent is a compact struct that serves as the domain separator for a
/// message that a signature commits to. It consists of three parts:
///     1. IntentScope (what the type of the message is)
///     2. IntentVersion
///     3. IntentAppId (what application the signature refers to).
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
#[derive(Debug, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq, Hash)]
pub struct Intent(pub iota_sdk::types::Intent);

#[uniffi::export]
impl Intent {
    /// Create a new signing intent.
    #[uniffi::constructor]
    pub fn new(scope: IntentScope, version: IntentVersion, app_id: IntentAppId) -> Self {
        Self(iota_sdk::types::Intent::new(
            scope.into(),
            version.into(),
            app_id.into(),
        ))
    }

    /// Create a new IOTA app signing intent.
    #[uniffi::constructor]
    pub fn new_iota_app(scope: IntentScope) -> Self {
        Self::new(scope, IntentVersion::V0, IntentAppId::Iota)
    }

    /// Create a new Consensus app signing intent.
    #[uniffi::constructor]
    pub fn new_consensus_app(scope: IntentScope) -> Self {
        Self::new(scope, IntentVersion::V0, IntentAppId::Consensus)
    }

    /// Create a new IOTA transaction signing intent.
    #[uniffi::constructor]
    pub fn new_iota_transaction() -> Self {
        Self::new(
            IntentScope::TransactionData,
            IntentVersion::V0,
            IntentAppId::Iota,
        )
    }

    /// Create a new IOTA personal message signing intent.
    #[uniffi::constructor]
    pub fn new_personal_message() -> Self {
        Self::new(
            IntentScope::PersonalMessage,
            IntentVersion::V0,
            IntentAppId::Iota,
        )
    }

    /// Create a signing intent from bytes.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: &[u8]) -> Result<Intent, IntentError> {
        Ok(Intent(iota_sdk::types::crypto::Intent::from_bytes(bytes)?))
    }

    /// Create a signing intent from a hex string.
    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Intent, IntentError> {
        Ok(Intent(iota_sdk::types::crypto::Intent::from_str(hex)?))
    }

    /// Get the scope of the signing intent.
    pub fn scope(&self) -> IntentScope {
        self.0.scope.into()
    }

    /// Get the version of the signing intent.
    pub fn version(&self) -> IntentVersion {
        self.0.version.into()
    }

    /// Get the app id of the signing intent.
    pub fn app_id(&self) -> IntentAppId {
        self.0.app_id.into()
    }

    /// Convert the signing intent to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A 1-byte domain separator for hashing Object ID in IOTA. It starts from
/// 0xf0 to ensure no hashing collision for any ObjectID vs IotaAddress which is
/// derived as the hash of `flag || pubkey`.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum HashingIntentScope {
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
}

impl From<iota_sdk::types::HashingIntentScope> for HashingIntentScope {
    fn from(value: iota_sdk::types::HashingIntentScope) -> Self {
        match value {
            iota_sdk::types::HashingIntentScope::ChildObjectId => Self::ChildObjectId,
            iota_sdk::types::HashingIntentScope::RegularObjectId => Self::RegularObjectId,
            _ => {
                unimplemented!("a new HashingIntentScope variant was added and needs to be handled")
            }
        }
    }
}

impl From<HashingIntentScope> for iota_sdk::types::HashingIntentScope {
    fn from(value: HashingIntentScope) -> Self {
        match value {
            HashingIntentScope::ChildObjectId => Self::ChildObjectId,
            HashingIntentScope::RegularObjectId => Self::RegularObjectId,
        }
    }
}

/// A personal message that wraps around a byte array.
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct PersonalMessage(pub(crate) iota_sdk::types::PersonalMessage<'static>);

#[uniffi::export]
impl PersonalMessage {
    /// Create a new personal message from bytes.
    #[uniffi::constructor]
    pub fn new(message_bytes: &[u8]) -> Self {
        Self(iota_sdk::types::PersonalMessage(std::borrow::Cow::Owned(
            message_bytes.to_vec(),
        )))
    }

    /// Get the message as bytes.
    pub fn message_bytes(&self) -> Vec<u8> {
        self.0.0.clone().into_owned()
    }

    /// Get the signing digest as bytes.
    pub fn signing_digest(&self) -> Vec<u8> {
        self.0.signing_digest().to_vec()
    }

    /// Get the signing digest as hex string.
    pub fn signing_digest_hex(&self) -> String {
        self.0.signing_digest_hex()
    }
}

crate::export_iota_types_display!(
    IntentError,
    IntentScope,
    IntentVersion,
    IntentAppId,
    HashingIntentScope
);
crate::export_iota_types_objects_display!(Intent, PersonalMessage);
