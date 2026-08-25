// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use iota_sdk::types::{HashingIntentScope, IntentAppId, IntentError, IntentScope, IntentVersion};

/// Intent errors.
#[uniffi::remote(Enum)]
#[uniffi::export(Debug)]
#[non_exhaustive]
pub enum IntentError {
    /// Invalid bytes for Intent
    Bytes,
    /// Invalid hex string for Intent
    Hex,
    /// Invalid Scope for Intent
    Scope,
    /// Invalid Version for Intent
    Version,
    /// Invalid AppId for Intent
    AppId,
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
#[uniffi::remote(Enum)]
#[uniffi::export(Debug, Eq, Hash)]
#[non_exhaustive]
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
#[uniffi::remote(Enum)]
#[uniffi::export(Debug, Eq, Hash)]
#[non_exhaustive]
pub enum IntentVersion {
    V0 = 0,
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
#[uniffi::remote(Enum)]
#[uniffi::export(Debug, Eq, Hash)]
#[non_exhaustive]
pub enum IntentAppId {
    Iota = 0,
    Consensus = 1,
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
        Self(iota_sdk::types::Intent::new(scope, version, app_id))
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
        self.0.scope
    }

    /// Get the version of the signing intent.
    pub fn version(&self) -> IntentVersion {
        self.0.version
    }

    /// Get the app id of the signing intent.
    pub fn app_id(&self) -> IntentAppId {
        self.0.app_id
    }

    /// Convert the signing intent to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

/// A 1-byte domain separator for hashing Object ID in IOTA. It starts from
/// 0xf0 to ensure no hashing collision for any ObjectID vs IotaAddress which is
/// derived as the hash of `flag || pubkey`.
#[uniffi::remote(Enum)]
#[uniffi::export(Eq, Debug, Hash)]
#[non_exhaustive]
pub enum HashingIntentScope {
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
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
