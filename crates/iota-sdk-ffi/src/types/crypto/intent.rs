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
    /// Invalid hex String for Intent
    String,
    /// Invalid Scope for Intent
    Scope,
    /// Invalid Version for Intent
    Version,
    /// Invalid AppId for Intent
    AppId,
}

/// Intent scopes.
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

/// Intent versions.
#[uniffi::remote(Enum)]
#[uniffi::export(Debug, Eq, Hash)]
#[non_exhaustive]
pub enum IntentVersion {
    V0 = 0,
}

/// App IDs.
#[uniffi::remote(Enum)]
#[uniffi::export(Debug, Eq, Hash)]
#[non_exhaustive]
pub enum IntentAppId {
    Iota = 0,
    Consensus = 1,
}

#[derive(Debug, PartialEq, Eq, Hash, uniffi::Object, derive_more::From)]
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
    pub fn iota_app(scope: IntentScope) -> Self {
        Self::new(scope, IntentVersion::V0, IntentAppId::Iota)
    }

    /// Create a new Consensus app signing intent.
    #[uniffi::constructor]
    pub fn consensus_app(scope: IntentScope) -> Self {
        Self::new(scope, IntentVersion::V0, IntentAppId::Consensus)
    }

    /// Create a new IOTA transaction signing intent.
    #[uniffi::constructor]
    pub fn iota_transaction() -> Self {
        Self::new(
            IntentScope::TransactionData,
            IntentVersion::V0,
            IntentAppId::Iota,
        )
    }

    /// Create a new IOTA personal message signing intent.
    #[uniffi::constructor]
    pub fn personal_message() -> Self {
        Self::new(
            IntentScope::PersonalMessage,
            IntentVersion::V0,
            IntentAppId::Iota,
        )
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
        vec![
            self.0.scope as u8,
            self.0.version as u8,
            self.0.app_id as u8,
        ]
    }
}

/// Returns the intent prefix length, i.e. the number of bytes prepended to the
/// data before being signed.
#[uniffi::export]
pub fn intent_prefix_length() -> u64 {
    iota_sdk::types::crypto::INTENT_PREFIX_LENGTH as u64
}

/// Create a signing intent from bytes.
#[uniffi::export]
pub fn intent_from_bytes(bytes: &[u8]) -> Result<Intent, IntentError> {
    Ok(Intent(iota_sdk::types::crypto::Intent::from_bytes(bytes)?))
}

/// Create a signing intent from a hex string.
#[uniffi::export]
pub fn intent_from_hex_string(hex: &str) -> Result<Intent, IntentError> {
    Ok(Intent(iota_sdk::types::crypto::Intent::from_str(hex)?))
}

#[uniffi::remote(Enum)]
#[uniffi::export(Eq, Debug, Hash)]
#[non_exhaustive]
pub enum HashingIntentScope {
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
}

#[derive(Debug, PartialEq, Eq, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct PersonalMessage(pub(crate) iota_sdk::types::PersonalMessage<'static>);

#[uniffi::export]
impl PersonalMessage {
    #[uniffi::constructor]
    pub fn new(message_bytes: &[u8]) -> Self {
        Self(iota_sdk::types::PersonalMessage(std::borrow::Cow::Owned(
            message_bytes.to_vec(),
        )))
    }

    pub fn message_bytes(&self) -> Vec<u8> {
        self.0.0.clone().into_owned()
    }

    pub fn signing_digest(&self) -> Vec<u8> {
        self.0.signing_digest().to_vec()
    }

    pub fn signing_digest_hex(&self) -> String {
        self.0.signing_digest_hex()
    }
}
