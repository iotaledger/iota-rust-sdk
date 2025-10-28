// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(doc_cfg, feature(doc_cfg))]

use iota_sdk_types::{PersonalMessage, Transaction, UserSignature};
pub use signature::{Error as SignatureError, Signer, Verifier};

/// Error type for private key encoding/decoding operations
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PrivateKeyError {
    /// Empty input data
    #[error("empty data: {0}")]
    EmptyData(String),
    /// Invalid signature scheme
    #[error("invalid signature scheme: {0}")]
    InvalidScheme(String),
    /// Bech32 encoding/decoding error
    #[error("bech32 error: {0}")]
    Bech32(String),
    /// HRP (Human Readable Part) error
    #[error("bech32 HRP error: {0}")]
    Bech32Hrp(String),
    #[cfg(feature = "mnemonic")]
    #[error("mnemonic error: {0}")]
    Bip32(#[from] bip32::Error),
    #[cfg(feature = "mnemonic")]
    #[error("mnemonic error: {0}")]
    Bip39(#[from] bip39::Error),
}

#[cfg(feature = "bls12381")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bls12381")))]
pub mod bls12381;

#[cfg(feature = "bls12381")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bls12381")))]
pub mod validator;

#[cfg(feature = "ed25519")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ed25519")))]
pub mod ed25519;

#[cfg(feature = "secp256k1")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "secp256k1")))]
pub mod secp256k1;

#[cfg(feature = "secp256r1")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "secp256r1")))]
pub mod secp256r1;

#[cfg(feature = "passkey")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "passkey")))]
pub mod passkey;

#[cfg(feature = "zklogin")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "zklogin")))]
pub mod zklogin;

#[cfg(any(
    feature = "ed25519",
    feature = "secp256r1",
    feature = "secp256k1",
    feature = "zklogin"
))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(any(
        feature = "ed25519",
        feature = "secp256r1",
        feature = "secp256k1",
        feature = "zklogin"
    )))
)]
pub mod simple;

#[cfg(any(
    feature = "ed25519",
    feature = "secp256r1",
    feature = "secp256k1",
    feature = "zklogin"
))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(any(
        feature = "ed25519",
        feature = "secp256r1",
        feature = "secp256k1",
        feature = "zklogin"
    )))
)]
pub mod multisig;

#[cfg(any(
    feature = "ed25519",
    feature = "secp256r1",
    feature = "secp256k1",
    feature = "zklogin"
))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(any(
        feature = "ed25519",
        feature = "secp256r1",
        feature = "secp256k1",
        feature = "zklogin"
    )))
)]
#[doc(inline)]
pub use multisig::UserSignatureVerifier;

/// Interface for signing user transactions and messages in IOTA
///
/// # Note
///
/// There is a blanket implementation of `IotaSigner` for all `T` where `T:
/// `[`Signer`]`<`[`UserSignature`]`>` so it is generally recommended for a
/// signer to implement `Signer<UserSignature>` and rely on the blanket
/// implementation which handles the proper construction of the signing message.
pub trait IotaSigner {
    fn sign_transaction(&self, transaction: &Transaction) -> Result<UserSignature, SignatureError>;
    fn sign_personal_message(
        &self,
        message: &PersonalMessage<'_>,
    ) -> Result<UserSignature, SignatureError>;
}

impl<T: Signer<UserSignature>> IotaSigner for T {
    fn sign_transaction(&self, transaction: &Transaction) -> Result<UserSignature, SignatureError> {
        let msg = transaction.signing_digest();
        self.try_sign(&msg)
    }

    fn sign_personal_message(
        &self,
        message: &PersonalMessage<'_>,
    ) -> Result<UserSignature, SignatureError> {
        let msg = message.signing_digest();
        self.try_sign(&msg)
    }
}

/// Interface for verifying user transactions and messages in IOTA
///
/// # Note
///
/// There is a blanket implementation of `IotaVerifier` for all `T` where `T:
/// `[`Verifier`]`<`[`UserSignature`]`>` so it is generally recommended for a
/// signer to implement `Verifier<UserSignature>` and rely on the blanket
/// implementation which handles the proper construction of the signing message.
pub trait IotaVerifier {
    fn verify_transaction(
        &self,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<(), SignatureError>;
    fn verify_personal_message(
        &self,
        message: &PersonalMessage<'_>,
        signature: &UserSignature,
    ) -> Result<(), SignatureError>;
}

impl<T: Verifier<UserSignature>> IotaVerifier for T {
    fn verify_transaction(
        &self,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        let message = transaction.signing_digest();
        self.verify(&message, signature)
    }

    fn verify_personal_message(
        &self,
        message: &PersonalMessage<'_>,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        let message = message.signing_digest();
        self.verify(&message, signature)
    }
}

/// Bech32 prefix for IOTA private keys
#[cfg(feature = "bech32")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bech32")))]
pub const IOTA_PRIV_KEY_PREFIX: &str = "iotaprivkey";

#[cfg(feature = "mnemonic")]
pub const DERIVATION_PATH_COIN_TYPE: u32 = 4218;
#[cfg(feature = "mnemonic")]
pub const DERIVATION_PATH_PURPOSE_ED25519: u32 = 44;
#[cfg(feature = "mnemonic")]
pub const DERIVATION_PATH_PURPOSE_SECP256K1: u32 = 54;
#[cfg(feature = "mnemonic")]
pub const DERIVATION_PATH_PURPOSE_SECP256R1: u32 = 74;

/// Defines a type which can be converted to bytes
pub trait ToBytes {
    /// Returns the raw bytes of this type.
    fn to_bytes(&self) -> Vec<u8>;
}

/// Defines a type which can be constructed from bytes
pub trait FromBytes {
    type Error;

    /// Create an instance from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Defines the const scheme of a private key
pub trait ConstPrivateKeyScheme {
    const SCHEME: iota_sdk_types::SignatureScheme;
}

/// Defines the scheme of a private key
pub trait PrivateKeyScheme {
    /// Returns the signature scheme for this private key
    fn scheme(&self) -> iota_sdk_types::SignatureScheme;
}

impl<T: ConstPrivateKeyScheme> PrivateKeyScheme for T {
    fn scheme(&self) -> iota_sdk_types::SignatureScheme {
        Self::SCHEME
    }
}

/// Defines a type that can be converted to and from flagged bytes, i.e. bytes
/// prepended by some variant indicator flag
pub trait ToFromFlaggedBytes {
    type Error;

    /// Returns the bytes with the flag prepended
    fn to_flagged_bytes(&self) -> Vec<u8>;

    /// Creates an instance from bytes that include the flag
    fn from_flagged_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl<T: ToBytes + FromBytes<Error = PrivateKeyError> + ConstPrivateKeyScheme> ToFromFlaggedBytes
    for T
{
    type Error = PrivateKeyError;

    /// Returns the bytes with signature scheme flag prepended
    fn to_flagged_bytes(&self) -> Vec<u8> {
        let key_bytes = self.to_bytes();
        let mut bytes = Vec::with_capacity(1 + key_bytes.len());
        bytes.push(self.scheme().to_u8());
        bytes.extend_from_slice(&key_bytes);
        bytes
    }

    fn from_flagged_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(PrivateKeyError::EmptyData("flagged bytes".to_string()));
        }

        let flag = iota_sdk_types::SignatureScheme::from_byte(bytes[0])
            .map_err(|e| PrivateKeyError::InvalidScheme(format!("{e:?}")))?;

        if flag != Self::SCHEME {
            return Err(PrivateKeyError::InvalidScheme(format!(
                "expected {:?}, got {flag:?}",
                Self::SCHEME
            )));
        }

        let key_bytes = &bytes[1..];
        Self::from_bytes(key_bytes)
    }
}

/// Defines a type which can be converted to and from bech32 strings
#[cfg(feature = "bech32")]
pub trait ToFromBech32 {
    type Error;

    /// Encode this private key in Bech32 format with "iotaprivkey" prefix
    fn to_bech32(&self) -> Result<String, Self::Error>;

    /// Decode a private key from Bech32 format with "iotaprivkey" prefix
    fn from_bech32(value: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[cfg(feature = "bech32")]
impl<T: ToFromFlaggedBytes<Error = PrivateKeyError>> ToFromBech32 for T {
    type Error = PrivateKeyError;

    #[cfg(feature = "bech32")]
    fn to_bech32(&self) -> Result<String, Self::Error> {
        use bech32::Hrp;

        let hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| PrivateKeyError::Bech32Hrp(format!("{e}")))?;

        let bytes = self.to_flagged_bytes();

        bech32::encode::<bech32::Bech32>(hrp, &bytes)
            .map_err(|e| PrivateKeyError::Bech32(format!("encoding failed: {e}")))
    }

    #[cfg(feature = "bech32")]
    fn from_bech32(value: &str) -> Result<Self, Self::Error> {
        use bech32::Hrp;

        let expected_hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| PrivateKeyError::Bech32Hrp(format!("{e}")))?;

        let (hrp, data) = bech32::decode(value)
            .map_err(|e| PrivateKeyError::Bech32(format!("decoding failed: {e}")))?;

        if hrp != expected_hrp {
            return Err(PrivateKeyError::Bech32Hrp(format!(
                "expected {IOTA_PRIV_KEY_PREFIX}, got {hrp}"
            )));
        }

        if data.is_empty() {
            return Err(PrivateKeyError::EmptyData("bech32 data".to_string()));
        }

        Self::from_flagged_bytes(&data)
    }
}

/// Defines a type which can be constructed from a mnemonic phrase
#[cfg(feature = "mnemonic")]
pub trait FromMnemonic {
    type Error;

    /// Create an instance from a mnemonic phrase
    fn from_mnemonic(
        phrase: &str,
        password: impl Into<Option<String>>,
        path: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
