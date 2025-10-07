// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(doc_cfg, feature(doc_cfg))]

use iota_sdk_types::{PersonalMessage, Transaction, UserSignature};
pub use signature::{Error as SignatureError, Signer, Verifier};

#[cfg(feature = "bls12381")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "bls12381")))]
pub mod bls12381;

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

/// Extension trait for private key types
pub trait PrivateKeyExt {
    /// The signature scheme for this key type
    const SCHEME: iota_sdk_types::SignatureScheme;

    /// Returns the signature scheme for this private key
    fn scheme(&self) -> iota_sdk_types::SignatureScheme {
        Self::SCHEME
    }

    /// Returns the raw bytes of this private key
    fn to_bytes(&self) -> Vec<u8>;

    /// Creates an instance from raw key bytes (without scheme flag)
    fn from_raw_bytes(bytes: &[u8]) -> Result<Self, SignatureError>
    where
        Self: Sized;

    /// Returns the bytes with signature scheme flag prepended
    fn to_flagged_bytes(&self) -> Vec<u8> {
        let key_bytes = self.to_bytes();
        let mut bytes = Vec::with_capacity(1 + key_bytes.len());
        bytes.push(self.scheme().to_u8());
        bytes.extend_from_slice(&key_bytes);
        bytes
    }

    /// Creates an instance from bytes that include the signature scheme flag
    fn from_flagged_bytes(bytes: &[u8]) -> Result<Self, SignatureError>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(SignatureError::from_source("empty flagged bytes"));
        }

        let flag = iota_sdk_types::SignatureScheme::from_byte(bytes[0])
            .map_err(|e| SignatureError::from_source(format!("invalid signature scheme: {e:?}")))?;

        if flag != Self::SCHEME {
            return Err(SignatureError::from_source(format!(
                "invalid signature scheme: expected {:?}, got {flag:?}",
                Self::SCHEME
            )));
        }

        let key_bytes = &bytes[1..];
        Self::from_raw_bytes(key_bytes)
    }

    /// Encode this private key in Bech32 format with "iotaprivkey" prefix
    #[cfg(feature = "bech32")]
    fn to_bech32(&self) -> Result<String, SignatureError> {
        use bech32::Hrp;

        let hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| SignatureError::from_source(format!("invalid HRP: {e}")))?;

        let bytes = self.to_flagged_bytes();

        bech32::encode::<bech32::Bech32>(hrp, &bytes)
            .map_err(|e| SignatureError::from_source(format!("bech32 encoding failed: {e}")))
    }

    /// Decode a private key from Bech32 format with "iotaprivkey" prefix
    #[cfg(feature = "bech32")]
    fn from_bech32(value: &str) -> Result<Self, SignatureError>
    where
        Self: Sized,
    {
        use bech32::Hrp;

        let expected_hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| SignatureError::from_source(format!("invalid HRP: {e}")))?;

        let (hrp, data) = bech32::decode(value)
            .map_err(|e| SignatureError::from_source(format!("bech32 decoding failed: {e}")))?;

        if hrp != expected_hrp {
            return Err(SignatureError::from_source(format!(
                "invalid HRP: expected {IOTA_PRIV_KEY_PREFIX}, got {hrp}"
            )));
        }

        if data.is_empty() {
            return Err(SignatureError::from_source("empty bech32 data"));
        }

        Self::from_flagged_bytes(&data)
    }
}
