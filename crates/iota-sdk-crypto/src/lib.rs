// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(doc_cfg, feature(doc_cfg))]

use iota_types::{PersonalMessage, Transaction, UserSignature};
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

#[cfg(feature = "mnemonic")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "mnemonic")))]
pub mod mnemonic;

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

/// Defines the scheme of a private key
pub trait PrivateKeyScheme {
    const SCHEME: iota_types::SignatureScheme;

    /// Returns the signature scheme for this private key
    fn scheme(&self) -> iota_types::SignatureScheme {
        Self::SCHEME
    }
}

/// Defines a type which can be constructed from bytes
pub trait ToFromBytes {
    type Error;
    type ByteArray;

    /// Returns the raw bytes as a byte array.
    fn to_bytes(&self) -> Self::ByteArray;

    /// Create an instance from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
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

impl<T: ToFromBytes<Error = PrivateKeyError> + PrivateKeyScheme> ToFromFlaggedBytes for T
where
    T::ByteArray: AsRef<[u8]>,
{
    type Error = PrivateKeyError;

    /// Returns the bytes with signature scheme flag prepended
    fn to_flagged_bytes(&self) -> Vec<u8> {
        let key_bytes = self.to_bytes();
        let mut bytes = Vec::with_capacity(1 + key_bytes.as_ref().len());
        bytes.push(self.scheme().to_u8());
        bytes.extend_from_slice(key_bytes.as_ref());
        bytes
    }

    fn from_flagged_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if bytes.is_empty() {
            return Err(PrivateKeyError::EmptyData("flagged bytes".to_string()));
        }

        let flag = iota_types::SignatureScheme::from_byte(bytes[0])
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
        account_index: impl Into<Option<u64>>,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Create an instance from a mnemonic phrase and a derivation path like:
    /// - Ed25519: `"m/44'/4218'/0'/0'/0'"`
    /// - Secp256k1: `"m/54'/4218'/0'/0/0"`
    /// - Secp256r1: `"m/74'/4218'/0'/0/0"`
    fn from_mnemonic_with_path(
        phrase: &str,
        path: String,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ed25519::Ed25519PrivateKey, secp256k1::Secp256k1PrivateKey, secp256r1::Secp256r1PrivateKey,
    };

    #[cfg(feature = "mnemonic")]
    #[test]
    fn test_mnemonics_ed25519() {
        const TEST_CASES: [[&str; 3]; 3] = [
            [
                "film crazy soon outside stand loop subway crumble thrive popular green nuclear struggle pistol arm wife phrase warfare march wheat nephew ask sunny firm",
                "iotaprivkey1qrqqxhsu3ndp96644fjk4z5ams5ulgmvprklngt2jhvg2ujn5w4q2d2vplv",
                "0x9f8e5379678525edf768d7b507dc1ba9016fc4f0eac976ab7f74077d95fba312",
            ],
            [
                "require decline left thought grid priority false tiny gasp angle royal system attack beef setup reward aunt skill wasp tray vital bounce inflict level",
                "iotaprivkey1qqcxaf57fnenvflpacacaumf6vl0rt0edddhytanvzhkqhwnjk0zspg902d",
                "0x862738192e40540e0a5c9a5aca636f53b0cd76b0a9bef3386e05647feb4914ac",
            ],
            [
                "organ crash swim stick traffic remember army arctic mesh slice swear summer police vast chaos cradle squirrel hood useless evidence pet hub soap lake",
                "iotaprivkey1qzq39vxzm0gq7l8dc5dj5allpuww4mavhwhg8mua4cl3lj2c3fvhcv5l2vn",
                "0x2391788ca49c7f0f00699bc2bad45f80c343b4d1df024285c132259433d7ff31",
            ],
        ];

        for [mnemonic, bech32, address] in TEST_CASES {
            let key = Ed25519PrivateKey::from_mnemonic(mnemonic, None, None).unwrap();
            assert_eq!(key.to_bech32().unwrap(), bech32);
            assert_eq!(key.public_key().derive_address().to_string(), address);
        }
    }

    #[cfg(feature = "mnemonic")]
    #[test]
    fn test_mnemonics_secp256k1() {
        const TEST_CASES: [[&str; 3]; 3] = [
            [
                "film crazy soon outside stand loop subway crumble thrive popular green nuclear struggle pistol arm wife phrase warfare march wheat nephew ask sunny firm",
                "iotaprivkey1q8cy2ll8a0dmzzzwn9zavrug0qf47cyuj6k2r4r6rnjtpjhrdh52vpegd4f",
                "0x8520d58dde1ab268349b9a46e5124ae6fe7e4c61df4ca2bc9c97d3c4d07b0b55",
            ],
            [
                "require decline left thought grid priority false tiny gasp angle royal system attack beef setup reward aunt skill wasp tray vital bounce inflict level",
                "iotaprivkey1q9hm330d05jcxfvmztv046p8kclyaj39hk6elqghgpq4sz4x23hk2wd6cfz",
                "0x3740d570eefba29dfc0fdd5829848902064e31ecd059ca05c401907fa8646f61",
            ],
            [
                "organ crash swim stick traffic remember army arctic mesh slice swear summer police vast chaos cradle squirrel hood useless evidence pet hub soap lake",
                "iotaprivkey1qx2dnch6363h7gdqqfkzmmlequzj4ul3x4fq6dzyajk7wc2c0jgcx32axh5",
                "0x943b852c37fef403047e06ff5a2fa216557a4386212fb29554babdd3e1899da5",
            ],
        ];

        for [mnemonic, bech32, address] in TEST_CASES {
            let key = Secp256k1PrivateKey::from_mnemonic(mnemonic, None, None).unwrap();
            assert_eq!(key.to_bech32().unwrap(), bech32);
            assert_eq!(key.public_key().derive_address().to_string(), address);
        }
    }

    #[cfg(feature = "mnemonic")]
    #[test]
    fn test_mnemonics_secp256r1() {
        const TEST_CASES: [[&str; 3]; 3] = [
            [
                "act wing dilemma glory episode region allow mad tourist humble muffin oblige",
                "iotaprivkey1qtt65ua2lhal76zg4cxd6umdqynv2rj2gzrntp5rwlnyj370jg3pwtqlwdn",
                "0x779a63b28528210a5ec6c4af5a70382fa3f0c2d3f98dcbe4e3a4ae2f8c39cc9c",
            ],
            [
                "flag rebel cabbage captain minimum purpose long already valley horn enrich salt",
                "iotaprivkey1qtcjgmue7q8u4gtutfvfpx3zj3aa2r9pqssuusrltxfv68eqhzsgjc3p4z7",
                "0x8b45523042933aa55f57e2ccc661304baed292529b6e67a0c9857c1f3f871806",
            ],
            [
                "area renew bar language pudding trial small host remind supreme cabbage era",
                "iotaprivkey1qtxafg26qxeqy7f56gd2rvsup0a5kl4cre7nt2rtcrf0p3v5pwd4cgrrff2",
                "0x8528ef86150ec331928a8b3edb8adbe2fb523db8c84679aa57a931da6a4cdb25",
            ],
        ];

        for [mnemonic, bech32, address] in TEST_CASES {
            let key = Secp256r1PrivateKey::from_mnemonic(mnemonic, None, None).unwrap();
            assert_eq!(key.to_bech32().unwrap(), bech32);
            assert_eq!(key.public_key().derive_address().to_string(), address);
        }
    }
}
