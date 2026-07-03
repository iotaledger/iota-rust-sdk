// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::{
    ed25519::{
        Ed25519KeyPair, Ed25519PublicKey as FcEd25519PublicKey,
        Ed25519Signature as FcEd25519Signature,
    },
    traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _},
};
use iota_types::{
    Ed25519PublicKey, Ed25519Signature, SignatureScheme, SimpleSignature, UserSignature,
};

use crate::{SignatureError, Signer, Verifier};

#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519PrivateKey([u8; Self::LENGTH]);

impl std::fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519PrivateKey")
            .field(&"__elided__")
            .finish()
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for Ed25519PrivateKey {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_map(Self::new)
            .boxed()
    }
}

impl Ed25519PrivateKey {
    /// The length of an ed25519 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Ed25519
    }

    /// Reconstruct the fastcrypto keypair, which performs all signing.
    fn keypair(&self) -> Ed25519KeyPair {
        Ed25519KeyPair::from_bytes(&self.0).expect("any 32 bytes are a valid ed25519 seed")
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.keypair().public().clone())
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        self.verifying_key().public_key()
    }

    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        ed25519_dalek::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
            .map(Self::from_dalek)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        self.as_dalek()
            .to_pkcs8_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.as_bytes().to_owned())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8-encoded private key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        ed25519_dalek::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
            .map(Self::from_dalek)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePrivateKey;

        self.as_dalek()
            .to_pkcs8_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
            .map(|pem| (*pem).to_owned())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_dalek(private_key: ed25519_dalek::SigningKey) -> Self {
        Self::new(private_key.to_bytes())
    }

    /// Re-expose the raw private key through ed25519-dalek, used only as a
    /// PKCS#8/PEM codec (signing itself always goes through fastcrypto).
    #[cfg(feature = "pem")]
    fn as_dalek(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
    }
}

impl crate::ToFromBytes for Ed25519PrivateKey {
    type Error = crate::PrivateKeyError;
    type ByteArray = [u8; Self::LENGTH];

    /// Return the raw 32-byte private key
    fn to_bytes(&self) -> Self::ByteArray {
        self.0
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = bytes.as_ref();
        if bytes.len() != Self::LENGTH {
            return Err(crate::PrivateKeyError::InvalidScheme(
                "invalid ed25519 key length".to_string(),
            ));
        }

        let mut arr = [0u8; Self::LENGTH];
        arr.copy_from_slice(bytes);
        Ok(Self::new(arr))
    }
}

impl crate::PrivateKeyScheme for Ed25519PrivateKey {
    const SCHEME: SignatureScheme = SignatureScheme::Ed25519;
}

#[cfg(feature = "mnemonic")]
impl crate::FromMnemonic for Ed25519PrivateKey {
    type Error = crate::PrivateKeyError;

    fn from_mnemonic(
        phrase: &str,
        account_index: impl Into<Option<u64>>,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let path = format!(
            "m/{}'/{}'/0'/0'/{}'",
            crate::DERIVATION_PATH_PURPOSE_ED25519,
            crate::DERIVATION_PATH_COIN_TYPE,
            account_index.into().unwrap_or_default()
        );
        Self::from_mnemonic_with_path(phrase, path, password)
    }

    fn from_mnemonic_with_path(
        phrase: &str,
        path: String,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        use std::str::FromStr;

        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)?;
        let seed = mnemonic.to_seed(password.into().unwrap_or_default());
        let path = bip32::DerivationPath::from_str(&path)?
            .into_iter()
            .map(|c| c.0)
            .collect::<Vec<_>>();
        Ok(Self::new(slip10_ed25519::derive_ed25519_private_key(
            &seed, &path,
        )))
    }
}

impl Signer<Ed25519Signature> for Ed25519PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Ed25519Signature, SignatureError> {
        let signature: FcEd25519Signature = self.keypair().sign(msg);
        Ok(Ed25519Signature::new(
            signature
                .as_ref()
                .try_into()
                .expect("ed25519 signature is 64 bytes"),
        ))
    }
}

impl Signer<SimpleSignature> for Ed25519PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<SimpleSignature, SignatureError> {
        <Self as Signer<Ed25519Signature>>::try_sign(self, msg).map(|signature| {
            SimpleSignature::Ed25519 {
                signature,
                public_key: self.public_key(),
            }
        })
    }
}

impl Signer<UserSignature> for Ed25519PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<UserSignature, SignatureError> {
        <Self as Signer<SimpleSignature>>::try_sign(self, msg).map(UserSignature::Simple)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519VerifyingKey(FcEd25519PublicKey);

impl std::fmt::Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519VerifyingKey")
            .field(&self.0.as_ref())
            .finish()
    }
}

impl Ed25519VerifyingKey {
    pub fn new(public_key: &Ed25519PublicKey) -> Result<Self, SignatureError> {
        FcEd25519PublicKey::from_bytes(public_key.inner())
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::new(
            self.0
                .as_ref()
                .try_into()
                .expect("ed25519 public key is 32 bytes"),
        )
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        ed25519_dalek::pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map(Self::from_dalek)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.as_dalek()?
            .to_public_key_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.into_vec())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        ed25519_dalek::pkcs8::DecodePublicKey::from_public_key_pem(s)
            .map(Self::from_dalek)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key into PEM format
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.as_dalek()?
            .to_public_key_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_dalek(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self(
            FcEd25519PublicKey::from_bytes(verifying_key.as_bytes())
                .expect("ed25519-dalek public key is a valid ed25519 point"),
        )
    }

    /// Re-expose the public key through ed25519-dalek, used only as a
    /// PKCS#8/PEM codec (verification itself always goes through
    /// fastcrypto).
    #[cfg(feature = "pem")]
    fn as_dalek(&self) -> Result<ed25519_dalek::VerifyingKey, SignatureError> {
        ed25519_dalek::VerifyingKey::from_bytes(
            self.0
                .as_ref()
                .try_into()
                .expect("ed25519 public key is 32 bytes"),
        )
        .map_err(SignatureError::from_source)
    }
}

impl Verifier<Ed25519Signature> for Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), SignatureError> {
        let signature = FcEd25519Signature::from_bytes(signature.inner())
            .map_err(SignatureError::from_source)?;
        self.0
            .verify(message, &signature)
            .map_err(SignatureError::from_source)
    }
}

impl Verifier<SimpleSignature> for Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Ed25519 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not an ed25519 signature"));
        };

        if public_key.inner().as_slice() != self.0.as_ref() {
            return Err(SignatureError::from_source(
                "public_key in signature does not match",
            ));
        }

        <Self as Verifier<Ed25519Signature>>::verify(self, message, signature)
    }
}

impl Verifier<UserSignature> for Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not an ed25519 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Ed25519Verifier {}

impl Ed25519Verifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl Verifier<SimpleSignature> for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Ed25519 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not an ed25519 signature"));
        };

        let verifying_key = Ed25519VerifyingKey::new(public_key)?;

        verifying_key.verify(message, signature)
    }
}

impl Verifier<UserSignature> for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not an ed25519 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::{PersonalMessage, Transaction};
    use test_strategy::proptest;

    use super::*;
    use crate::{IotaSigner, IotaVerifier};

    #[proptest]
    fn transaction_signing(signer: Ed25519PrivateKey, transaction: Transaction) {
        let signature = signer.sign_transaction(&transaction).unwrap();
        let verifier = signer.verifying_key();
        verifier
            .verify_transaction(&transaction, &signature)
            .unwrap();
    }

    #[proptest]
    fn personal_message_signing(signer: Ed25519PrivateKey, message: Vec<u8>) {
        let message = PersonalMessage(message.into());
        let signature = signer.sign_personal_message(&message).unwrap();
        let verifying_key = signer.verifying_key();
        verifying_key
            .verify_personal_message(&message, &signature)
            .unwrap();

        let verifier = Ed25519Verifier::default();
        verifier
            .verify_personal_message(&message, &signature)
            .unwrap();
    }
}
