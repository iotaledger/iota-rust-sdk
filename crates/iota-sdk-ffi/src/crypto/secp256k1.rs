// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::{Result, SdkFfiError},
    types::{
        crypto::Secp256k1Signature,
        signature::{SimpleSignature, UserSignature},
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1PrivateKey(iota_crypto::secp256k1::Secp256k1PrivateKey);

#[uniffi::export]
impl Secp256k1PrivateKey {
    //     pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
    //         SigningKey::from_bytes(&bytes.into()).map(Self)
    //     }

    //     pub fn scheme(&self) -> SignatureScheme {
    //         SignatureScheme::Secp256k1
    //     }

    //     pub fn verifying_key(&self) -> Secp256k1VerifyingKey {
    //         let verifying_key = self.0.verifying_key();
    //         Secp256k1VerifyingKey(*verifying_key)
    //     }

    //     pub fn public_key(&self) -> Secp256k1PublicKey {
    //         Secp256k1PublicKey::new(self.0.verifying_key().as_ref().to_bytes().
    // into())     }

    //     pub fn generate<R>(mut rng: R) -> Self
    //     where
    //         R: rand_core::RngCore + rand_core::CryptoRng,
    //     {
    //         Self(SigningKey::random(&mut rng))
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    //     /// format).
    //     pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
    //         k256::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
    //             .map(Self)
    //             .map_err(SignatureError::from_source)
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Serialize this private key as DER-encoded PKCS#8
    //     pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
    //         use k256::pkcs8::EncodePrivateKey;

    //         self.0
    //             .to_pkcs8_der()
    //             .map_err(SignatureError::from_source)
    //             .map(|der| der.as_bytes().to_owned())
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Deserialize PKCS#8-encoded private key from PEM.
    //     pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
    //         k256::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
    //             .map(Self)
    //             .map_err(SignatureError::from_source)
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Serialize this private key as PEM-encoded PKCS#8
    //     pub fn to_pem(&self) -> Result<String, SignatureError> {
    //         use pkcs8::EncodePrivateKey;

    //         self.0
    //             .to_pkcs8_pem(pkcs8::LineEnding::default())
    //             .map_err(SignatureError::from_source)
    //             .map(|pem| (*pem).to_owned())
    //     }

    //     #[cfg(feature = "pem")]
    //     pub(crate) fn from_k256(private_key: SigningKey) -> Self {
    //         Self(private_key)
    //     }

    pub fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1Signature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::Secp256k1Signature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_simple(&self, msg: &[u8]) -> Result<SimpleSignature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::SimpleSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }

    pub fn try_sign_user(&self, msg: &[u8]) -> Result<UserSignature> {
        <iota_crypto::secp256k1::Secp256k1PrivateKey as iota_crypto::Signer<
            iota_types::UserSignature,
        >>::try_sign(&self.0, msg)
        .map_err(SdkFfiError::custom)
        .map(Into::into)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1VerifyingKey(iota_crypto::secp256k1::Secp256k1VerifyingKey);

#[uniffi::export]
impl Secp256k1VerifyingKey {
    //     pub fn new(public_key: &Secp256k1PublicKey) -> Result<Self,
    // SignatureError> {         VerifyingKey::try_from(public_key.inner().
    // as_ref()).map(Self)     }

    //     pub fn public_key(&self) -> Secp256k1PublicKey {
    //         Secp256k1PublicKey::new(self.0.as_ref().to_bytes().into())
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    //     pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
    //         k256::pkcs8::DecodePublicKey::from_public_key_der(bytes)
    //             .map(Self)
    //             .map_err(SignatureError::from_source)
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Serialize this public key as DER-encoded data
    //     pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
    //         use pkcs8::EncodePublicKey;

    //         self.0
    //             .to_public_key_der()
    //             .map_err(SignatureError::from_source)
    //             .map(|der| der.into_vec())
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Deserialize public key from PEM.
    //     pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
    //         k256::pkcs8::DecodePublicKey::from_public_key_pem(s)
    //             .map(Self)
    //             .map_err(SignatureError::from_source)
    //     }

    //     #[cfg(feature = "pem")]
    //     #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    //     /// Serialize this public key into PEM
    //     pub fn to_pem(&self) -> Result<String, SignatureError> {
    //         use pkcs8::EncodePublicKey;

    //         self.0
    //             .to_public_key_pem(pkcs8::LineEnding::default())
    //             .map_err(SignatureError::from_source)
    //     }

    //     #[cfg(feature = "pem")]
    //     pub(crate) fn from_k256(verifying_key: VerifyingKey) -> Self {
    //         Self(verifying_key)
    //     }

    pub fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::Secp256k1Signature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    pub fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1VerifyingKey as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Secp256k1Verifier(iota_crypto::secp256k1::Secp256k1Verifier);

#[uniffi::export]
impl Secp256k1Verifier {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(iota_crypto::secp256k1::Secp256k1Verifier::new())
    }

    fn verify_simple(&self, message: &[u8], signature: &SimpleSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1Verifier as iota_crypto::Verifier<
            iota_types::SimpleSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }

    fn verify_user(&self, message: &[u8], signature: &UserSignature) -> Result<()> {
        <iota_crypto::secp256k1::Secp256k1Verifier as iota_crypto::Verifier<
            iota_types::UserSignature,
        >>::verify(&self.0, message, &signature.0)
        .map_err(SdkFfiError::custom)
    }
}
