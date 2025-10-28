// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::RwLock;

use iota_sdk::types::SignatureScheme;
use rand::rngs::OsRng;

use crate::{
    error::{Result, SdkFfiError},
    types::{
        checkpoint::CheckpointSummary,
        crypto::{Bls12381PublicKey, Bls12381Signature},
        validator::{ValidatorCommittee, ValidatorSignature},
    },
};

#[derive(derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct Bls12381PrivateKey(pub iota_sdk::crypto::bls12381::Bls12381PrivateKey);

#[uniffi::export]
impl Bls12381PrivateKey {
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::crypto::bls12381::Bls12381PrivateKey::new(
            bytes.try_into().map_err(|v: Vec<u8>| {
                SdkFfiError::custom(format!("expected bytes of length 32, found {}", v.len()))
            })?,
        )?))
    }

    pub fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }

    pub fn verifying_key(&self) -> Bls12381VerifyingKey {
        self.0.verifying_key().into()
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key().into()
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        Self(iota_sdk::crypto::bls12381::Bls12381PrivateKey::generate(
            OsRng,
        ))
    }

    pub fn sign_checkpoint_summary(&self, summary: &CheckpointSummary) -> ValidatorSignature {
        self.0.sign_checkpoint_summary(&summary.0).into()
    }

    pub fn try_sign(&self, message: &[u8]) -> Result<Bls12381Signature> {
        Ok(
            iota_sdk::crypto::Signer::<iota_sdk::types::Bls12381Signature>::try_sign(
                &self.0, message,
            )?
            .into(),
        )
    }
}

#[derive(derive_more::From, uniffi::Object)]
pub struct Bls12381VerifyingKey(pub iota_sdk::crypto::bls12381::Bls12381VerifyingKey);

#[uniffi::export]
impl Bls12381VerifyingKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Bls12381PublicKey) -> Result<Self> {
        Ok(iota_sdk::crypto::bls12381::Bls12381VerifyingKey::new(&public_key.0).map(Self)?)
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.0.public_key().into()
    }

    pub fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> Result<()> {
        Ok(iota_sdk::crypto::Verifier::<
            iota_sdk::types::Bls12381Signature,
        >::verify(&self.0, message, &signature.0)?)
    }
}
