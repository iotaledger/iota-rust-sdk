// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blst::min_sig::{PublicKey, SecretKey, Signature};
use iota_types::{
    Bls12381PublicKey, Bls12381Signature, CheckpointSummary, SignatureScheme, ValidatorSignature,
};

use crate::{SignatureError, Signer, Verifier};

const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug)]
#[allow(unused)]
pub(crate) struct BlstError(pub(crate) blst::BLST_ERROR);

impl std::fmt::Display for BlstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BlstError {}

#[derive(Clone)]
pub struct Bls12381PrivateKey(SecretKey);

impl std::fmt::Debug for Bls12381PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bls12381PrivateKey")
            .field(&"__elided__")
            .finish()
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for Bls12381PrivateKey {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_map(|bytes| {
                let secret_key = SecretKey::key_gen(&bytes, &[]).unwrap();
                Self(secret_key)
            })
            .boxed()
    }
}

impl Bls12381PrivateKey {
    /// The length of an bls12381 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        SecretKey::from_bytes(&bytes)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
            .map(Self)
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Bls12381
    }

    pub fn verifying_key(&self) -> Bls12381VerifyingKey {
        let verifying_key = self.0.sk_to_pk();
        Bls12381VerifyingKey(verifying_key)
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        self.verifying_key().public_key()
    }

    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        let secret_key = SecretKey::key_gen(&buf, &[]).unwrap();
        Self(secret_key)
    }

    pub fn sign_checkpoint_summary(&self, summary: &CheckpointSummary) -> ValidatorSignature {
        let message = summary.signing_message();
        let signature = self.sign(&message);
        ValidatorSignature {
            epoch: summary.epoch,
            public_key: self.public_key(),
            signature,
        }
    }
}

impl Signer<Bls12381Signature> for Bls12381PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Bls12381Signature, SignatureError> {
        let signature = self.0.sign(msg, DST_G1, &[]);
        Ok(Bls12381Signature::new(signature.to_bytes()))
    }
}

#[derive(Debug)]
pub struct Bls12381VerifyingKey(pub(crate) PublicKey);

impl Bls12381VerifyingKey {
    pub fn new(public_key: &Bls12381PublicKey) -> Result<Self, SignatureError> {
        PublicKey::key_validate(public_key.inner())
            .map(Self)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        Bls12381PublicKey::new(self.0.to_bytes())
    }
}

impl Verifier<Bls12381Signature> for Bls12381VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> Result<(), SignatureError> {
        let signature = Signature::sig_validate(signature.inner(), true)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)?;

        let err = signature.verify(true, message, DST_G1, &[], &self.0, false);
        if err == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(SignatureError::from_source(BlstError(err)))
        }
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn basic_signing(signer: Bls12381PrivateKey, message: Vec<u8>) {
        let signature = signer.sign(&message);
        signer.verifying_key().verify(&message, &signature).unwrap();
    }
}
