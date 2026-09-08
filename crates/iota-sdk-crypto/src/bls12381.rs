// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blst::min_sig::{PublicKey, SecretKey, Signature};
use iota_types::{
    Address, Bls12381PublicKey, Bls12381Signature, CheckpointSummary, SignatureScheme,
    ValidatorSignature,
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

#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Bls12381PrivateKey(SecretKey);

impl PartialEq for Bls12381PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        zeroize::Zeroizing::new(self.0.to_bytes()) == zeroize::Zeroizing::new(other.0.to_bytes())
    }
}

impl Eq for Bls12381PrivateKey {}

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

    pub fn random_with<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        let secret_key = SecretKey::key_gen(&buf, &[]).unwrap();
        Self(secret_key)
    }

    /// Generate a new private key using the operating system's random number
    /// generator.
    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random() -> Self {
        Self::random_with(rand_core::OsRng)
    }

    /// Sign a proof that this key's holder also controls `address`, which a
    /// validator submits alongside its public key so the network can check
    /// that the key is not someone else's.
    pub fn generate_proof_of_possession(&self, address: Address) -> Bls12381Signature {
        self.sign(&self.public_key().proof_of_possession_message(address))
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

impl crate::ToFromBytes for Bls12381PrivateKey {
    type Error = crate::PrivateKeyError;
    type ByteArray = [u8; Self::LENGTH];

    /// Return the raw 32-byte private key
    fn to_bytes(&self) -> Self::ByteArray {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = bytes.as_ref();
        let bytes: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| {
            crate::PrivateKeyError::InvalidScheme("invalid bls12381 key length".to_string())
        })?;

        Self::new(bytes).map_err(|e| crate::PrivateKeyError::InvalidScheme(e.to_string()))
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
        PublicKey::key_validate(public_key.bytes())
            .map(Self)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        Bls12381PublicKey::new(self.0.to_bytes())
    }

    /// Check a proof of possession produced by
    /// [`Bls12381PrivateKey::generate_proof_of_possession`] for `address`.
    pub fn verify_proof_of_possession(
        &self,
        address: Address,
        proof: &Bls12381Signature,
    ) -> Result<(), SignatureError> {
        self.verify(
            &self.public_key().proof_of_possession_message(address),
            proof,
        )
    }
}

impl Verifier<Bls12381Signature> for Bls12381VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> Result<(), SignatureError> {
        let signature = Signature::sig_validate(signature.bytes(), true)
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

    #[proptest]
    fn proof_of_possession(signer: Bls12381PrivateKey, address: Address, other: Address) {
        let proof = signer.generate_proof_of_possession(address);
        signer
            .verifying_key()
            .verify_proof_of_possession(address, &proof)
            .unwrap();

        if address != other {
            signer
                .verifying_key()
                .verify_proof_of_possession(other, &proof)
                .unwrap_err();
        }
    }

    #[proptest]
    fn proof_of_possession_is_bound_to_its_key(
        signer: Bls12381PrivateKey,
        other: Bls12381PrivateKey,
        address: Address,
    ) {
        let proof = signer.generate_proof_of_possession(address);
        other
            .verifying_key()
            .verify_proof_of_possession(address, &proof)
            .unwrap_err();
    }

    #[proptest]
    fn base64_roundtrip(signer: Bls12381PrivateKey) {
        use crate::{ToFromBase64 as _, ToFromBytes as _};

        let decoded = Bls12381PrivateKey::from_base64(&signer.to_base64()).unwrap();
        assert_eq!(decoded.to_bytes(), signer.to_bytes());
    }

    #[test]
    fn from_base64_rejects_invalid_input() {
        use crate::ToFromBase64 as _;

        Bls12381PrivateKey::from_base64("not-base64!").unwrap_err();
        // Valid base64, wrong length.
        Bls12381PrivateKey::from_base64("aGVsbG8=").unwrap_err();
    }

    #[test]
    fn base64_encodes_the_unflagged_raw_key() {
        use crate::ToFromBase64 as _;

        let signer = Bls12381PrivateKey::new([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ])
        .unwrap();

        assert_eq!(
            signer.to_base64(),
            "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
        );
    }

    // Proofs of possession are checked on-chain against what the node
    // produces, so the message this crate signs has to stay byte-identical to
    // it. This vector was generated with the node's
    // `generate_proof_of_possession`.
    #[test]
    fn proof_of_possession_matches_the_node() {
        let signer = Bls12381PrivateKey::new([7; Bls12381PrivateKey::LENGTH]).unwrap();
        let address = Address::new([3; Address::LENGTH]);
        let expected = "a717b0fcfc8aab7de211daad6b896659657f93094eab6a284c29710b2abc1abe5f08cb7f4a6dcfc2f44734f8dbcc2eb8";

        let proof = signer.generate_proof_of_possession(address);
        assert_eq!(hex::encode(proof.bytes()), expected);

        signer
            .verifying_key()
            .verify_proof_of_possession(address, &proof)
            .unwrap();
    }
}
