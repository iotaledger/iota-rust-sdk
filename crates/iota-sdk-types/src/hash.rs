// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2::Digest as DigestTrait;

use crate::{Address, Digest, PublicKeyExt, crypto::PublicKey};

type Blake2b256 = blake2::Blake2b<blake2::digest::consts::U32>;

/// A Blake2b256 Hasher
#[derive(Debug, Default)]
pub struct Hasher(Blake2b256);

impl Hasher {
    /// Initialize a new Blake2b256 Hasher instance.
    pub fn new() -> Self {
        Self(Blake2b256::new())
    }

    /// Process the provided data, updating internal state.
    pub fn update<T: AsRef<[u8]>>(&mut self, data: T) {
        self.0.update(data)
    }

    /// Finalize hashing, consuming the Hasher instance and returning the
    /// resultant hash or `Digest`.
    pub fn finalize(self) -> Digest {
        let mut buf = [0; Digest::LENGTH];
        let result = self.0.finalize();

        buf.copy_from_slice(&result);

        Digest::new(buf)
    }

    /// Convenience function for creating a new Hasher instance, hashing the
    /// provided data, and returning the resultant `Digest`
    pub fn digest<T: AsRef<[u8]>>(data: T) -> Digest {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl crate::Ed25519PublicKey {
    /// Derive an `Address` from this Public Key
    ///
    /// An `Address` can be derived from an `Ed25519PublicKey` by hashing the
    /// bytes of the public key with no prefix flag.
    ///
    /// `hash(32-byte ed25519 public key)`
    ///
    /// ```
    /// use iota_sdk_types::{Address, Ed25519PublicKey, hash::Hasher};
    ///
    /// let public_key_bytes = [0; 32];
    /// let mut hasher = Hasher::new();
    /// hasher.update(public_key_bytes);
    /// let address = Address::new(hasher.finalize().into_inner());
    /// println!("Address: {}", address);
    ///
    /// let public_key = Ed25519PublicKey::new(public_key_bytes);
    /// assert_eq!(address, public_key.derive_address());
    /// ```
    pub fn derive_address(&self) -> Address {
        let mut hasher = Hasher::new();
        self.write_into_hasher(&mut hasher);
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    fn write_into_hasher(&self, hasher: &mut Hasher) {
        hasher.update(self.inner());
    }
}

impl From<crate::Ed25519PublicKey> for Address {
    fn from(public_key: crate::Ed25519PublicKey) -> Self {
        public_key.derive_address()
    }
}

impl crate::Secp256k1PublicKey {
    /// Derive an `Address` from this Public Key
    ///
    /// An `Address` can be derived from a `Secp256k1PublicKey` by hashing the
    /// bytes of the public key prefixed with the Secp256k1
    /// `SignatureScheme` flag (`0x01`).
    ///
    /// `hash( 0x01 || 33-byte secp256k1 public key)`
    ///
    /// ```
    /// use iota_sdk_types::{Address, Secp256k1PublicKey, hash::Hasher};
    ///
    /// let public_key_bytes = [0; 33];
    /// let mut hasher = Hasher::new();
    /// hasher.update([0x01]); // The SignatureScheme flag for Secp256k1 is `1`
    /// hasher.update(public_key_bytes);
    /// let address = Address::new(hasher.finalize().into_inner());
    /// println!("Address: {}", address);
    ///
    /// let public_key = Secp256k1PublicKey::new(public_key_bytes);
    /// assert_eq!(address, public_key.derive_address());
    /// ```
    pub fn derive_address(&self) -> Address {
        let mut hasher = Hasher::new();
        self.write_into_hasher(&mut hasher);
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    fn write_into_hasher(&self, hasher: &mut Hasher) {
        hasher.update([self.scheme().to_u8()]);
        hasher.update(self.inner());
    }
}

impl From<crate::Secp256k1PublicKey> for Address {
    fn from(public_key: crate::Secp256k1PublicKey) -> Self {
        public_key.derive_address()
    }
}

impl crate::Secp256r1PublicKey {
    /// Derive an `Address` from this Public Key
    ///
    /// An `Address` can be derived from a `Secp256r1PublicKey` by hashing the
    /// bytes of the public key prefixed with the Secp256r1
    /// `SignatureScheme` flag (`0x02`).
    ///
    /// `hash( 0x02 || 33-byte secp256r1 public key)`
    ///
    /// ```
    /// use iota_sdk_types::{Address, Secp256r1PublicKey, hash::Hasher};
    ///
    /// let public_key_bytes = [0; 33];
    /// let mut hasher = Hasher::new();
    /// hasher.update([0x02]); // The SignatureScheme flag for Secp256r1 is `2`
    /// hasher.update(public_key_bytes);
    /// let address = Address::new(hasher.finalize().into_inner());
    /// println!("Address: {}", address);
    ///
    /// let public_key = Secp256r1PublicKey::new(public_key_bytes);
    /// assert_eq!(address, public_key.derive_address());
    /// ```
    pub fn derive_address(&self) -> Address {
        let mut hasher = Hasher::new();
        self.write_into_hasher(&mut hasher);
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    fn write_into_hasher(&self, hasher: &mut Hasher) {
        hasher.update([self.scheme().to_u8()]);
        hasher.update(self.inner());
    }
}

impl From<crate::Secp256r1PublicKey> for Address {
    fn from(public_key: crate::Secp256r1PublicKey) -> Self {
        public_key.derive_address()
    }
}

impl crate::PasskeyPublicKey {
    /// Derive an `Address` from this Passkey Public Key
    ///
    /// An `Address` can be derived from a `PasskeyPublicKey` by hashing the
    /// bytes of the `Secp256r1PublicKey` that corresponds to this passkey
    /// prefixed with the Passkey `SignatureScheme` flag (`0x06`).
    ///
    /// `hash( 0x06 || 33-byte secp256r1 public key)`
    pub fn derive_address(&self) -> Address {
        let mut hasher = Hasher::new();
        self.write_into_hasher(&mut hasher);
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    fn write_into_hasher(&self, hasher: &mut Hasher) {
        hasher.update([self.scheme().to_u8()]);
        hasher.update(self.inner().inner());
    }
}

impl From<crate::PasskeyPublicKey> for Address {
    fn from(public_key: crate::PasskeyPublicKey) -> Self {
        public_key.derive_address()
    }
}

impl crate::PublicKey {
    pub fn derive_address(&self) -> Address {
        match self {
            Self::Ed25519(pk) => pk.derive_address(),
            Self::Secp256k1(pk) => pk.derive_address(),
            Self::Secp256r1(pk) => pk.derive_address(),
            Self::Passkey(pk) => pk.derive_address(),
        }
    }
}

impl From<crate::PublicKey> for Address {
    fn from(public_key: crate::PublicKey) -> Self {
        public_key.derive_address()
    }
}

impl crate::MultisigCommittee {
    /// Derive an `Address` from this MultisigCommittee.
    ///
    /// A MultiSig address
    /// is defined as the 32-byte Blake2b hash of serializing the
    /// `SignatureScheme` flag (0x03), the threshold (in little endian), and
    /// the concatenation of all n flag, public keys and its weight.
    ///
    /// `hash(0x03 || threshold || flag_1 || pk_1 || weight_1
    /// || ... || flag_n || pk_n || weight_n)`.
    pub fn derive_address(&self) -> Address {
        let mut hasher = Hasher::new();
        hasher.update([self.scheme().to_u8()]);
        hasher.update(self.threshold().to_le_bytes());

        for member in self.members() {
            match member.public_key() {
                PublicKey::Ed25519(p) => p.write_into_hasher(&mut hasher),
                PublicKey::Secp256k1(p) => p.write_into_hasher(&mut hasher),
                PublicKey::Secp256r1(p) => p.write_into_hasher(&mut hasher),
                PublicKey::Passkey(p) => p.write_into_hasher(&mut hasher),
            }

            hasher.update(member.weight().to_le_bytes());
        }

        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }
}

impl From<crate::MultisigCommittee> for Address {
    fn from(public_key: crate::MultisigCommittee) -> Self {
        public_key.derive_address()
    }
}

impl crate::UserSignature {
    /// Derive the `Address` of the signer that this signature authenticates.
    pub fn derive_address(&self) -> Address {
        match self {
            Self::Simple(simple) => simple.to_public_key().derive_address(),
            Self::Multisig(multisig) => multisig.committee().derive_address(),
            Self::PasskeyAuthenticator(passkey) => passkey.public_key().derive_address(),
            Self::MoveAuthenticator(move_authenticator) => move_authenticator.address(),
        }
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod type_digest {
    use base64ct::Encoding;

    use super::Hasher;
    use crate::{
        CheckpointContentsDigest, CheckpointDigest, Digest, ObjectDigest, TransactionDigest,
        TransactionEffectsDigest, TransactionEventsDigest,
    };

    impl crate::Object {
        /// Calculate the digest of this `Object`
        ///
        /// This is done by hashing the BCS bytes of this `Object` prefixed
        /// with a salt.
        pub fn digest(&self) -> ObjectDigest {
            const SALT: &str = "Object::";
            type_digest(SALT, self).into()
        }
    }

    impl crate::CheckpointSummary {
        pub fn digest(&self) -> CheckpointDigest {
            const SALT: &str = "CheckpointSummary::";
            type_digest(SALT, self).into()
        }
    }

    impl crate::CheckpointContents {
        pub fn digest(&self) -> CheckpointContentsDigest {
            const SALT: &str = "CheckpointContents::";
            type_digest(SALT, self).into()
        }
    }

    impl crate::Transaction {
        pub fn digest(&self) -> TransactionDigest {
            const SALT: &str = "TransactionData::";
            type_digest(SALT, &self).into()
        }

        /// Serialize the transaction as a `Vec<u8>` of BCS bytes.
        pub fn to_bcs(&self) -> Vec<u8> {
            bcs::to_bytes(self).expect("bcs serialization failed")
        }

        /// Serialize the transaction as a base64-encoded string.
        pub fn to_base64(&self) -> String {
            base64ct::Base64::encode_string(&self.to_bcs())
        }

        /// Deserialize a transaction from a `Vec<u8>` of BCS bytes.
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes::<Self>(bytes)
        }

        /// Deserialize a transaction from a base64-encoded string.
        pub fn from_base64(bytes: &str) -> Result<Self, bcs::Error> {
            let decoded = base64ct::Base64::decode_vec(bytes)
                .map_err(|e| bcs::Error::Custom(e.to_string()))?;
            Self::from_bcs(&decoded)
        }
    }

    impl crate::TransactionV1 {
        pub fn digest(&self) -> TransactionDigest {
            const SALT: &str = "TransactionData::";
            type_digest(SALT, &crate::Transaction::V1(self.clone())).into()
        }

        /// Serialize the transaction as a `Vec<u8>` of BCS bytes.
        pub fn to_bcs(&self) -> Vec<u8> {
            bcs::to_bytes(self).expect("bcs serialization failed")
        }

        /// Serialize the transaction as a base64-encoded string.
        pub fn to_base64(&self) -> String {
            base64ct::Base64::encode_string(&self.to_bcs())
        }

        /// Deserialize a transaction from a `Vec<u8>` of BCS bytes.
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes::<Self>(bytes)
        }

        /// Deserialize a transaction from a base64-encoded string.
        pub fn from_base64(bytes: &str) -> Result<Self, bcs::Error> {
            let decoded = base64ct::Base64::decode_vec(bytes)
                .map_err(|e| bcs::Error::Custom(e.to_string()))?;
            Self::from_bcs(&decoded)
        }
    }

    impl crate::TransactionEffects {
        pub fn digest(&self) -> TransactionEffectsDigest {
            const SALT: &str = "TransactionEffects::";
            type_digest(SALT, self).into()
        }
    }

    impl crate::TransactionEvents {
        pub fn digest(&self) -> TransactionEventsDigest {
            const SALT: &str = "TransactionEvents::";
            type_digest(SALT, self).into()
        }
    }

    impl crate::MoveAuthenticator {
        pub fn digest(&self) -> Digest {
            const SALT: &str = "MoveAuthenticator::";
            type_digest(SALT, self)
        }
    }

    fn type_digest<T: serde::Serialize>(salt: &str, ty: &T) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(salt);
        bcs::serialize_into(&mut hasher, ty).unwrap();
        hasher.finalize()
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod signing_message {
    use crate::{
        Digest, Intent, IntentAppId, IntentMessage, IntentScope, IntentVersion, PersonalMessage,
        SigningDigest, Transaction, TransactionV1, hash::Hasher,
    };

    impl Transaction {
        pub fn signing_digest(&self) -> SigningDigest {
            const INTENT: Intent = Intent::iota_transaction();
            let digest = signing_digest(INTENT, self);
            digest.into_inner()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    impl TransactionV1 {
        pub fn signing_digest(&self) -> SigningDigest {
            const INTENT: Intent = Intent::iota_transaction();
            let digest = signing_digest(INTENT, &Transaction::V1(self.clone()));
            digest.into_inner()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    fn signing_digest<T: serde::Serialize + ?Sized>(intent: Intent, ty: &T) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(intent.to_bytes());
        bcs::serialize_into(&mut hasher, ty).unwrap();
        hasher.finalize()
    }

    impl PersonalMessage<'_> {
        pub fn signing_digest(&self) -> SigningDigest {
            const INTENT: Intent = Intent::personal_message();
            let digest = signing_digest(INTENT, &self.0);
            digest.into_inner()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    impl crate::CheckpointSummary {
        pub fn signing_message(&self) -> Vec<u8> {
            const INTENT: Intent = Intent {
                scope: IntentScope::CheckpointSummary,
                version: IntentVersion::V0,
                app_id: IntentAppId::Iota,
            };
            let mut message = Vec::new();
            message.extend(INTENT.to_bytes());
            bcs::serialize_into(&mut message, self).unwrap();
            bcs::serialize_into(&mut message, &self.epoch).unwrap();
            message
        }

        pub fn signing_message_hex(&self) -> String {
            hex::encode(self.signing_message())
        }
    }

    impl<T> IntentMessage<T>
    where
        T: serde::Serialize,
    {
        pub fn signing_digest(&self) -> Digest {
            let mut hasher = Hasher::default();
            bcs::serialize_into(&mut hasher, self).unwrap();
            hasher.finalize()
        }
    }
}

/// A 1-byte domain separator for hashing Object ID in IOTA. It is starting from
/// 0xf0 to ensure no hashing collision for any ObjectId vs Address which is
/// derived as the hash of `flag || pubkey`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[repr(u8)]
enum HashingIntent {
    #[cfg(feature = "serde")]
    ChildObjectId = 0xf0,
    RegularObjectId = 0xf1,
}

impl crate::ObjectId {
    /// Create an ObjectId from a transaction digest and `count`.
    ///
    /// `count` is the number of objects that have been created during a
    /// transactions.
    pub fn derive_id(digest: crate::TransactionDigest, count: u64) -> Self {
        let mut hasher = Hasher::new();
        hasher.update([HashingIntent::RegularObjectId as u8]);
        hasher.update(digest);
        hasher.update(count.to_le_bytes());
        let digest = hasher.finalize();
        Self::new(digest.into_inner())
    }

    /// Derive an ObjectId for a Dynamic Child Object.
    ///
    /// hash(parent || len(key) || key || key_type_tag)
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    pub fn derive_dynamic_child_id(&self, key_type_tag: &crate::TypeTag, key_bytes: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update([HashingIntent::ChildObjectId as u8]);
        hasher.update(self);
        hasher.update(
            u64::try_from(key_bytes.len())
                .expect("key_bytes must fit into a u64")
                .to_le_bytes(),
        );
        hasher.update(key_bytes);
        bcs::serialize_into(&mut hasher, key_type_tag)
            .expect("bcs serialization of `TypeTag` cannot fail");
        let digest = hasher.finalize();

        Self::new(digest.into_inner())
    }
}

#[cfg(all(test, feature = "proptest"))]
mod tests {
    use test_strategy::proptest;

    use super::HashingIntent;
    use crate::SignatureScheme;

    impl HashingIntent {
        fn from_byte(byte: u8) -> Result<Self, u8> {
            match byte {
                0xf0 => Ok(Self::ChildObjectId),
                0xf1 => Ok(Self::RegularObjectId),
                invalid => Err(invalid),
            }
        }
    }

    #[proptest]
    fn hashing_intent_does_not_overlap_with_signature_scheme(intent: HashingIntent) {
        SignatureScheme::from_byte(intent as u8).unwrap_err();
    }

    #[proptest]
    fn signature_scheme_does_not_overlap_with_hashing_intent(scheme: SignatureScheme) {
        HashingIntent::from_byte(scheme.to_u8()).unwrap_err();
    }

    #[proptest]
    fn roundtrip_hashing_intent(intent: HashingIntent) {
        assert_eq!(Ok(intent), HashingIntent::from_byte(intent as u8));
    }
}
