// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use blake2::Digest as DigestTrait;

use crate::{Address, Digest, PublicKeyExt};

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

impl crate::ZkLoginPublicIdentifier {
    /// Derive an `Address` from this `ZkLoginPublicIdentifier` by hashing the
    /// byte length of the `iss` followed by the `iss` bytes themselves and
    /// the full 32 byte `address_seed` value, all prefixed with the zklogin
    /// `SignatureScheme` flag (`0x05`).
    ///
    /// `hash( 0x05 || iss_bytes_len || iss_bytes || 32_byte_address_seed )`
    pub fn derive_address_padded(&self) -> Address {
        let mut hasher = Hasher::new();
        self.write_into_hasher_padded(&mut hasher);
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    fn write_into_hasher_padded(&self, hasher: &mut Hasher) {
        hasher.update([self.scheme().to_u8()]);
        hasher.update([self.iss().len() as u8]); // TODO enforce iss is less than 255 bytes
        hasher.update(self.iss());
        hasher.update(self.address_seed().padded());
    }

    /// Derive an `Address` from this `ZkLoginPublicIdentifier` by hashing the
    /// byte length of the `iss` followed by the `iss` bytes themselves and
    /// the `address_seed` bytes with any leading zero-bytes stripped, all
    /// prefixed with the zklogin `SignatureScheme` flag (`0x05`).
    ///
    /// `hash( 0x05 || iss_bytes_len || iss_bytes ||
    /// unpadded_32_byte_address_seed )`
    pub fn derive_address_unpadded(&self) -> Address {
        let mut hasher = Hasher::new();
        hasher.update([self.scheme().to_u8()]);
        hasher.update([self.iss().len() as u8]); // TODO enforce iss is less than 255 bytes
        hasher.update(self.iss());
        hasher.update(self.address_seed().unpadded());
        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }

    /// Provides an iterator over the addresses that correspond to this zklogin
    /// authenticator.
    ///
    /// In the majority of instances this will only yield a single address,
    /// except for the instances where the `address_seed` value has a
    /// leading zero-byte, in such cases the returned iterator will yield
    /// two addresses.
    pub fn derive_address(&self) -> impl Iterator<Item = Address> {
        let main_address = self.derive_address_padded();
        let mut addresses = [Some(main_address), None];
        // If address_seed starts with a zero byte then we know that this zklogin
        // authenticator has two addresses
        if self.address_seed().padded()[0] == 0 {
            let secondary_address = self.derive_address_unpadded();

            addresses[1] = Some(secondary_address);
        }

        addresses.into_iter().flatten()
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
    ///
    /// When flag_i is ZkLogin, the pk_i for the [`ZkLoginPublicIdentifier`]
    /// refers to the same input used when deriving the address using the
    /// [`ZkLoginPublicIdentifier::derive_address_padded`] method (using the
    /// full 32-byte `address_seed` value).
    ///
    /// [`ZkLoginPublicIdentifier`]: crate::ZkLoginPublicIdentifier
    /// [`ZkLoginPublicIdentifier::derive_address_padded`]: crate::ZkLoginPublicIdentifier::derive_address_padded
    pub fn derive_address(&self) -> Address {
        use crate::MultisigMemberPublicKey::*;

        let mut hasher = Hasher::new();
        hasher.update([self.scheme().to_u8()]);
        hasher.update(self.threshold().to_le_bytes());

        for member in self.members() {
            match member.public_key() {
                Ed25519(p) => p.write_into_hasher(&mut hasher),
                Secp256k1(p) => p.write_into_hasher(&mut hasher),
                Secp256r1(p) => p.write_into_hasher(&mut hasher),
                ZkLogin(p) => p.write_into_hasher_padded(&mut hasher),
            }

            hasher.update(member.weight().to_le_bytes());
        }

        let digest = hasher.finalize();
        Address::new(digest.into_inner())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod type_digest {
    use base64ct::Encoding;

    use super::Hasher;
    use crate::Digest;

    impl crate::Object {
        /// Calculate the digest of this `Object`
        ///
        /// This is done by hashing the BCS bytes of this `Object` prefixed
        /// with a salt.
        pub fn digest(&self) -> Digest {
            const SALT: &str = "Object::";
            type_digest(SALT, self)
        }
    }

    impl crate::CheckpointSummary {
        pub fn digest(&self) -> Digest {
            const SALT: &str = "CheckpointSummary::";
            type_digest(SALT, self)
        }
    }

    impl crate::CheckpointContents {
        pub fn digest(&self) -> Digest {
            const SALT: &str = "CheckpointContents::";
            type_digest(SALT, self)
        }
    }

    impl crate::Transaction {
        pub fn digest(&self) -> Digest {
            const SALT: &str = "TransactionData::";
            type_digest(SALT, &self)
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
        pub fn digest(&self) -> Digest {
            const SALT: &str = "TransactionData::";
            type_digest(SALT, &crate::Transaction::V1(self.clone()))
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
        pub fn digest(&self) -> Digest {
            const SALT: &str = "TransactionEffects::";
            type_digest(SALT, self)
        }
    }

    impl crate::TransactionEvents {
        pub fn digest(&self) -> Digest {
            const SALT: &str = "TransactionEvents::";
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
        Digest, Intent, IntentAppId, IntentScope, IntentVersion, PersonalMessage, SigningDigest,
        Transaction, TransactionV1, hash::Hasher,
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
}

/// A 1-byte domain separator for hashing Object ID in IOTA. It is starting from
/// 0xf0 to ensure no hashing collision for any ObjectId vs Address which is
/// derived as the hash of `flag || pubkey`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
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
    pub fn derive_id(digest: crate::Digest, count: u64) -> Self {
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

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;
    use crate::{
        Address, Ed25519PublicKey, MultisigCommittee, MultisigMember, MultisigMemberPublicKey,
        PasskeyPublicKey, Secp256k1PublicKey, Secp256r1PublicKey, SignatureScheme,
    };

    // --- Hasher Tests ---

    #[test]
    fn hasher_basic_usage() {
        let mut hasher = Hasher::new();
        hasher.update(b"hello");
        hasher.update(b" world");
        let digest = hasher.finalize();

        // BLAKE2b-256("hello world")
        // Calculated via external tool: 256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610
        let expected =
            hex::decode("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")
                .unwrap();
        assert_eq!(digest.into_inner().to_vec(), expected);
    }

    #[test]
    fn hasher_convenience_digest() {
        let digest = Hasher::digest(b"hello world");
        let expected =
            hex::decode("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")
                .unwrap();
        assert_eq!(digest.into_inner().to_vec(), expected);
    }

    #[test]
    fn hasher_write_trait() {
        use std::io::Write;
        let mut hasher = Hasher::new();
        hasher.write_all(b"hello world").unwrap();
        hasher.flush().unwrap();
        let digest = hasher.finalize();
        let expected =
            hex::decode("256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610")
                .unwrap();
        assert_eq!(digest.into_inner().to_vec(), expected);
    }

    // --- Address Derivation Tests ---

    #[test]
    fn ed25519_address_derivation() {
        let pk_bytes = [0xAA; 32];
        let pk = Ed25519PublicKey::new(pk_bytes);

        // Ed25519 address = Blake2b256(pk_bytes) (No prefix)
        let mut hasher = Hasher::new();
        hasher.update(pk_bytes);
        let expected_addr = Address::new(hasher.finalize().into_inner());

        assert_eq!(pk.derive_address(), expected_addr);
    }

    #[test]
    fn secp256k1_address_derivation() {
        let pk_bytes = [0xBB; 33];
        let pk = Secp256k1PublicKey::new(pk_bytes);

        // Secp256k1 address = Blake2b256(0x01 || pk_bytes)
        let mut hasher = Hasher::new();
        hasher.update([0x01]);
        hasher.update(pk_bytes);
        let expected_addr = Address::new(hasher.finalize().into_inner());

        assert_eq!(pk.derive_address(), expected_addr);
    }

    #[test]
    fn secp256r1_address_derivation() {
        let pk_bytes = [0xCC; 33];
        let pk = Secp256r1PublicKey::new(pk_bytes);

        // Secp256r1 address = Blake2b256(0x02 || pk_bytes)
        let mut hasher = Hasher::new();
        hasher.update([0x02]);
        hasher.update(pk_bytes);
        let expected_addr = Address::new(hasher.finalize().into_inner());

        assert_eq!(pk.derive_address(), expected_addr);
    }

    #[test]
    fn passkey_address_derivation() {
        let pk_bytes = [0xDD; 33];
        let inner = Secp256r1PublicKey::new(pk_bytes);
        let pk = PasskeyPublicKey::new(inner);

        // Passkey address = Blake2b256(0x06 || pk_bytes)
        let mut hasher = Hasher::new();
        hasher.update([0x06]);
        hasher.update(pk_bytes);
        let expected_addr = Address::new(hasher.finalize().into_inner());

        assert_eq!(pk.derive_address(), expected_addr);
    }

    #[test]
    fn multisig_address_derivation() {
        // Create a simple multisig committee with one member
        let pk_bytes = [0xAA; 32];
        let pk = Ed25519PublicKey::new(pk_bytes);
        let member = MultisigMember::new(MultisigMemberPublicKey::Ed25519(pk), 1);
        let committee = MultisigCommittee::new(vec![member], 1);

        // Multisig address logic verification
        let addr = committee.derive_address();
        
        // Manual verification
        let mut hasher = Hasher::new();
        hasher.update([0x03]); // Multisig Scheme
        hasher.update(1u16.to_le_bytes()); // Threshold
        // Member 1: Ed25519 has no prefix in write_into_hasher
        hasher.update(pk_bytes); 
        hasher.update(1u8.to_le_bytes()); // Weight
        
        let expected = Address::new(hasher.finalize().into_inner());
        
        assert_eq!(addr, expected);
    }
    
    // --- HashingIntent Tests (Ported from existing) ---

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

    #[test]
    fn zklogin_address_derivation() {
        use crate::ZkLoginPublicIdentifier;
        use crate::crypto::Bn254FieldElement;
        
        let iss = "https://accounts.google.com".to_string();
        let seed_bytes = [1u8; 32];
        let address_seed = Bn254FieldElement::new(seed_bytes);
        // Note: New returns Option, but we know inputs are valid
        let zk_id = ZkLoginPublicIdentifier::new(iss.clone(), address_seed).unwrap();
        
        // Manual derivation
        let mut hasher = Hasher::new();
        hasher.update([0x05]); // ZkLogin Scheme
        hasher.update([iss.len() as u8]);
        hasher.update(iss.as_bytes());
        hasher.update(seed_bytes); // Padded
        let expected = Address::new(hasher.finalize().into_inner());
        
        assert_eq!(zk_id.derive_address_padded(), expected);
    }
    
    #[test]
    fn zklogin_address_derivation_unpadded() {
        use crate::ZkLoginPublicIdentifier;
        use crate::crypto::Bn254FieldElement;
        
        let iss = "https://accounts.google.com".to_string();
        let mut seed_bytes = [0u8; 32];
        seed_bytes[31] = 1; // 0x00...01
        let address_seed = Bn254FieldElement::new(seed_bytes);
        let zk_id = ZkLoginPublicIdentifier::new(iss.clone(), address_seed).unwrap();
        
        // Manual derivation unpadded
        let mut hasher = Hasher::new();
        hasher.update([0x05]); // ZkLogin Scheme
        hasher.update([iss.len() as u8]);
        hasher.update(iss.as_bytes());
        hasher.update([1]); // Unpadded 0x01 (last byte of seed)
        let expected = Address::new(hasher.finalize().into_inner());
        
        assert_eq!(zk_id.derive_address_unpadded(), expected);
    }
    
    #[test]
    fn object_id_derivation() {
        use crate::ObjectId;
        let digest = Digest::new([1u8; 32]);
        let count: u64 = 0;
        let id = ObjectId::derive_id(digest, count);
        
        let mut hasher = Hasher::new();
        hasher.update([0xf1]); // RegularObjectId (HashingIntent::RegularObjectId)
        hasher.update(digest);
        hasher.update(count.to_le_bytes());
        let expected = ObjectId::new(hasher.finalize().into_inner());
        
        assert_eq!(id, expected);
    }

    #[test]
    fn object_id_derive_dynamic_child() {
        use crate::ObjectId;
        let parent = ObjectId::new([2u8; 32]);
        // Use parse for TypeTag
        use crate::TypeTag;
        let type_tag: TypeTag = "0x0::test::Test".parse().unwrap();
        let key_bytes = b"verification_key";
        
        let child_id = parent.derive_dynamic_child_id(&type_tag, key_bytes);
        
        let mut hasher = Hasher::new();
        hasher.update([0xf0]); // ChildObjectId (HashingIntent::ChildObjectId)
        hasher.update(parent);
        hasher.update((key_bytes.len() as u64).to_le_bytes());
        hasher.update(key_bytes);
        bcs::serialize_into(&mut hasher, &type_tag).unwrap();
        let expected = ObjectId::new(hasher.finalize().into_inner());
        
        assert_eq!(child_id, expected);
    }

}
