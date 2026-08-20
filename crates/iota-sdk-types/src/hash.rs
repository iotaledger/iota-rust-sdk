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

impl From<crate::UserSignature> for Address {
    fn from(signature: crate::UserSignature) -> Self {
        signature.derive_address()
    }
}

/// Error returned when no signature in a
/// [`SignedTransaction`](crate::SignedTransaction) commits to an expected
/// signer address.
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("no signature found for address {address}")]
pub struct MissingSignatureError {
    /// The address no signature commits to.
    pub address: Address,
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod type_digest {
    use super::Hasher;
    use crate::{
        CheckpointContentsDigest, CheckpointDigest, Digest, ObjectDigest, SenderSignedDataDigest,
        TransactionDigest, TransactionEffectsDigest, TransactionEventsDigest,
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
    }

    impl crate::TransactionV1 {
        pub fn digest(&self) -> TransactionDigest {
            const SALT: &str = "TransactionData::";
            type_digest(SALT, &crate::Transaction::V1(self.clone())).into()
        }
    }

    impl crate::SenderSignedTransaction {
        /// Calculate the digest of the full message, committing to the signing
        /// intent, the transaction, and all signatures.
        ///
        /// Unlike the other type digests, this hashes the BCS bytes directly,
        /// without a salt prefix.
        pub fn full_message_digest(&self) -> SenderSignedDataDigest {
            let mut hasher = Hasher::new();
            bcs::serialize_into(&mut hasher, self).expect("bcs serialization failed");
            hasher.finalize().into()
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

    impl crate::UserSignature {
        /// Calculate the auth digest for this signature.
        ///
        /// For [`MoveAuthenticator`](crate::MoveAuthenticator) signatures this
        /// equals
        /// [`MoveAuthenticator::digest()`](crate::MoveAuthenticator::digest).
        /// For all other signature types it is the Blake2b256 of the
        /// serialized (flag-prefixed) signature bytes.
        pub fn auth_digest(&self) -> Digest {
            match self {
                Self::MoveAuthenticator(authenticator) => authenticator.digest(),
                Self::Simple(_) | Self::Multisig(_) | Self::PasskeyAuthenticator(_) => {
                    Hasher::digest(self.to_bytes())
                }
            }
        }
    }

    impl crate::SignedTransaction {
        /// Computes the auth digest for the sender and, if sponsored, for the
        /// sponsor. See
        /// [`UserSignature::auth_digest`](crate::UserSignature::auth_digest)
        /// for the per-signature logic.
        ///
        /// Returns an error if no signature commits to the sender or sponsor
        /// address.
        pub fn compute_auth_digests(
            &self,
        ) -> Result<(Digest, Option<Digest>), super::MissingSignatureError> {
            let crate::Transaction::V1(transaction) = &self.transaction;

            let digest_for_address = |address| {
                self.signatures
                    .iter()
                    .find(|signature| signature.derive_address() == address)
                    .map(crate::UserSignature::auth_digest)
                    .ok_or(super::MissingSignatureError { address })
            };

            let sender_auth_digest = digest_for_address(transaction.sender)?;
            let gas_owner = transaction.gas_payment.owner;
            let sponsor_auth_digest = if gas_owner != transaction.sender {
                Some(digest_for_address(gas_owner)?)
            } else {
                None
            };

            Ok((sender_auth_digest, sponsor_auth_digest))
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
        Digest, Intent, IntentMessage, IntentScope, PersonalMessage, SigningDigest, Transaction,
        TransactionV1, hash::Hasher,
    };

    impl Transaction {
        pub fn signing_digest(&self) -> SigningDigest {
            self.intent_message().signing_digest().into()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    impl TransactionV1 {
        pub fn signing_digest(&self) -> SigningDigest {
            Transaction::V1(self.clone()).signing_digest()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    impl PersonalMessage<'_> {
        pub fn signing_digest(&self) -> SigningDigest {
            IntentMessage::new(Intent::personal_message(), &self.0)
                .signing_digest()
                .into()
        }

        pub fn signing_digest_hex(&self) -> String {
            hex::encode(self.signing_digest())
        }
    }

    impl crate::CheckpointSummary {
        pub fn signing_message(&self) -> Vec<u8> {
            let mut message = Vec::new();
            message.extend(Intent::iota_app(IntentScope::CheckpointSummary).to_bytes());
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

    /// Derive the ObjectId of a derived object (`0x2::derived_object`).
    ///
    /// hash(parent || len(key) || key || DerivedObjectKey(key_type_tag))
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    pub fn derive_object_id(&self, key_type_tag: &crate::TypeTag, key_bytes: &[u8]) -> Self {
        // Wrap the key type into `DerivedObjectKey<K>` to preserve on-chain
        // namespacing
        let wrapper_type_tag = crate::TypeTag::Struct(Box::new(crate::StructTag::new(
            crate::Address::FRAMEWORK,
            crate::Identifier::DERIVED_OBJECT_MODULE,
            crate::Identifier::DERIVED_OBJECT_KEY,
            vec![key_type_tag.clone()],
        )));

        self.derive_dynamic_child_id(&wrapper_type_tag, key_bytes)
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

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use std::str::FromStr;

    use base64ct::Encoding;

    use crate::{Address, Identifier, ObjectId, StructTag, TypeTag, UserSignature};

    // Guards the address derivation from serialized signatures: every
    // UserSignature kind, given as base64, must keep deriving the same address.
    #[test]
    fn test_address_from_user_signature() {
        let fixtures = [
            // Ed25519
            (
                "AO/2qtqkYPqq3UzI7dVLmqt7dy2B5Ta2Hv7F1ssYO9auPyrcRGpawALnzyNyPBT/v/PIxSbNTskTs+ts6kGtkQYNfas1jI2tqk76AEmnWwdDZVWxCjaCGbtoD3BXE0nXdQ==",
                "0xebb23f93d022ac213e99ac7d85b7f7e1e4a18f045b379755565cffa08804c9a1",
            ),
            // Secp256k1
            (
                "ASWDBpw4ETzLiQlwS0kDKJA9PK47V8fp4e9S+7bpaJXfd4HfZ5oLSXTyezaHTRfcryQn3mdshteXwrEvj/ZAmiUCDhfNWTnkaxlmQZaM11mRC6JXfif6c/3jh225vsW86ys=",
                "0xd9607cd03428c904949572b51471e7a9f60019aeb9a3d7ee5e72921cab8e8be7",
            ),
            // Secp256r1
            (
                "Ai1Hdv4ZtEslPN424BGG5+6BhzGrp4d4ykoyiQhG2hDzbGDdCPgXVLLv26sfFP77nhJi78OAWfD+ytdQRyYPpKcDR/uvI/A4q8TDCKJxEXoqTP+u3bxf+Bx1F7xsdKfttDA=",
                "0x600b1081644fe46f76da3bdc19f8743b9f04458516364374c7d82959e790c19e",
            ),
            // MultiSig (2-of-3: Ed25519 + Secp256k1, over the pubkeys above)
            (
                "AwIArJTVgdzrD8V+em1zREsmT0jD/fduXgh/zo+Z+lZTYoBLZpaAw9PNO4YNDYBTK9vT646klVBV4ntBmFcYzdDVDQGia/pl6A/nh/uixuM1hc84fokvTk37j/DNq3/OtckvsV1Mg84ygJ7UXsuohtKjHc+zfuu2uwcjh2lOPVBgZotQAwADAA19qzWMja2qTvoASadbB0NlVbEKNoIZu2gPcFcTSdd1AQECDhfNWTnkaxlmQZaM11mRC6JXfif6c/3jh225vsW86ysBAgNH+68j8DirxMMIonEReipM/67dvF/4HHUXvGx0p+20MAECAA==",
                "0x34b66b6d090baea4effa1d1bf22e1adff466c3fb9425ded9c5bbb605865b2560",
            ),
            // PasskeyAuthenticator (Secp256r1-backed)
            (
                "BgByeyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vdGVzdC5pb3RhLm9yZyJ9YgJsW7qQ7IeOJMhUEgb7PFfoHEFCbk7qLZ27Nhqxpq8OLCapbkIG0nOO1iQgY7KjGPykr/gcDF+FtKxxcebcDOPXA0f7ryPwOKvEwwiicRF6Kkz/rt28X/gcdRe8bHSn7bQw",
                "0x79214f7090abbaf3d14fdbe357ea794650f41783ea64ece65314682144f658a7",
            ),
            // MoveAuthenticator
            (
                "BwAAAAEB7mKDoFTKsmYgpTHRjEnqNWAjnP2LqDo5O7qn1+7SCCoBAAAAAAAAAAA=",
                "0xee6283a054cab26620a531d18c49ea3560239cfd8ba83a393bbaa7d7eed2082a",
            ),
        ];

        for (b64, expected) in fixtures {
            let sig = UserSignature::from_base64(b64).unwrap();
            assert_eq!(sig.derive_address().to_string(), expected);
        }

        // zkLogin (flag 0x05) is deprecated: serialized signatures are rejected
        // at deserialization.
        let zklogin_b64 = base64ct::Base64::encode_string(&[0x05u8, 0, 0, 0]);
        assert!(UserSignature::from_base64(&zklogin_b64).is_err());
    }

    // Snapshot tests that match the on-chain `derive_address` logic.
    // These snapshots can also be found in the `derived_object_tests.move` unit
    // tests.
    #[test]
    fn test_derive_object_id_snapshot() {
        let key_bytes = bcs::to_bytes("foo".as_bytes()).unwrap();
        let key_type_tag = TypeTag::Vector(Box::new(TypeTag::U8));

        let id = ObjectId::from_str("0x2")
            .unwrap()
            .derive_object_id(&key_type_tag, &key_bytes);

        assert_eq!(
            id,
            ObjectId::from_str(
                "0xa2b411aa9588c398d8e3bc97dddbdd430b5ded7f81545d05e33916c3ca0f30c3"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_derive_object_id_with_struct_key_snapshot() {
        #[derive(serde::Serialize)]
        struct DemoStruct {
            value: u64,
        }

        let key_bytes = bcs::to_bytes(&DemoStruct { value: 1 }).unwrap();
        let key_type_tag = TypeTag::Struct(Box::new(StructTag::new(
            Address::FRAMEWORK,
            Identifier::from_static("derived_object_tests"),
            Identifier::from_static("DemoStruct"),
            vec![],
        )));

        let id = ObjectId::from_str("0x2")
            .unwrap()
            .derive_object_id(&key_type_tag, &key_bytes);

        assert_eq!(
            id,
            ObjectId::from_str(
                "0x20c58d8790a5d2214c159c23f18a5fdc347211e511186353e785ad543abcea6b"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_derive_object_id_with_generic_struct_key_snapshot() {
        #[derive(serde::Serialize)]
        struct GenericStruct<T> {
            value: T,
        }

        let key_bytes = bcs::to_bytes(&GenericStruct::<u64> { value: 1 }).unwrap();
        let key_type_tag = TypeTag::Struct(Box::new(StructTag::new(
            Address::FRAMEWORK,
            Identifier::from_static("derived_object_tests"),
            Identifier::from_static("GenericStruct"),
            vec![TypeTag::U64],
        )));

        let id = ObjectId::from_str("0x2")
            .unwrap()
            .derive_object_id(&key_type_tag, &key_bytes);

        assert_eq!(
            id,
            ObjectId::from_str(
                "0xb497b8dcf1e297ae5fa69c040e4a08ef8240d5373bbc9d6b686ffbd7dfe04cbe"
            )
            .unwrap()
        );
    }
}
