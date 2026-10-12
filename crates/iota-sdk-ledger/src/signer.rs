// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::DerivationPath;
use iota_types::{
    Address, Ed25519PublicKey, Ed25519Signature, Object, PersonalMessage, SimpleSignature,
    Transaction, UserSignature,
};

use crate::{Ledger, LedgerError};

/// Signs with the key at one derivation path on a Ledger device.
///
/// The device hashes the intent message itself, so the signer sends the whole
/// transaction or message rather than its digest. Before each signature it
/// reads the public key again and fails with [`LedgerError::AddressMismatch`]
/// if it changed, which happens when another device is connected.
#[derive(Debug)]
pub struct LedgerSigner {
    ledger: Ledger,
    path: DerivationPath,
    public_key: Ed25519PublicKey,
}

impl LedgerSigner {
    /// Read the public key at `path` and sign with it.
    pub async fn new(ledger: Ledger, path: DerivationPath) -> Result<Self, LedgerError> {
        let public_key = ledger.get_public_key(&path).await?;
        Ok(Self {
            ledger,
            path,
            public_key,
        })
    }

    /// Fail with [`LedgerError::AddressMismatch`] unless the key belongs to
    /// `address`, to catch a wrong device or derivation path.
    pub fn with_expected_address(self, address: &Address) -> Result<Self, LedgerError> {
        if self.address() != *address {
            return Err(LedgerError::AddressMismatch);
        }
        Ok(self)
    }

    /// The derivation path of the signing key.
    pub fn path(&self) -> &DerivationPath {
        &self.path
    }

    /// The public key that signs.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The address of the signing key.
    pub fn address(&self) -> Address {
        self.public_key.derive_address()
    }

    /// The device the signer uses.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Return the device.
    pub fn into_ledger(self) -> Ledger {
        self.ledger
    }

    /// Sign a transaction without its input objects. The device only signs
    /// when blind signing is enabled in the IOTA app's settings.
    pub async fn sign_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<UserSignature, LedgerError> {
        self.sign_transaction_with_objects(transaction, &[]).await
    }

    /// Sign a transaction, passing its input objects so the device can show
    /// what the transaction does instead of requiring blind signing.
    pub async fn sign_transaction_with_objects(
        &self,
        transaction: &Transaction,
        objects: &[Object],
    ) -> Result<UserSignature, LedgerError> {
        self.ensure_same_key().await?;
        let signature = self
            .ledger
            .sign_transaction(&self.path, transaction, objects)
            .await?;
        Ok(self.user_signature(signature))
    }

    /// Sign a personal message.
    pub async fn sign_personal_message(
        &self,
        message: &PersonalMessage<'_>,
    ) -> Result<UserSignature, LedgerError> {
        self.ensure_same_key().await?;
        let signature = self
            .ledger
            .sign_personal_message(&self.path, message)
            .await?;
        Ok(self.user_signature(signature))
    }

    async fn ensure_same_key(&self) -> Result<(), LedgerError> {
        if self.ledger.get_public_key(&self.path).await? != self.public_key {
            return Err(LedgerError::AddressMismatch);
        }
        Ok(())
    }

    fn user_signature(&self, signature: Ed25519Signature) -> UserSignature {
        UserSignature::Simple(SimpleSignature::Ed25519 {
            signature,
            public_key: self.public_key,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures::executor::block_on;

    use super::*;
    use crate::{ApduAnswer, ApduCommand, Transport, TransportFuture};

    /// An IOTA plain transfer from the IOTA app's ragger tests.
    const TRANSACTION: &str = "00000100201b3669e321893ee49c387a08fc251dbfff37cd2a981e6c473a5b2afde19d363e010101000100000f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6011eec6c32ef36467331fb7b088b4acb1ce46f736354308e03ff6ce913a42734e2860000000000000020c7ebc6c4430b3cf7e58d75ab53ddb9180274def63b1ab5619fbdb7096cdbd7120f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b6e80300000000000040420f000000000000";
    const SIGNATURE: [u8; 64] = [9; 64];

    /// Answers every command with its final result at once, using whichever
    /// key is currently set.
    struct FakeDevice {
        public_key: Arc<Mutex<Ed25519PublicKey>>,
    }

    impl Transport for FakeDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                let public_key = *self.public_key.lock().unwrap();
                let result = match command.ins() {
                    // version
                    0x00 => vec![1, 0, 1],
                    // public key
                    0x02 => [
                        &[32][..],
                        public_key.bytes(),
                        &[32],
                        public_key.derive_address().as_bytes(),
                    ]
                    .concat(),
                    // sign
                    0x03 => SIGNATURE.to_vec(),
                    ins => panic!("unexpected instruction {ins:#04x}"),
                };
                ApduAnswer::from_bytes([&[1][..], &result, &[0x90, 0x00]].concat())
            })
        }
    }

    fn signer(public_key: &Arc<Mutex<Ed25519PublicKey>>) -> LedgerSigner {
        let ledger = Ledger::new(FakeDevice {
            public_key: public_key.clone(),
        });
        block_on(LedgerSigner::new(
            ledger,
            "m/44'/4218'/0'/0'/0'".parse().unwrap(),
        ))
        .unwrap()
    }

    fn transaction() -> Transaction {
        bcs::from_bytes(&hex::decode(TRANSACTION).unwrap()).unwrap()
    }

    #[test]
    fn signs_with_the_device_key() {
        let public_key = Ed25519PublicKey::new([7; 32]);
        let signer = signer(&Arc::new(Mutex::new(public_key)));
        assert_eq!(signer.address(), public_key.derive_address());

        let expected = UserSignature::Simple(SimpleSignature::Ed25519 {
            signature: Ed25519Signature::new(SIGNATURE),
            public_key,
        });
        assert_eq!(
            block_on(signer.sign_transaction(&transaction())).unwrap(),
            expected
        );
        assert_eq!(
            block_on(signer.sign_personal_message(&PersonalMessage(b"Hello".into()))).unwrap(),
            expected
        );
    }

    #[test]
    fn checks_the_expected_address() {
        let public_key = Ed25519PublicKey::new([7; 32]);
        let signer = signer(&Arc::new(Mutex::new(public_key)));
        let signer = signer
            .with_expected_address(&public_key.derive_address())
            .unwrap();

        let other = Ed25519PublicKey::new([8; 32]).derive_address();
        assert!(matches!(
            signer.with_expected_address(&other),
            Err(LedgerError::AddressMismatch)
        ));
    }

    #[test]
    fn rejects_a_changed_key() {
        let public_key = Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32])));
        let signer = signer(&public_key);
        *public_key.lock().unwrap() = Ed25519PublicKey::new([8; 32]);

        assert!(matches!(
            block_on(signer.sign_transaction(&transaction())),
            Err(LedgerError::AddressMismatch)
        ));
    }

    #[test]
    fn futures_are_send() {
        fn assert_send<T: Send>(_: T) {}
        let signer = signer(&Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32]))));
        let transaction = transaction();
        assert_send(signer.sign_transaction(&transaction));
        assert_send(signer.sign_personal_message(&PersonalMessage(b"".into())));
    }
}
