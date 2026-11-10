// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::DerivationPath;
use iota_types::{
    Address, Ed25519PublicKey, Ed25519Signature, Intent, Object, PersonalMessage, SimpleSignature,
    Transaction, UserSignature,
};
use serde::Serialize;

use crate::{Ledger, LedgerError, commands::sign};

impl Ledger {
    /// Create a signer for the key at `path`; see [`LedgerSigner::new`].
    pub async fn into_signer(self, path: DerivationPath) -> Result<LedgerSigner, LedgerError> {
        LedgerSigner::new(self, path).await
    }
}

/// Signs with the key at one derivation path on a Ledger device.
///
/// The device hashes the intent message itself, so the signer sends the whole
/// transaction or message rather than its digest. Before each signature it
/// reads the public key again and fails with [`LedgerError::KeyMismatch`] if
/// it differs, which happens when another device is connected or the device
/// was unlocked with a different seed or passphrase.
#[derive(Debug)]
pub struct LedgerSigner {
    ledger: Ledger,
    path: DerivationPath,
    public_key: Ed25519PublicKey,
}

impl LedgerSigner {
    /// Read the public key at `path` so it can be used for signing.
    pub async fn new(ledger: Ledger, path: DerivationPath) -> Result<Self, LedgerError> {
        let public_key = ledger.get_public_key(&path).await?;
        Ok(Self {
            ledger,
            path,
            public_key,
        })
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

    /// Sign a transaction without its input objects. Fails with
    /// [`LedgerError::BlindSigningDisabled`] if blind signing is disabled in
    /// the IOTA app's settings.
    pub async fn sign_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<UserSignature, LedgerError> {
        self.sign_transaction_with_objects(transaction, &[]).await
    }

    /// Sign a transaction, passing its input objects so the device can
    /// clear-sign it. With an IOTA app older than 1.0, it logs a warning and
    /// blind-signs.
    pub async fn sign_transaction_with_objects(
        &self,
        transaction: &Transaction,
        objects: &[Object],
    ) -> Result<UserSignature, LedgerError> {
        let mut device = self.ledger.device.lock().await;
        let objects = if objects.is_empty() {
            objects
        } else {
            let version = device.version().await?;
            if version.major() == 0 {
                tracing::warn!("IOTA app {version} cannot clear-sign, blind signing instead");
                &[]
            } else {
                objects
            }
        };
        device
            .ensure_public_key(&self.path, &self.public_key)
            .await?;
        let signature = device
            .sign_transaction(&self.path, transaction, objects)
            .await?;
        Ok(self.user_signature(signature))
    }

    /// Sign a personal message.
    pub async fn sign_personal_message(
        &self,
        message: &PersonalMessage<'_>,
    ) -> Result<UserSignature, LedgerError> {
        let device = self.ledger.device.lock().await;
        device
            .ensure_public_key(&self.path, &self.public_key)
            .await?;
        let signature =
            sign::personal_message(device.transport.as_ref(), &self.path, message).await?;
        Ok(self.user_signature(signature))
    }

    /// Sign `message` under `intent`; see [`Ledger::sign_intent`].
    pub async fn sign_intent<T: Serialize + ?Sized>(
        &self,
        intent: Intent,
        message: &T,
    ) -> Result<UserSignature, LedgerError> {
        let device = self.ledger.device.lock().await;
        device
            .ensure_public_key(&self.path, &self.public_key)
            .await?;
        let signature =
            sign::intent(device.transport.as_ref(), &self.path, intent, message).await?;
        Ok(self.user_signature(signature))
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
    /// The gas coin of [`TRANSACTION`], from the same tests.
    const GAS_COIN: &str = "00018600000000000000281eec6c32ef36467331fb7b088b4acb1ce46f736354308e03ff6ce913a42734e2005ed0b200000000000f58eb1351454d623a6a4366198d6cd5aa4a12a12a3caefb501476e06d8bd5b620a7e7993dd298e10fb373fb708b9f9005be1963c6f074b202bbe7a7cf9d75d717b0f50e0000000000";
    const SIGNATURE: [u8; 64] = [9; 64];

    /// Answers every command with its final result at once, using whichever
    /// key is currently set, and records how many parameters each signing
    /// request carries: three when the input objects are sent, two otherwise.
    struct FakeDevice {
        version: [u8; 3],
        public_key: Arc<Mutex<Ed25519PublicKey>>,
        public_key_reads: Arc<Mutex<usize>>,
        sign_parameters: Arc<Mutex<Vec<usize>>>,
    }

    impl FakeDevice {
        fn new(version: [u8; 3], public_key: &Arc<Mutex<Ed25519PublicKey>>) -> Self {
            Self {
                version,
                public_key: public_key.clone(),
                public_key_reads: Default::default(),
                sign_parameters: Default::default(),
            }
        }
    }

    impl Transport for FakeDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                let public_key = *self.public_key.lock().unwrap();
                let result = match command.ins() {
                    // version
                    0x00 => self.version.to_vec(),
                    // public key
                    0x02 => {
                        *self.public_key_reads.lock().unwrap() += 1;
                        [
                            &[32][..],
                            public_key.bytes(),
                            &[32],
                            public_key.derive_address().as_bytes(),
                        ]
                        .concat()
                    }
                    // sign; the start request is a tag byte and one hash per
                    // parameter
                    0x03 => {
                        let parameters = (command.data().len() - 1) / 32;
                        self.sign_parameters.lock().unwrap().push(parameters);
                        SIGNATURE.to_vec()
                    }
                    ins => panic!("unexpected instruction {ins:#04x}"),
                };
                ApduAnswer::from_bytes([&[1][..], &result, &[0x90, 0x00]].concat())
            })
        }
    }

    fn signer(public_key: &Arc<Mutex<Ed25519PublicKey>>) -> LedgerSigner {
        let ledger = Ledger::new(FakeDevice::new([1, 0, 1], public_key));
        block_on(ledger.into_signer("m/44'/4218'/0'/0'/0'".parse().unwrap())).unwrap()
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
        assert_eq!(
            block_on(signer.sign_intent(Intent::iota_transaction(), &transaction())).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_a_different_key() {
        let public_key = Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32])));
        let signer = signer(&public_key);
        *public_key.lock().unwrap() = Ed25519PublicKey::new([8; 32]);

        assert!(matches!(
            block_on(signer.sign_transaction(&transaction())),
            Err(LedgerError::KeyMismatch)
        ));
        assert!(matches!(
            block_on(signer.sign_personal_message(&PersonalMessage(b"Hello".into()))),
            Err(LedgerError::KeyMismatch)
        ));
    }

    #[test]
    fn blind_signs_when_the_app_cannot_clear_sign() {
        let device = FakeDevice::new(
            [0, 9, 2],
            &Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32]))),
        );
        let (public_key_reads, sign_parameters) = (
            device.public_key_reads.clone(),
            device.sign_parameters.clone(),
        );
        let signer =
            block_on(Ledger::new(device).into_signer("m/44'/4218'/0'/0'/0'".parse().unwrap()))
                .unwrap();
        let gas_coin: Object = bcs::from_bytes(&hex::decode(GAS_COIN).unwrap()).unwrap();

        block_on(signer.sign_transaction_with_objects(&transaction(), &[gas_coin])).unwrap();

        assert_eq!(*sign_parameters.lock().unwrap(), [2]);
        // once creating the signer and once before signing
        assert_eq!(*public_key_reads.lock().unwrap(), 2);
    }

    /// Wraps [`FakeDevice`], returning `Pending` once before each answer and
    /// logging each command's instruction.
    struct LoggingDevice {
        inner: FakeDevice,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Transport for LoggingDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                self.log
                    .lock()
                    .unwrap()
                    .push(format!("{:#04x}", command.ins()));
                let mut yielded = false;
                std::future::poll_fn(|cx| {
                    if yielded {
                        std::task::Poll::Ready(())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                })
                .await;
                self.inner.exchange(command).await
            })
        }
    }

    /// Logs when it is woken, which for a task waiting on the device happens
    /// as the lock is released.
    struct LogWake(Arc<Mutex<Vec<String>>>);

    impl futures::task::ArcWake for LogWake {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.lock().unwrap().push("unlocked".to_owned());
        }
    }

    #[test]
    fn keeps_the_device_locked_between_the_key_check_and_the_signature() {
        use std::{future::Future, task::Context};

        let log = Arc::new(Mutex::new(Vec::new()));
        let device = LoggingDevice {
            inner: FakeDevice::new(
                [1, 0, 1],
                &Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32]))),
            ),
            log: log.clone(),
        };
        let signer =
            block_on(Ledger::new(device).into_signer("m/44'/4218'/0'/0'/0'".parse().unwrap()))
                .unwrap();
        let clone = signer.ledger().clone();
        log.lock().unwrap().clear();

        // Start signing until the device holds the key request, then queue a
        // command on the clone behind it.
        let message = PersonalMessage(b"Hello".into());
        let mut signing = Box::pin(signer.sign_personal_message(&message));
        let noop = futures::task::noop_waker();
        assert!(
            signing
                .as_mut()
                .poll(&mut Context::from_waker(&noop))
                .is_pending()
        );
        let mut waiting = Box::pin(clone.get_public_key(signer.path()));
        let log_wake = futures::task::waker(Arc::new(LogWake(log.clone())));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&log_wake))
                .is_pending()
        );

        block_on(signing).unwrap();

        assert_eq!(*log.lock().unwrap(), ["0x02", "0x03", "unlocked"]);
    }

    #[test]
    fn futures_are_send() {
        fn assert_send<T: Send>(_: T) {}
        let signer = signer(&Arc::new(Mutex::new(Ed25519PublicKey::new([7; 32]))));
        let transaction = transaction();
        assert_send(signer.sign_transaction(&transaction));
        assert_send(signer.sign_personal_message(&PersonalMessage(b"".into())));
        assert_send(signer.sign_intent(Intent::iota_transaction(), &transaction));
    }
}
