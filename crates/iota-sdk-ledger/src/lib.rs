// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

mod commands;
mod error;
mod transport;

use std::{fmt, sync::OnceLock, time::Duration};

use futures::lock::Mutex;
pub use iota_crypto;
use iota_crypto::DerivationPath;
pub use iota_types;
use iota_types::{Ed25519PublicKey, Ed25519Signature, Object, PersonalMessage, Transaction};

use crate::commands::{app, bolos, sign};
#[cfg(feature = "hid")]
pub use crate::transport::hid::HidDeviceInfo;
pub use crate::{
    commands::app::AppVersion,
    error::{ApduError, LedgerError},
    transport::{ApduAnswer, ApduCommand, MaybeSendSync, Transport, TransportFuture},
};

const IOTA_APP_NAME: &str = "IOTA";
const DASHBOARD_APP_NAME: &str = "BOLOS";

/// How many times to reconnect while waiting for an app to start.
const APP_SWITCH_ATTEMPTS: usize = 40;
/// How long to wait before each attempt.
const APP_SWITCH_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// A connection to the IOTA app on a Ledger device.
///
/// Every call completes once the device answers, which for signing and
/// address verification includes waiting for the user to confirm on the
/// device.
///
/// Calls on the same `Ledger` run one at a time: each waits for the previous
/// one to finish, since a command can take several exchanges with the device.
pub struct Ledger {
    /// Locked for the whole of each command.
    transport: Mutex<Box<dyn Transport>>,
    version: OnceLock<AppVersion>,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ledger")
            .field("version", &self.version.get())
            .finish_non_exhaustive()
    }
}

impl Ledger {
    /// Communicate with the device through a custom transport.
    pub fn new<T: Transport + 'static>(transport: T) -> Self {
        Self {
            transport: Mutex::new(Box::new(transport)),
            version: OnceLock::new(),
        }
    }

    /// Check whether the IOTA app is the app running on the device.
    ///
    /// Speculos reports a placeholder app name unless started with
    /// `SPECULOS_APPNAME=IOTA:<version>`, so this returns `false` there.
    pub async fn is_app_open(&self) -> Result<bool, LedgerError> {
        let transport = self.transport.lock().await;
        Ok(bolos::app_name(transport.as_ref()).await? == IOTA_APP_NAME)
    }

    /// Open the IOTA app, from the dashboard or by closing another app first.
    ///
    /// Does nothing if the IOTA app is already running, or on transports that
    /// cannot switch apps, such as Speculos.
    pub async fn open_app(&mut self) -> Result<(), LedgerError> {
        if !self.transport.get_mut().can_switch_apps() {
            return Ok(());
        }
        match bolos::app_name(self.transport.get_mut().as_ref())
            .await?
            .as_str()
        {
            IOTA_APP_NAME => return Ok(()),
            DASHBOARD_APP_NAME => {}
            _ => {
                bolos::exit_app(self.transport.get_mut().as_ref()).await?;
                self.wait_for_app(DASHBOARD_APP_NAME).await?;
            }
        }
        bolos::open_app(self.transport.get_mut().as_ref(), IOTA_APP_NAME).await?;
        self.wait_for_app(IOTA_APP_NAME).await
    }

    /// Close the app running on the device and return to the dashboard.
    ///
    /// On transports that cannot switch apps, such as Speculos, this ends the
    /// emulated app.
    pub async fn exit_app(&mut self) -> Result<(), LedgerError> {
        bolos::exit_app(self.transport.get_mut().as_ref()).await?;
        if !self.transport.get_mut().can_switch_apps() {
            return Ok(());
        }
        self.wait_for_app(DASHBOARD_APP_NAME).await
    }

    /// Read the version of the IOTA app.
    pub async fn version(&self) -> Result<AppVersion, LedgerError> {
        if let Some(version) = self.version.get() {
            return Ok(*version);
        }
        let version = app::version(self.transport.lock().await.as_ref()).await?;
        Ok(*self.version.get_or_init(|| version))
    }

    /// Read the public key at `path`.
    pub async fn get_public_key(
        &self,
        path: &DerivationPath,
    ) -> Result<Ed25519PublicKey, LedgerError> {
        app::public_key(self.transport.lock().await.as_ref(), path, false).await
    }

    /// Show the address at `path` on the device for the user to confirm, and
    /// return its public key.
    pub async fn verify_address(
        &self,
        path: &DerivationPath,
    ) -> Result<Ed25519PublicKey, LedgerError> {
        app::public_key(self.transport.lock().await.as_ref(), path, true).await
    }

    /// Sign a transaction with the key at `path`.
    ///
    /// `objects` are the transaction's input objects. With them the device
    /// shows what the transaction does; without them it only signs when blind
    /// signing is enabled in the app's settings. Passing objects to an app
    /// older than 1.0 fails with [`LedgerError::ClearSigningUnsupported`].
    pub async fn sign_transaction(
        &self,
        path: &DerivationPath,
        transaction: &Transaction,
        objects: &[Object],
    ) -> Result<Ed25519Signature, LedgerError> {
        if !objects.is_empty() {
            let version = self.version().await?;
            if version.major() == 0 {
                return Err(LedgerError::ClearSigningUnsupported(version));
            }
        }
        let transport = self.transport.lock().await;
        sign::transaction(transport.as_ref(), path, transaction, objects).await
    }

    /// Sign a personal message with the key at `path`.
    pub async fn sign_personal_message(
        &self,
        path: &DerivationPath,
        message: &PersonalMessage<'_>,
    ) -> Result<Ed25519Signature, LedgerError> {
        sign::personal_message(self.transport.lock().await.as_ref(), path, message).await
    }

    /// Wait until `app` runs on the device, reconnecting as the device
    /// re-enumerates after an app switch.
    async fn wait_for_app(&mut self, app: &str) -> Result<(), LedgerError> {
        self.version = OnceLock::new();
        let transport = self.transport.get_mut();
        let mut error = LedgerError::from(ApduError::DeviceNotReady);
        for _ in 0..APP_SWITCH_ATTEMPTS {
            futures_timer::Delay::new(APP_SWITCH_POLL_INTERVAL).await;
            if let Err(e) = transport.reconnect().await {
                error = e;
                continue;
            }
            match bolos::app_name(transport.as_ref()).await {
                Ok(name) if name == app => return Ok(()),
                Ok(_) => error = ApduError::DeviceNotReady.into(),
                Err(e) => error = e,
            }
        }
        Err(error)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::{
        Address, GasPayment, ProgrammableTransaction, TransactionExpiration, TransactionKind,
        TransactionV1,
    };

    use super::*;

    struct NoDevice;

    impl Transport for NoDevice {
        fn exchange<'a>(&'a self, _: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async { Err(LedgerError::DeviceNotFound) })
        }
    }

    /// Answers public key requests through the block protocol, yielding once
    /// before each answer, and records whether a new command starts while
    /// another is still in progress.
    #[derive(Default)]
    struct FakeDevice {
        in_progress: std::sync::Mutex<bool>,
        interleaved: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Transport for FakeDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                yield_now().await;
                let mut in_progress = self.in_progress.lock().unwrap();
                let mut data = match command.data()[0] {
                    // Start: request the path chunk by its hash
                    0 => {
                        if *in_progress {
                            self.interleaved
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        *in_progress = true;
                        [&[2], &command.data()[1..33]].concat()
                    }
                    // Chunk received: return the public key and its address
                    _ => {
                        *in_progress = false;
                        let public_key = Ed25519PublicKey::new([7; 32]);
                        [
                            &[1, 32][..],
                            public_key.bytes(),
                            &[32],
                            public_key.derive_address().as_bytes(),
                        ]
                        .concat()
                    }
                };
                data.extend([0x90, 0x00]);
                ApduAnswer::from_bytes(data)
            })
        }
    }

    /// Return `Pending` once, so that concurrent futures get polled in between.
    async fn yield_now() {
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
        .await
    }

    #[test]
    fn concurrent_calls_do_not_interleave() {
        let device = FakeDevice::default();
        let interleaved = device.interleaved.clone();
        let ledger = Ledger::new(device);
        let path: DerivationPath = "m/44'/4218'/0'/0'/0'".parse().unwrap();

        let (a, b) = futures::executor::block_on(futures::future::join(
            ledger.get_public_key(&path),
            ledger.get_public_key(&path),
        ));
        a.unwrap();
        b.unwrap();
        assert!(!interleaved.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Runs the dashboard, opens the IOTA app when asked and answers with its
    /// name only after `startup`, like a device that restarts to switch apps.
    /// Reconnecting is instant.
    struct SlowSwitchingDevice {
        startup: std::time::Duration,
        opened_at: std::sync::Mutex<Option<std::time::Instant>>,
    }

    impl Transport for SlowSwitchingDevice {
        fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
            Box::pin(async move {
                let mut opened_at = self.opened_at.lock().unwrap();
                let data = match (command.cla(), command.ins()) {
                    // app name
                    (0xb0, 0x01) => {
                        let started = opened_at.is_some_and(|at| at.elapsed() >= self.startup);
                        let name: &[u8] = if started { b"IOTA" } else { b"BOLOS" };
                        [&[1, name.len() as u8][..], name, &[0x90, 0x00]].concat()
                    }
                    // open app
                    (0xe0, 0xd8) => {
                        *opened_at = Some(std::time::Instant::now());
                        vec![0x90, 0x00]
                    }
                    (cla, ins) => panic!("unexpected command {cla:#04x} {ins:#04x}"),
                };
                ApduAnswer::from_bytes(data)
            })
        }
    }

    #[test]
    fn waits_for_the_app_between_attempts() {
        let mut ledger = Ledger::new(SlowSwitchingDevice {
            startup: std::time::Duration::from_millis(600),
            opened_at: Default::default(),
        });
        futures::executor::block_on(ledger.open_app()).unwrap();
    }

    fn assert_send<T: Send>(_: T) {}

    #[test]
    fn futures_are_send() {
        let mut ledger = Ledger::new(NoDevice);
        let path: DerivationPath = "m/44'/4218'/0'/0'/0'".parse().unwrap();
        let transaction = Transaction::V1(TransactionV1 {
            kind: TransactionKind::Programmable(ProgrammableTransaction {
                inputs: vec![],
                commands: vec![],
            }),
            sender: Address::ZERO,
            gas_payment: GasPayment {
                objects: vec![],
                owner: Address::ZERO,
                price: 0,
                budget: 0,
            },
            expiration: TransactionExpiration::None,
        });
        assert_send(ledger.is_app_open());
        assert_send(ledger.open_app());
        assert_send(ledger.exit_app());
        assert_send(ledger.version());
        assert_send(ledger.get_public_key(&path));
        assert_send(ledger.verify_address(&path));
        assert_send(ledger.sign_transaction(&path, &transaction, &[]));
        assert_send(ledger.sign_personal_message(&path, &PersonalMessage(b"".into())));
    }
}
