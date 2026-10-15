// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

mod commands;
mod error;
mod transport;

use std::{
    fmt,
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

pub use iota_crypto;
use iota_crypto::DerivationPath;
pub use iota_types;
use iota_types::{Ed25519PublicKey, Ed25519Signature, Object, PersonalMessage, Transaction};

use crate::commands::{app, bolos, sign};
#[cfg(feature = "hid")]
pub use crate::transport::hid::HidDeviceInfo;
pub use crate::{
    commands::app::AppVersion,
    error::LedgerError,
    transport::{ApduAnswer, ApduCommand, Transport},
};

const IOTA_APP_NAME: &str = "IOTA";
const DASHBOARD_APP_NAME: &str = "BOLOS";

/// How long to wait for the device to come back after switching apps.
const APP_SWITCH_TIMEOUT: Duration = Duration::from_secs(10);
const APP_SWITCH_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// A connection to the IOTA app on a Ledger device.
///
/// Every call blocks until the device answers, which for signing and address
/// verification includes waiting for the user to confirm on the device.
pub struct Ledger {
    transport: Box<dyn Transport>,
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
            transport: Box::new(transport),
            version: OnceLock::new(),
        }
    }

    /// Check whether the IOTA app is the app running on the device.
    ///
    /// Speculos reports a placeholder app name unless started with
    /// `SPECULOS_APPNAME=IOTA:<version>`, so this returns `false` there.
    pub fn is_app_open(&self) -> Result<bool, LedgerError> {
        Ok(bolos::app_name(self.transport.as_ref())? == IOTA_APP_NAME)
    }

    /// Make sure the IOTA app is running, opening it from the dashboard or
    /// closing another app first.
    ///
    /// Does nothing on transports that cannot switch apps, such as Speculos.
    pub fn ensure_app_is_open(&mut self) -> Result<(), LedgerError> {
        if !self.transport.can_switch_apps() {
            return Ok(());
        }
        match bolos::app_name(self.transport.as_ref())?.as_str() {
            IOTA_APP_NAME => return Ok(()),
            DASHBOARD_APP_NAME => {}
            _ => {
                bolos::exit_app(self.transport.as_ref())?;
                self.wait_for_app(DASHBOARD_APP_NAME)?;
            }
        }
        bolos::open_app(self.transport.as_ref(), IOTA_APP_NAME)?;
        self.wait_for_app(IOTA_APP_NAME)
    }

    /// Close the IOTA app and return to the dashboard.
    ///
    /// On transports that cannot switch apps, such as Speculos, this ends the
    /// emulated app.
    pub fn exit_app(&mut self) -> Result<(), LedgerError> {
        app::exit(self.transport.as_ref())?;
        if !self.transport.can_switch_apps() {
            return Ok(());
        }
        self.wait_for_app(DASHBOARD_APP_NAME)
    }

    /// Read the version of the IOTA app.
    pub fn version(&self) -> Result<AppVersion, LedgerError> {
        if let Some(version) = self.version.get() {
            return Ok(*version);
        }
        let version = app::version(self.transport.as_ref())?;
        Ok(*self.version.get_or_init(|| version))
    }

    /// Read the public key at `path`.
    pub fn get_public_key(&self, path: &DerivationPath) -> Result<Ed25519PublicKey, LedgerError> {
        app::public_key(self.transport.as_ref(), path, false)
    }

    /// Show the address at `path` on the device for the user to confirm, and
    /// return its public key.
    pub fn verify_address(&self, path: &DerivationPath) -> Result<Ed25519PublicKey, LedgerError> {
        app::public_key(self.transport.as_ref(), path, true)
    }

    /// Sign a transaction with the key at `path`.
    ///
    /// `objects` are the transaction's input objects. With them the device
    /// shows what the transaction does; without them it only signs when blind
    /// signing is enabled in the app's settings. Passing objects to an app
    /// older than 1.0 fails with [`LedgerError::ClearSigningUnsupported`].
    pub fn sign_transaction(
        &self,
        path: &DerivationPath,
        transaction: &Transaction,
        objects: &[Object],
    ) -> Result<Ed25519Signature, LedgerError> {
        if !objects.is_empty() {
            let version = self.version()?;
            if version.major() == 0 {
                return Err(LedgerError::ClearSigningUnsupported(version));
            }
        }
        sign::transaction(self.transport.as_ref(), path, transaction, objects)
    }

    /// Sign a personal message with the key at `path`.
    pub fn sign_personal_message(
        &self,
        path: &DerivationPath,
        message: &PersonalMessage<'_>,
    ) -> Result<Ed25519Signature, LedgerError> {
        sign::personal_message(self.transport.as_ref(), path, message)
    }

    /// Wait until `app` runs on the device, reconnecting as the device
    /// re-enumerates after an app switch.
    fn wait_for_app(&mut self, app: &str) -> Result<(), LedgerError> {
        self.version = OnceLock::new();
        let deadline = Instant::now() + APP_SWITCH_TIMEOUT;
        loop {
            thread::sleep(APP_SWITCH_POLL_INTERVAL);
            let result = self
                .transport
                .reconnect()
                .and_then(|()| bolos::app_name(self.transport.as_ref()));
            let error = match result {
                Ok(name) if name == app => return Ok(()),
                Ok(_) => LedgerError::DeviceNotReady,
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                return Err(error);
            }
        }
    }
}
