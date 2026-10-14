// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "hid")]
pub(crate) mod hid;
#[cfg(feature = "speculos")]
pub(crate) mod speculos;

use crate::LedgerError;

/// An APDU command sent to the device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApduCommand {
    pub(crate) cla: u8,
    pub(crate) ins: u8,
    pub(crate) p1: u8,
    pub(crate) p2: u8,
    pub(crate) data: Vec<u8>,
}

impl ApduCommand {
    /// The instruction class.
    pub fn cla(&self) -> u8 {
        self.cla
    }

    /// The instruction code.
    pub fn ins(&self) -> u8 {
        self.ins
    }

    /// The first instruction parameter.
    pub fn p1(&self) -> u8 {
        self.p1
    }

    /// The second instruction parameter.
    pub fn p2(&self) -> u8 {
        self.p2
    }

    /// The command payload.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The command as sent over the wire: `cla ins p1 p2 len data`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + self.data.len());
        bytes.extend([self.cla, self.ins, self.p1, self.p2, self.data.len() as u8]);
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

/// An APDU response received from the device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApduAnswer {
    pub(crate) data: Vec<u8>,
    pub(crate) status_word: u16,
}

impl ApduAnswer {
    /// Parse a response as received over the wire: the payload followed by a
    /// big-endian two-byte status word.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, LedgerError> {
        let Some(split) = bytes.len().checked_sub(2) else {
            return Err(LedgerError::transport("APDU response is too short"));
        };
        let status_word = u16::from_be_bytes([bytes[split], bytes[split + 1]]);
        bytes.truncate(split);
        Ok(Self {
            data: bytes,
            status_word,
        })
    }

    /// The response payload.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The status word; `0x9000` means success.
    pub fn status_word(&self) -> u16 {
        self.status_word
    }
}

/// A future returned by a [`Transport`]. It is `Send` except on wasm32, where
/// futures backed by JavaScript are not.
#[cfg(not(target_arch = "wasm32"))]
pub type TransportFuture<'a, T> = futures::future::BoxFuture<'a, Result<T, LedgerError>>;
/// A future returned by a [`Transport`]. It is `Send` except on wasm32, where
/// futures backed by JavaScript are not.
#[cfg(target_arch = "wasm32")]
pub type TransportFuture<'a, T> = futures::future::LocalBoxFuture<'a, Result<T, LedgerError>>;

/// `Send + Sync` except on wasm32, where values backed by JavaScript are
/// neither.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MaybeSendSync for T {}
/// `Send + Sync` except on wasm32, where values backed by JavaScript are
/// neither.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSendSync for T {}

/// A link to a Ledger device that exchanges APDUs.
///
/// The crate provides transports for USB HID (behind the `hid` feature) and
/// the Speculos emulator (behind the `speculos` feature); implement this trait
/// to talk to the device over another link.
pub trait Transport: MaybeSendSync {
    /// Send a command and wait for the device's answer.
    fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer>;

    /// Wait for the device to come back after it switched apps, and
    /// re-establish the link, which closes on some transports.
    ///
    /// While waiting for an app to start, [`Ledger`](crate::Ledger) calls this
    /// at intervals until the app answers.
    fn reconnect(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Whether the device behind this transport can open and close apps.
    ///
    /// Return `false` for emulators such as Speculos, which run a single app
    /// and report a placeholder app name unless configured otherwise.
    fn can_switch_apps(&self) -> bool {
        true
    }
}
