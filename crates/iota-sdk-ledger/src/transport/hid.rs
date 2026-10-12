// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{ffi::CString, thread, time::Duration};

use ledger_transport_hid::{
    LedgerHIDError, TransportNativeHID,
    hidapi::{DeviceInfo, HidApi},
};

use super::{ApduAnswer, ApduCommand, Transport, TransportFuture};
use crate::{Ledger, LedgerError};

impl Ledger {
    /// List the Ledger devices attached over USB.
    pub fn hid_devices() -> Result<Vec<HidDeviceInfo>, LedgerError> {
        let api = HidApi::new().map_err(LedgerError::transport)?;
        Ok(TransportNativeHID::list_ledgers(&api)
            .map(HidDeviceInfo::from)
            .collect())
    }

    /// Connect to the first Ledger device attached over USB.
    pub fn native_hid() -> Result<Self, LedgerError> {
        HidTransport::open_first().map(Self::new)
    }

    /// Connect to a Ledger device from [`Ledger::hid_devices`].
    ///
    /// The device's path usually changes when it switches apps, so with
    /// several Ledger devices attached, [`Ledger::ensure_app_is_open`] and
    /// [`Ledger::exit_app`] cannot find it again and fail with
    /// [`LedgerError::DeviceNotFound`].
    pub fn native_hid_device(device: &HidDeviceInfo) -> Result<Self, LedgerError> {
        HidTransport::open(device).map(Self::new)
    }
}

/// A Ledger device connected over USB.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HidDeviceInfo {
    path: CString,
    product: Option<String>,
}

impl HidDeviceInfo {
    /// The operating system's path to the device. It usually changes when the
    /// device switches apps.
    pub fn path(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// The product name the device reports, such as `Nano S Plus`.
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }
}

impl From<&DeviceInfo> for HidDeviceInfo {
    fn from(info: &DeviceInfo) -> Self {
        Self {
            path: info.path().to_owned(),
            product: info.product_string().map(str::to_owned),
        }
    }
}

/// How long to wait before each attempt to reopen the device after an app
/// switch.
const RECONNECT_DELAY: Duration = Duration::from_millis(250);

/// Talks to a Ledger device connected over USB.
struct HidTransport {
    /// `None` while reconnecting: the previous handle is closed before a new
    /// one is opened, since two open handles to the same device can lock it.
    device: Option<TransportNativeHID>,
    path: CString,
}

impl HidTransport {
    /// Open the first Ledger device found.
    fn open_first() -> Result<Self, LedgerError> {
        let api = HidApi::new().map_err(LedgerError::transport)?;
        let info = TransportNativeHID::list_ledgers(&api)
            .next()
            .ok_or(LedgerError::DeviceNotFound)?;
        Self::open_info(&api, info)
    }

    /// Open `device`, which must still be connected at the same path.
    fn open(device: &HidDeviceInfo) -> Result<Self, LedgerError> {
        let api = HidApi::new().map_err(LedgerError::transport)?;
        let info = TransportNativeHID::list_ledgers(&api)
            .find(|info| info.path() == device.path.as_c_str())
            .ok_or(LedgerError::DeviceNotFound)?;
        Self::open_info(&api, info)
    }

    fn open_info(api: &HidApi, info: &DeviceInfo) -> Result<Self, LedgerError> {
        let device = TransportNativeHID::open_device(api, info).map_err(|e| match e {
            LedgerHIDError::DeviceNotFound => LedgerError::DeviceNotFound,
            e => LedgerError::transport(e),
        })?;
        Ok(Self {
            device: Some(device),
            path: info.path().to_owned(),
        })
    }
}

impl Transport for HidTransport {
    /// Exchange the command, blocking the thread that polls the future until
    /// the device answers.
    fn exchange<'a>(&'a self, command: &'a ApduCommand) -> TransportFuture<'a, ApduAnswer> {
        Box::pin(async move {
            let device = self.device.as_ref().ok_or(LedgerError::DeviceNotFound)?;
            let answer = device
                .exchange(&ledger_transport::APDUCommand {
                    cla: command.cla,
                    ins: command.ins,
                    p1: command.p1,
                    p2: command.p2,
                    data: command.data.as_slice(),
                })
                .map_err(LedgerError::transport)?;
            Ok(ApduAnswer {
                data: answer.data().to_vec(),
                status_word: answer.retcode(),
            })
        })
    }

    /// Reopen the device at its previous path, or, as the path usually
    /// changes when the device switches apps, the only Ledger device
    /// connected. Ledger devices share a serial number, so with several
    /// connected the device cannot be told apart and this fails.
    fn reconnect(&mut self) -> TransportFuture<'_, ()> {
        Box::pin(async move {
            self.device = None;
            thread::sleep(RECONNECT_DELAY);
            let api = HidApi::new().map_err(LedgerError::transport)?;
            let ledgers = TransportNativeHID::list_ledgers(&api).collect::<Vec<_>>();
            let info = match ledgers
                .iter()
                .find(|info| info.path() == self.path.as_c_str())
            {
                Some(info) => info,
                None => match ledgers.as_slice() {
                    [only] => only,
                    _ => return Err(LedgerError::DeviceNotFound),
                },
            };
            *self = Self::open_info(&api, info)?;
            Ok(())
        })
    }
}
