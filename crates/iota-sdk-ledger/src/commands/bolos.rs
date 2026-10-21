// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Commands handled by the device's operating system (BOLOS) rather than by
//! the IOTA app.

use super::{Reader, exec};
use crate::{LedgerError, Transport, transport::ApduCommand};

/// Instruction class of the commands the Ledger SDK answers inside every app
/// and the dashboard: reading the running app's name and exiting it.
const CLA_APP: u8 = 0xb0;
/// Instruction class of the dashboard's commands, such as opening an app.
const CLA_DASHBOARD: u8 = 0xe0;

const INS_GET_APP_NAME: u8 = 0x01;
const INS_EXIT_APP: u8 = 0xa7;
const INS_OPEN_APP: u8 = 0xd8;

/// Status word for an invalid counter syscall error, returned when the app to
/// open is not installed.
const SW_INVALID_COUNTER: u16 = 0x6807;

fn command(cla: u8, ins: u8, data: Vec<u8>) -> ApduCommand {
    // Neither instruction parameter is used
    ApduCommand {
        cla,
        ins,
        p1: 0,
        p2: 0,
        data,
    }
}

/// Read the name of the app running on the device; the dashboard is named
/// `BOLOS`.
pub(crate) async fn app_name(transport: &dyn Transport) -> Result<String, LedgerError> {
    // Dashboard:
    // HID => b001000000
    // HID <= 0105|424f4c4f53|05|322e302e30|9000
    // B O L O S      2 . 0 . 0
    //
    // "IOTA"
    // HID => b001000000
    // HID <= 0104|494f5441|05|302e372e30|0102|9000
    // I O T A      0 . 7 . 0
    let response = exec(transport, command(CLA_APP, INS_GET_APP_NAME, Vec::new())).await?;

    let mut reader = Reader::new(&response);
    // The format byte is always 0x01; the app version and flags follow the
    // name
    reader.u8()?;
    String::from_utf8(reader.length_prefixed()?.to_vec())
        .map_err(|_| LedgerError::invalid_response("app name is not UTF-8"))
}

/// Open `app` from the dashboard.
pub(crate) async fn open_app(transport: &dyn Transport, app: &str) -> Result<(), LedgerError> {
    // The APDU length byte carries the name's length, so the data holds the
    // bare name
    match exec(
        transport,
        command(CLA_DASHBOARD, INS_OPEN_APP, app.as_bytes().to_vec()),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(LedgerError::Status(SW_INVALID_COUNTER)) => Err(LedgerError::AppNotFound),
        Err(e) => Err(e),
    }
}

/// Close the running app and return to the dashboard.
pub(crate) async fn exit_app(transport: &dyn Transport) -> Result<(), LedgerError> {
    exec(transport, command(CLA_APP, INS_EXIT_APP, Vec::new()))
        .await
        .map(drop)
}
