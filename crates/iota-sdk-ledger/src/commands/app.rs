// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Commands of the IOTA app.

use std::fmt;

use iota_crypto::DerivationPath;
use iota_types::{Address, Ed25519PublicKey};

use super::{Reader, block_protocol, command, encode_path, exec};
use crate::{LedgerError, Transport, transport::ApduCommand};

/// Instruction class of the app's commands; the app rejects any other class
/// as a bad instruction.
const CLA: u8 = 0x00;

/// Status word the app returns for a derivation path outside the prefixes it
/// allows. The app returns syscall error numbers as bare status words, here
/// `InvalidParameter`.
const SW_INVALID_PARAMETER: u16 = 0x0002;
/// Status word the app returns for a transaction it cannot clear-sign while
/// blind signing is disabled (syscall error `NotSupported`).
const SW_NOT_SUPPORTED: u16 = 0x0008;

/// Map the status words specific to the app to their errors.
pub(super) fn map_app_error(error: LedgerError) -> LedgerError {
    match error {
        LedgerError::Status(SW_INVALID_PARAMETER) => LedgerError::DerivationPathNotAllowed,
        LedgerError::Status(SW_NOT_SUPPORTED) => LedgerError::BlindSigningDisabled,
        error => error,
    }
}

/// Instruction codes of the app's commands.
#[derive(Clone, Copy, Debug)]
pub(super) enum Instruction {
    GetVersion = 0x00,
    VerifyAddress = 0x01,
    GetPublicKey = 0x02,
    /// Signs any intent message, not only transactions.
    Sign = 0x03,
    Exit = 0xff,
}

impl Instruction {
    pub(super) fn command(self, data: Vec<u8>) -> ApduCommand {
        command(CLA, self as u8, data)
    }
}

/// The version of the IOTA app running on the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl AppVersion {
    /// The major version.
    pub fn major(&self) -> u8 {
        self.major
    }

    /// The minor version.
    pub fn minor(&self) -> u8 {
        self.minor
    }

    /// The patch version.
    pub fn patch(&self) -> u8 {
        self.patch
    }
}

impl fmt::Display for AppVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Read the app's version.
pub(crate) fn version(transport: &dyn Transport) -> Result<AppVersion, LedgerError> {
    // The command takes a single empty parameter
    let response = block_protocol::send(transport, Instruction::GetVersion, &[&[]])?;
    // The app name follows the version
    let [major, minor, patch] = Reader::new(&response).array()?;
    Ok(AppVersion {
        major,
        minor,
        patch,
    })
}

/// Read the public key at `path`, first showing its address on the device for
/// the user to confirm when `show_to_user` is set.
pub(crate) fn public_key(
    transport: &dyn Transport,
    path: &DerivationPath,
    show_to_user: bool,
) -> Result<Ed25519PublicKey, LedgerError> {
    let instruction = if show_to_user {
        Instruction::VerifyAddress
    } else {
        Instruction::GetPublicKey
    };
    let response = block_protocol::send(transport, instruction, &[&encode_path(path)?])
        .map_err(map_app_error)?;

    let mut reader = Reader::new(&response);
    let public_key = Ed25519PublicKey::new(
        reader
            .length_prefixed()?
            .try_into()
            .map_err(|_| LedgerError::invalid_response("public key has the wrong length"))?,
    );
    let address = Address::new(
        reader
            .length_prefixed()?
            .try_into()
            .map_err(|_| LedgerError::invalid_response("address has the wrong length"))?,
    );
    if address != public_key.derive_address() {
        return Err(LedgerError::invalid_response(
            "address does not match the public key",
        ));
    }
    Ok(public_key)
}

/// Close the app.
pub(crate) fn exit(transport: &dyn Transport) -> Result<(), LedgerError> {
    exec(transport, Instruction::Exit.command(Vec::new())).map(drop)
}
