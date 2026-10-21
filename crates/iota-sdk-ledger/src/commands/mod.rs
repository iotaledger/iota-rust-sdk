// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! APDU commands of the IOTA app and of the device's operating system.

pub(crate) mod app;
mod block_protocol;
pub(crate) mod bolos;
pub(crate) mod sign;

use iota_crypto::DerivationPath;
use tracing::debug;

use crate::{LedgerError, Transport, transport::ApduCommand};

/// Encode `path` as the device expects: the number of indices followed by
/// each index as a little-endian `u32`.
fn encode_path(path: &DerivationPath) -> Result<Vec<u8>, LedgerError> {
    let indices = path.indices();
    let len = u8::try_from(indices.len()).map_err(|_| LedgerError::PayloadTooLong)?;
    let mut bytes = Vec::with_capacity(1 + indices.len() * 4);
    bytes.push(len);
    for index in indices {
        bytes.extend_from_slice(&index.to_le_bytes());
    }
    Ok(bytes)
}

/// Build a command with both instruction parameters zero. The IOTA app
/// requires zero, as command arguments travel in the data through the block
/// protocol, and the device's operating system does not use them.
fn command(cla: u8, ins: u8, data: Vec<u8>) -> ApduCommand {
    ApduCommand {
        cla,
        ins,
        p1: 0,
        p2: 0,
        data,
    }
}

/// Send a single command and return the answer's data.
fn exec(transport: &dyn Transport, command: ApduCommand) -> Result<Vec<u8>, LedgerError> {
    if command.data.len() > u8::MAX as usize {
        return Err(LedgerError::PayloadTooLong);
    }
    debug!(
        "Exchanging APDU command: {}",
        hex::encode(command.to_bytes())
    );
    let answer = transport.exchange(&command)?;
    match LedgerError::from_status_word(answer.status_word) {
        Some(error) => Err(error),
        None => Ok(answer.data),
    }
}

/// Reads fields from a device response.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], LedgerError> {
        let (bytes, rest) = self
            .0
            .split_at_checked(len)
            .ok_or_else(|| LedgerError::invalid_response("response is too short"))?;
        self.0 = rest;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, LedgerError> {
        Ok(self.bytes(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], LedgerError> {
        Ok(self.bytes(N)?.try_into().expect("slice has length N"))
    }

    /// A field prefixed with its length as one byte.
    fn length_prefixed(&mut self) -> Result<&'a [u8], LedgerError> {
        let len = self.u8()?;
        self.bytes(len as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_derivation_path() {
        let path = "m/44'/4218'/0'/1/2".parse().unwrap();
        let expected = [
            [5].as_slice(),
            &0x8000_002cu32.to_le_bytes(),
            &0x8000_107au32.to_le_bytes(),
            &0x8000_0000u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &2u32.to_le_bytes(),
        ]
        .concat();
        assert_eq!(encode_path(&path).unwrap(), expected);
    }
}
