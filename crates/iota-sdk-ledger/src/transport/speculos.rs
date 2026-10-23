// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use super::{ApduAnswer, ApduCommand, Transport};
use crate::{Ledger, LedgerError};

impl Ledger {
    /// Connect to the APDU port of a Speculos emulator, by default
    /// `127.0.0.1:9999`.
    pub fn speculos(host: &str, port: u16) -> Self {
        Self::new(SpeculosTransport::new(host, port))
    }
}

/// Talks to the APDU port of the Speculos emulator over TCP, one connection
/// per exchange.
struct SpeculosTransport {
    address: String,
}

impl SpeculosTransport {
    fn new(host: &str, port: u16) -> Self {
        Self {
            address: format!("{host}:{port}"),
        }
    }

    fn request(stream: &mut TcpStream, command: &[u8]) -> std::io::Result<Vec<u8>> {
        // Both directions are prefixed with the payload length as a 32-bit
        // big-endian integer; the answer length excludes its status word.
        stream.write_all(&(command.len() as u32).to_be_bytes())?;
        stream.write_all(command)?;

        let mut len = [0u8; 4];
        stream.read_exact(&mut len)?;
        let mut answer = vec![0u8; u32::from_be_bytes(len) as usize + 2];
        stream.read_exact(&mut answer)?;
        Ok(answer)
    }
}

impl Transport for SpeculosTransport {
    fn exchange(&self, command: &ApduCommand) -> Result<ApduAnswer, LedgerError> {
        let mut stream = TcpStream::connect(&self.address).map_err(LedgerError::transport)?;
        let answer =
            Self::request(&mut stream, &command.to_bytes()).map_err(LedgerError::transport)?;
        ApduAnswer::from_bytes(answer)
    }

    fn can_switch_apps(&self) -> bool {
        false
    }
}
