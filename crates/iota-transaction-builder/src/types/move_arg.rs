// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Digest;

/// Pure BCS bytes
pub struct PureBytes(pub Vec<u8>);

/// A trait which defines how types are serialized for move calls.
pub trait MoveArg {
    /// Get the pure BCS bytes.
    fn pure_bytes(&self) -> Vec<u8>;
}

impl MoveArg for PureBytes {
    fn pure_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl MoveArg for Digest {
    fn pure_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("bcs serialization failed")
    }
}

impl MoveArg for () {
    fn pure_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl MoveArg for str {
    fn pure_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("bcs serialization failed")
    }
}

impl MoveArg for &str {
    fn pure_bytes(&self) -> Vec<u8> {
        (*self).pure_bytes()
    }
}

impl MoveArg for String {
    fn pure_bytes(&self) -> Vec<u8> {
        self.as_str().pure_bytes()
    }
}

impl<T: MoveArg> MoveArg for Vec<T> {
    fn pure_bytes(&self) -> Vec<u8> {
        u32_as_uleb128(self.len() as u32)
            .into_iter()
            .chain(self.iter().map(|val| val.pure_bytes()).flatten())
            .collect()
    }
}

fn u32_as_uleb128(mut value: u32) -> Vec<u8> {
    let mut res = Vec::new();
    while value >= 0x80 {
        // Write 7 (lowest) bits of data and set the 8th bit to 1.
        let byte = (value & 0x7f) as u8;
        res.push(byte | 0x80);
        value >>= 7;
    }
    // Write the remaining bits of data and set the highest bit to 0.
    res.push(value as u8);
    res
}

impl<T: MoveArg> MoveArg for Option<T> {
    fn pure_bytes(&self) -> Vec<u8> {
        match self {
            Some(value) => [&[1], &value.pure_bytes()[..]].concat(),
            None => vec![0; 1],
        }
    }
}

impl<T: MoveArg> MoveArg for &T {
    fn pure_bytes(&self) -> Vec<u8> {
        (*self).pure_bytes()
    }
}
