// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Digest;

/// Pure BCS bytes
#[derive(Clone, Debug, Default)]
pub struct PureBytes(pub Vec<u8>);

/// A trait which defines how types are serialized for move calls.
pub trait MoveArg {
    /// Get the pure BCS bytes.
    fn pure_bytes(self) -> PureBytes;
}

impl MoveArg for PureBytes {
    fn pure_bytes(self) -> PureBytes {
        self
    }
}

impl MoveArg for &Digest {
    fn pure_bytes(self) -> PureBytes {
        PureBytes(bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl MoveArg for Digest {
    fn pure_bytes(self) -> PureBytes {
        PureBytes(bcs::to_bytes(&self).expect("bcs serialization failed"))
    }
}

impl MoveArg for &str {
    fn pure_bytes(self) -> PureBytes {
        PureBytes(bcs::to_bytes(&self).expect("bcs serialization failed"))
    }
}

impl MoveArg for &String {
    fn pure_bytes(self) -> PureBytes {
        self.as_str().pure_bytes()
    }
}

impl MoveArg for String {
    fn pure_bytes(self) -> PureBytes {
        self.as_str().pure_bytes()
    }
}

impl<T: MoveArgCollection> MoveArg for T {
    fn pure_bytes(self) -> PureBytes {
        self.collection_bytes()
    }
}

/// A trait which defines how collections of move arg types are serialized for
/// move calls.
pub trait MoveArgCollection {
    /// Get the pure BCS bytes.
    fn collection_bytes(self) -> PureBytes;
}

impl<const N: usize, T: MoveArg> MoveArgCollection for [T; N] {
    fn collection_bytes(self) -> PureBytes {
        PureBytes(
            u32_as_uleb128(self.len() as u32)
                .into_iter()
                .chain(self.into_iter().flat_map(|val| val.pure_bytes().0))
                .collect(),
        )
    }
}

impl<T> MoveArgCollection for &[T]
where
    for<'a> &'a T: MoveArg,
{
    fn collection_bytes(self) -> PureBytes {
        PureBytes(
            u32_as_uleb128(self.len() as u32)
                .into_iter()
                .chain(self.iter().flat_map(|val| val.pure_bytes().0))
                .collect(),
        )
    }
}

impl<T: MoveArg> MoveArgCollection for Vec<T> {
    fn collection_bytes(self) -> PureBytes {
        PureBytes(
            u32_as_uleb128(self.len() as u32)
                .into_iter()
                .chain(self.into_iter().flat_map(|val| val.pure_bytes().0))
                .collect(),
        )
    }
}

impl<T: MoveArg> MoveArgCollection for Option<T> {
    fn collection_bytes(self) -> PureBytes {
        match self {
            Some(value) => PureBytes([&[1], &value.pure_bytes().0[..]].concat()),
            None => PureBytes(vec![0; 1]),
        }
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
