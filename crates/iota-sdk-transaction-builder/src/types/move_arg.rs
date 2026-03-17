// Copyright (c) 2025 IOTA Stiftung
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- ULEB128 encoding ---

    #[test]
    fn uleb128_zero() {
        assert_eq!(u32_as_uleb128(0), vec![0x00]);
    }

    #[test]
    fn uleb128_single_byte_max() {
        // 127 = 0x7f fits in one byte
        assert_eq!(u32_as_uleb128(127), vec![0x7f]);
    }

    #[test]
    fn uleb128_two_bytes() {
        // 128 = 0x80 needs two bytes: 0x80 0x01
        assert_eq!(u32_as_uleb128(128), vec![0x80, 0x01]);
    }

    #[test]
    fn uleb128_300() {
        // 300 = 0x12C -> ULEB128: 0xAC 0x02
        assert_eq!(u32_as_uleb128(300), vec![0xac, 0x02]);
    }

    #[test]
    fn uleb128_large_value() {
        // 16384 = 0x4000 -> ULEB128: 0x80 0x80 0x01
        assert_eq!(u32_as_uleb128(16384), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn uleb128_max_u32() {
        let encoded = u32_as_uleb128(u32::MAX);
        // u32::MAX = 4294967295, needs 5 bytes in ULEB128
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded, vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    // --- Option collection encoding ---

    #[test]
    fn option_none_encodes_as_zero_byte() {
        let none: Option<PureBytes> = None;
        let bytes = none.collection_bytes();
        assert_eq!(bytes.0, vec![0]);
    }

    #[test]
    fn option_some_encodes_with_prefix_one() {
        let val = PureBytes(vec![0x42, 0x43]);
        let some = Some(val);
        let bytes = some.collection_bytes();
        assert_eq!(bytes.0, vec![1, 0x42, 0x43]);
    }

    // --- Array collection encoding ---

    #[test]
    fn array_encodes_length_prefix_and_elements() {
        let arr: [PureBytes; 2] = [PureBytes(vec![0xAA]), PureBytes(vec![0xBB])];
        let bytes = arr.collection_bytes();
        // ULEB128(2) = [0x02], then 0xAA, then 0xBB
        assert_eq!(bytes.0, vec![0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn empty_array_encodes_zero_length() {
        let arr: [PureBytes; 0] = [];
        let bytes = arr.collection_bytes();
        assert_eq!(bytes.0, vec![0x00]);
    }

    // --- Vec collection encoding ---

    #[test]
    fn vec_encodes_length_prefix_and_elements() {
        let v = vec![PureBytes(vec![1]), PureBytes(vec![2]), PureBytes(vec![3])];
        let bytes = v.collection_bytes();
        assert_eq!(bytes.0, vec![0x03, 1, 2, 3]);
    }

    #[test]
    fn empty_vec_encodes_zero_length() {
        let v: Vec<PureBytes> = vec![];
        let bytes = v.collection_bytes();
        assert_eq!(bytes.0, vec![0x00]);
    }

    // --- MoveArg impls ---

    #[test]
    fn pure_bytes_move_arg_identity() {
        let pb = PureBytes(vec![1, 2, 3]);
        let result = pb.pure_bytes();
        assert_eq!(result.0, vec![1, 2, 3]);
    }

    #[test]
    fn str_move_arg_produces_bcs() {
        let bytes = "hello".pure_bytes();
        // BCS encodes strings with a length prefix
        assert!(!bytes.0.is_empty());
        // BCS string: ULEB128 length + UTF-8 bytes
        assert_eq!(bytes.0[0], 5); // length of "hello"
        assert_eq!(&bytes.0[1..], b"hello");
    }

    #[test]
    fn string_move_arg_matches_str() {
        let s = String::from("test");
        let from_string = s.pure_bytes();
        let from_str = "test".pure_bytes();
        assert_eq!(from_string.0, from_str.0);
    }

    #[test]
    fn string_ref_move_arg_matches_str() {
        let s = String::from("test");
        let from_ref = (&s).pure_bytes();
        let from_str = "test".pure_bytes();
        assert_eq!(from_ref.0, from_str.0);
    }
}
