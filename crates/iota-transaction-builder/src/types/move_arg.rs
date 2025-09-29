// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Digest, ObjectId};

use crate::types::ArgType;

/// A trait which defines how types are serialized for move calls.
pub trait MoveArg {
    /// Get the param type.
    fn param(&self) -> ArgType;
}

impl MoveArg for ObjectId {
    fn param(&self) -> ArgType {
        ArgType::Object(*self)
    }
}

impl MoveArg for Digest {
    fn param(&self) -> ArgType {
        ArgType::Pure(bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl MoveArg for ArgType {
    fn param(&self) -> ArgType {
        self.clone()
    }
}

impl MoveArg for () {
    fn param(&self) -> ArgType {
        ArgType::Pure(Vec::new())
    }
}

impl MoveArg for str {
    fn param(&self) -> ArgType {
        ArgType::Pure(bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl MoveArg for &str {
    fn param(&self) -> ArgType {
        (*self).param()
    }
}

impl MoveArg for String {
    fn param(&self) -> ArgType {
        self.as_str().param()
    }
}

impl<T: MoveArg> MoveArg for Vec<T> {
    fn param(&self) -> ArgType {
        let mut res = u32_as_uleb128(self.len() as u32);
        for val in self {
            match val.param() {
                ArgType::Object(object_id) => res.extend(object_id.as_bytes()),
                ArgType::Pure(items) => res.extend(items),
            }
        }
        ArgType::Pure(res)
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

impl<T: MoveArg> MoveArg for Box<T> {
    fn param(&self) -> ArgType {
        self.as_ref().param()
    }
}

impl<T: MoveArg> MoveArg for Option<T> {
    fn param(&self) -> ArgType {
        match self {
            Some(value) => match value.param() {
                ArgType::Object(object_id) => ArgType::Pure([&[1], object_id.as_bytes()].concat()),
                ArgType::Pure(items) => ArgType::Pure([&[1], &items[..]].concat()),
            },
            None => ArgType::Pure(vec![0; 1]),
        }
    }
}

impl<T: MoveArg> MoveArg for &T {
    fn param(&self) -> ArgType {
        (*self).param()
    }
}
