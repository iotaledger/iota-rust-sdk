// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Digest, ObjectId};

use crate::types::ParamType;

/// A trait which defines how types are serialized for move calls.
pub trait MoveParam {
    /// Get the param type.
    fn param(&self) -> ParamType;
}

impl MoveParam for ObjectId {
    fn param(&self) -> ParamType {
        ParamType::Object(*self)
    }
}

impl MoveParam for Digest {
    fn param(&self) -> ParamType {
        ParamType::Pure(bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl MoveParam for ParamType {
    fn param(&self) -> ParamType {
        self.clone()
    }
}

impl MoveParam for () {
    fn param(&self) -> ParamType {
        ParamType::Pure(Vec::new())
    }
}

impl MoveParam for str {
    fn param(&self) -> ParamType {
        ParamType::Pure(bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl MoveParam for &str {
    fn param(&self) -> ParamType {
        (*self).param()
    }
}

impl MoveParam for String {
    fn param(&self) -> ParamType {
        self.as_str().param()
    }
}

impl<T: MoveParam> MoveParam for Vec<T> {
    fn param(&self) -> ParamType {
        let mut res = u32_as_uleb128(self.len() as u32);
        for val in self {
            match val.param() {
                ParamType::Object(object_id) => res.extend(object_id.as_bytes()),
                ParamType::Pure(items) => res.extend(items),
            }
        }
        ParamType::Pure(res)
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

impl<T: MoveParam> MoveParam for Box<T> {
    fn param(&self) -> ParamType {
        self.as_ref().param()
    }
}

impl<T: MoveParam> MoveParam for Option<T> {
    fn param(&self) -> ParamType {
        match self {
            Some(value) => match value.param() {
                ParamType::Object(object_id) => {
                    ParamType::Pure([&[1], object_id.as_bytes()].concat())
                }
                ParamType::Pure(items) => ParamType::Pure([&[1], &items[..]].concat()),
            },
            None => ParamType::Pure(vec![0; 1]),
        }
    }
}

impl<T: MoveParam> MoveParam for &T {
    fn param(&self) -> ParamType {
        (*self).param()
    }
}
