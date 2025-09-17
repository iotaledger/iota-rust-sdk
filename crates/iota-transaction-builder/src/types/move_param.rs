// Copyright 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Digest, ObjectId};
use serde::{Serialize, de::DeserializeOwned};

use crate::types::{ParamType, Vector};

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

impl<T: Serialize> MoveParam for Vector<T> {
    fn param(&self) -> ParamType {
        ParamType::Pure(bcs::to_bytes(&self.0).expect("bcs serialization failed"))
    }
}

impl<T: MoveParam> MoveParam for Box<T> {
    fn param(&self) -> ParamType {
        self.as_ref().param()
    }
}

impl<T: MoveParam + Serialize + DeserializeOwned> MoveParam for Option<T> {
    fn param(&self) -> ParamType {
        match self {
            Some(value) => match value.param() {
                ParamType::Object(object_id) => ParamType::Pure(
                    bcs::to_bytes(&Some(object_id)).expect("bcs serialization failed"),
                ),
                ParamType::Pure(items) => ParamType::Pure(
                    bcs::to_bytes(&Some(
                        bcs::from_bytes::<T>(&items).expect("bcs deserialization failed"),
                    ))
                    .expect("bcs serialization failed"),
                ),
            },
            None => ParamType::Pure(vec![0; core::mem::size_of::<T>() + 1]),
        }
    }
}

impl MoveParam for [u8] {
    fn param(&self) -> ParamType {
        ParamType::Pure(self.to_vec())
    }
}

impl<const N: usize> MoveParam for [u8; N] {
    fn param(&self) -> ParamType {
        ParamType::Pure(self.to_vec())
    }
}

impl<T: MoveParam> MoveParam for &T {
    fn param(&self) -> ParamType {
        (*self).param()
    }
}
