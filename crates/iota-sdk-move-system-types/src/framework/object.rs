// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

use iota_types::ObjectId;

/// Rust version of the Move `iota::object::UID` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UID {
    pub id: ID,
}

impl UID {
    pub fn new(object_id: ObjectId) -> Self {
        Self {
            id: ID::new(object_id),
        }
    }

    pub fn object_id(&self) -> &ObjectId {
        &self.id.bytes
    }
}

impl From<ObjectId> for UID {
    fn from(object_id: ObjectId) -> Self {
        Self::new(object_id)
    }
}

impl fmt::Display for UID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.id.fmt(f)
    }
}

/// Rust version of the Move `iota::object::ID` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ID {
    pub bytes: ObjectId,
}

impl ID {
    pub fn new(object_id: ObjectId) -> Self {
        Self { bytes: object_id }
    }
}

impl From<ObjectId> for ID {
    fn from(object_id: ObjectId) -> Self {
        Self::new(object_id)
    }
}

impl From<ID> for ObjectId {
    fn from(id: ID) -> Self {
        id.bytes
    }
}

impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes.fmt(f)
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    fn sample_object_id() -> ObjectId {
        ObjectId::new([0xab; ObjectId::LENGTH])
    }

    #[test]
    fn id_bcs_roundtrip() {
        let id = ID::new(sample_object_id());
        let bytes = bcs::to_bytes(&id).unwrap();
        // `#[serde(transparent)]`: an ID encodes exactly as its inner ObjectId.
        assert_eq!(bytes, bcs::to_bytes(&sample_object_id()).unwrap());
        let decoded: ID = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn uid_bcs_roundtrip() {
        let uid = UID::new(sample_object_id());
        let bytes = bcs::to_bytes(&uid).unwrap();
        // UID is a single-field struct wrapping an ID, which is transparent
        // over ObjectId, so the wire format is exactly an ObjectId.
        assert_eq!(bytes, bcs::to_bytes(&sample_object_id()).unwrap());
        let decoded: UID = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(uid, decoded);
    }
}
