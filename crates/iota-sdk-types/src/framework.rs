// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust definitions of move/iota framework types.

use super::{Object, ObjectId, TypeTag};

#[derive(Debug, Clone)]
pub struct Coin {
    coin_type: TypeTag,
    id: ObjectId,
    balance: u64,
}

impl Coin {
    pub fn coin_type(&self) -> &TypeTag {
        &self.coin_type
    }

    pub fn id(&self) -> &ObjectId {
        &self.id
    }

    pub fn balance(&self) -> u64 {
        self.balance
    }

    pub fn try_from_object(object: &Object) -> Result<Self, CoinFromObjectError> {
        match &object.data {
            super::ObjectData::Struct(move_struct) => {
                let coin_type = move_struct
                    .type_
                    .coin_type_opt()
                    .ok_or(CoinFromObjectError::NotACoin)?;

                let contents = &move_struct.contents;
                if contents.len() != ObjectId::LENGTH + std::mem::size_of::<u64>() {
                    return Err(CoinFromObjectError::InvalidContentLength);
                }

                let id = ObjectId::new((&contents[..ObjectId::LENGTH]).try_into().unwrap());
                let balance =
                    u64::from_le_bytes((&contents[ObjectId::LENGTH..]).try_into().unwrap());

                Ok(Self {
                    coin_type: coin_type.clone(),
                    id,
                    balance,
                })
            }
            _ => Err(CoinFromObjectError::NotACoin), // package
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoinFromObjectError {
    NotACoin,
    InvalidContentLength,
}

impl CoinFromObjectError {
    crate::def_is!(NotACoin, InvalidContentLength);
}

impl std::fmt::Display for CoinFromObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CoinFromObjectError::NotACoin => write!(f, "not a coin"),
            CoinFromObjectError::InvalidContentLength => write!(f, "invalid content length"),
        }
    }
}

impl std::error::Error for CoinFromObjectError {}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn coin_from_object_error_display_not_a_coin() {
        let err = CoinFromObjectError::NotACoin;
        assert_eq!(err.to_string(), "not a coin");
    }

    #[test]
    fn coin_from_object_error_display_invalid_content_length() {
        let err = CoinFromObjectError::InvalidContentLength;
        assert_eq!(err.to_string(), "invalid content length");
    }

    #[test]
    fn coin_from_object_error_is_methods() {
        let not_a_coin = CoinFromObjectError::NotACoin;
        assert!(not_a_coin.is_not_a_coin());
        assert!(!not_a_coin.is_invalid_content_length());

        let invalid_len = CoinFromObjectError::InvalidContentLength;
        assert!(!invalid_len.is_not_a_coin());
        assert!(invalid_len.is_invalid_content_length());
    }

    #[test]
    fn coin_from_object_error_equality() {
        assert_eq!(CoinFromObjectError::NotACoin, CoinFromObjectError::NotACoin);
        assert_ne!(
            CoinFromObjectError::NotACoin,
            CoinFromObjectError::InvalidContentLength
        );
    }

    #[test]
    fn coin_from_object_error_clone() {
        let err = CoinFromObjectError::InvalidContentLength;
        let cloned = err;
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_coin_accessors() {
        let id = ObjectId::new([1; 32]);
        let coin_type = TypeTag::U64; // Just a dummy type
        let coin = Coin {
            coin_type: coin_type.clone(),
            id,
            balance: 1000,
        };

        assert_eq!(coin.coin_type(), &coin_type);
        assert_eq!(coin.id(), &id);
        assert_eq!(coin.balance(), 1000);
    }

    #[test]
    fn test_coin_try_from_object_success() {
        use crate::{Object, ObjectData, Owner, Digest, MoveStruct, StructTag};

        let id_bytes = [1u8; 32];
        let balance = 500u64;
        let mut contents = Vec::new();
        contents.extend_from_slice(&id_bytes);
        contents.extend_from_slice(&balance.to_le_bytes());

        let coin_type_tag = TypeTag::U64;
        let struct_tag = StructTag::new_coin(coin_type_tag.clone());

        let move_struct = MoveStruct {
            type_: struct_tag,
            version: 1,
            contents,
        };

        let object = Object::new(
            ObjectData::Struct(move_struct),
            Owner::Immutable, // Owner doesn't matter strictly for parsing
            Digest::new([0; 32]),
            0,
        );

        let coin = Coin::try_from_object(&object).expect("Should parse coin");
        assert_eq!(coin.id(), &ObjectId::new(id_bytes));
        assert_eq!(coin.balance(), balance);
        assert_eq!(coin.coin_type(), &coin_type_tag);
    }

    #[test]
    fn test_coin_try_from_object_not_a_coin() {
        use crate::{Object, ObjectData, Owner, Digest, MoveStruct, StructTag};

        // Struct that is NOT a coin
        let struct_tag = StructTag::new(
            crate::Address::ZERO,
            crate::Identifier::new("foo").unwrap(),
            crate::Identifier::new("Bar").unwrap(),
            vec![],
        );

        let move_struct = MoveStruct {
            type_: struct_tag,
            version: 1,
            contents: vec![],
        };

        let object = Object::new(
            ObjectData::Struct(move_struct),
            Owner::Immutable,
            Digest::new([0; 32]),
            0,
        );

        let err = Coin::try_from_object(&object).unwrap_err();
        assert_eq!(err, CoinFromObjectError::NotACoin);

        // Package object
        let object_pkg = Object::new(
             ObjectData::Package(crate::MovePackage {
                 id: ObjectId::ZERO,
                 version: 1,
                 modules: std::collections::BTreeMap::new(),
                 type_origin_table: vec![],
                 linkage_table: std::collections::BTreeMap::new(),
             }),
             Owner::Immutable,
             Digest::new([0; 32]),
             0,
        );
        let err_pkg = Coin::try_from_object(&object_pkg).unwrap_err();
        assert_eq!(err_pkg, CoinFromObjectError::NotACoin);
    }

    #[test]
    fn test_coin_try_from_object_invalid_length() {
        use crate::{Object, ObjectData, Owner, Digest, MoveStruct, StructTag};

        let coin_type_tag = TypeTag::U64;
        let struct_tag = StructTag::new_coin(coin_type_tag);

        // Contents too short
        let move_struct = MoveStruct {
            type_: struct_tag,
            version: 1,
            contents: vec![0u8; 10], // Needs 32 + 8 = 40
        };

        let object = Object::new(
            ObjectData::Struct(move_struct),
            Owner::Immutable,
            Digest::new([0; 32]),
            0,
        );

        let err = Coin::try_from_object(&object).unwrap_err();
        assert_eq!(err, CoinFromObjectError::InvalidContentLength);
    }
}
