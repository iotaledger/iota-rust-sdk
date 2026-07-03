// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust definitions of move/iota framework types.

use super::{Object, ObjectId, TypeTag};

#[derive(Clone, Debug)]
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
                    .object_type()
                    .coin_type_opt()
                    .ok_or(CoinFromObjectError::NotACoin)?;

                let contents = move_struct.contents();
                if contents.len() != ObjectId::LENGTH + std::mem::size_of::<u64>() {
                    return Err(CoinFromObjectError::InvalidContentLength);
                }

                let balance =
                    u64::from_le_bytes((&contents[ObjectId::LENGTH..]).try_into().unwrap());

                Ok(Self {
                    coin_type: coin_type.clone(),
                    id: move_struct.id(),
                    balance,
                })
            }
            _ => Err(CoinFromObjectError::NotACoin), // package
        }
    }
}

impl crate::TreeDisplay for Coin {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Coin")?;
        w.leaf("Coin Type", &self.coin_type, false)?;
        w.leaf("ID", &self.id, false)?;
        w.leaf("Balance", &self.balance, true)
    }
}

crate::impl_tree_display!(Coin);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
