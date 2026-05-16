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

impl std::fmt::Display for Coin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Coin {{\n  type: {},\n  balance: {},\n  id: {}\n}}",
            self.coin_type, self.balance, self.id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectId, StructTag, Address, Identifier};

    #[test]
    fn test_coin_display() {
        let coin = Coin {
            id: ObjectId::ZERO,
            coin_type: StructTag {
                address: Address::ZERO,
                module: Identifier::new("m").unwrap(),
                name: Identifier::new("n").unwrap(),
                type_params: vec![],
            },
            balance: 100,
        };
        let s = format!("{}", coin);
        assert!(s.contains("balance: 100"));
        assert!(s.contains("id:"));
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
