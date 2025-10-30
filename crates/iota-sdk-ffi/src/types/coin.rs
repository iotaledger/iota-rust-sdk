// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::Result,
    types::{
        object::{Object, ObjectId},
        type_tag::TypeTag,
    },
};

#[derive(derive_more::From, uniffi::Object)]
pub struct Coin(pub iota_sdk::types::framework::Coin);

#[uniffi::export]
impl Coin {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(iota_sdk::types::framework::Coin::try_from_object(&object.0)?.into())
    }

    pub fn coin_type(&self) -> TypeTag {
        self.0.coin_type().clone().into()
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id()).into()
    }

    pub fn balance(&self) -> u64 {
        self.0.balance()
    }
}
