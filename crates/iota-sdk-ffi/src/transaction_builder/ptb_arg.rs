// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_transaction_builder::{
    PureBytes, Receiving, Shared, SharedMut, builder::ptb_arguments::Res, res,
};
use primitive_types::U256;

use crate::{
    error::Result,
    types::{address::Address, digest::Digest, object::ObjectId},
};

#[derive(uniffi::Object, derive_more::From)]
pub enum PTBArgument {
    ObjectId(iota_types::ObjectId),
    Address(iota_types::Address),
    Digest(iota_types::Digest),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(U256),
    String(String),
    Res(Res),
    Shared(Shared<iota_types::ObjectId>),
    SharedMut(SharedMut<iota_types::ObjectId>),
    Receiving(Receiving<iota_types::ObjectId>),
    Gas,
}

#[uniffi::export]
impl PTBArgument {
    #[uniffi::constructor]
    pub fn res(name: String) -> Self {
        Self::Res(res(name))
    }

    #[uniffi::constructor]
    pub fn object_id(id: &ObjectId) -> Self {
        Self::ObjectId(**id)
    }

    #[uniffi::constructor]
    pub fn object_id_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::ObjectId(iota_types::ObjectId::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn address(address: &Address) -> Self {
        Self::Address(**address)
    }

    #[uniffi::constructor]
    pub fn address_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::Address(iota_types::Address::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn shared(id: &ObjectId) -> Self {
        Self::Shared(Shared(**id))
    }

    #[uniffi::constructor]
    pub fn shared_mut(id: &ObjectId) -> Self {
        Self::SharedMut(SharedMut(**id))
    }

    #[uniffi::constructor]
    pub fn receiving(id: &ObjectId) -> Self {
        Self::Receiving(Receiving(**id))
    }

    #[uniffi::constructor]
    pub fn digest(digest: &Digest) -> Self {
        Self::Digest(**digest)
    }

    #[uniffi::constructor]
    pub fn u8(value: u8) -> Self {
        Self::U8(value)
    }

    #[uniffi::constructor]
    pub fn u16(value: u16) -> Self {
        Self::U16(value)
    }

    #[uniffi::constructor]
    pub fn u32(value: u32) -> Self {
        Self::U32(value)
    }

    #[uniffi::constructor]
    pub fn u64(value: u64) -> Self {
        Self::U64(value)
    }

    #[uniffi::constructor]
    pub fn u128(value: &str) -> Result<Self> {
        Ok(Self::U128(value.parse::<u128>()?))
    }

    #[uniffi::constructor]
    pub fn u256(value: &str) -> Result<Self> {
        Ok(Self::U256(U256::from_dec_str(value)?))
    }

    #[uniffi::constructor]
    pub fn string(string: String) -> Self {
        Self::String(string)
    }

    #[uniffi::constructor]
    pub fn gas() -> Self {
        Self::Gas
    }
}

impl iota_transaction_builder::PTBArgument for &PTBArgument {
    fn arg(
        self,
        ptb: &mut iota_transaction_builder::builder::TransactionBuildData,
    ) -> iota_transaction_builder::unresolved::Argument {
        match self {
            PTBArgument::ObjectId(object_id) => object_id.arg(ptb),
            PTBArgument::Address(address) => address.arg(ptb),
            PTBArgument::Digest(digest) => digest.arg(ptb),
            PTBArgument::U8(val) => val.arg(ptb),
            PTBArgument::U16(val) => val.arg(ptb),
            PTBArgument::U32(val) => val.arg(ptb),
            PTBArgument::U64(val) => val.arg(ptb),
            PTBArgument::U128(val) => val.arg(ptb),
            PTBArgument::U256(val) => val.arg(ptb),
            PTBArgument::String(val) => val.arg(ptb),
            PTBArgument::Res(res) => res.arg(ptb),
            PTBArgument::Shared(shared) => shared.arg(ptb),
            PTBArgument::SharedMut(shared_mut) => shared_mut.arg(ptb),
            PTBArgument::Receiving(receiving) => receiving.arg(ptb),
            PTBArgument::Gas => iota_transaction_builder::unresolved::Argument::Gas,
        }
    }
}
