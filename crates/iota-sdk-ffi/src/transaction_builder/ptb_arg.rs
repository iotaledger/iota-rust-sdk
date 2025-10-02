// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_transaction_builder::{
    PureBytes, Receiving, Shared, SharedMut, builder::ptb_arguments::Res, res,
};

use crate::types::{address::Address, digest::Digest, object::ObjectId};

#[derive(derive_more::From)]
enum PTBArg {
    ObjectId(iota_types::ObjectId),
    Address(iota_types::Address),
    Digest(iota_types::Digest),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    String(String),
    Vector(Vec<PureBytes>),
    Res(Res),
    Shared(Shared<iota_types::ObjectId>),
    SharedMut(SharedMut<iota_types::ObjectId>),
    Receiving(Receiving<iota_types::ObjectId>),
    Gas,
}

#[derive(uniffi::Object)]
pub struct PTBArgument(PTBArg);

#[uniffi::export]
impl PTBArgument {
    #[uniffi::constructor]
    pub fn res(name: String) -> Self {
        Self(res(name).into())
    }

    #[uniffi::constructor]
    pub fn object_id(id: &ObjectId) -> Self {
        Self((**id).into())
    }

    #[uniffi::constructor]
    pub fn address(address: &Address) -> Self {
        Self((**address).into())
    }

    #[uniffi::constructor]
    pub fn shared(id: &ObjectId) -> Self {
        Self(Shared(**id).into())
    }

    #[uniffi::constructor]
    pub fn shared_mut(id: &ObjectId) -> Self {
        Self(SharedMut(**id).into())
    }

    #[uniffi::constructor]
    pub fn receiving(id: &ObjectId) -> Self {
        Self(Receiving(**id).into())
    }

    #[uniffi::constructor]
    pub fn digest(digest: &Digest) -> Self {
        Self((**digest).into())
    }

    #[uniffi::constructor]
    pub fn u8(value: u8) -> Self {
        Self(value.into())
    }

    #[uniffi::constructor]
    pub fn u16(value: u16) -> Self {
        Self(value.into())
    }

    #[uniffi::constructor]
    pub fn u32(value: u32) -> Self {
        Self(value.into())
    }

    #[uniffi::constructor]
    pub fn u64(value: u64) -> Self {
        Self(value.into())
    }

    #[uniffi::constructor]
    pub fn u128(bytes: &[u8]) -> Self {
        Self(u128::from_le_bytes(bytes.try_into().expect("invalid le bytes for u128")).into())
    }

    #[uniffi::constructor]
    pub fn string(string: String) -> Self {
        Self(string.into())
    }

    #[uniffi::constructor]
    pub fn vector(vec: Vec<Vec<u8>>) -> Self {
        Self(vec.into_iter().map(PureBytes).collect::<Vec<_>>().into())
    }

    #[uniffi::constructor]
    pub fn gas() -> Self {
        Self(PTBArg::Gas)
    }
}

impl iota_transaction_builder::PTBArgument for PTBArgument {
    fn arg(
        self,
        ptb: &mut iota_transaction_builder::builder::TransactionBuildData,
    ) -> iota_transaction_builder::unresolved::Argument {
        self.0.arg(ptb)
    }
}

impl iota_transaction_builder::PTBArgument for &PTBArgument {
    fn arg(
        self,
        ptb: &mut iota_transaction_builder::builder::TransactionBuildData,
    ) -> iota_transaction_builder::unresolved::Argument {
        self.0.arg(ptb)
    }
}

pub struct PTBArgs(pub Vec<Arc<PTBArgument>>);

impl iota_transaction_builder::PTBArguments for PTBArgs {
    fn push_args(
        self,
        ptb: &mut iota_transaction_builder::builder::TransactionBuildData,
        args: &mut Vec<iota_transaction_builder::unresolved::Argument>,
    ) {
        for arg in &self.0 {
            args.push(iota_transaction_builder::PTBArgument::arg(&arg.0, ptb))
        }
    }
}

impl iota_transaction_builder::PTBArgument for &PTBArg {
    fn arg(
        self,
        ptb: &mut iota_transaction_builder::builder::TransactionBuildData,
    ) -> iota_transaction_builder::unresolved::Argument {
        match self {
            PTBArg::ObjectId(object_id) => object_id.arg(ptb),
            PTBArg::Address(address) => address.arg(ptb),
            PTBArg::Digest(digest) => digest.arg(ptb),
            PTBArg::U8(val) => val.arg(ptb),
            PTBArg::U16(val) => val.arg(ptb),
            PTBArg::U32(val) => val.arg(ptb),
            PTBArg::U64(val) => val.arg(ptb),
            PTBArg::U128(val) => val.arg(ptb),
            PTBArg::String(val) => val.arg(ptb),
            PTBArg::Vector(pure_bytes) => pure_bytes.clone().arg(ptb),
            PTBArg::Res(res) => res.arg(ptb),
            PTBArg::Shared(shared) => shared.arg(ptb),
            PTBArg::SharedMut(shared_mut) => shared_mut.arg(ptb),
            PTBArg::Receiving(receiving) => receiving.arg(ptb),
            PTBArg::Gas => iota_transaction_builder::unresolved::Argument::Gas,
        }
    }
}
