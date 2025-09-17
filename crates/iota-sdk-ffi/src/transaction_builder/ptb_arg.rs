// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_transaction_builder::{
    builder::{Mut, Receiving},
    types::Vector,
};

use crate::types::{address::Address, digest::Digest, object::ObjectId};

type PTBArguments = Box<dyn iota_transaction_builder::builder::PTBArguments + Send + Sync>;

pub struct Res(String);

impl iota_transaction_builder::builder::PTBArguments for Res {
    fn push_args(
        &self,
        ptb: &mut iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>,
        args: &mut Vec<iota_types::Argument>,
    ) {
        if let Some(arg) = ptb.get_named_command(&self.0) {
            args.push(arg);
        } else {
            panic!("no command named `{}` exists", self.0)
        }
    }
}

#[derive(uniffi::Object)]
pub struct PTBArgument(PTBArguments);

#[uniffi::export]
impl PTBArgument {
    #[uniffi::constructor]
    pub fn res(name: String) -> Self {
        Self(Box::new(Res(name)))
    }

    #[uniffi::constructor]
    pub fn object_id(id: &ObjectId) -> Self {
        Self(Box::new(**id))
    }

    #[uniffi::constructor]
    pub fn address(address: &Address) -> Self {
        Self(Box::new(**address))
    }

    #[uniffi::constructor]
    pub fn mutable(id: &ObjectId) -> Self {
        Self(Box::new(Mut(**id)))
    }

    #[uniffi::constructor]
    pub fn receiving(id: &ObjectId) -> Self {
        Self(Box::new(Receiving(**id)))
    }

    #[uniffi::constructor]
    pub fn digest(digest: &Digest) -> Self {
        Self(Box::new(**digest))
    }

    #[uniffi::constructor]
    pub fn u8(value: u8) -> Self {
        Self(Box::new(value))
    }

    #[uniffi::constructor]
    pub fn u16(value: u16) -> Self {
        Self(Box::new(value))
    }

    #[uniffi::constructor]
    pub fn u32(value: u32) -> Self {
        Self(Box::new(value))
    }

    #[uniffi::constructor]
    pub fn u64(value: u64) -> Self {
        Self(Box::new(value))
    }

    #[uniffi::constructor]
    pub fn u128(bytes: &[u8]) -> Self {
        Self(Box::new(u128::from_le_bytes(
            bytes.try_into().expect("invalid le bytes for u128"),
        )))
    }

    #[uniffi::constructor]
    pub fn vector(vec: Vec<Vec<u8>>) -> Self {
        Self(Box::new(Vector(vec)))
    }
}

impl iota_transaction_builder::builder::PTBArguments for PTBArgument {
    fn push_args(
        &self,
        ptb: &mut iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>,
        args: &mut Vec<iota_types::Argument>,
    ) {
        self.0.push_args(ptb, args);
    }
}

impl iota_transaction_builder::builder::PTBArguments for &PTBArgument {
    fn push_args(
        &self,
        ptb: &mut iota_transaction_builder::TransactionBuilder<iota_graphql_client::Client>,
        args: &mut Vec<iota_types::Argument>,
    ) {
        self.0.push_args(ptb, args);
    }
}
