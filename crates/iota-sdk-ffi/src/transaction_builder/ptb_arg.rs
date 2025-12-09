// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::transaction_builder::{
    PureBytes, Receiving, Shared, SharedMut, builder::ptb_arguments::Res, res,
};
use primitive_types::U256;

use crate::{
    error::Result,
    types::{
        address::Address,
        digest::Digest,
        object::{ObjectId, ObjectReference},
    },
};

#[derive(Clone, uniffi::Object)]
pub enum MoveArg {
    Address(iota_sdk::types::Address),
    Digest(iota_sdk::types::Digest),
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(U256),
    String(String),
    Option(Option<Arc<MoveArg>>),
    Vector(Vec<MoveArg>),
}

#[uniffi::export]
impl MoveArg {
    #[uniffi::constructor]
    pub fn address(address: &Address) -> Self {
        Self::Address(**address)
    }

    #[uniffi::constructor]
    pub fn address_from_hex(hex: String) -> Result<Self> {
        Ok(Self::Address(iota_sdk::types::Address::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn digest(digest: &Digest) -> Self {
        Self::Digest(**digest)
    }

    #[uniffi::constructor]
    pub fn digest_from_base58(base58: String) -> Result<Self> {
        Ok(Self::Digest(iota_sdk::types::Digest::from_base58(base58)?))
    }

    #[uniffi::constructor]
    pub fn bool(value: bool) -> Self {
        Self::Bool(value)
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
    pub fn u128(value: String) -> Result<Self> {
        Ok(Self::U128(value.parse::<u128>()?))
    }

    #[uniffi::constructor]
    pub fn u256(value: String) -> Result<Self> {
        Ok(Self::U256(U256::from_dec_str(&value)?))
    }

    #[uniffi::constructor]
    pub fn string(string: String) -> Self {
        Self::String(string)
    }

    #[uniffi::constructor]
    pub fn option(value: Option<Arc<MoveArg>>) -> Self {
        Self::Option(value)
    }

    #[uniffi::constructor]
    pub fn address_vec(addresses: Vec<Arc<Address>>) -> Self {
        Self::Vector(
            addresses
                .into_iter()
                .map(|a| MoveArg::address(&a))
                .collect(),
        )
    }

    #[uniffi::constructor]
    pub fn address_vec_from_hex(addresses: Vec<String>) -> Result<Self> {
        Ok(Self::Vector(
            addresses
                .into_iter()
                .map(MoveArg::address_from_hex)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    #[uniffi::constructor]
    pub fn digest_vec(digests: Vec<Arc<Digest>>) -> Self {
        Self::Vector(digests.into_iter().map(|d| MoveArg::digest(&d)).collect())
    }

    #[uniffi::constructor]
    pub fn digest_vec_from_base58(digests: Vec<String>) -> Result<Self> {
        Ok(Self::Vector(
            digests
                .into_iter()
                .map(MoveArg::digest_from_base58)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    #[uniffi::constructor]
    pub fn bool_vec(values: Vec<bool>) -> Self {
        Self::Vector(values.into_iter().map(MoveArg::bool).collect())
    }

    #[uniffi::constructor]
    pub fn u8_vec(values: Vec<u8>) -> Self {
        Self::Vector(values.into_iter().map(MoveArg::u8).collect())
    }

    #[uniffi::constructor]
    pub fn u16_vec(values: Vec<u16>) -> Self {
        Self::Vector(values.into_iter().map(MoveArg::u16).collect())
    }

    #[uniffi::constructor]
    pub fn u32_vec(values: Vec<u32>) -> Self {
        Self::Vector(values.into_iter().map(MoveArg::u32).collect())
    }

    #[uniffi::constructor]
    pub fn u64_vec(values: Vec<u64>) -> Self {
        Self::Vector(values.into_iter().map(MoveArg::u64).collect())
    }

    #[uniffi::constructor]
    pub fn u128_vec(values: Vec<String>) -> Result<Self> {
        Ok(Self::Vector(
            values
                .into_iter()
                .map(MoveArg::u128)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    #[uniffi::constructor]
    pub fn u256_vec(values: Vec<String>) -> Result<Self> {
        Ok(Self::Vector(
            values
                .into_iter()
                .map(MoveArg::u256)
                .collect::<Result<Vec<_>>>()?,
        ))
    }

    #[uniffi::constructor]
    pub fn string_vec(addresses: Vec<String>) -> Self {
        Self::Vector(addresses.into_iter().map(MoveArg::string).collect())
    }
}

impl iota_sdk::transaction_builder::types::MoveArg for &MoveArg {
    fn pure_bytes(self) -> PureBytes {
        match self {
            MoveArg::Address(address) => address.pure_bytes(),
            MoveArg::Digest(digest) => digest.pure_bytes(),
            MoveArg::Bool(val) => val.pure_bytes(),
            MoveArg::U8(val) => val.pure_bytes(),
            MoveArg::U16(val) => val.pure_bytes(),
            MoveArg::U32(val) => val.pure_bytes(),
            MoveArg::U64(val) => val.pure_bytes(),
            MoveArg::U128(val) => val.pure_bytes(),
            MoveArg::U256(val) => val.pure_bytes(),
            MoveArg::String(val) => val.pure_bytes(),
            MoveArg::Option(opt) => opt.as_deref().pure_bytes(),
            MoveArg::Vector(vec) => vec.pure_bytes(),
        }
    }
}

#[derive(uniffi::Object)]
pub enum PTBArgument {
    ObjectId(iota_sdk::types::ObjectId),
    ObjectRef(iota_sdk::types::ObjectReference),
    Move(MoveArg),
    Res(Res),
    Shared(Shared<iota_sdk::types::ObjectId>),
    SharedMut(SharedMut<iota_sdk::types::ObjectId>),
    Receiving(Receiving<iota_sdk::types::ObjectId>),
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
    pub fn object_ref(id: ObjectReference) -> Self {
        Self::ObjectRef(id.into())
    }

    #[uniffi::constructor]
    pub fn move_arg(arg: &MoveArg) -> Self {
        Self::Move(arg.clone())
    }

    #[uniffi::constructor]
    pub fn object_id_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::ObjectId(iota_sdk::types::ObjectId::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn shared(id: &ObjectId) -> Self {
        Self::Shared(Shared(**id))
    }

    #[uniffi::constructor]
    pub fn shared_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::Shared(Shared(iota_sdk::types::ObjectId::from_hex(
            hex,
        )?)))
    }

    #[uniffi::constructor]
    pub fn shared_mut(id: &ObjectId) -> Self {
        Self::SharedMut(SharedMut(**id))
    }

    #[uniffi::constructor]
    pub fn shared_mut_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::SharedMut(SharedMut(
            iota_sdk::types::ObjectId::from_hex(hex)?,
        )))
    }

    #[uniffi::constructor]
    pub fn receiving(id: &ObjectId) -> Self {
        Self::Receiving(Receiving(**id))
    }

    #[uniffi::constructor]
    pub fn receiving_from_hex(hex: &str) -> Result<Self> {
        Ok(Self::Receiving(Receiving(
            iota_sdk::types::ObjectId::from_hex(hex)?,
        )))
    }

    #[uniffi::constructor]
    pub fn gas() -> Self {
        Self::Gas
    }

    #[uniffi::constructor]
    pub fn address(address: &Address) -> Self {
        Self::Move(MoveArg::address(address))
    }

    #[uniffi::constructor]
    pub fn address_from_hex(hex: String) -> Result<Self> {
        Ok(Self::Move(MoveArg::address_from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn digest(digest: &Digest) -> Self {
        Self::Move(MoveArg::digest(digest))
    }

    #[uniffi::constructor]
    pub fn digest_from_base58(base58: String) -> Result<Self> {
        Ok(Self::Move(MoveArg::digest_from_base58(base58)?))
    }

    #[uniffi::constructor]
    pub fn bool(value: bool) -> Self {
        Self::Move(MoveArg::bool(value))
    }

    #[uniffi::constructor]
    pub fn u8(value: u8) -> Self {
        Self::Move(MoveArg::u8(value))
    }

    #[uniffi::constructor]
    pub fn u16(value: u16) -> Self {
        Self::Move(MoveArg::u16(value))
    }

    #[uniffi::constructor]
    pub fn u32(value: u32) -> Self {
        Self::Move(MoveArg::u32(value))
    }

    #[uniffi::constructor]
    pub fn u64(value: u64) -> Self {
        Self::Move(MoveArg::u64(value))
    }

    #[uniffi::constructor]
    pub fn u128(value: String) -> Result<Self> {
        Ok(Self::Move(MoveArg::u128(value)?))
    }

    #[uniffi::constructor]
    pub fn u256(value: String) -> Result<Self> {
        Ok(Self::Move(MoveArg::u256(value)?))
    }

    #[uniffi::constructor]
    pub fn string(string: String) -> Self {
        Self::Move(MoveArg::string(string))
    }

    #[uniffi::constructor]
    pub fn option(value: Option<Arc<MoveArg>>) -> Self {
        Self::Move(MoveArg::option(value))
    }

    #[uniffi::constructor]
    pub fn address_vec(addresses: Vec<Arc<Address>>) -> Self {
        Self::Move(MoveArg::address_vec(addresses))
    }

    #[uniffi::constructor]
    pub fn address_vec_from_hex(addresses: Vec<String>) -> Result<Self> {
        Ok(Self::Move(MoveArg::address_vec_from_hex(addresses)?))
    }

    #[uniffi::constructor]
    pub fn digest_vec(digests: Vec<Arc<Digest>>) -> Self {
        Self::Move(MoveArg::digest_vec(digests))
    }

    #[uniffi::constructor]
    pub fn digest_vec_from_base58(digests: Vec<String>) -> Result<Self> {
        Ok(Self::Move(MoveArg::digest_vec_from_base58(digests)?))
    }

    #[uniffi::constructor]
    pub fn bool_vec(values: Vec<bool>) -> Self {
        Self::Move(MoveArg::bool_vec(values))
    }

    #[uniffi::constructor]
    pub fn u8_vec(values: Vec<u8>) -> Self {
        Self::Move(MoveArg::u8_vec(values))
    }

    #[uniffi::constructor]
    pub fn u16_vec(values: Vec<u16>) -> Self {
        Self::Move(MoveArg::u16_vec(values))
    }

    #[uniffi::constructor]
    pub fn u32_vec(values: Vec<u32>) -> Self {
        Self::Move(MoveArg::u32_vec(values))
    }

    #[uniffi::constructor]
    pub fn u64_vec(values: Vec<u64>) -> Self {
        Self::Move(MoveArg::u64_vec(values))
    }

    #[uniffi::constructor]
    pub fn u128_vec(values: Vec<String>) -> Result<Self> {
        Ok(Self::Move(MoveArg::u128_vec(values)?))
    }

    #[uniffi::constructor]
    pub fn u256_vec(values: Vec<String>) -> Result<Self> {
        Ok(Self::Move(MoveArg::u256_vec(values)?))
    }
}

impl iota_sdk::transaction_builder::PTBArgument for &PTBArgument {
    fn arg(
        self,
        ptb: &mut iota_sdk::transaction_builder::builder::TransactionBuildData,
    ) -> iota_sdk::transaction_builder::unresolved::Argument {
        match self {
            PTBArgument::ObjectId(object_id) => object_id.arg(ptb),
            PTBArgument::ObjectRef(obj_ref) => obj_ref.clone().arg(ptb),
            PTBArgument::Move(arg) => arg.arg(ptb),
            PTBArgument::Res(res) => res.arg(ptb),
            PTBArgument::Shared(shared) => shared.arg(ptb),
            PTBArgument::SharedMut(shared_mut) => shared_mut.arg(ptb),
            PTBArgument::Receiving(receiving) => receiving.arg(ptb),
            PTBArgument::Gas => iota_sdk::transaction_builder::unresolved::Argument::Gas,
        }
    }
}
