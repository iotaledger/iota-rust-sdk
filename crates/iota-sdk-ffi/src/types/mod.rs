// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;

pub mod address;
pub mod checkpoint;
pub mod coin;
pub mod crypto;
pub mod digest;
pub mod events;
pub mod execution_status;
pub mod gas;
pub mod graphql;
pub mod iota_names;
pub mod move_package;
pub mod object;
pub mod signature;
pub mod struct_tag;
pub mod transaction;
pub mod type_tag;
pub mod validator;

#[derive(derive_more::From, uniffi::Object)]
pub struct PersonalMessage(pub(crate) iota_sdk::types::PersonalMessage<'static>);

#[uniffi::export]
impl PersonalMessage {
    #[uniffi::constructor]
    pub fn new(message_bytes: &[u8]) -> Self {
        Self(iota_sdk::types::PersonalMessage(Cow::Owned(
            message_bytes.to_vec(),
        )))
    }

    pub fn message_bytes(&self) -> Vec<u8> {
        self.0.0.clone().into_owned()
    }

    pub fn signing_digest(&self) -> Vec<u8> {
        self.0.signing_digest().to_vec()
    }

    pub fn signing_digest_hex(&self) -> String {
        self.0.signing_digest_hex()
    }
}
