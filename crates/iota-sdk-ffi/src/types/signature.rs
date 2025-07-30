// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct UserSignature(pub iota_types::UserSignature);
