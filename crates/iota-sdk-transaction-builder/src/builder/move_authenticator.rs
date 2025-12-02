// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::TypeTag;

use crate::unresolved::Argument;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct MoveAuthenticatorData {
    /// Input objects or primitive values
    pub inputs: Vec<Argument>,
    /// Type arguments for the Move authenticate function
    pub type_arguments: Vec<TypeTag>,
}
