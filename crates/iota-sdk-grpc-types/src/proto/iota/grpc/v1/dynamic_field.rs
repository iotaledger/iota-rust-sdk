// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

include!("../../../generated/iota.grpc.v1.dynamic_field.rs");
include!("../../../generated/iota.grpc.v1.dynamic_field.field_info.rs");
include!("../../../generated/iota.grpc.v1.dynamic_field.accessors.rs");

use crate::proto::TryFromProtoError;

impl DynamicField {
    /// Get the JSON rendering of the dynamic field's "name".
    ///
    /// **Read mask:** `"json_name"` (see
    /// [`DYNAMIC_FIELD_JSON_NAME`](crate::read_masks::DYNAMIC_FIELD_JSON_NAME)).
    pub fn json_name(&self) -> Result<serde_json::Value, TryFromProtoError> {
        self.json_name
            .as_ref()
            .map(crate::proto::prost_to_json)
            .ok_or_else(|| TryFromProtoError::missing(DynamicField::JSON_NAME_FIELD.name))
    }
}
