// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::large_enum_variant)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::module_inception)]
#![allow(clippy::result_large_err)]

use google::rpc::bad_request::FieldViolation;
use iota::grpc::v1::error_reason::ErrorReason;

pub(crate) mod google;
pub(crate) mod iota;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug)]
pub struct TryFromProtoError {
    field_violation: FieldViolation,
    source: Option<BoxError>,
}

impl std::fmt::Display for TryFromProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error converting from protobuf: ")?;

        write!(f, "field: {}", self.field_violation.field)?;

        if !self.field_violation.reason.is_empty() {
            write!(f, " reason: {}", self.field_violation.reason)?;
        }

        if !self.field_violation.description.is_empty() {
            write!(f, " description: {}", self.field_violation.description)?;
        }

        Ok(())
    }
}

impl std::error::Error for TryFromProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|s| s as _)
    }
}

impl TryFromProtoError {
    pub fn nested<T: AsRef<str>>(mut self, field: T) -> Self {
        let field = field.as_ref();
        self.field_violation = self.field_violation.nested(field);
        self
    }

    pub fn nested_at<T: AsRef<str>>(mut self, field: T, index: usize) -> Self {
        let field = field.as_ref();
        self.field_violation = self.field_violation.nested_at(field, index);
        self
    }

    pub fn missing<T: AsRef<str>>(field: T) -> Self {
        let field = field.as_ref();

        Self {
            field_violation: FieldViolation::new(field).with_reason(ErrorReason::FieldMissing),
            source: None,
        }
    }

    pub fn invalid<T: AsRef<str>, E: Into<BoxError>>(field: T, error: E) -> Self {
        let field = field.as_ref();
        let error = error.into();

        Self {
            field_violation: FieldViolation::new(field)
                .with_reason(ErrorReason::FieldInvalid)
                .with_description(error.to_string()),
            source: Some(error),
        }
    }

    pub fn field_violation(&self) -> &FieldViolation {
        &self.field_violation
    }
}

/// Macro to reduce boilerplate when accessing an optional field and calling
/// an inner method that returns `Result<T, TryFromProtoError>`.
///
/// # Usage
/// ```ignore
/// get_inner_field!(self.transaction, Self::TRANSACTION_FIELD, digest)
/// ```
macro_rules! get_inner_field {
    // Variant for try_into() that needs explicit TryFromProtoError type annotation
    // This must come first to match before the general case
    ($field:expr, $FIELD:expr, try_into) => {{
        <_ as core::convert::TryInto<_>>::try_into(
            $field
                .as_ref()
                .ok_or_else(|| $crate::proto::TryFromProtoError::missing($FIELD.name))?,
        )
        .map_err(|e: $crate::proto::TryFromProtoError| e.nested($FIELD.name))
    }};
    // Standard case: call a method on the inner value
    ($field:expr, $FIELD:expr, $inner:ident) => {{
        $field
            .as_ref()
            .ok_or_else(|| $crate::proto::TryFromProtoError::missing($FIELD.name))?
            .$inner()
            .map_err(|e| e.nested($FIELD.name))
    }};
}

pub(crate) use get_inner_field;

#[derive(Debug)]
pub enum GrpcConversionError {
    UnsupportedArgumentType { arg_type: String },
    BcsSerializationFailed { message: String },
}

impl std::fmt::Display for GrpcConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedArgumentType { arg_type } => {
                write!(
                    f,
                    "Unsupported argument type for gRPC conversion: {arg_type}"
                )
            }
            Self::BcsSerializationFailed { message } => {
                write!(f, "Failed to serialize BCS data: {message}")
            }
        }
    }
}

impl std::error::Error for GrpcConversionError {}

// TimeStamp
//

pub fn timestamp_ms_to_proto(timestamp_ms: u64) -> prost_types::Timestamp {
    let timestamp = std::time::Duration::from_millis(timestamp_ms);
    prost_types::Timestamp {
        seconds: timestamp.as_secs() as i64,
        nanos: timestamp.subsec_nanos() as i32,
    }
}

pub fn proto_to_timestamp_ms(timestamp: prost_types::Timestamp) -> Result<u64, TryFromProtoError> {
    let seconds = std::time::Duration::from_secs(
        timestamp
            .seconds
            .try_into()
            .map_err(|e| TryFromProtoError::invalid("seconds", e))?,
    );
    let nanos = std::time::Duration::from_nanos(
        timestamp
            .nanos
            .try_into()
            .map_err(|e| TryFromProtoError::invalid("nanos", e))?,
    );

    (seconds + nanos)
        .as_millis()
        .try_into()
        .map_err(|e| TryFromProtoError::invalid("seconds + nanos", e))
}

// prost_types::Value <-> serde_json::Value conversion
//

/// Converts a prost_types::Value to serde_json::Value.
pub fn prost_to_json(value: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;

    match &value.kind {
        None => serde_json::Value::Null,
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::NumberValue(n)) => serde_json::json!(*n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => {
            let map: serde_json::Map<String, serde_json::Value> = s
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), prost_to_json(v)))
                .collect();
            serde_json::Value::Object(map)
        }
        Some(Kind::ListValue(l)) => {
            let arr: Vec<serde_json::Value> = l.values.iter().map(prost_to_json).collect();
            serde_json::Value::Array(arr)
        }
    }
}

/// Converts a serde_json::Value to prost_types::Value.
///
/// `google.protobuf.Value` carries every number as an `f64`, which cannot hold
/// every integer exactly. All numeric values go as strings for the receiver to
/// parse against the type it expects. This applies at every depth, so a number
/// nested in an array or object becomes a string too.
///
/// Numeric values not representable by `serde_json::Number`, eg.
/// a Move `u128`/`u256` argument, must be passed as
/// `serde_json::Value::String` directly.
pub fn json_to_prost(value: &serde_json::Value) -> prost_types::Value {
    use prost_types::{ListValue, Struct, value::Kind};

    let kind = match value {
        serde_json::Value::Null => Kind::NullValue(0),
        serde_json::Value::Bool(b) => Kind::BoolValue(*b),
        // `Display` renders the number as it was parsed, so this neither
        // rounds nor depends on how `serde_json::Number` stores it.
        serde_json::Value::Number(n) => Kind::StringValue(n.to_string()),
        serde_json::Value::String(s) => Kind::StringValue(s.clone()),
        serde_json::Value::Array(a) => Kind::ListValue(ListValue {
            values: a.iter().map(json_to_prost).collect(),
        }),
        serde_json::Value::Object(o) => Kind::StructValue(Struct {
            fields: o
                .iter()
                .map(|(k, v)| (k.clone(), json_to_prost(v)))
                .collect(),
        }),
    };

    prost_types::Value { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use super::{json_to_prost, prost_to_json};

    /// Everything that is not a number is carried through unchanged, at every
    /// depth.
    #[test]
    fn nesting_survives_the_round_trip_through_prost() {
        let value = serde_json::json!({
            "list": ["0x2", true],
            "nested": {"flag": false, "nothing": null},
            "text": "0x2::hash::blake2b256",
        });

        assert_eq!(prost_to_json(&json_to_prost(&value)), value);
    }

    /// Numbers do not round-trip: they arrive as strings, so nothing is
    /// rounded on the way to a receiver that knows the type it wants.
    #[test]
    fn numbers_go_as_strings() {
        for (number, expected) in [
            (serde_json::json!(2), "2"),
            (serde_json::json!(-1), "-1"),
            (serde_json::json!(1.5), "1.5"),
            (serde_json::json!(u64::MAX), "18446744073709551615"),
        ] {
            assert_eq!(
                prost_to_json(&json_to_prost(&number)),
                serde_json::json!(expected),
                "{number} did not arrive as a string"
            );
        }

        // Above `u64::MAX` there is no JSON number to start from, so the caller
        // writes a string — which arrives as itself.
        let u128_max = serde_json::json!(u128::MAX.to_string());
        assert_eq!(prost_to_json(&json_to_prost(&u128_max)), u128_max);
    }

    /// Stringification recurses, so a `vector<u8>` argument written as JSON
    /// numbers reaches the node as an array of strings.
    #[test]
    fn nested_numbers_go_as_strings() {
        assert_eq!(
            prost_to_json(&json_to_prost(&serde_json::json!([0, 1, 2]))),
            serde_json::json!(["0", "1", "2"])
        );

        assert_eq!(
            prost_to_json(&json_to_prost(&serde_json::json!({
                "amount": 5,
                "nested": [{"weight": 1}],
            }))),
            serde_json::json!({
                "amount": "5",
                "nested": [{"weight": "1"}],
            })
        );
    }
}
