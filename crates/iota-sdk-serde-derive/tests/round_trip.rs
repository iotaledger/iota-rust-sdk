// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Behavioural tests for `#[derive(SplitSerde)]`: the JSON (human-readable)
//! form carries the `json(...)` directives while the BCS (binary) form is a
//! plain `serde` representation of the base type.

use iota_sdk_serde_derive::SplitSerde;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Inner {
    x: u16,
}

// ---------------------------------------------------------------------------
// Enum: internally tagged + renamed in JSON, variant-index in BCS.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, SplitSerde)]
#[split_serde(json(tag = "kind", rename_all = "snake_case"))]
enum Tagged {
    Empty,
    Fields { a: u8, b: String },
    Wrapped(Inner),
}

#[test]
fn tagged_enum_json_is_internally_tagged_and_snake_cased() {
    let v = Tagged::Fields {
        a: 1,
        b: "hi".to_owned(),
    };
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json, serde_json::json!({"kind": "fields", "a": 1, "b": "hi"}));
    assert_eq!(serde_json::from_value::<Tagged>(json).unwrap(), v);

    assert_eq!(
        serde_json::to_value(Tagged::Empty).unwrap(),
        serde_json::json!({"kind": "empty"})
    );
}

#[test]
fn tagged_enum_bcs_is_variant_index() {
    // The binary form ignores the JSON tag and encodes the variant index.
    assert_eq!(bcs::to_bytes(&Tagged::Empty).unwrap(), [0]);

    let v = Tagged::Fields {
        a: 7,
        b: "x".to_owned(),
    };
    let bytes = bcs::to_bytes(&v).unwrap();
    assert_eq!(bytes[0], 1);
    assert_eq!(bcs::from_bytes::<Tagged>(&bytes).unwrap(), v);

    let n = Tagged::Wrapped(Inner { x: 9 });
    let bytes = bcs::to_bytes(&n).unwrap();
    assert_eq!(bytes[0], 2);
    assert_eq!(bcs::from_bytes::<Tagged>(&bytes).unwrap(), n);
}

// ---------------------------------------------------------------------------
// Enum without `json` directives: externally tagged in both formats. Exercises
// unit/tuple/newtype variant codegen.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, SplitSerde)]
enum Plain {
    A,
    B(u32),
    C(u16, u16),
}

#[test]
fn plain_enum_round_trips_in_both_formats() {
    for v in [Plain::A, Plain::B(5), Plain::C(1, 2)] {
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(serde_json::from_value::<Plain>(json).unwrap(), v);

        let bytes = bcs::to_bytes(&v).unwrap();
        assert_eq!(bcs::from_bytes::<Plain>(&bytes).unwrap(), v);
    }
    assert_eq!(
        serde_json::to_value(Plain::B(5)).unwrap(),
        serde_json::json!({"B": 5})
    );
}

// ---------------------------------------------------------------------------
// Struct: `with` is forwarded to both shadows; `json(...)` only affects JSON.
// ---------------------------------------------------------------------------

/// Serializes a `u64` as a decimal string in every format. Used to prove that
/// `with` is applied to both the readable and the binary shadow.
mod as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        value.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, SplitSerde)]
struct WithAndSkip {
    #[split_serde(with = "as_string")]
    n: u64,
    #[split_serde(json(skip_serializing_if = "Option::is_none", default))]
    opt: Option<u32>,
}

#[test]
fn struct_with_forwarding_and_json_only_skip() {
    let v = WithAndSkip { n: 42, opt: None };

    // `with` applied (n is a string), `opt` skipped in JSON because it is None.
    assert_eq!(
        serde_json::to_value(&v).unwrap(),
        serde_json::json!({"n": "42"})
    );
    // `default` lets the missing field deserialize back.
    assert_eq!(
        serde_json::from_value::<WithAndSkip>(serde_json::json!({"n": "42"})).unwrap(),
        v
    );

    // BCS keeps `opt` positional (no skip) and round-trips.
    assert_eq!(
        bcs::from_bytes::<WithAndSkip>(&bcs::to_bytes(&v).unwrap()).unwrap(),
        v
    );

    let v2 = WithAndSkip { n: 7, opt: Some(9) };
    assert_eq!(
        serde_json::to_value(&v2).unwrap(),
        serde_json::json!({"n": "7", "opt": 9})
    );
    assert_eq!(
        bcs::from_bytes::<WithAndSkip>(&bcs::to_bytes(&v2).unwrap()).unwrap(),
        v2
    );
}

// ---------------------------------------------------------------------------
// Enum with a renamed variant (e.g. a version tag).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, SplitSerde)]
#[split_serde(json(tag = "version"))]
enum Versioned {
    #[split_serde(json(rename = "1"))]
    V1(Inner),
}

#[test]
fn variant_level_rename_applies_in_json_only() {
    let v = Versioned::V1(Inner { x: 3 });
    assert_eq!(
        serde_json::to_value(&v).unwrap(),
        serde_json::json!({"version": "1", "x": 3})
    );
    assert_eq!(
        serde_json::from_value::<Versioned>(serde_json::json!({"version": "1", "x": 3})).unwrap(),
        v
    );
    // BCS: single variant => index 0.
    assert_eq!(bcs::to_bytes(&v).unwrap()[0], 0);
    assert_eq!(
        bcs::from_bytes::<Versioned>(&bcs::to_bytes(&v).unwrap()).unwrap(),
        v
    );
}
