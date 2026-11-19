// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]

pub mod field;
pub mod headers;
pub mod proto;
pub mod read_mask_fields;
pub mod read_masks;

pub use iota_types;
pub use prost;
pub use prost_types;
pub use tonic;

/// Joins field names with commas to build a read mask string constant.
///
/// Accepts string **literals** only (for compile-time concatenation via
/// `concat!`). To combine pre-defined constants at runtime, use
/// [`field_masks_merge!`] instead.
///
/// # Example
/// ```
/// use iota_sdk_grpc_types::field_mask;
///
/// const MASK: &str = field_mask!("transaction.digest", "effects.bcs");
/// assert_eq!(MASK, "transaction.digest,effects.bcs");
/// ```
#[macro_export]
macro_rules! field_mask {
    ($field:literal) => {
        $field
    };
    ($first:literal, $($rest:literal),+ $(,)?) => {
        concat!($first, ",", $crate::field_mask!($($rest),+))
    };
}

/// Normalizes a comma-separated field mask by removing paths that are
/// subsumed by broader (ancestor) paths.
///
/// A path `"a.b"` is subsumed by `"a"` because requesting `"a"` already
/// includes all of its sub-fields. Exact duplicates are also removed.
///
/// A path that names a server-rendered field
/// ([`field::SERVER_RENDERED_FIELD_NAMES`]) in any component is **not**
/// subsumed by its parent: the server renders these only when named explicitly,
/// so `"output_objects,output_objects.json"` keeps both paths. Matching any
/// component (not just the leaf) also keeps a sub-path into one, such as
/// `"output_objects.display.fields"`, in step with
/// [`field::FieldMaskTree`]. Within the response messages a read mask selects,
/// these names belong only to the server-rendered fields, so no ordinary path
/// is caught.
///
/// # Examples
/// ```
/// use iota_sdk_grpc_types::field_mask_normalize;
///
/// assert_eq!(field_mask_normalize("effects,effects.bcs"), "effects");
/// assert_eq!(field_mask_normalize("effects.bcs,effects"), "effects");
/// assert_eq!(field_mask_normalize("a,b.c,b"), "a,b");
/// assert_eq!(
///     field_mask_normalize("output_objects,output_objects.json"),
///     "output_objects,output_objects.json"
/// );
/// assert_eq!(
///     field_mask_normalize("output_objects,output_objects.display.fields"),
///     "output_objects,output_objects.display.fields"
/// );
/// ```
pub fn field_mask_normalize(mask: &str) -> String {
    let mut paths: Vec<&str> = mask.split(',').filter(|s| !s.is_empty()).collect();
    // Sort by length so broader (shorter) paths are processed first.
    paths.sort_by_key(|p| p.len());

    let mut result: Vec<&str> = Vec::new();
    for path in paths {
        let explicit_only = path
            .split(field::FIELD_SEPARATOR)
            .any(|component| field::SERVER_RENDERED_FIELD_NAMES.contains(&component));
        let subsumed = result.iter().any(|&kept| {
            path == kept
                || (!explicit_only
                    && path.starts_with(kept)
                    && path.as_bytes().get(kept.len()) == Some(&b'.'))
        });
        if !subsumed {
            result.push(path);
        }
    }
    result.join(",")
}

/// Merges multiple read mask expressions into a single comma-separated
/// [`String`], normalizing overlapping paths.
///
/// Unlike [`field_mask!`], this macro works with any expression that
/// evaluates to `&str`, including `const` values from
/// [`read_masks`](crate::read_masks). The result is a heap-allocated
/// `String` suitable for passing to the client's `read_mask` setters.
///
/// Overlapping paths are normalized: a broader path subsumes all of its
/// sub-paths. For example, `"effects"` and `"effects.bcs"` are merged into
/// just `"effects"`.
///
/// # Examples
/// ```
/// use iota_sdk_grpc_types::{field_masks_merge, read_masks::*};
///
/// let mask = field_masks_merge!(CHECKPOINT_RESPONSE_SUMMARY, CHECKPOINT_RESPONSE_CONTENTS,);
/// assert_eq!(mask, "checkpoint.summary,checkpoint.contents");
/// ```
///
/// Broader paths subsume narrower ones:
/// ```
/// use iota_sdk_grpc_types::field_masks_merge;
///
/// let mask = field_masks_merge!("effects", "effects.bcs");
/// assert_eq!(mask, "effects");
/// ```
#[macro_export]
macro_rules! field_masks_merge {
    ($mask:expr $(,)?) => {
        $crate::field_mask_normalize($mask)
    };
    ($first:expr, $($rest:expr),+ $(,)?) => {{
        let parts: &[&str] = &[$first, $($rest),+];
        $crate::field_mask_normalize(&parts.join(","))
    }};
}

// Re-export google namespace
pub mod google {
    pub use super::proto::google::*;
}

// Re-export under v1 namespace
pub mod v1 {
    pub use super::proto::iota::grpc::v1::*;
}
