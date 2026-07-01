// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! `Debug` helpers for rendering byte containers as base64 instead of the
//! default per-byte numeric list, mirroring how these fields are already
//! encoded by `serde` in the human-readable format.

use std::collections::BTreeMap;

use base64ct::Encoding;

/// Renders a byte slice as a base64 string, e.g. for use in `Display` impls.
pub(crate) struct Base64Display<'a>(pub &'a [u8]);

impl std::fmt::Display for Base64Display<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&base64ct::Base64::encode_string(self.0))
    }
}

/// Renders a byte slice as a quoted base64 string, for use as a `Debug`
/// field value, e.g. `.field("contents", &Base64Debug(&self.contents))`.
pub(crate) struct Base64Debug<'a>(pub &'a [u8]);

impl std::fmt::Debug for Base64Debug<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", Base64Display(self.0))
    }
}

/// Renders a list of byte vectors as a list of quoted base64 strings.
pub(crate) struct Base64DebugList<'a>(pub &'a [Vec<u8>]);

impl std::fmt::Debug for Base64DebugList<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|bytes| Base64Debug(bytes)))
            .finish()
    }
}

/// Renders a map of byte vector values as a map of quoted base64 strings.
pub(crate) struct Base64DebugMap<'a, K>(pub &'a BTreeMap<K, Vec<u8>>);

impl<K: std::fmt::Debug> std::fmt::Debug for Base64DebugMap<'_, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, bytes)| (k, Base64Debug(bytes))))
            .finish()
    }
}
