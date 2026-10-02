// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use iota_types::Object;

/// Determines what to wait for after executing a transaction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum WaitForTransaction {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode, so queries
    /// served by the fullnode will find it.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer, so queries served by an indexer may not find it yet. Use
    /// [`WaitForTransaction::Finalized`] with those clients.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    #[default]
    Finalized,
}

/// One page of objects plus an optional cursor for the next page. See
/// [`LedgerClient::objects`](crate::LedgerClient::objects).
#[derive(Clone, Debug)]
pub struct ObjectsPage {
    /// The objects in this page.
    pub data: Vec<Object>,
    /// Opaque continuation cursor for fetching the next page; `None` when no
    /// further pages exist. Pass it back as the `cursor` argument to
    /// [`LedgerClient::objects`](crate::LedgerClient::objects) to advance.
    pub next_cursor: Option<Vec<u8>>,
}

/// Transport-neutral view of the chain's protocol configuration: flat maps of
/// attribute and feature flag names to their values.
#[derive(Clone, Debug, Default)]
pub struct ProtocolConfig {
    protocol_version: Option<u64>,
    attributes: BTreeMap<String, String>,
    feature_flags: BTreeMap<String, bool>,
}

impl ProtocolConfig {
    /// Builds a config from attributes keyed by their canonical protocol name
    /// (e.g. `"max_gas_payment_objects"`).
    pub fn new(attributes: BTreeMap<String, String>) -> Self {
        Self {
            attributes,
            ..Default::default()
        }
    }

    /// Sets the protocol version these values belong to.
    pub fn with_protocol_version(mut self, protocol_version: u64) -> Self {
        self.protocol_version = Some(protocol_version);
        self
    }

    /// Sets the feature flags, keyed by their canonical protocol name.
    pub fn with_feature_flags(mut self, feature_flags: BTreeMap<String, bool>) -> Self {
        self.feature_flags = feature_flags;
        self
    }

    /// The protocol version these values belong to, when the client reports
    /// it.
    pub fn protocol_version(&self) -> Option<u64> {
        self.protocol_version
    }

    /// All available configuration attributes, keyed by their canonical
    /// protocol name (e.g. `"max_gas_payment_objects"`).
    pub fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Looks up one attribute by its canonical protocol name.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    /// All feature flags the client reports, keyed by their canonical protocol
    /// name.
    pub fn feature_flags(&self) -> &BTreeMap<String, bool> {
        &self.feature_flags
    }

    /// Looks up one feature flag by its canonical protocol name.
    pub fn feature_flag(&self, name: &str) -> Option<bool> {
        self.feature_flags.get(name).copied()
    }
}
