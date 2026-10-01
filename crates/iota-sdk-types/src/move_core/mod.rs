// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod parse;

mod identifier;
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization;
mod struct_tag;
mod type_tag;

pub use identifier::Identifier;
pub use parse::{MAX_IDENTIFIER_LENGTH, MAX_TYPE_TAG_NESTING};
pub use struct_tag::StructTag;
pub use type_tag::TypeTag;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TypeParseError {
    #[error("failed to parse {input}: {}", source.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "unknown error".to_string()))]
    Parse {
        input: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    #[error(
        "nesting exceeded limit of {}",
        crate::move_core::parse::MAX_TYPE_TAG_NESTING
    )]
    NestingLimitExceeded,
    #[error(
        "identifier length {actual} exceeded limit of {}",
        crate::move_core::parse::MAX_IDENTIFIER_LENGTH
    )]
    IdentifierMaxLengthExceeded { actual: usize },
    #[error(transparent)]
    Address(#[from] crate::AddressParseError),
}
