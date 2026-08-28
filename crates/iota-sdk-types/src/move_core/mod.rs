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

impl winnow::error::ParserError<&str> for TypeParseError {
    type Inner = Self;

    fn from_input(input: &&str) -> Self {
        Self::Parse {
            input: (*input).to_owned(),
            source: None,
        }
    }

    fn into_inner(self) -> winnow::Result<Self::Inner, Self> {
        Ok(self)
    }
}

impl winnow::error::AddContext<&str> for TypeParseError {
    fn add_context(
        self,
        _input: &&str,
        _token_start: &<&str as winnow::stream::Stream>::Checkpoint,
        _context: &'static str,
    ) -> Self {
        self
    }
}

impl<E: std::error::Error + Send + Sync + 'static> winnow::error::FromExternalError<&str, E>
    for TypeParseError
{
    fn from_external_error(input: &&str, e: E) -> Self {
        Self::Parse {
            input: (*input).to_owned(),
            source: Some(Box::new(e)),
        }
    }
}
