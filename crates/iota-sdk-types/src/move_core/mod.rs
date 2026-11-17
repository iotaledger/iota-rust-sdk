// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod parse;

mod identifier;
#[cfg(feature = "serde")]
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
    #[error("failed to parse {}: {}", error_input(input), source.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "unknown error".to_string()))]
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

/// Maximum number of bytes of the unparsed input that a
/// [`TypeParseError::Parse`] message shows.
const MAX_ERROR_INPUT_LENGTH: usize = 128;

/// `input` for an error message, cut to [`MAX_ERROR_INPUT_LENGTH`] bytes.
fn error_input(input: &str) -> std::borrow::Cow<'_, str> {
    if input.len() <= MAX_ERROR_INPUT_LENGTH {
        return input.into();
    }
    let end = (0..=MAX_ERROR_INPUT_LENGTH)
        .rev()
        .find(|&end| input.is_char_boundary(end))
        .unwrap_or_default();
    format!("{}... ({} bytes)", &input[..end], input.len()).into()
}
