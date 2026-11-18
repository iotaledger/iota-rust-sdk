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

#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum TypeParseError {
    #[error("failed to parse {}: {}", ErrorInput(input), source.as_ref().map(|s| s.to_string()).unwrap_or_else(|| "unknown error".to_string()))]
    Parse {
        /// The input from where parsing stopped to its end.
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

impl std::fmt::Debug for TypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { input, source } => f
                .debug_struct("Parse")
                .field("input", &format_args!("\"{}\"", ErrorInput(input)))
                .field("source", source)
                .finish(),
            Self::NestingLimitExceeded => f.write_str("NestingLimitExceeded"),
            Self::IdentifierMaxLengthExceeded { actual } => f
                .debug_struct("IdentifierMaxLengthExceeded")
                .field("actual", actual)
                .finish(),
            Self::Address(error) => f.debug_tuple("Address").field(error).finish(),
        }
    }
}

/// Maximum number of bytes of the unparsed input that a
/// [`TypeParseError::Parse`] message shows.
const MAX_ERROR_INPUT_LENGTH: usize = 128;

/// Shows the unparsed input in an error message: cut to
/// [`MAX_ERROR_INPUT_LENGTH`] bytes, with control characters escaped.
struct ErrorInput<'a>(&'a str);

impl std::fmt::Display for ErrorInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;

        let input = self.0;
        let end = input.floor_char_boundary(MAX_ERROR_INPUT_LENGTH);
        for c in input[..end].chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_debug())?;
            } else {
                f.write_char(c)?;
            }
        }
        if end < input.len() {
            write!(f, "... ({} bytes)", input.len())?;
        }
        Ok(())
    }
}
