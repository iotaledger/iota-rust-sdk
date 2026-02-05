// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use bytestring::ByteString;

use crate::TypeParseError;

/// A move identifier
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// identifier = %x01-80    ; length of the identifier
///              (ALPHA *127(ALPHA / DIGIT / UNDERSCORE)) /
///              (UNDERSCORE 1*127(ALPHA / DIGIT / UNDERSCORE))
///
/// UNDERSCORE = %x95
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Identifier(
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Strategy::prop_map(
            "[a-zA-Z][a-zA-Z0-9_]{0,127}",
            Into::into
        ))
    )]
    ByteString,
);

impl Identifier {
    /// Creates a new `Identifier` from the given string slice, checking
    /// that it is a valid Move identifier and returning an error if not.
    pub fn new(identifier: impl AsRef<str>) -> Result<Self, TypeParseError> {
        if !Self::is_valid(identifier.as_ref()) {
            return Err(TypeParseError {
                source: identifier.as_ref().into(),
            });
        }

        Ok(Self(identifier.as_ref().into()))
    }

    /// Creates a new `Identifier` from the given string slice without
    /// validation.
    ///
    /// The caller must ensure that the provided string is a valid Move
    /// identifier. Otherwise this method is safe to use, but invalid
    /// identifiers will lead to downstream errors.
    pub fn new_unchecked(identifier: impl AsRef<str>) -> Self {
        Self(identifier.as_ref().into())
    }

    /// Creates a new `Identifier` from the given static string slice.
    ///
    /// This function will panic if the string is not a valid Move identifier.
    pub const fn from_static(s: &'static str) -> Self {
        if !Self::is_valid(s) {
            panic!("String is not a valid Move identifier");
        }

        Self(ByteString::from_static(s))
    }

    /// Returns the string slice representation of the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the byte slice representation of the identifier.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the length of the identifier.
    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    /// Returns `true` if the identifier has a length of zero.
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    /// Returns `true` if the provided string is a valid Move identifier. Valid
    /// identifiers must start with an alphabetic character (a-z, A-Z) or an
    /// underscore (_), and may be followed by up to 127 alphanumeric
    /// characters (a-z, A-Z, 0-9) or underscores (_). The maximum length of
    /// an identifier is 128 characters.
    ///
    /// Note: this function allows the special identifier `<SELF>`.
    pub const fn is_valid(s: &str) -> bool {
        if s.len() == 0 || s.len() > 128 {
            return false;
        }

        /// Returns `true` if all bytes in `b` after the offset `start_offset`
        /// are valid ASCII identifier characters.
        const fn all_bytes_valid(b: &[u8], start_offset: usize) -> bool {
            let mut i = start_offset;
            while i < b.len() {
                if !Identifier::is_valid_char(b[i] as char) {
                    return false;
                }
                i += 1;
            }
            true
        }
        // Rust const fn's don't currently support slicing or indexing &str's, so we
        // have to operate on the underlying byte slice. This is not a problem as
        // valid identifiers are (currently) ASCII-only.
        let b = s.as_bytes();
        match b {
            b"<SELF>" => true,
            [b'a'..=b'z', ..] | [b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
            [b'_', ..] if b.len() > 1 => all_bytes_valid(b, 1),
            _ => false,
        }
    }

    /// Return true if this character can appear in a Move identifier.
    ///
    /// Note: there are stricter restrictions on whether a character can begin a
    /// Move identifier--only alphabetic characters are allowed here.
    #[inline]
    pub const fn is_valid_char(c: char) -> bool {
        matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9')
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl std::str::FromStr for Identifier {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl std::ops::Deref for Identifier {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl From<&'static str> for Identifier {
    fn from(s: &'static str) -> Self {
        Self::from_static(s)
    }
}
