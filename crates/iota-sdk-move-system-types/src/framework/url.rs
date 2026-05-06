// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::fmt;

/// Rust version of the Move `iota::url::Url` type.
///
/// # SAFETY
///
/// The Move `Url` is ASCII-encoded. This Rust type stores the URL as a
/// `String` (UTF-8) but the constructors enforce that the contents are valid
/// ASCII so the on-the-wire BCS bytes match.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Url {
    url: String,
}

impl Url {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TryFrom<String> for Url {
    type Error = NonAsciiUrl;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        if !url.is_ascii() {
            return Err(NonAsciiUrl);
        }
        Ok(Self { url })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonAsciiUrl;

impl fmt::Display for NonAsciiUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("url is not valid ASCII")
    }
}

impl core::error::Error for NonAsciiUrl {}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn url_bcs_roundtrip() {
        let url = Url::try_from("https://iota.org/".to_owned()).unwrap();
        let bytes = bcs::to_bytes(&url).unwrap();
        // Wire format: BCS-encoded `String` (a length-prefixed byte sequence).
        assert_eq!(bytes, bcs::to_bytes(&"https://iota.org/".to_owned()).unwrap());
        let decoded: Url = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(url, decoded);
    }

    #[test]
    fn url_rejects_non_ascii() {
        assert!(Url::try_from("héllo".to_owned()).is_err());
    }
}
