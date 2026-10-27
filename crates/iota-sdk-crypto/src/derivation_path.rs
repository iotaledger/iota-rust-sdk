// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{fmt, str::FromStr};

/// Bit set on hardened indices.
const HARDENED: u32 = 1 << 31;

/// A BIP-32 derivation path, parsed from a string like
/// `m/44'/4218'/0'/0'/0'`; `'` or `h` marks a hardened index.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    /// The path's indices, with bit 31 set on hardened ones.
    pub fn indices(&self) -> &[u32] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut components = path.split('/');
        if components.next() != Some("m") {
            return Err(DerivationPathError(path.to_owned()));
        }
        components
            .map(|component| {
                let (index, hardened) = match component.strip_suffix(['\'', 'h']) {
                    Some(index) => (index, true),
                    None => (component, false),
                };
                let index = index.parse::<u32>().ok().filter(|i| *i < HARDENED)?;
                Some(if hardened { index | HARDENED } else { index })
            })
            .collect::<Option<Vec<_>>>()
            .map(Self)
            .ok_or_else(|| DerivationPathError(path.to_owned()))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for index in &self.0 {
            if index & HARDENED == 0 {
                write!(f, "/{index}")?;
            } else {
                write!(f, "/{}'", index & !HARDENED)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DerivationPath({})", self)
    }
}

/// Error returned when a string is not a valid derivation path.
#[derive(Debug, thiserror::Error)]
#[error("invalid derivation path: {0:?}")]
pub struct DerivationPathError(String);

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn parse() {
        let path: DerivationPath = "m/44'/4218'/0h/1/2".parse().unwrap();
        assert_eq!(
            path.indices(),
            [44 | HARDENED, 4218 | HARDENED, HARDENED, 1, 2]
        );
        assert_eq!(path.to_string(), "m/44'/4218'/0'/1/2");
    }

    #[test]
    fn reject_invalid() {
        for path in [
            "",
            "44'/4218'",
            "m/",
            "m//0",
            "m/x",
            "m/0''",
            "m/2147483648",
            "M/0",
        ] {
            assert!(path.parse::<DerivationPath>().is_err(), "{path:?}");
        }
    }
}
