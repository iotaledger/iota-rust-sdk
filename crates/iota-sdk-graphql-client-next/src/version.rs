// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// The response header carrying the server's version.
pub(crate) const VERSION_HEADER: &str = "x-iota-rpc-version";

/// The version of the GraphQL server, as reported in its responses, e.g.
/// `1.33.1-rc-d864b0092161`.
///
/// Queries that select fields only newer servers have choose their selection
/// from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerVersion {
    major: u64,
    minor: u64,
    patch: u64,
    raw: String,
}

impl ServerVersion {
    /// Parses a version such as `1.33.1` or `1.33.1-rc-d864b0092161`. Returns
    /// `None` if it does not start with three dot-separated numbers.
    pub fn parse(version: &str) -> Option<Self> {
        let core = version.split(['-', '+']).next()?;
        let mut numbers = core.split('.').map(|number| number.parse::<u64>().ok());
        let (Some(Some(major)), Some(Some(minor)), Some(Some(patch)), None) = (
            numbers.next(),
            numbers.next(),
            numbers.next(),
            numbers.next(),
        ) else {
            return None;
        };
        Some(Self {
            major,
            minor,
            patch,
            raw: version.to_owned(),
        })
    }

    /// The major version.
    pub fn major(&self) -> u64 {
        self.major
    }

    /// The minor version.
    pub fn minor(&self) -> u64 {
        self.minor
    }

    /// The patch version.
    pub fn patch(&self) -> u64 {
        self.patch
    }

    /// Whether this is `major.minor.patch` or newer. Pre-release suffixes are
    /// not compared: `1.33.0-beta` counts as `1.33.0`.
    pub fn is_at_least(&self, major: u64, minor: u64, patch: u64) -> bool {
        (self.major, self.minor, self.patch) >= (major, minor, patch)
    }

    /// The version exactly as the server reported it.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for ServerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_and_pre_release_versions() {
        let version = ServerVersion::parse("1.33.1-rc-d864b0092161").unwrap();
        assert_eq!(
            (version.major(), version.minor(), version.patch()),
            (1, 33, 1)
        );
        assert_eq!(version.as_str(), "1.33.1-rc-d864b0092161");
        assert!(version.is_at_least(1, 33, 0));
        assert!(!version.is_at_least(1, 34, 0));

        assert!(
            ServerVersion::parse("1.33.0-beta-ddf3b327ed06")
                .unwrap()
                .is_at_least(1, 33, 0)
        );
        assert!(
            !ServerVersion::parse("1.32.1-de85b83edc93")
                .unwrap()
                .is_at_least(1, 33, 0)
        );
    }

    #[test]
    fn rejects_other_formats() {
        assert_eq!(ServerVersion::parse("1.33"), None);
        assert_eq!(ServerVersion::parse("1.33.1.4"), None);
        assert_eq!(ServerVersion::parse("v1.33.1"), None);
        assert_eq!(ServerVersion::parse(""), None);
    }
}
