// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rejects responses from a node that requires a newer SDK than this one.
//!
//! The node's GraphQL service stamps every response with the lowest
//! `iota-sdk-graphql-client` version able to decode it, in the
//! [`X_MIN_IOTA_SDK_GRAPHQL_CLIENT_VERSION`] header. The check runs on the
//! response headers, before any body is decoded, so an outdated client fails
//! with a clear error instead of tripping over a value it does not know.

use reqwest::header::HeaderMap;
use semver::Version;

use crate::error::{GraphQLError, GraphQLResult};

/// Version of this crate, which the node's minimum SDK version is compared
/// against.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lowest `iota-sdk-graphql-client` version able to decode the server's
/// responses, as a semantic version. Clients below it fail their requests
/// instead of decoding values they do not know.
pub const X_MIN_IOTA_SDK_GRAPHQL_CLIENT_VERSION: &str = "x-min-iota-sdk-graphql-client-version";

/// Fails with [`GraphQLError::IncompatibleSdkVersion`] when the response
/// headers name a minimum SDK version newer than this crate.
///
/// A response without the header, or with one that is not a semantic version,
/// passes.
pub(crate) fn check_min_sdk_version(response_headers: &HeaderMap) -> GraphQLResult<()> {
    // `CARGO_PKG_VERSION` comes from this crate's manifest, which cargo only
    // accepts with a valid semantic version.
    let current = Version::parse(VERSION).expect("CARGO_PKG_VERSION is a valid version");
    check_against(response_headers, &current)
}

fn check_against(response_headers: &HeaderMap, current: &Version) -> GraphQLResult<()> {
    let Some(minimum) = response_headers
        .get(X_MIN_IOTA_SDK_GRAPHQL_CLIENT_VERSION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Version::parse(value).ok())
    else {
        return Ok(());
    };

    if *current >= minimum {
        return Ok(());
    }

    Err(GraphQLError::IncompatibleSdkVersion {
        minimum: minimum.to_string(),
        current: current.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    fn headers_with_minimum(minimum: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_MIN_IOTA_SDK_GRAPHQL_CLIENT_VERSION,
            HeaderValue::from_str(minimum).unwrap(),
        );
        headers
    }

    fn check(headers: &HeaderMap, current: &str) -> GraphQLResult<()> {
        check_against(headers, &Version::parse(current).unwrap())
    }

    #[test]
    fn passes_when_client_matches_minimum() {
        check(&headers_with_minimum("1.2.3"), "1.2.3").unwrap();
    }

    #[test]
    fn passes_when_client_is_newer() {
        check(&headers_with_minimum("1.2.3"), "1.3.0").unwrap();
        check(&headers_with_minimum("1.0.0-beta.1"), "1.0.0").unwrap();
    }

    #[test]
    fn fails_when_client_is_older() {
        let error = check(&headers_with_minimum("1.3.0"), "1.2.9").unwrap_err();
        let GraphQLError::IncompatibleSdkVersion { minimum, current } = &error else {
            panic!("expected GraphQLError::IncompatibleSdkVersion, got {error:?}");
        };
        assert_eq!(minimum, "1.3.0");
        assert_eq!(current, "1.2.9");
        assert_eq!(
            error.to_string(),
            "node requires iota-sdk-graphql-client >= 1.3.0, this client is 1.2.9"
        );
    }

    #[test]
    fn fails_when_client_is_older_pre_release() {
        let error = check(&headers_with_minimum("1.0.0-beta.2"), "1.0.0-beta.1").unwrap_err();
        assert!(
            matches!(error, GraphQLError::IncompatibleSdkVersion { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn passes_without_header() {
        check(&HeaderMap::new(), "1.2.3").unwrap();
    }

    #[test]
    fn passes_with_unparsable_header() {
        check(&headers_with_minimum("latest"), "1.2.3").unwrap();
    }

    #[test]
    fn crate_version_is_valid_semver() {
        Version::parse(VERSION).unwrap();
    }
}
