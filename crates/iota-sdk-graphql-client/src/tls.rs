// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Client construction for the constructors that build their own
//! [`reqwest::Client`].
//!
//! The crypto provider and the trust anchors are both chosen by feature.
//! `tls-ring` and `tls-aws-lc` are what turn on `reqwest`'s own TLS, and they
//! turn it on with `rustls-no-provider` so that neither choice is made on our
//! behalf. Without either of them `reqwest` is built with no TLS at all, so an
//! HTTP-only build needs no provider and reaches a plain-HTTP endpoint as-is.

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent and trust
/// anchors.
///
/// With the default features the bundled Mozilla roots are merged into the
/// platform trust store rather than replacing it, so corporate CAs and
/// user-installed certificates keep working while the bundled set acts as a
/// floor. That floor matters because reqwest builds its certificate verifier
/// eagerly, before it knows whether a request will use TLS at all: on Linux the
/// platform verifier refuses to build when the system store is empty, which
/// otherwise breaks plain-HTTP use on images without `ca-certificates`. A build
/// with no provider feature has no verifier to build and so is unaffected.
///
/// Note that merging is a union, not a fallback. A CA the platform has
/// deliberately distrusted is still accepted if the bundled set carries it.
/// Build with only `tls-webpki-roots`, or only `tls-native-roots`, to get one
/// set alone.
///
/// Android is the exception: reqwest cannot merge roots there and rejects the
/// attempt, and its platform verifier aborts the process unless the hosting
/// application performs a JNI handshake the SDK cannot do on its behalf. The
/// bundled roots are used on their own instead, whenever they are available.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn default_http_client_builder() -> reqwest::ClientBuilder {
    install_default_crypto_provider();
    apply_roots(reqwest::Client::builder().user_agent(crate::client::USER_AGENT))
}

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent.
///
/// On wasm32 the browser owns certificate verification, so there are no trust
/// anchors and no crypto provider to configure.
#[cfg(target_arch = "wasm32")]
pub(crate) fn default_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(crate::client::USER_AGENT)
}

/// Select this crate's rustls crypto provider for the process, if nothing has
/// chosen one already.
///
/// A provider feature builds `reqwest` with `rustls-no-provider`, so a provider
/// has to be installed before any client is built. The first caller wins, so an
/// application that has already chosen one keeps it.
///
/// Does nothing when neither `tls-ring` nor `tls-aws-lc` is enabled.
#[cfg(not(target_arch = "wasm32"))]
fn install_default_crypto_provider() {
    // `install_default` returns `Err` when a provider is already installed,
    // which is the application's prerogative rather than our problem.
    #[cfg(feature = "tls-ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(all(feature = "tls-aws-lc", not(feature = "tls-ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Trust the bundled roots, merged into the platform store where that is
/// supported. Mirrors the platforms on which reqwest routes extra roots to
/// `rustls_platform_verifier::Verifier::new_with_extra_roots`; anywhere else it
/// returns a builder error, so the bundled set is used alone.
///
/// Needs a provider feature as well as `tls-webpki-roots`:
/// `reqwest::Certificate` does not exist without reqwest's TLS.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "tls-webpki-roots",
    any(feature = "tls-ring", feature = "tls-aws-lc")
))]
fn apply_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|cert| reqwest::Certificate::from_der(cert).ok());

    #[cfg(all(
        feature = "tls-native-roots",
        any(all(unix, not(target_os = "android")), target_os = "windows")
    ))]
    {
        builder.tls_certs_merge(roots)
    }
    #[cfg(not(all(
        feature = "tls-native-roots",
        any(all(unix, not(target_os = "android")), target_os = "windows")
    )))]
    {
        builder.tls_certs_only(roots)
    }
}

/// Without `tls-webpki-roots` there is nothing to add, so verification is left
/// to reqwest and the platform trust store. Also taken when no provider
/// feature is enabled, where there is no TLS to configure and the bundled roots
/// are compiled in but unused.
#[cfg(all(
    not(target_arch = "wasm32"),
    not(all(
        feature = "tls-webpki-roots",
        any(feature = "tls-ring", feature = "tls-aws-lc")
    ))
))]
fn apply_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
}

/// The scheme of `server` when this build cannot reach it, or `None` when it
/// can.
///
/// Without a provider feature `reqwest` is built with no TLS, so an `https` or
/// `wss` URL fails at request time with a transport error that names neither
/// TLS nor the feature that would enable it. Reporting it from the constructor
/// puts the cause where the caller can act on it.
///
/// A URL that does not parse is left for the caller's own parse to report.
#[cfg(all(
    not(target_arch = "wasm32"),
    not(any(feature = "tls-ring", feature = "tls-aws-lc"))
))]
pub(crate) fn unsupported_scheme(server: &str) -> Option<String> {
    let scheme = reqwest::Url::parse(server).ok()?.scheme().to_owned();
    matches!(scheme.as_str(), "https" | "wss").then_some(scheme)
}

/// Every scheme this crate accepts is reachable once TLS is compiled in, and on
/// wasm32 the browser provides it.
#[cfg(any(target_arch = "wasm32", feature = "tls-ring", feature = "tls-aws-lc"))]
pub(crate) fn unsupported_scheme(_server: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::unsupported_scheme;

    #[test]
    fn plain_schemes_need_no_tls() {
        assert_eq!(unsupported_scheme("http://127.0.0.1:9125"), None);
        assert_eq!(unsupported_scheme("ws://127.0.0.1:9125"), None);
    }

    #[test]
    fn unparseable_url_is_left_to_the_caller() {
        assert_eq!(unsupported_scheme("not a url"), None);
    }

    #[cfg(all(
        not(target_arch = "wasm32"),
        not(any(feature = "tls-ring", feature = "tls-aws-lc"))
    ))]
    #[test]
    fn tls_schemes_are_rejected_without_a_provider() {
        assert_eq!(
            unsupported_scheme("https://graphql.testnet.iota.cafe").as_deref(),
            Some("https")
        );
        assert_eq!(
            unsupported_scheme("wss://graphql.testnet.iota.cafe").as_deref(),
            Some("wss")
        );
    }

    #[cfg(any(target_arch = "wasm32", feature = "tls-ring", feature = "tls-aws-lc"))]
    #[test]
    fn tls_schemes_are_accepted_with_a_provider() {
        assert_eq!(
            unsupported_scheme("https://graphql.testnet.iota.cafe"),
            None
        );
        assert_eq!(unsupported_scheme("wss://graphql.testnet.iota.cafe"), None);
    }
}
