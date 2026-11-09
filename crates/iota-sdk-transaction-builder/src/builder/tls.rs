// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The gas station's default [`reqwest::Client`].
//!
//! The crypto provider and the trust anchors are both chosen by feature.
//! `tls-ring` and `tls-aws-lc` are what turn on `reqwest`'s own TLS, and they
//! turn it on with `rustls-no-provider` so that neither choice is made on the
//! caller's behalf. Without either of them this crate builds `reqwest` with no
//! TLS at all.

/// The user agent sent by the gas station's default HTTP client.
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent and trust
/// anchors.
///
/// With `tls-native-roots` and `tls-webpki-roots` the bundled Mozilla roots are
/// merged into the platform trust store rather than replacing it. Android
/// cannot merge them, so the bundled roots are used alone there.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn default_http_client_builder() -> reqwest::ClientBuilder {
    install_default_crypto_provider();
    apply_roots(reqwest::Client::builder().user_agent(USER_AGENT))
}

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent.
///
/// On wasm32 the browser owns certificate verification, so there are no trust
/// anchors and no crypto provider to configure.
#[cfg(target_arch = "wasm32")]
pub(crate) fn default_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(USER_AGENT)
}

/// Select this crate's rustls crypto provider for the process, if nothing has
/// chosen one already.
///
/// Does nothing when neither `tls-ring` nor `tls-aws-lc` is enabled.
#[cfg(not(target_arch = "wasm32"))]
fn install_default_crypto_provider() {
    // `install_default` returns `Err` when a provider is already installed,
    // and the one installed first is kept.
    #[cfg(feature = "tls-ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(all(feature = "tls-aws-lc", not(feature = "tls-ring")))]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Trust the bundled roots, merged into the platform store on the platforms
/// where reqwest supports merging, and on their own elsewhere.
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

/// Without `tls-webpki-roots`, or without TLS, verification is left to reqwest
/// and the platform trust store.
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
