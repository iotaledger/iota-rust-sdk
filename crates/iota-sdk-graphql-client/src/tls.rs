// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Client construction for the constructors that build their own
//! [`reqwest::Client`].
//!
//! The crypto provider and the trust anchors are both chosen by feature.
//! `reqwest` is built with `rustls-no-provider` so that neither choice is made
//! on our behalf.

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent and trust
/// anchors.
///
/// With the default features the bundled Mozilla roots are merged into the
/// platform trust store rather than replacing it, so corporate CAs and
/// user-installed certificates keep working while the bundled set acts as a
/// floor. That floor matters because reqwest builds its certificate verifier
/// eagerly, before it knows whether a request will use TLS at all: on Linux the
/// platform verifier refuses to build when the system store is empty, which
/// otherwise breaks plain-HTTP use on images without `ca-certificates`.
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
///
/// Useful for keeping the SDK's trust anchors while overriding something else:
///
/// ```no_run
/// # use iota_sdk_graphql_client::{Client, default_http_client_builder};
/// let http = default_http_client_builder()
///     .timeout(std::time::Duration::from_secs(5))
///     .build()?;
/// let client = Client::with_http_client("https://graphql.testnet.iota.cafe", http)?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn default_http_client_builder() -> reqwest::ClientBuilder {
    install_default_crypto_provider();
    apply_roots(reqwest::Client::builder().user_agent(crate::client::USER_AGENT))
}

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent.
///
/// On wasm32 the browser owns certificate verification, so there are no trust
/// anchors and no crypto provider to configure.
#[cfg(target_arch = "wasm32")]
pub fn default_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(crate::client::USER_AGENT)
}

/// Select this crate's rustls crypto provider for the process, if nothing has
/// chosen one already.
///
/// `reqwest` is built with `rustls-no-provider` so that the provider is a
/// feature of this crate rather than aws-lc-rs by fiat, and in exchange one has
/// to be installed before any client is built. Installing is a once-per-process
/// operation and the first caller wins, so an application that has already
/// chosen a provider keeps it and this is a no-op.
///
/// Callers who build their own [`reqwest::Client`] for
/// [`crate::Client::with_http_client`] should call this first; reqwest panics
/// when it finds no provider installed.
///
/// Does nothing when neither `tls-ring` nor `tls-aws-lc` is enabled.
#[cfg(not(target_arch = "wasm32"))]
pub fn install_default_crypto_provider() {
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
#[cfg(all(not(target_arch = "wasm32"), feature = "tls-webpki-roots"))]
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
/// to reqwest and the platform trust store.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "tls-webpki-roots")))]
fn apply_roots(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
}
