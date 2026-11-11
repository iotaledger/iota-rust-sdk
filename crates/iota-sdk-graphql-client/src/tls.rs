// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Client construction for the constructors that build their own
//! [`reqwest::Client`], and for the WebSocket that subscriptions use.
//!
//! The crypto provider and the trust anchors are both chosen by feature.
//! `tls-ring` and `tls-aws-lc` are what turn on `reqwest`'s own TLS, and they
//! turn it on with `rustls-no-provider` so that neither choice is made on our
//! behalf. Without either of them `reqwest` is built with no TLS at all, so an
//! HTTP-only build needs no provider and reaches a plain-HTTP endpoint as-is.

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent and trust
/// anchors, and a connect timeout of
/// [`DEFAULT_CONNECT_TIMEOUT`](crate::client::DEFAULT_CONNECT_TIMEOUT).
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
    without_proxy_unless_tls(apply_roots(
        reqwest::Client::builder()
            .user_agent(crate::client::USER_AGENT)
            .connect_timeout(crate::client::DEFAULT_CONNECT_TIMEOUT),
    ))
}

/// Ignore the proxies set in the environment when neither `tls-ring` nor
/// `tls-aws-lc` is enabled.
///
/// A `reqwest` without TLS cannot tunnel an `https` request through a proxy, so
/// it forwards the request to the proxy unencrypted and accepts the proxy's
/// reply as the server's.
#[cfg(all(
    not(target_arch = "wasm32"),
    not(any(feature = "tls-ring", feature = "tls-aws-lc"))
))]
fn without_proxy_unless_tls(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder.no_proxy()
}

/// With a provider feature `reqwest` tunnels `https` through a proxy, so the
/// proxies set in the environment are kept.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc")
))]
fn without_proxy_unless_tls(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
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

/// The rustls configuration subscriptions open `wss` connections with,
/// trusting the same roots as [`default_http_client_builder`].
///
/// `tokio-tungstenite` has no access to `reqwest`'s configuration, so the
/// verifier is rebuilt here from the same features: the platform verifier, with
/// the bundled roots merged in where `reqwest` merges them, or the bundled
/// roots alone where it uses them alone.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc")
))]
pub(crate) fn websocket_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    install_default_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(default_crypto_provider()));
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    Ok(websocket_verification(builder, provider)?.with_no_client_auth())
}

/// The provider [`install_default_crypto_provider`] installs, for when another
/// one cannot be read back.
#[cfg(all(not(target_arch = "wasm32"), feature = "tls-ring"))]
fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "tls-aws-lc",
    not(feature = "tls-ring")
))]
fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// The bundled roots merged into the platform verifier.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc"),
    feature = "tls-webpki-roots",
    feature = "tls-native-roots",
    any(all(unix, not(target_os = "android")), target_os = "windows")
))]
fn websocket_verification(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
) -> Result<
    rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
    rustls::Error,
> {
    let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
        webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
        provider,
    )?;
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier)))
}

/// The bundled roots alone.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc"),
    feature = "tls-webpki-roots",
    not(all(
        feature = "tls-native-roots",
        any(all(unix, not(target_os = "android")), target_os = "windows")
    ))
))]
fn websocket_verification(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    _provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
) -> Result<
    rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
    rustls::Error,
> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    Ok(builder.with_root_certificates(roots))
}

/// The platform verifier alone.
#[cfg(all(
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc"),
    not(feature = "tls-webpki-roots")
))]
fn websocket_verification(
    builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
) -> Result<
    rustls::ConfigBuilder<rustls::ClientConfig, rustls::client::WantsClientCert>,
    rustls::Error,
> {
    let verifier = rustls_platform_verifier::Verifier::new(provider)?;
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier)))
}

#[cfg(all(
    test,
    not(target_arch = "wasm32"),
    any(feature = "tls-ring", feature = "tls-aws-lc")
))]
mod tests {
    #[test]
    fn websocket_tls_config_builds() {
        super::websocket_tls_config().unwrap();
    }
}
