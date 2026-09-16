// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Client construction for the constructors that build their own
//! [`reqwest::Client`].

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent and trust
/// anchors.
///
/// The bundled Mozilla root set is added to the platform trust store rather
/// than replacing it, so corporate CAs and user-installed certificates keep
/// working while the bundled set acts as a floor. That floor matters because
/// reqwest builds its certificate verifier eagerly, before it knows whether a
/// request will use TLS at all: on Linux the platform verifier refuses to build
/// when the system store is empty, which otherwise breaks plain-HTTP use on
/// images without `ca-certificates`.
///
/// Note that this is a union, not a fallback. A CA the platform has
/// deliberately distrusted is still accepted if the bundled set carries it.
/// Pass your own client to [`crate::Client::with_http_client`] if you need the
/// platform store to be authoritative.
///
/// Android is the exception: reqwest cannot merge roots there and rejects the
/// attempt, and its platform verifier aborts the process unless the hosting
/// application performs a JNI handshake the SDK cannot do on its behalf. The
/// bundled roots are used on their own instead.
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
    let builder = reqwest::Client::builder().user_agent(crate::client::USER_AGENT);
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|cert| reqwest::Certificate::from_der(cert).ok());

    // Mirrors the platforms on which reqwest routes extra roots to
    // `rustls_platform_verifier::Verifier::new_with_extra_roots`; anywhere else
    // it returns a builder error instead.
    #[cfg(any(all(unix, not(target_os = "android")), target_os = "windows"))]
    {
        builder.tls_certs_merge(roots)
    }
    #[cfg(not(any(all(unix, not(target_os = "android")), target_os = "windows")))]
    {
        builder.tls_certs_only(roots)
    }
}

/// A [`reqwest::ClientBuilder`] carrying this crate's user agent.
///
/// On wasm32 the browser owns certificate verification, so there are no trust
/// anchors to configure.
#[cfg(target_arch = "wasm32")]
pub fn default_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(crate::client::USER_AGENT)
}
