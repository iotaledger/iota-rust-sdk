// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! `reqwest` client construction for the gas station.

/// A [`reqwest::Client`] trusting the platform store plus the bundled Mozilla
/// roots.
///
/// The bundled set is merged into the platform store rather than replacing it,
/// so corporate CAs and user-installed certificates keep working while the
/// bundled set acts as a floor. That floor matters even for a plain-HTTP gas
/// station, because reqwest builds its certificate verifier eagerly, before it
/// knows whether a request will use TLS: on Linux the platform verifier
/// refuses to build at all when the system store is empty.
///
/// This is a union, not a fallback — a CA the platform has deliberately
/// distrusted is still accepted if the bundled set carries it.
///
/// Android is the exception: reqwest cannot merge roots there and rejects the
/// attempt, and its platform verifier aborts the process without a JNI
/// handshake the SDK cannot perform. The bundled roots are used alone instead.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn client() -> Result<reqwest::Client, reqwest::Error> {
    // `reqwest` is built with `rustls-no-provider` to keep the aws-lc-rs C
    // library out of the graph, so a provider has to be installed first. The
    // first caller wins, so an application that chose its own keeps it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let builder = reqwest::Client::builder();
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|cert| reqwest::Certificate::from_der(cert).ok());

    // Mirrors the platforms on which reqwest routes extra roots to
    // `rustls_platform_verifier::Verifier::new_with_extra_roots`; anywhere else
    // it returns a builder error instead.
    #[cfg(any(all(unix, not(target_os = "android")), target_os = "windows"))]
    {
        builder.tls_certs_merge(roots).build()
    }
    #[cfg(not(any(all(unix, not(target_os = "android")), target_os = "windows")))]
    {
        builder.tls_certs_only(roots).build()
    }
}

/// On wasm32 the browser owns certificate verification, so there are no trust
/// anchors to configure.
#[cfg(target_arch = "wasm32")]
pub(crate) fn client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().build()
}
