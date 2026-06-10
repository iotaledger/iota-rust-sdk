// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// async-compat patched for iota-rust-sdk: pass-through `Compat` on wasm32
// (no threads / no Instant), original tokio-compat behaviour elsewhere.
// Only the API surface UniFFI uses is provided: `Compat::new` on a future.

#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub use native::*;

// ─── wasm32 impl ────────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    use pin_project_lite::pin_project;

    pin_project! {
        /// Pass-through on wasm32 — futures already run in the wasm-bindgen
        /// executor and reqwest uses Fetch, so no tokio context is needed.
        pub struct Compat<T> {
            #[pin]
            inner: T,
        }
    }

    impl<T> Compat<T> {
        /// Wrap a value in the compatibility adapter.
        pub fn new(t: T) -> Compat<T> {
            Compat { inner: t }
        }
    }

    impl<T: Future> Future for Compat<T> {
        type Output = T::Output;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.project().inner.poll(cx)
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
