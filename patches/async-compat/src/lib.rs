// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Patched async-compat for iota-rust-sdk.
//
// On wasm32-unknown-unknown there are no threads and std::time::Instant is
// unavailable, so the original crate's global TOKIO1 runtime setup panics.
// This patch replaces the Compat wrapper with a transparent pass-through on
// wasm32 (the futures already run in the correct wasm-bindgen executor) while
// keeping the original tokio-compat behaviour on all other targets.

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
        /// Transparent pass-through wrapper (wasm32 only).
        ///
        /// On native targets this adapter enters a tokio runtime context so that
        /// tokio-based futures work from any executor.  On wasm32 the futures are
        /// already driven by the wasm-bindgen executor and reqwest uses the
        /// browser Fetch API, so no tokio context is needed.
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

        pub fn get_ref(&self) -> &T {
            &self.inner
        }

        pub fn get_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        pub fn into_inner(self) -> T {
            self.inner
        }
    }

    impl<T: Future> Future for Compat<T> {
        type Output = T::Output;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.project().inner.poll(cx)
        }
    }

    /// Extension trait that adds `.compat()` to any future.
    pub trait CompatExt: Sized {
        fn compat(self) -> Compat<Self> {
            Compat::new(self)
        }
    }

    impl<T: Future> CompatExt for T {}
}

#[cfg(target_arch = "wasm32")]
pub use wasm::*;
