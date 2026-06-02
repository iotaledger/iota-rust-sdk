// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Minimal async-compat for native targets.
//
// UniFFI only uses `Compat::new(future)` to enter a tokio runtime context
// when polling async futures.  The I/O trait adapters (AsyncRead, AsyncWrite,
// AsyncBufRead, AsyncSeek) from the original crate are unused and omitted.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;

use once_cell::sync::Lazy;
use pin_project_lite::pin_project;

/// Extension trait that adds `.compat()` to any value.
pub trait CompatExt {
    fn compat(self) -> Compat<Self>
    where
        Self: Sized,
    {
        Compat::new(self)
    }
}

impl<T> CompatExt for T {}

pin_project! {
    /// Compatibility adapter that enters a tokio runtime context when polled.
    pub struct Compat<T> {
        #[pin]
        inner: T,
    }
}

impl<T> Compat<T> {
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
        let _guard = TOKIO1.enter();
        self.project().inner.poll(cx)
    }
}

static TOKIO1: Lazy<tokio::runtime::Handle> = Lazy::new(|| {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("cannot start tokio-1 runtime");
    let handle = rt.handle().clone();

    // Move the runtime into the worker thread so it lives as long as the
    // thread does — and so the thread never has to reach back into TOKIO1
    // while TOKIO1 itself is still being initialized.
    thread::Builder::new()
        .name("async-compat/tokio-1".into())
        .spawn(move || rt.block_on(Pending))
        .unwrap();

    handle
});

struct Pending;

impl Future for Pending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
