// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Minimal async-compat for native targets — UniFFI only uses `Compat::new`
// to enter a tokio runtime context, so the I/O trait adapters are omitted.

use std::{
    future::Future,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
    thread,
};

use pin_project_lite::pin_project;

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
}

impl<T: Future> Future for Compat<T> {
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _guard = TOKIO1.enter();
        self.project().inner.poll(cx)
    }
}

static TOKIO1: LazyLock<tokio::runtime::Handle> = LazyLock::new(|| {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("cannot start tokio-1 runtime");
    let handle = rt.handle().clone();

    // Move `rt` into the worker thread so it lives as long as the thread —
    // and so the thread never re-enters TOKIO1 while it's still initializing.
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
