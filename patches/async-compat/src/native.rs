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
        let _guard = TOKIO1.handle.enter();
        self.project().inner.poll(cx)
    }
}

static TOKIO1: Lazy<GlobalRuntime> = Lazy::new(|| {
    let mut fallback_rt = None;
    let handle = tokio::runtime::Handle::try_current().unwrap_or_else(|_| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("cannot start tokio-1 runtime");
        let handle = rt.handle().clone();
        fallback_rt = Some(rt);

        thread::Builder::new()
            .name("async-compat/tokio-1".into())
            .spawn(move || TOKIO1.fallback_rt.as_ref().unwrap().block_on(Pending))
            .unwrap();

        handle
    });

    GlobalRuntime {
        handle,
        fallback_rt,
    }
});

struct GlobalRuntime {
    handle: tokio::runtime::Handle,
    fallback_rt: Option<tokio::runtime::Runtime>,
}

struct Pending;

impl Future for Pending {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
