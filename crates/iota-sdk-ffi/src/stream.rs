// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Cancelable handle objects over streams that are pulled with `next`.

use std::sync::atomic::{AtomicBool, Ordering};

use futures::{Stream, StreamExt, future::Either};
use tokio::sync::{Mutex, Notify};

/// A cancellation flag that a pending `next` can wait on.
///
/// Foreign async support is uneven — Kotlin, Swift and Python can cancel a
/// pending call, Go and C# cannot — so cancellation has to be something the
/// handle itself understands rather than something the caller's runtime does
/// to it.
#[derive(Default)]
struct Cancel {
    canceled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    /// Resolve once [`Cancel::cancel`] has been called.
    async fn wait(&self) {
        loop {
            // Register for a wake-up before reading the flag, so a `cancel`
            // racing with this call cannot be missed.
            let notified = self.notify.notified();
            if self.is_canceled() {
                return;
            }
            notified.await;
        }
    }
}

/// A stream exposed to foreign code as a handle object.
///
/// uniffi has no equivalent of a `Stream`, so a stream is pulled one item at a
/// time with [`StreamHandle::next`] and closed with [`StreamHandle::cancel`].
/// The uniffi object wrapping this handle only maps items to their foreign
/// representation.
pub(crate) struct StreamHandle<S> {
    /// `None` once the stream has been canceled or exhausted, so that the
    /// connection behind it is dropped right away instead of being held until
    /// the handle is freed.
    stream: Mutex<Option<S>>,
    cancel: Cancel,
}

impl<S: Stream + Unpin> StreamHandle<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Mutex::new(Some(stream)),
            cancel: Cancel::default(),
        }
    }

    /// Wait for the next item.
    ///
    /// Returns `None` once the stream is exhausted or the handle has been
    /// canceled. Concurrent calls are serialized; there is no ordering
    /// guarantee between them.
    pub(crate) async fn next(&self) -> Option<S::Item> {
        // No early return on the cancellation flag: a `next` that was dropped
        // by the caller's runtime while `cancel` lost the `try_lock` race
        // leaves the stream in place, and only reaching the `select` below
        // (which polls `canceled` first) drops it.
        let mut stream = self.stream.lock().await;
        let canceled = std::pin::pin!(self.cancel.wait());
        let next = stream.as_mut()?.next();
        let item = match futures::future::select(canceled, next).await {
            Either::Left(((), _)) => None,
            Either::Right((item, _)) => item,
        };
        if item.is_none() {
            *stream = None;
        }
        item
    }

    /// Cancel the handle, dropping the stream and unblocking a pending `next`.
    ///
    /// Idempotent, and safe to call while `next` is pending — the pending call
    /// drops the stream on its way out.
    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
        if let Ok(mut stream) = self.stream.try_lock() {
            *stream = None;
        }
    }

    /// Whether the handle has been canceled.
    pub(crate) fn is_canceled(&self) -> bool {
        self.cancel.is_canceled()
    }
}

#[cfg(test)]
mod tests {
    use std::task::Context;

    use futures::{channel::mpsc, executor::block_on, future::join, task::noop_waker_ref};

    use super::*;

    #[test]
    fn yields_items_until_exhausted() {
        let (sender, receiver) = mpsc::unbounded();
        let handle = StreamHandle::new(receiver);
        sender.unbounded_send(1).unwrap();
        sender.unbounded_send(2).unwrap();
        drop(sender);

        block_on(async {
            assert_eq!(handle.next().await, Some(1));
            assert_eq!(handle.next().await, Some(2));
            assert_eq!(handle.next().await, None);
            assert_eq!(handle.next().await, None);
        });
        assert!(!handle.is_canceled());
    }

    #[test]
    fn cancel_drops_the_stream_and_ends_the_handle() {
        let (sender, receiver) = mpsc::unbounded::<u8>();
        let handle = StreamHandle::new(receiver);
        sender.unbounded_send(1).unwrap();

        handle.cancel();
        handle.cancel();

        assert!(handle.is_canceled());
        assert!(sender.is_closed());
        assert_eq!(block_on(handle.next()), None);
    }

    #[test]
    fn cancel_unblocks_a_pending_next() {
        let (sender, receiver) = mpsc::unbounded::<u8>();
        let handle = StreamHandle::new(receiver);

        // `join` polls `next` first, so it is pending on the empty channel and
        // holding the mutex when `cancel` runs.
        let (item, ()) = block_on(join(handle.next(), async { handle.cancel() }));

        assert_eq!(item, None);
        assert!(handle.is_canceled());
        assert!(sender.is_closed());
    }

    #[test]
    fn next_after_a_dropped_pending_next_drops_the_stream() {
        let (sender, receiver) = mpsc::unbounded::<u8>();
        let handle = StreamHandle::new(receiver);

        // Poll `next` once so it holds the mutex and is pending on the empty
        // channel, then drop it the way a foreign runtime does when it cancels
        // the call, after `cancel` lost the `try_lock` race against it.
        let mut cx = Context::from_waker(noop_waker_ref());
        let mut pending = Box::pin(handle.next());
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        handle.cancel();
        assert!(!sender.is_closed());
        drop(pending);

        assert_eq!(block_on(handle.next()), None);
        assert!(sender.is_closed());
    }
}
