// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Cooperative cancellation for handle objects that are pulled with `next`.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// A cancellation flag that a pending `next` can wait on.
///
/// Foreign async support is uneven — Kotlin, Swift and Python can cancel a
/// pending call, Go and C# cannot — so cancellation has to be something the
/// handle itself understands rather than something the caller's runtime does
/// to it.
#[derive(Default)]
pub(crate) struct Cancel {
    canceled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    pub(crate) fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    /// Resolve once [`Cancel::cancel`] has been called.
    pub(crate) async fn wait(&self) {
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
