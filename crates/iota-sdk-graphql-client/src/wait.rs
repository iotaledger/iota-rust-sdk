// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Async `sleep` / `timeout`. Tokio's time driver isn't available on wasm32,
//! so on that target we drive a cancellable `setTimeout`-backed future
//! instead.

use std::{future::Future, time::Duration};

/// Sleep for the given duration.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn sleep(duration: Duration) {
    wasm_time::Sleep::new(duration).await;
}

/// Race `f` against a timer. Returns `Err(Elapsed)` if the timer fires first.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn timeout<F: Future>(duration: Duration, f: F) -> Result<F::Output, Elapsed> {
    tokio::time::timeout(duration, f).await.map_err(|_| Elapsed)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn timeout<F: Future>(duration: Duration, f: F) -> Result<F::Output, Elapsed> {
    use futures::future::Either;
    let work = std::pin::pin!(f);
    let timer = std::pin::pin!(wasm_time::Sleep::new(duration));
    match futures::future::select(work, timer).await {
        Either::Left((v, _)) => Ok(v),
        Either::Right((_, _)) => Err(Elapsed),
    }
}

/// Marker type returned by [`timeout`] when the deadline elapses.
#[derive(Debug)]
pub(crate) struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline elapsed")
    }
}

impl std::error::Error for Elapsed {}

#[cfg(target_arch = "wasm32")]
mod wasm_time {
    use std::{
        cell::Cell,
        future::Future,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use wasm_bindgen::{closure::Closure, prelude::*};

    #[wasm_bindgen]
    unsafe extern "C" {
        #[wasm_bindgen(js_name = setTimeout)]
        fn set_timeout(callback: &js_sys::Function, ms: i32) -> JsValue;
        #[wasm_bindgen(js_name = clearTimeout)]
        fn clear_timeout(handle: &JsValue);
    }

    struct State {
        fired: Cell<bool>,
        waker: Cell<Option<Waker>>,
    }

    /// Cancellable sleep — `clearTimeout` on drop so Node's event loop
    /// doesn't stay alive past a future that's been raced out.
    pub(super) struct Sleep {
        state: Rc<State>,
        handle: Option<JsValue>,
        _closure: Option<Closure<dyn FnMut()>>,
    }

    impl Sleep {
        pub(super) fn new(duration: Duration) -> Self {
            let state = Rc::new(State {
                fired: Cell::new(false),
                waker: Cell::new(None),
            });
            let cb_state = state.clone();
            let closure: Closure<dyn FnMut()> = Closure::new(move || {
                cb_state.fired.set(true);
                if let Some(w) = cb_state.waker.take() {
                    w.wake();
                }
            });
            let ms = duration.as_millis().min(i32::MAX as u128) as i32;
            let handle = set_timeout(closure.as_ref().unchecked_ref(), ms);
            Self {
                state,
                handle: Some(handle),
                _closure: Some(closure),
            }
        }
    }

    impl Future for Sleep {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.state.fired.get() {
                self.handle = None;
                Poll::Ready(())
            } else {
                self.state.waker.set(Some(cx.waker().clone()));
                Poll::Pending
            }
        }
    }

    impl Drop for Sleep {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                clear_timeout(&handle);
            }
        }
    }
}
