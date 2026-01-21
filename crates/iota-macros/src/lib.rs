// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use futures::future::BoxFuture;
pub use iota_proc_macros::*;

fn get_sync_fp_result(result: Box<dyn std::any::Any + Send + 'static>) {
    if result.downcast::<()>().is_err() {
        panic!("sync failpoint must return ()");
    }
}

fn get_async_fp_result(result: Box<dyn std::any::Any + Send + 'static>) -> BoxFuture<'static, ()> {
    match result.downcast::<BoxFuture<'static, ()>>() {
        Ok(fut) => *fut,
        Err(err) => panic!("async failpoint must return BoxFuture<'static, ()> {err:?}"),
    }
}

fn get_fp_if_result(result: Box<dyn std::any::Any + Send + 'static>) -> bool {
    match result.downcast::<bool>() {
        Ok(b) => *b,
        Err(_) => panic!("failpoint-if must return bool"),
    }
}

fn get_fp_some_result<T: Send + 'static>(
    result: Box<dyn std::any::Any + Send + 'static>,
) -> Option<T> {
    match result.downcast::<Option<T>>() {
        Ok(opt) => *opt,
        Err(_) => panic!("failpoint-arg must return Option<T>"),
    }
}

/// Trigger a fail point. Tests can trigger various behavior when the fail point
/// is hit.
#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {
        $crate::handle_fail_point($tag)
    };
}

/// Trigger an async fail point. Tests can trigger various async behavior when
/// the fail point is hit.
#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {
        $crate::handle_fail_point_async($tag).await
    };
}

/// Trigger a failpoint that runs a callback at the callsite if it is enabled.
/// (whether it is enabled is controlled by whether the registration callback
/// returns true/false).
#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point_if {
    ($tag: expr, $callback: expr) => {
        if $crate::handle_fail_point_if($tag) {
            ($callback)();
        }
    };
}

/// Trigger a failpoint that runs a callback at the callsite if it is enabled.
/// If the registration callback returns Some(v), then the `v` is passed to the
/// callback in the test. Otherwise the failpoint is skipped
#[cfg(any(msim, fail_points))]
#[macro_export]
macro_rules! fail_point_arg {
    ($tag: expr, $callback: expr) => {
        if let Some(arg) = $crate::handle_fail_point_arg($tag) {
            ($callback)(arg);
        }
    };
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point {
    ($tag: expr) => {};
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point_async {
    ($tag: expr) => {};
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point_if {
    ($tag: expr, $callback: expr) => {};
}

#[cfg(not(any(msim, fail_points)))]
#[macro_export]
macro_rules! fail_point_arg {
    ($tag: expr, $callback: expr) => {};
}

/// Use to write INFO level logs only when REPLAY_LOG
/// environment variable is set. Useful for log lines that
/// are only relevant to test infra which still may need to
/// run a release build. Also note that since logs of a chain
/// replay are exceedingly verbose, this will allow one to bubble
/// up "debug level" info while running with RUST_LOG=info.
#[macro_export]
macro_rules! replay_log {
    ($($arg:tt)+) => {
        if std::env::var("REPLAY_LOG").is_ok() {
            tracing::info!($($arg)+);
        }
    };
}

// These tests need to be run in release mode, since debug mode does overflow
// checks by default!
#[cfg(test)]
mod test {
    use super::*;

    // Uncomment to test error messages
    // #[with_checked_arithmetic]
    // struct TestStruct;

    macro_rules! pass_through {
        ($($tt:tt)*) => {
            $($tt)*
        }
    }
}
