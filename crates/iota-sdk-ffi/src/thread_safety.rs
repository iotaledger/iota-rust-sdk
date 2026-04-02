// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Platform-conditional thread-safety helper.
// uniffi's `wasm-unstable-single-threaded` feature does not generate Send+Sync
// impls for callback handler types, so the trait itself can't require Send+Sync
// on wasm32 or the generated `impl Trait for UniFFICallback…` won't satisfy the
// supertrait bounds.
// On all other targets uniffi expects Arc<dyn Trait> to be Send+Sync, so the
// supertrait must carry those bounds.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait ThreadSafety: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> ThreadSafety for T {}
#[cfg(target_arch = "wasm32")]
pub(crate) trait ThreadSafety {}
#[cfg(target_arch = "wasm32")]
impl<T> ThreadSafety for T {}
