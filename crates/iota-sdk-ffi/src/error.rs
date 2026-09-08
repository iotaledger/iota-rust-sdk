// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

pub type Result<T, E = SdkFfiError> = std::result::Result<T, E>;

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SdkFfiError {
    Generic(String),
}

impl SdkFfiError {
    /// Flatten an error and its cause chain into a single message. Bindings
    /// only ever see this string, so a wrapping error that renders just its own
    /// message would otherwise arrive without any detail.
    pub fn new<E: std::error::Error>(err: E) -> Self {
        let mut message = err.to_string();
        let mut cause = err.source();
        while let Some(error) = cause {
            // Some SDK errors already render their source inline; only append
            // a cause the message does not carry yet.
            let text = error.to_string();
            if !message.contains(&text) {
                message.push_str(": ");
                message.push_str(&text);
            }
            cause = error.source();
        }
        Self::Generic(message)
    }

    pub fn custom(s: impl ToString) -> Self {
        Self::Generic(s.to_string())
    }
}

impl fmt::Display for SdkFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::error::Error> From<E> for SdkFfiError {
    fn from(e: E) -> SdkFfiError {
        Self::new(e)
    }
}
