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
    pub fn new<E: std::error::Error>(err: E) -> Self {
        Self::Generic(err.to_string())
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
