// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use uniffi::Error;

pub type Result<T, E = BindingsSdkError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
#[uniffi(flat_error)]
pub enum BindingsSdkError {
    Generic(String),
}

impl BindingsSdkError {
    pub fn new<E: std::error::Error>(err: E) -> Self {
        Self::Generic(err.to_string())
    }

    pub fn custom(s: impl ToString) -> Self {
        Self::Generic(s.to_string())
    }
}

impl fmt::Display for BindingsSdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic(e) => write!(f, "{e}"),
        }
    }
}

impl<E: std::error::Error> From<E> for BindingsSdkError {
    fn from(e: E) -> BindingsSdkError {
        Self::new(e)
    }
}
