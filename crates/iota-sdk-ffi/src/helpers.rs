// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub(crate) trait SetIfSome: Sized {
    fn set_if_some<T>(self, value: Option<T>, set: impl FnOnce(Self, T) -> Self) -> Self {
        match value {
            Some(value) => set(self, value),
            None => self,
        }
    }
}

impl<Q> SetIfSome for Q {}
