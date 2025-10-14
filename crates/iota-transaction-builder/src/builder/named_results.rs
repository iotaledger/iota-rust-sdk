// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{builder::TransactionBuildData, unresolved::Argument};

/// A trait that defines a named result, either a string or nothing.
pub trait NamedResult {
    /// Get the named result argument.
    fn named_result(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    /// Push the named result to the PTB.
    fn push_named_result(self, arg: Argument, ptb: &mut TransactionBuildData);
}

impl NamedResult for () {
    fn push_named_result(self, _: Argument, _: &mut TransactionBuildData) {}
}

impl NamedResult for &str {
    fn push_named_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.named_results.insert(self.to_owned(), arg);
    }
}

impl NamedResult for String {
    fn push_named_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.named_results.insert(self.to_owned(), arg);
    }
}

impl<T: NamedResult> NamedResult for Option<T> {
    fn push_named_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        if let Some(s) = self {
            s.push_named_result(arg, ptb)
        }
    }
}

/// A trait that allows tuples to be used to bind nested named results.
pub trait NamedResults {
    /// Push the named results to the PTB.
    fn push_named_results(self, ptb: &mut TransactionBuildData);
}

impl<T: NamedResult> NamedResults for T {
    fn push_named_results(self, ptb: &mut TransactionBuildData) {
        let arg = Argument::Result((ptb.commands.len() - 1) as _);
        self.push_named_result(arg, ptb)
    }
}

impl<T: NamedResult> NamedResults for Vec<T> {
    fn push_named_results(self, ptb: &mut TransactionBuildData) {
        for (i, v) in self.into_iter().enumerate() {
            let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, i as _);
            v.push_named_result(arg, ptb);
        }
    }
}

macro_rules! impl_named_result_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> NamedResults for ($($T),+)
        where $($T: NamedResult),+
        {
            fn push_named_results(self, ptb: &mut TransactionBuildData) {
                $(
                    let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, $n);
                    self.$n.push_named_result(arg, ptb);
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_named_result_tuple, 2, 10, T);
