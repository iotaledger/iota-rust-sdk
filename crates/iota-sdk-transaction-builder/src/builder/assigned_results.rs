// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{builder::TransactionBuildData, unresolved::Argument};

/// A trait that defines an assigned result, either a string or nothing.
pub trait AssignedResult {
    /// Get the assigned result argument.
    fn assigned_result(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    /// Push the assigned result to the PTB.
    fn push_assigned_result(self, arg: Argument, ptb: &mut TransactionBuildData);
}

impl AssignedResult for () {
    fn push_assigned_result(self, _: Argument, _: &mut TransactionBuildData) {}
}

impl AssignedResult for &str {
    fn push_assigned_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.assigned_results.insert(self.to_owned(), arg);
    }
}

impl AssignedResult for String {
    fn push_assigned_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.assigned_results.insert(self.to_owned(), arg);
    }
}

impl<T: AssignedResult> AssignedResult for Option<T> {
    fn push_assigned_result(self, arg: Argument, ptb: &mut TransactionBuildData) {
        if let Some(s) = self {
            s.push_assigned_result(arg, ptb)
        }
    }
}

/// A trait that allows tuples to be used to bind nested assigned results.
pub trait AssignedResults {
    /// Push the assigned results to the PTB.
    fn push_assigned_results(self, ptb: &mut TransactionBuildData);
}

impl<T: AssignedResult> AssignedResults for T {
    fn push_assigned_results(self, ptb: &mut TransactionBuildData) {
        let arg = Argument::Result((ptb.commands.len() - 1) as _);
        self.push_assigned_result(arg, ptb)
    }
}

impl<T: AssignedResult> AssignedResults for Vec<T> {
    fn push_assigned_results(self, ptb: &mut TransactionBuildData) {
        for (i, v) in self.into_iter().enumerate() {
            let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, i as _);
            v.push_assigned_result(arg, ptb);
        }
    }
}

macro_rules! impl_assigned_result_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> AssignedResults for ($($T),+)
        where $($T: AssignedResult),+
        {
            fn push_assigned_results(self, ptb: &mut TransactionBuildData) {
                $(
                    let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, $n);
                    self.$n.push_assigned_result(arg, ptb);
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_assigned_result_tuple, 2, 10, T);
