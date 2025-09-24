// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{builder::TransactionBuildData, unresolved::Argument};

/// A trait that defines a named command, either a string or nothing.
pub trait NamedCommand {
    /// Get the named command argument.
    fn named_command(&self, ptb: &mut TransactionBuildData) -> Argument;

    /// Push the named command to the PTB.
    fn push_named_command(self, arg: Argument, ptb: &mut TransactionBuildData);
}

impl NamedCommand for () {
    fn named_command(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command(self, _: Argument, _: &mut TransactionBuildData) {}
}

impl NamedCommand for &str {
    fn named_command(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl NamedCommand for String {
    fn named_command(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command(self, arg: Argument, ptb: &mut TransactionBuildData) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl<T: NamedCommand> NamedCommand for Option<T> {
    fn named_command(&self, ptb: &mut TransactionBuildData) -> Argument {
        Argument::Result((ptb.commands.len() - 1) as _)
    }

    fn push_named_command(self, arg: Argument, ptb: &mut TransactionBuildData) {
        if let Some(s) = self {
            s.push_named_command(arg, ptb)
        }
    }
}

/// A trait that allows tuples to be used to bind nested named commands.
pub trait NamedCommands {
    /// Push the named commands to the PTB.
    fn push_named_commands(self, ptb: &mut TransactionBuildData);
}

impl<T: NamedCommand> NamedCommands for T {
    fn push_named_commands(self, ptb: &mut TransactionBuildData) {
        let arg = Argument::Result((ptb.commands.len() - 1) as _);
        self.push_named_command(arg, ptb)
    }
}

impl<T: NamedCommand> NamedCommands for Vec<T> {
    fn push_named_commands(self, ptb: &mut TransactionBuildData) {
        for (i, v) in self.into_iter().enumerate() {
            let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, i as _);
            v.push_named_command(arg, ptb);
        }
    }
}

macro_rules! impl_named_command_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> NamedCommands for ($($tup),+)
        where $($tup: NamedCommand),+
        {
            fn push_named_commands(self, ptb: &mut TransactionBuildData) {
                $(
                    let arg = Argument::NestedResult((ptb.commands.len() - 1) as _, $idx);
                    self.$idx.push_named_command(arg, ptb);
                )+
            }
        }
    };
}
impl_named_command_tuple!(T1.0, T2.1);
impl_named_command_tuple!(T1.0, T2.1, T3.2);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);
impl_named_command_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4, T6.5);
