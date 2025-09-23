// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{TransactionBuilder, unresolved::Argument};

/// A trait that defines a named command, either a string or nothing.
pub trait NamedCommand {
    /// Get the named command argument.
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument;

    /// Push the named command to the PTB.
    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>);
}

impl NamedCommand for () {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len()) as _)
    }

    fn push_named_command<C>(self, _: Argument, _: &mut TransactionBuilder<C>) {}
}

impl NamedCommand for &str {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len()) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl NamedCommand for String {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len()) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        ptb.named_commands.insert(self.to_owned(), arg);
    }
}

impl<T: NamedCommand> NamedCommand for Option<T> {
    fn named_command<C>(&self, ptb: &mut TransactionBuilder<C>) -> Argument {
        Argument::Result((ptb.commands.len()) as _)
    }

    fn push_named_command<C>(self, arg: Argument, ptb: &mut TransactionBuilder<C>) {
        if let Some(s) = self {
            s.push_named_command(arg, ptb)
        }
    }
}

/// A trait that allows tuples to be used to bind nested named commands.
pub trait NamedCommands {
    /// Push the named commands to the PTB.
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>);
}

impl<T: NamedCommand> NamedCommands for T {
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
        let arg = Argument::Result(ptb.commands.len() as _);
        self.push_named_command(arg, ptb)
    }
}

impl<T: NamedCommand> NamedCommands for Vec<T> {
    fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
        for (i, v) in self.into_iter().enumerate() {
            let arg = Argument::NestedResult(ptb.commands.len() as _, i as _);
            v.push_named_command(arg, ptb);
        }
    }
}

macro_rules! impl_named_command_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> NamedCommands for ($($tup),+)
        where $($tup: NamedCommand),+
        {
            fn push_named_commands<C>(self, ptb: &mut TransactionBuilder<C>) {
                $(
                    let arg = Argument::NestedResult((ptb.commands.len()) as _, $idx);
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
