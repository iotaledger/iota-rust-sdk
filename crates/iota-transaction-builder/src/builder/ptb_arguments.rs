// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    builder::TransactionBuildData,
    types::{MoveArg, ArgType},
    unresolved::{Argument, InputKind},
};

/// A trait which defines arguments for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
pub trait PTBArguments {
    /// Get the arguments.
    fn args(&self, ptb: &mut TransactionBuildData) -> Vec<Argument> {
        let mut args = Vec::new();
        self.push_args(ptb, &mut args);
        args
    }

    /// Push the args onto the list.
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>);
}

macro_rules! impl_ptb_args_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> PTBArguments for ($($T),+)
        where $($T: PTBArguments),+
        {
            fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
                $(
                    self.$n.push_args(ptb, args);
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_ptb_args_tuple, 2, 15, T);

impl<T: MoveArg> PTBArguments for T {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.param() {
            ArgType::Object(id) => ptb.set_input(InputKind::ImmutableOrOwned(id), false),
            ArgType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

impl<T: PTBArguments> PTBArguments for std::sync::Arc<T> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        self.as_ref().push_args(ptb, args);
    }
}

impl PTBArguments for Box<dyn PTBArguments> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        self.as_ref().push_args(ptb, args);
    }
}

impl PTBArguments for Argument {
    fn push_args(&self, _: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        args.push(*self);
    }
}

impl PTBArguments for iota_types::Input {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = ptb.input(self.clone());
        args.push(arg);
    }
}

impl PTBArguments for Vec<iota_types::Input> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            input.push_args(ptb, args);
        }
    }
}

/// Allows specifying mutable parameters.
pub struct Mut<T>(pub T);

impl<T: MoveArg> PTBArguments for Mut<T> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ArgType::Object(id) => ptb.set_input(
                InputKind::Shared {
                    object_id: id,
                    mutable: true,
                },
                false,
            ),
            ArgType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveArg> PTBArguments for Receiving<T> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ArgType::Object(id) => ptb.set_input(InputKind::Receiving(id), false),
            ArgType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

/// The result of a previous command by name.
pub struct Res(String);

/// Get the result of a previous command by name.
pub fn res(name: impl Into<String>) -> Res {
    Res(name.into())
}

impl PTBArguments for Res {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        if let Some(arg) = ptb.named_commands.get(&self.0) {
            args.push(*arg);
        } else {
            panic!("no command named `{}` exists", self.0)
        }
    }
}
