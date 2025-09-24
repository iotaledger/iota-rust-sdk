// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    builder::TransactionBuildData,
    types::{MoveParam, ParamType},
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
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> PTBArguments for ($($tup),+)
        where $($tup: PTBArguments),+
        {
            fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
                $(
                    self.$idx.push_args(ptb, args);
                )+
            }
        }
    };
}
impl_ptb_args_tuple!(T1.0, T2.1);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_ptb_args_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);

impl<T: MoveParam> PTBArguments for T {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.param() {
            ParamType::Object(id) => ptb.set_input(InputKind::ImmutableOrOwned(id), false),
            ParamType::Pure(v) => ptb.pure_bytes(v),
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

/// Allows specifying mutable parameters.
pub struct Mut<T>(pub T);

impl<T: MoveParam> PTBArguments for Mut<T> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ParamType::Object(id) => ptb.set_input(
                InputKind::Shared {
                    object_id: id,
                    mutable: true,
                },
                false,
            ),
            ParamType::Pure(v) => ptb.pure_bytes(v),
        };
        args.push(arg);
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveParam> PTBArguments for Receiving<T> {
    fn push_args(&self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        let arg = match self.0.param() {
            ParamType::Object(id) => ptb.set_input(InputKind::Receiving(id), false),
            ParamType::Pure(v) => ptb.pure_bytes(v),
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
