// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{ObjectId, ObjectReference};

use crate::{
    builder::TransactionBuildData,
    types::MoveArg,
    unresolved::{Argument, InputKind},
};

/// A trait which defines a single argument for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
#[diagnostic::on_unimplemented(message = "Provided value is not a valid move argument.")]
pub trait PTBArgument: Sized {
    /// Get the argument.
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        ptb.set_input(self.input(), false)
    }

    /// Get the input kind.
    fn input(self) -> InputKind;
}

impl PTBArgument for Argument {
    fn arg(self, _ptb: &mut TransactionBuildData) -> Argument {
        self
    }

    fn input(self) -> InputKind {
        panic!("Transaction inputs cannot be derived from command arguments")
    }
}

impl PTBArgument for iota_types::Input {
    fn input(self) -> InputKind {
        InputKind::Input(self)
    }
}

impl PTBArgument for ObjectId {
    fn input(self) -> InputKind {
        InputKind::ImmutableOrOwned(self)
    }
}

impl PTBArgument for &ObjectId {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (*self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (*self).input()
    }
}

impl PTBArgument for ObjectReference {
    fn input(self) -> InputKind {
        InputKind::Input(iota_types::Input::ImmutableOrOwned(self))
    }
}

impl<T: MoveArg> PTBArgument for T {
    fn input(self) -> InputKind {
        InputKind::Input(iota_types::Input::Pure(self.pure_bytes().0))
    }
}

impl<T> PTBArgument for std::sync::Arc<T>
where
    for<'a> &'a T: PTBArgument,
{
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.as_ref().arg(ptb)
    }

    fn input(self) -> InputKind {
        self.as_ref().input()
    }
}

/// A trait which defines a list of arguments for a
/// [`TransactionBuilder`](crate::TransactionBuilder).
#[diagnostic::on_unimplemented(
    message = "Provided value is not a valid list of arguments.",
    note = "Expected a tuple, vector, array, or slice of types that implement `PTBArgument`."
)]
pub trait PTBArgumentList {
    /// Get the arguments.
    fn args(self, ptb: &mut TransactionBuildData) -> Vec<Argument>
    where
        Self: Sized,
    {
        let mut args = Vec::new();
        self.push_args(ptb, &mut args);
        args
    }

    /// Push the args onto the list.
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>);

    /// Get the inputs.
    fn inputs(self) -> Vec<InputKind>
    where
        Self: Sized,
    {
        let mut inputs = Vec::new();
        self.push_inputs(&mut inputs);
        inputs
    }

    /// Push the inputs onto the list.
    fn push_inputs(self, args: &mut Vec<InputKind>);
}

macro_rules! impl_ptb_args_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> PTBArgumentList for ($($T),+)
        where $($T: PTBArgument),+
        {
            fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
                $(
                    args.push(self.$n.arg(ptb));
                )+
            }

            fn push_inputs(self, args: &mut Vec<InputKind>) {
                $(
                    args.push(self.$n.input());
                )+
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_ptb_args_tuple, 2, 15, T);

impl<T: PTBArgument> PTBArgumentList for Vec<T> {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }

    fn push_inputs(self, args: &mut Vec<InputKind>) {
        for input in self {
            args.push(input.input());
        }
    }
}

impl<const N: usize, T: PTBArgument> PTBArgumentList for [T; N] {
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }

    fn push_inputs(self, args: &mut Vec<InputKind>) {
        for input in self {
            args.push(input.input());
        }
    }
}

impl<T> PTBArgumentList for &[T]
where
    for<'a> &'a T: PTBArgument,
{
    fn push_args(self, ptb: &mut TransactionBuildData, args: &mut Vec<Argument>) {
        for input in self {
            args.push(input.arg(ptb));
        }
    }

    fn push_inputs(self, args: &mut Vec<InputKind>) {
        for input in self {
            args.push(input.input());
        }
    }
}

/// Allows specifying shared parameters.
pub struct Shared<T>(pub T);

impl<T: MoveArg> PTBArgument for Shared<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }

    fn input(self) -> InputKind {
        self.0.input()
    }
}

impl PTBArgument for Shared<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &Shared<ObjectId> {
    fn input(self) -> InputKind {
        InputKind::Shared {
            object_id: self.0,
            mutable: false,
        }
    }
}

impl PTBArgument for Shared<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &Shared<ObjectReference> {
    fn input(self) -> InputKind {
        InputKind::Input(iota_types::Input::Shared(
            iota_types::SharedObjectReference {
                object_id: self.0.object_id,
                mutable: false,
                initial_shared_version: self.0.version,
            },
        ))
    }
}

/// Allows specifying shared mutable parameters.
pub struct SharedMut<T>(pub T);

impl<T: MoveArg> PTBArgument for SharedMut<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }

    fn input(self) -> InputKind {
        self.0.input()
    }
}

impl PTBArgument for SharedMut<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &SharedMut<ObjectId> {
    fn input(self) -> InputKind {
        InputKind::Shared {
            object_id: self.0,
            mutable: true,
        }
    }
}

impl PTBArgument for SharedMut<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &SharedMut<ObjectReference> {
    fn input(self) -> InputKind {
        InputKind::Input(iota_types::Input::Shared(
            iota_types::SharedObjectReference {
                object_id: self.0.object_id,
                mutable: true,
                initial_shared_version: self.0.version,
            },
        ))
    }
}

/// Allows specifying receiving parameters.
pub struct Receiving<T>(pub T);

impl<T: MoveArg> PTBArgument for Receiving<T> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        self.0.arg(ptb)
    }

    fn input(self) -> InputKind {
        self.0.input()
    }
}

impl PTBArgument for Receiving<ObjectId> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &Receiving<ObjectId> {
    fn input(self) -> InputKind {
        InputKind::Receiving(self.0)
    }
}

impl PTBArgument for Receiving<ObjectReference> {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &Receiving<ObjectReference> {
    fn input(self) -> InputKind {
        InputKind::Input(iota_types::Input::Receiving(self.0))
    }
}

/// A result of a previous command to which a name was assigned.
#[derive(Clone, Debug)]
pub struct Assigned(String);

/// Get the result of a previous command by its assigned name.
pub fn assigned(name: impl Into<String>) -> Assigned {
    Assigned(name.into())
}

impl PTBArgument for Assigned {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        (&self).arg(ptb)
    }

    fn input(self) -> InputKind {
        (&self).input()
    }
}

impl PTBArgument for &Assigned {
    fn arg(self, ptb: &mut TransactionBuildData) -> Argument {
        if let Some(arg) = ptb.assigned_results.get(&self.0) {
            *arg
        } else {
            panic!("no command result assigned to `{}` exists", self.0)
        }
    }

    fn input(self) -> InputKind {
        panic!("Transaction inputs cannot be derived from command results")
    }
}
