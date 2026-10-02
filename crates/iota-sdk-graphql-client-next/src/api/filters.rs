// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use iota_types::{Address, Identifier, StructTag};

/// The Move types an object or event filter matches.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TypeFilter {
    /// Every type defined in a package.
    Package(Address),
    /// Every type defined in a module.
    Module(Address, Identifier),
    /// One type. Without type parameters, every instantiation of a generic
    /// type matches, e.g. `0x2::coin::Coin` matches every coin.
    Type(StructTag),
}

impl From<StructTag> for TypeFilter {
    fn from(struct_tag: StructTag) -> Self {
        Self::Type(struct_tag)
    }
}

impl fmt::Display for TypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(package) => write!(f, "{package}"),
            Self::Module(package, module) => write!(f, "{package}::{module}"),
            Self::Type(struct_tag) => write!(f, "{struct_tag}"),
        }
    }
}

/// The modules an event filter matches by the module that emitted the event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ModuleFilter {
    /// Every module of a package.
    Package(Address),
    /// One module.
    Module(Address, Identifier),
}

impl fmt::Display for ModuleFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(package) => write!(f, "{package}"),
            Self::Module(package, module) => write!(f, "{package}::{module}"),
        }
    }
}

/// The Move functions a transaction filter matches by the functions the
/// transaction calls.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FunctionFilter {
    /// Every function of a package.
    Package(Address),
    /// Every function of a module.
    Module(Address, Identifier),
    /// One function.
    Function(Address, Identifier, Identifier),
}

impl fmt::Display for FunctionFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(package) => write!(f, "{package}"),
            Self::Module(package, module) => write!(f, "{package}::{module}"),
            Self::Function(package, module, function) => {
                write!(f, "{package}::{module}::{function}")
            }
        }
    }
}

/// A kind of transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransactionKindFilter {
    /// Any system transaction.
    System,
    /// A transaction a user submitted.
    Programmable,
    /// The genesis transaction.
    Genesis,
    /// A consensus commit prologue.
    ConsensusCommitPrologue,
    /// A randomness state update.
    RandomnessStateUpdate,
    /// An end of epoch transaction.
    EndOfEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_render_as_the_server_expects() {
        let module = Identifier::new("coin").unwrap();
        assert_eq!(
            TypeFilter::Module(Address::FRAMEWORK, module.clone()).to_string(),
            format!("{}::coin", Address::FRAMEWORK)
        );
        assert_eq!(
            FunctionFilter::Function(
                Address::FRAMEWORK,
                module,
                Identifier::new("value").unwrap()
            )
            .to_string(),
            format!("{}::coin::value", Address::FRAMEWORK)
        );
        assert_eq!(
            TypeFilter::from(StructTag::new_gas_coin()).to_string(),
            StructTag::new_gas_coin().to_string()
        );
    }
}
