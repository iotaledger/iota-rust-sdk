// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::{CommandArgumentError, Identifier, TypeArgumentError};

use crate::{
    error::Result,
    types::{address::Address, digest::Digest, object::ObjectId},
};

/// The status of an executed Transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// execution-status = success / failure
/// success = %x00
/// failure = %x01 execution-error (option u64)
/// ```
#[derive(uniffi::Enum)]
pub enum ExecutionStatus {
    /// The Transaction successfully executed.
    Success,
    /// The Transaction didn't execute successfully.
    ///
    /// Failed transactions are still committed to the blockchain but any
    /// intended effects are rolled back to prior to this transaction
    /// executing with the caveat that gas objects are still smashed and gas
    /// usage is still charged.
    Failure {
        /// The error encountered during execution.
        error: ExecutionError,
        /// The command, if any, during which the error occurred.
        command: Option<u64>,
    },
}

impl From<iota_sdk::types::ExecutionStatus> for ExecutionStatus {
    fn from(value: iota_sdk::types::ExecutionStatus) -> Self {
        match value {
            iota_sdk::types::ExecutionStatus::Success => Self::Success,
            iota_sdk::types::ExecutionStatus::Failure { error, command } => Self::Failure {
                error: error.into(),
                command,
            },
        }
    }
}

impl From<ExecutionStatus> for iota_sdk::types::ExecutionStatus {
    fn from(value: ExecutionStatus) -> Self {
        match value {
            ExecutionStatus::Success => Self::Success,
            ExecutionStatus::Failure { error, command } => Self::Failure {
                error: error.into(),
                command,
            },
        }
    }
}

/// An error that can occur during the execution of a transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// 
/// execution-error =  insufficient-gas
///                 =/ invalid-gas-object
///                 =/ invariant-violation
///                 =/ feature-not-yet-supported
///                 =/ object-too-big
///                 =/ package-too-big
///                 =/ circular-object-ownership
///                 =/ insufficient-coin-balance
///                 =/ coin-balance-overflow
///                 =/ publish-error-non-zero-address
///                 =/ iota-move-verification-error
///                 =/ move-primitive-runtime-error
///                 =/ move-abort
///                 =/ vm-verification-or-deserialization-error
///                 =/ vm-invariant-violation
///                 =/ function-not-found
///                 =/ arity-mismatch
///                 =/ type-arity-mismatch
///                 =/ non-entry-function-invoked
///                 =/ command-argument-error
///                 =/ type-argument-error
///                 =/ unused-value-without-drop
///                 =/ invalid-public-function-return-type
///                 =/ invalid-transfer-object
///                 =/ effects-too-large
///                 =/ publish-upgrade-missing-dependency
///                 =/ publish-upgrade-dependency-downgrade
///                 =/ package-upgrade-error
///                 =/ written-objects-too-large
///                 =/ certificate-denied
///                 =/ iota-move-verification-timeout
///                 =/ shared-object-operation-not-allowed
///                 =/ input-object-deleted
///                 =/ execution-cancelled-due-to-shared-object-congestion
///                 =/ address-denied-for-coin
///                 =/ coin-type-global-pause
///                 =/ execution-cancelled-due-to-randomness-unavailable
///
/// insufficient-gas                                    = %x00
/// invalid-gas-object                                  = %x01
/// invariant-violation                                 = %x02
/// feature-not-yet-supported                           = %x03
/// object-too-big                                      = %x04 u64 u64
/// package-too-big                                     = %x05 u64 u64
/// circular-object-ownership                           = %x06 object-id
/// insufficient-coin-balance                           = %x07
/// coin-balance-overflow                               = %x08
/// publish-error-non-zero-address                      = %x09
/// iota-move-verification-error                        = %x0a
/// move-primitive-runtime-error                        = %x0b (option move-location)
/// move-abort                                          = %x0c move-location u64
/// vm-verification-or-deserialization-error            = %x0d
/// vm-invariant-violation                              = %x0e
/// function-not-found                                  = %x0f
/// arity-mismatch                                      = %x10
/// type-arity-mismatch                                 = %x11
/// non-entry-function-invoked                          = %x12
/// command-argument-error                              = %x13 u16 command-argument-error
/// type-argument-error                                 = %x14 u16 type-argument-error
/// unused-value-without-drop                           = %x15 u16 u16
/// invalid-public-function-return-type                 = %x16 u16
/// invalid-transfer-object                             = %x17
/// effects-too-large                                   = %x18 u64 u64
/// publish-upgrade-missing-dependency                  = %x19
/// publish-upgrade-dependency-downgrade                = %x1a
/// package-upgrade-error                               = %x1b package-upgrade-error
/// written-objects-too-large                           = %x1c u64 u64
/// certificate-denied                                  = %x1d
/// iota-move-verification-timeout                      = %x1e
/// shared-object-operation-not-allowed                 = %x1f
/// input-object-deleted                                = %x20
/// execution-cancelled-due-to-shared-object-congestion = %x21 (vector object-id)
/// address-denied-for-coin                             = %x22 address string
/// coin-type-global-pause                              = %x23 string
/// execution-cancelled-due-to-randomness-unavailable   = %x24
/// ```
#[derive(uniffi::Enum)]
pub enum ExecutionError {
    // General transaction errors
    /// Insufficient Gas
    InsufficientGas,
    /// Invalid Gas Object.
    InvalidGasObject,
    /// Invariant Violation
    InvariantViolation,
    /// Attempted to used feature that is not supported yet
    FeatureNotYetSupported,
    /// Move object is larger than the maximum allowed size
    ObjectTooBig {
        object_size: u64,
        max_object_size: u64,
    },
    /// Package is larger than the maximum allowed size
    PackageTooBig {
        object_size: u64,
        max_object_size: u64,
    },
    /// Circular Object Ownership
    CircularObjectOwnership { object: Arc<ObjectId> },
    // Coin errors
    /// Insufficient coin balance for requested operation
    InsufficientCoinBalance,
    /// Coin balance overflowed an u64
    CoinBalanceOverflow,
    // Publish/Upgrade errors
    /// Publish Error, Non-zero Address.
    /// The modules in the package must have their self-addresses set to zero.
    PublishErrorNonZeroAddress,
    /// IOTA Move Bytecode Verification Error.
    IotaMoveVerification,
    // MoveVm Errors
    /// Error from a non-abort instruction.
    /// Possible causes:
    ///     Arithmetic error, stack overflow, max value depth, etc."
    MovePrimitiveRuntime { location: Option<MoveLocation> },
    /// Move runtime abort
    MoveAbort { location: MoveLocation, code: u64 },
    /// Bytecode verification error.
    VmVerificationOrDeserialization,
    /// MoveVm invariant violation
    VmInvariantViolation,
    // Programmable Transaction Errors
    /// Function not found
    FunctionNotFound,
    /// Arity mismatch for Move function.
    /// The number of arguments does not match the number of parameters
    ArityMismatch,
    /// Type arity mismatch for Move function.
    /// Mismatch between the number of actual versus expected type arguments.
    TypeArityMismatch,
    /// Non Entry Function Invoked. Move Call must start with an entry function.
    NonEntryFunctionInvoked,
    /// Invalid command argument
    CommandArgument {
        argument: u16,
        kind: CommandArgumentError,
    },
    /// Type argument error
    TypeArgument {
        /// Index of the problematic type argument
        type_argument: u16,
        kind: TypeArgumentError,
    },
    /// Unused result without the drop ability.
    UnusedValueWithoutDrop { result: u16, subresult: u16 },
    /// Invalid public Move function signature.
    /// Unsupported return type for return value
    InvalidPublicFunctionReturnType { index: u16 },
    /// Invalid Transfer Object, object does not have public transfer.
    InvalidTransferObject,
    // Post-execution errors
    /// Effects from the transaction are too large
    EffectsTooLarge { current_size: u64, max_size: u64 },
    /// Publish or Upgrade is missing dependency
    PublishUpgradeMissingDependency,
    /// Publish or Upgrade dependency downgrade.
    ///
    /// Indirect (transitive) dependency of published or upgraded package has
    /// been assigned an on-chain version that is less than the version
    /// required by one of the package's transitive dependencies.
    PublishUpgradeDependencyDowngrade,
    /// Invalid package upgrade
    PackageUpgrade { kind: PackageUpgradeError },
    /// Indicates the transaction tried to write objects too large to storage
    WrittenObjectsTooLarge {
        object_size: u64,
        max_object_size: u64,
    },
    /// Certificate is on the deny list
    CertificateDenied,
    /// IOTA Move Bytecode verification timed out.
    IotaMoveVerificationTimeout,
    /// The requested shared object operation is not allowed
    SharedObjectOperationNotAllowed,
    /// Requested shared object has been deleted
    InputObjectDeleted,
    /// Certificate is cancelled due to congestion on shared objects
    ExecutionCancelledDueToSharedObjectCongestion {
        congested_objects: Vec<Arc<ObjectId>>,
    },
    /// Certificate is cancelled due to congestion on shared objects;
    /// suggested gas price can be used to give this certificate more priority.
    ExecutionCancelledDueToSharedObjectCongestionV2 {
        congested_objects: Vec<Arc<ObjectId>>,
        suggested_gas_price: u64,
    },
    /// Address is denied for this coin type
    AddressDeniedForCoin {
        address: Arc<Address>,
        coin_type: String,
    },
    /// Coin type is globally paused for use
    CoinTypeGlobalPause { coin_type: String },
    /// Certificate is cancelled because randomness could not be generated this
    /// epoch
    ExecutionCancelledDueToRandomnessUnavailable,
    /// A valid linkage was unable to be determined for the transaction or one
    /// of its commands.
    InvalidLinkage,
}

impl From<iota_sdk::types::ExecutionError> for ExecutionError {
    fn from(value: iota_sdk::types::ExecutionError) -> Self {
        match value {
            iota_sdk::types::ExecutionError::InsufficientGas => Self::InsufficientGas,
            iota_sdk::types::ExecutionError::InvalidGasObject => Self::InvalidGasObject,
            iota_sdk::types::ExecutionError::InvariantViolation => Self::InvariantViolation,
            iota_sdk::types::ExecutionError::FeatureNotYetSupported => Self::FeatureNotYetSupported,
            iota_sdk::types::ExecutionError::ObjectTooBig {
                object_size,
                max_object_size,
            } => Self::ObjectTooBig {
                object_size,
                max_object_size,
            },
            iota_sdk::types::ExecutionError::PackageTooBig {
                object_size,
                max_object_size,
            } => Self::PackageTooBig {
                object_size,
                max_object_size,
            },
            iota_sdk::types::ExecutionError::CircularObjectOwnership { object } => {
                Self::CircularObjectOwnership {
                    object: Arc::new(object.into()),
                }
            }
            iota_sdk::types::ExecutionError::InsufficientCoinBalance => {
                Self::InsufficientCoinBalance
            }
            iota_sdk::types::ExecutionError::CoinBalanceOverflow => Self::CoinBalanceOverflow,
            iota_sdk::types::ExecutionError::PublishErrorNonZeroAddress => {
                Self::PublishErrorNonZeroAddress
            }
            iota_sdk::types::ExecutionError::IotaMoveVerificationError => {
                Self::IotaMoveVerification
            }
            iota_sdk::types::ExecutionError::MovePrimitiveRuntimeError { location } => {
                Self::MovePrimitiveRuntime {
                    location: location.map(Into::into),
                }
            }
            iota_sdk::types::ExecutionError::MoveAbort { location, code } => Self::MoveAbort {
                location: location.into(),
                code,
            },
            iota_sdk::types::ExecutionError::VmVerificationOrDeserializationError => {
                Self::VmVerificationOrDeserialization
            }
            iota_sdk::types::ExecutionError::VmInvariantViolation => Self::VmInvariantViolation,
            iota_sdk::types::ExecutionError::FunctionNotFound => Self::FunctionNotFound,
            iota_sdk::types::ExecutionError::ArityMismatch => Self::ArityMismatch,
            iota_sdk::types::ExecutionError::TypeArityMismatch => Self::TypeArityMismatch,
            iota_sdk::types::ExecutionError::NonEntryFunctionInvoked => {
                Self::NonEntryFunctionInvoked
            }
            iota_sdk::types::ExecutionError::CommandArgumentError { argument, kind } => {
                Self::CommandArgument { argument, kind }
            }
            iota_sdk::types::ExecutionError::TypeArgumentError {
                type_argument,
                kind,
            } => Self::TypeArgument {
                type_argument,
                kind,
            },
            iota_sdk::types::ExecutionError::UnusedValueWithoutDrop { result, subresult } => {
                Self::UnusedValueWithoutDrop { result, subresult }
            }
            iota_sdk::types::ExecutionError::InvalidPublicFunctionReturnType { index } => {
                Self::InvalidPublicFunctionReturnType { index }
            }
            iota_sdk::types::ExecutionError::InvalidTransferObject => Self::InvalidTransferObject,
            iota_sdk::types::ExecutionError::EffectsTooLarge {
                current_size,
                max_size,
            } => Self::EffectsTooLarge {
                current_size,
                max_size,
            },
            iota_sdk::types::ExecutionError::PublishUpgradeMissingDependency => {
                Self::PublishUpgradeMissingDependency
            }
            iota_sdk::types::ExecutionError::PublishUpgradeDependencyDowngrade => {
                Self::PublishUpgradeDependencyDowngrade
            }
            iota_sdk::types::ExecutionError::PackageUpgradeError { kind } => {
                Self::PackageUpgrade { kind: kind.into() }
            }
            iota_sdk::types::ExecutionError::WrittenObjectsTooLarge {
                object_size,
                max_object_size,
            } => Self::WrittenObjectsTooLarge {
                object_size,
                max_object_size,
            },
            iota_sdk::types::ExecutionError::CertificateDenied => Self::CertificateDenied,
            iota_sdk::types::ExecutionError::IotaMoveVerificationTimeout => {
                Self::IotaMoveVerificationTimeout
            }
            iota_sdk::types::ExecutionError::SharedObjectOperationNotAllowed => {
                Self::SharedObjectOperationNotAllowed
            }
            iota_sdk::types::ExecutionError::InputObjectDeleted => Self::InputObjectDeleted,
            iota_sdk::types::ExecutionError::ExecutionCancelledDueToSharedObjectCongestion {
                congested_objects,
            } => Self::ExecutionCancelledDueToSharedObjectCongestion {
                congested_objects: congested_objects
                    .into_iter()
                    .map(Into::into)
                    .map(Arc::new)
                    .collect(),
            },
            iota_sdk::types::ExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                congested_objects,
                suggested_gas_price,
            } => Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                congested_objects: congested_objects
                    .into_iter()
                    .map(Into::into)
                    .map(Arc::new)
                    .collect(),
                suggested_gas_price,
            },
            iota_sdk::types::ExecutionError::AddressDeniedForCoin { address, coin_type } => {
                Self::AddressDeniedForCoin {
                    address: Arc::new(address.into()),
                    coin_type,
                }
            }
            iota_sdk::types::ExecutionError::CoinTypeGlobalPause { coin_type } => {
                Self::CoinTypeGlobalPause { coin_type }
            }
            iota_sdk::types::ExecutionError::ExecutionCancelledDueToRandomnessUnavailable => {
                Self::ExecutionCancelledDueToRandomnessUnavailable
            }
            iota_sdk::types::ExecutionError::InvalidLinkage => Self::InvalidLinkage,
        }
    }
}

impl From<ExecutionError> for iota_sdk::types::ExecutionError {
    fn from(value: ExecutionError) -> Self {
        match value {
            ExecutionError::InsufficientGas => Self::InsufficientGas,
            ExecutionError::InvalidGasObject => Self::InvalidGasObject,
            ExecutionError::InvariantViolation => Self::InvariantViolation,
            ExecutionError::FeatureNotYetSupported => Self::FeatureNotYetSupported,
            ExecutionError::ObjectTooBig {
                object_size,
                max_object_size,
            } => Self::ObjectTooBig {
                object_size,
                max_object_size,
            },
            ExecutionError::PackageTooBig {
                object_size,
                max_object_size,
            } => Self::PackageTooBig {
                object_size,
                max_object_size,
            },
            ExecutionError::CircularObjectOwnership { object } => {
                Self::CircularObjectOwnership { object: **object }
            }
            ExecutionError::InsufficientCoinBalance => Self::InsufficientCoinBalance,
            ExecutionError::CoinBalanceOverflow => Self::CoinBalanceOverflow,
            ExecutionError::PublishErrorNonZeroAddress => Self::PublishErrorNonZeroAddress,
            ExecutionError::IotaMoveVerification => Self::IotaMoveVerificationError,
            ExecutionError::MovePrimitiveRuntime { location } => Self::MovePrimitiveRuntimeError {
                location: location.map(Into::into),
            },
            ExecutionError::MoveAbort { location, code } => Self::MoveAbort {
                location: location.into(),
                code,
            },
            ExecutionError::VmVerificationOrDeserialization => {
                Self::VmVerificationOrDeserializationError
            }
            ExecutionError::VmInvariantViolation => Self::VmInvariantViolation,
            ExecutionError::FunctionNotFound => Self::FunctionNotFound,
            ExecutionError::ArityMismatch => Self::ArityMismatch,
            ExecutionError::TypeArityMismatch => Self::TypeArityMismatch,
            ExecutionError::NonEntryFunctionInvoked => Self::NonEntryFunctionInvoked,
            ExecutionError::CommandArgument { argument, kind } => {
                Self::CommandArgumentError { argument, kind }
            }
            ExecutionError::TypeArgument {
                type_argument,
                kind,
            } => Self::TypeArgumentError {
                type_argument,
                kind,
            },
            ExecutionError::UnusedValueWithoutDrop { result, subresult } => {
                Self::UnusedValueWithoutDrop { result, subresult }
            }
            ExecutionError::InvalidPublicFunctionReturnType { index } => {
                Self::InvalidPublicFunctionReturnType { index }
            }
            ExecutionError::InvalidTransferObject => Self::InvalidTransferObject,
            ExecutionError::EffectsTooLarge {
                current_size,
                max_size,
            } => Self::EffectsTooLarge {
                current_size,
                max_size,
            },
            ExecutionError::PublishUpgradeMissingDependency => {
                Self::PublishUpgradeMissingDependency
            }
            ExecutionError::PublishUpgradeDependencyDowngrade => {
                Self::PublishUpgradeDependencyDowngrade
            }
            ExecutionError::PackageUpgrade { kind } => {
                Self::PackageUpgradeError { kind: kind.into() }
            }
            ExecutionError::WrittenObjectsTooLarge {
                object_size,
                max_object_size,
            } => Self::WrittenObjectsTooLarge {
                object_size,
                max_object_size,
            },
            ExecutionError::CertificateDenied => Self::CertificateDenied,
            ExecutionError::IotaMoveVerificationTimeout => Self::IotaMoveVerificationTimeout,
            ExecutionError::SharedObjectOperationNotAllowed => {
                Self::SharedObjectOperationNotAllowed
            }
            ExecutionError::InputObjectDeleted => Self::InputObjectDeleted,
            ExecutionError::ExecutionCancelledDueToSharedObjectCongestion { congested_objects } => {
                Self::ExecutionCancelledDueToSharedObjectCongestion {
                    congested_objects: congested_objects.into_iter().map(|v| **v).collect(),
                }
            }
            ExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                congested_objects,
                suggested_gas_price,
            } => Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                congested_objects: congested_objects.into_iter().map(|v| **v).collect(),
                suggested_gas_price,
            },
            ExecutionError::AddressDeniedForCoin { address, coin_type } => {
                Self::AddressDeniedForCoin {
                    address: **address,
                    coin_type,
                }
            }
            ExecutionError::CoinTypeGlobalPause { coin_type } => {
                Self::CoinTypeGlobalPause { coin_type }
            }
            ExecutionError::ExecutionCancelledDueToRandomnessUnavailable => {
                Self::ExecutionCancelledDueToRandomnessUnavailable
            }
            ExecutionError::InvalidLinkage => Self::InvalidLinkage,
        }
    }
}

/// Location in move bytecode where an error occurred
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// move-location = object-id identifier u16 u16 (option identifier)
/// ```
#[derive(uniffi::Record)]
pub struct MoveLocation {
    /// The package id
    pub package: Arc<ObjectId>,
    /// The module name
    pub module: String,
    /// The function index
    pub function: u16,
    /// Index into the code stream for a jump. The offset is relative to the
    /// beginning of the instruction stream.
    pub instruction: u16,
    /// The name of the function if available
    #[uniffi(default = None)]
    pub function_name: Option<String>,
}

impl From<iota_sdk::types::MoveLocation> for MoveLocation {
    fn from(value: iota_sdk::types::MoveLocation) -> Self {
        Self {
            package: Arc::new(value.package.into()),
            module: value.module.to_string(),
            function: value.function,
            instruction: value.instruction,
            function_name: value.function_name.map(|v| v.to_string()),
        }
    }
}

impl From<MoveLocation> for iota_sdk::types::MoveLocation {
    fn from(value: MoveLocation) -> Self {
        Self {
            package: **value.package,
            module: Identifier::new(value.module).unwrap(),
            function: value.function,
            instruction: value.instruction,
            function_name: value.function_name.map(|v| Identifier::new(v).unwrap()),
        }
    }
}

/// An error with an argument to a command
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// command-argument-error =  type-mismatch
///                        =/ invalid-bcs-bytes
///                        =/ invalid-usage-of-pure-argument
///                        =/ invalid-argument-to-private-entry-function
///                        =/ index-out-of-bounds
///                        =/ secondary-index-out-of-bound
///                        =/ invalid-result-arity
///                        =/ invalid-gas-coin-usage
///                        =/ invalid-value-usage
///                        =/ invalid-object-by-value
///                        =/ invalid-object-by-mut-ref
///                        =/ shared-object-operation-not-allowed
///
/// type-mismatch                               = %x00
/// invalid-bcs-bytes                           = %x01
/// invalid-usage-of-pure-argument              = %x02
/// invalid-argument-to-private-entry-function  = %x03
/// index-out-of-bounds                         = %x04 u16
/// secondary-index-out-of-bound                = %x05 u16 u16
/// invalid-result-arity                        = %x06 u16
/// invalid-gas-coin-usage                      = %x07
/// invalid-value-usage                         = %x08
/// invalid-object-by-value                     = %x09
/// invalid-object-by-mut-ref                   = %x0a
/// shared-object-operation-not-allowed         = %x0b
/// ```
#[uniffi::remote(Enum)]
pub enum CommandArgumentError {
    /// The type of the value does not match the expected type
    TypeMismatch,
    /// The argument cannot be deserialized into a value of the specified type
    InvalidBcsBytes,
    /// The argument cannot be instantiated from raw bytes
    InvalidUsageOfPureArgument,
    /// Invalid argument to private entry function.
    /// Private entry functions cannot take arguments from other Move functions.
    InvalidArgumentToPrivateEntryFunction,
    /// Out of bounds access to input or results
    IndexOutOfBounds { index: u16 },
    /// Out of bounds access to subresult
    SecondaryIndexOutOfBounds { result: u16, subresult: u16 },
    /// Invalid usage of result.
    /// Expected a single result but found either no return value or multiple.
    InvalidResultArity { result: u16 },
    /// Invalid usage of Gas coin.
    /// The Gas coin can only be used by-value with a TransferObjects command.
    InvalidGasCoinUsage,
    /// Invalid usage of move value.
    //     Mutably borrowed values require unique usage.
    //     Immutably borrowed values cannot be taken or borrowed mutably.
    //     Taken values cannot be used again.
    InvalidValueUsage,
    /// Immutable objects cannot be passed by-value.
    InvalidObjectByValue,
    /// Immutable objects cannot be passed by mutable reference, &mut.
    InvalidObjectByMutRef,
    /// Shared object operations such a wrapping, freezing, or converting to
    /// owned are not allowed.
    SharedObjectOperationNotAllowed,
    /// Invalid argument arity. Expected a single argument but found a result
    /// that expanded to multiple arguments.
    InvalidArgumentArity,
}

/// An error with a upgrading a package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// package-upgrade-error = unable-to-fetch-package /
///                         not-a-package           /
///                         incompatible-upgrade    /
///                         digest-does-not-match   /
///                         unknown-upgrade-policy  /
///                         package-id-does-not-match
///
/// unable-to-fetch-package     = %x00 object-id
/// not-a-package               = %x01 object-id
/// incompatible-upgrade        = %x02
/// digest-does-not-match       = %x03 digest
/// unknown-upgrade-policy      = %x04 u8
/// package-id-does-not-match   = %x05 object-id object-id
/// ```
#[derive(uniffi::Enum)]
pub enum PackageUpgradeError {
    /// Unable to fetch package
    UnableToFetchPackage { package_id: Arc<ObjectId> },
    /// Object is not a package
    NotAPackage { object_id: Arc<ObjectId> },
    /// Package upgrade is incompatible with previous version
    IncompatibleUpgrade,
    /// Digest in upgrade ticket and computed digest differ
    DigestDoesNotMatch { digest: Arc<Digest> },
    /// Upgrade policy is not valid
    UnknownUpgradePolicy { policy: u8 },
    /// PackageId does not matach PackageId in upgrade ticket
    PackageIdDoesNotMatch {
        package_id: Arc<ObjectId>,
        ticket_id: Arc<ObjectId>,
    },
}

impl From<iota_sdk::types::PackageUpgradeError> for PackageUpgradeError {
    fn from(value: iota_sdk::types::PackageUpgradeError) -> Self {
        match value {
            iota_sdk::types::PackageUpgradeError::UnableToFetchPackage { package_id } => {
                Self::UnableToFetchPackage {
                    package_id: Arc::new(package_id.into()),
                }
            }
            iota_sdk::types::PackageUpgradeError::NotAPackage { object_id } => Self::NotAPackage {
                object_id: Arc::new(object_id.into()),
            },
            iota_sdk::types::PackageUpgradeError::IncompatibleUpgrade => Self::IncompatibleUpgrade,
            iota_sdk::types::PackageUpgradeError::DigestDoesNotMatch { digest } => {
                Self::DigestDoesNotMatch {
                    digest: Arc::new(digest.into()),
                }
            }
            iota_sdk::types::PackageUpgradeError::UnknownUpgradePolicy { policy } => {
                Self::UnknownUpgradePolicy { policy }
            }
            iota_sdk::types::PackageUpgradeError::PackageIdDoesNotMatch {
                package_id,
                ticket_id,
            } => Self::PackageIdDoesNotMatch {
                package_id: Arc::new(package_id.into()),
                ticket_id: Arc::new(ticket_id.into()),
            },
        }
    }
}

impl From<PackageUpgradeError> for iota_sdk::types::PackageUpgradeError {
    fn from(value: PackageUpgradeError) -> Self {
        match value {
            PackageUpgradeError::UnableToFetchPackage { package_id } => {
                Self::UnableToFetchPackage {
                    package_id: **package_id,
                }
            }
            PackageUpgradeError::NotAPackage { object_id } => Self::NotAPackage {
                object_id: **object_id,
            },
            PackageUpgradeError::IncompatibleUpgrade => Self::IncompatibleUpgrade,
            PackageUpgradeError::DigestDoesNotMatch { digest } => {
                Self::DigestDoesNotMatch { digest: **digest }
            }
            PackageUpgradeError::UnknownUpgradePolicy { policy } => {
                Self::UnknownUpgradePolicy { policy }
            }
            PackageUpgradeError::PackageIdDoesNotMatch {
                package_id,
                ticket_id,
            } => Self::PackageIdDoesNotMatch {
                package_id: **package_id,
                ticket_id: **ticket_id,
            },
        }
    }
}

/// An error with a type argument
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-argument-error = type-not-found / constraint-not-satisfied
/// type-not-found = %x00
/// constraint-not-satisfied = %x01
/// ```
#[uniffi::remote(Enum)]
#[repr(u8)]
pub enum TypeArgumentError {
    /// A type was not found in the module specified
    TypeNotFound,
    /// A type provided did not match the specified constraint
    ConstraintNotSatisfied,
}

crate::export_iota_types_bcs_conversion!(
    ExecutionStatus,
    ExecutionError,
    MoveLocation,
    CommandArgumentError,
    PackageUpgradeError,
    TypeArgumentError
);
