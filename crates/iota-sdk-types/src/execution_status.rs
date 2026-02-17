// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, Digest, Identifier, ObjectId};

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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
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
        #[cfg_attr(feature = "proptest", map(|x: Option<u16>| x.map(Into::into)))]
        command: Option<u64>,
    },
}

impl ExecutionStatus {
    crate::def_is!(Success, Failure);

    /// The error encountered during execution.
    pub fn error(&self) -> Option<&ExecutionError> {
        if let Self::Failure { error, .. } = self {
            Some(error)
        } else {
            None
        }
    }

    /// The command, if any, during which the error occurred.
    pub fn error_command(&self) -> Option<u64> {
        if let Self::Failure { command, .. } = self {
            *command
        } else {
            None
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "error", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum ExecutionError {
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
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        object_size: u64,
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        max_object_size: u64,
    },
    /// Package is larger than the maximum allowed size
    PackageTooBig {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        object_size: u64,
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        max_object_size: u64,
    },
    /// Circular Object Ownership
    CircularObjectOwnership { object: ObjectId },
    /// Insufficient coin balance for requested operation
    InsufficientCoinBalance,
    /// Coin balance overflowed an u64
    CoinBalanceOverflow,
    /// Publish Error, Non-zero Address.
    /// The modules in the package must have their self-addresses set to zero.
    PublishErrorNonZeroAddress,
    /// IOTA Move Bytecode Verification Error.
    IotaMoveVerificationError,
    /// Error from a non-abort instruction.
    /// Possible causes:
    ///     Arithmetic error, stack overflow, max value depth, etc."
    MovePrimitiveRuntimeError { location: Option<MoveLocation> },
    /// Move runtime abort
    MoveAbort {
        location: MoveLocation,
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        code: u64,
    },
    /// Bytecode verification error.
    VmVerificationOrDeserializationError,
    /// MoveVm invariant violation
    VmInvariantViolation,
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
    CommandArgumentError {
        argument: u16,
        kind: CommandArgumentError,
    },
    /// Type argument error
    TypeArgumentError {
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
    /// Effects from the transaction are too large
    EffectsTooLarge {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        current_size: u64,
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        max_size: u64,
    },
    /// Publish or Upgrade is missing dependency
    PublishUpgradeMissingDependency,
    /// Publish or Upgrade dependency downgrade.
    ///
    /// Indirect (transitive) dependency of published or upgraded package has
    /// been assigned an on-chain version that is less than the version
    /// required by one of the package's transitive dependencies.
    PublishUpgradeDependencyDowngrade,
    /// Invalid package upgrade
    #[cfg_attr(feature = "schemars", schemars(title = "PackageUpgradeError"))]
    PackageUpgradeError { kind: PackageUpgradeError },
    /// Indicates the transaction tried to write objects too large to storage
    WrittenObjectsTooLarge {
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        object_size: u64,
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
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
    ExecutionCancelledDueToSharedObjectCongestion { congested_objects: Vec<ObjectId> },
    /// Certificate is cancelled due to congestion on shared objects;
    /// suggested gas price can be used to give this certificate more priority.
    ExecutionCancelledDueToSharedObjectCongestionV2 {
        congested_objects: Vec<ObjectId>,
        suggested_gas_price: u64,
    },
    /// Address is denied for this coin type
    AddressDeniedForCoin { address: Address, coin_type: String },
    /// Coin type is globally paused for use
    CoinTypeGlobalPause { coin_type: String },
    /// Certificate is cancelled because randomness could not be generated this
    /// epoch
    ExecutionCancelledDueToRandomnessUnavailable,
    /// A valid linkage was unable to be determined for the transaction or one
    /// of its commands.
    InvalidLinkage,
}

impl ExecutionError {
    crate::def_is!(
        InsufficientGas,
        InvalidGasObject,
        InvariantViolation,
        FeatureNotYetSupported,
        ObjectTooBig,
        PackageTooBig,
        CircularObjectOwnership,
        InsufficientCoinBalance,
        CoinBalanceOverflow,
        PublishErrorNonZeroAddress,
        IotaMoveVerificationError,
        MovePrimitiveRuntimeError,
        MoveAbort,
        VmVerificationOrDeserializationError,
        VmInvariantViolation,
        FunctionNotFound,
        ArityMismatch,
        TypeArityMismatch,
        NonEntryFunctionInvoked,
        CommandArgumentError,
        TypeArgumentError,
        UnusedValueWithoutDrop,
        InvalidPublicFunctionReturnType,
        InvalidTransferObject,
        EffectsTooLarge,
        PublishUpgradeMissingDependency,
        PublishUpgradeDependencyDowngrade,
        PackageUpgradeError,
        WrittenObjectsTooLarge,
        CertificateDenied,
        IotaMoveVerificationTimeout,
        SharedObjectOperationNotAllowed,
        InputObjectDeleted,
        ExecutionCancelledDueToSharedObjectCongestion,
        ExecutionCancelledDueToSharedObjectCongestionV2,
        AddressDeniedForCoin,
        CoinTypeGlobalPause,
        ExecutionCancelledDueToRandomnessUnavailable,
        InvalidLinkage,
    );
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveLocation {
    /// The package id
    pub package: ObjectId,
    /// The module name
    pub module: Identifier,
    /// The function index
    pub function: u16,
    /// Index into the code stream for a jump. The offset is relative to the
    /// beginning of the instruction stream.
    pub instruction: u16,
    /// The name of the function if available
    pub function_name: Option<Identifier>,
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "kind", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
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

impl CommandArgumentError {
    crate::def_is!(
        TypeMismatch,
        InvalidBcsBytes,
        InvalidUsageOfPureArgument,
        InvalidArgumentToPrivateEntryFunction,
        IndexOutOfBounds,
        SecondaryIndexOutOfBounds,
        InvalidResultArity,
        InvalidGasCoinUsage,
        InvalidValueUsage,
        InvalidObjectByValue,
        InvalidObjectByMutRef,
        SharedObjectOperationNotAllowed,
    );
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
#[derive(Eq, PartialEq, Clone, Debug)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(tag = "kind", rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum PackageUpgradeError {
    /// Unable to fetch package
    UnableToFetchPackage { package_id: ObjectId },
    /// Object is not a package
    NotAPackage { object_id: ObjectId },
    /// Package upgrade is incompatible with previous version
    IncompatibleUpgrade,
    /// Digest in upgrade ticket and computed digest differ
    DigestDoesNotMatch { digest: Digest },
    /// Upgrade policy is not valid
    UnknownUpgradePolicy { policy: u8 },
    /// PackageId does not matach PackageId in upgrade ticket
    PackageIdDoesNotMatch {
        package_id: ObjectId,
        ticket_id: ObjectId,
    },
}

impl PackageUpgradeError {
    crate::def_is!(
        UnableToFetchPackage,
        NotAPackage,
        IncompatibleUpgrade,
        DigestDoesNotMatch,
        UnknownUpgradePolicy,
        PackageIdDoesNotMatch,
    );
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
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[cfg_attr(
    feature = "schemars",
    derive(schemars::JsonSchema),
    schemars(rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum TypeArgumentError {
    /// A type was not found in the module specified
    TypeNotFound,
    /// A type provided did not match the specified constraint
    ConstraintNotSatisfied,
}

impl TypeArgumentError {
    crate::def_is!(TypeNotFound, ConstraintNotSatisfied);
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename = "ExecutionStatus")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct ReadableExecutionStatus {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<FailureStatus>,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for ExecutionStatus {
        fn schema_name() -> String {
            ReadableExecutionStatus::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            ReadableExecutionStatus::json_schema(generator)
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct FailureStatus {
        error: ExecutionError,
        #[serde(skip_serializing_if = "Option::is_none")]
        command: Option<u16>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryExecutionStatus {
        Success,
        Failure {
            error: ExecutionError,
            command: Option<u64>,
        },
    }

    impl Serialize for ExecutionStatus {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    ExecutionStatus::Success => ReadableExecutionStatus {
                        success: true,
                        status: None,
                    },
                    ExecutionStatus::Failure { error, command } => ReadableExecutionStatus {
                        success: false,
                        status: Some(FailureStatus {
                            error,
                            command: command.map(|c| c as u16),
                        }),
                    },
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    ExecutionStatus::Success => BinaryExecutionStatus::Success,
                    ExecutionStatus::Failure { error, command } => {
                        BinaryExecutionStatus::Failure { error, command }
                    }
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ExecutionStatus {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableExecutionStatus { success, status } =
                    Deserialize::deserialize(deserializer)?;
                match (success, status) {
                    (true, None) => Ok(ExecutionStatus::Success),
                    (false, Some(FailureStatus { error, command })) => {
                        Ok(ExecutionStatus::Failure {
                            error,
                            command: command.map(Into::into),
                        })
                    }
                    // invalid cases
                    (true, Some(_)) | (false, None) => {
                        Err(serde::de::Error::custom("invalid execution status"))
                    }
                }
            } else {
                BinaryExecutionStatus::deserialize(deserializer).map(|readable| match readable {
                    BinaryExecutionStatus::Success => Self::Success,
                    BinaryExecutionStatus::Failure { error, command } => {
                        Self::Failure { error, command }
                    }
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "error", rename_all = "snake_case")]
    enum ReadableExecutionError {
        InsufficientGas,
        InvalidGasObject,
        InvariantViolation,
        FeatureNotYetSupported,
        ObjectTooBig {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            object_size: u64,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            max_object_size: u64,
        },
        PackageTooBig {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            object_size: u64,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            max_object_size: u64,
        },
        CircularObjectOwnership {
            object: ObjectId,
        },
        InsufficientCoinBalance,
        CoinBalanceOverflow,
        PublishErrorNonZeroAddress,
        IotaMoveVerificationError,
        MovePrimitiveRuntimeError {
            location: Option<MoveLocation>,
        },
        MoveAbort {
            location: MoveLocation,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            code: u64,
        },
        VmVerificationOrDeserializationError,
        VmInvariantViolation,
        FunctionNotFound,
        ArityMismatch,
        TypeArityMismatch,
        NonEntryFunctionInvoked,
        CommandArgumentError {
            argument: u16,
            kind: CommandArgumentError,
        },
        TypeArgumentError {
            type_argument: u16,
            kind: TypeArgumentError,
        },
        UnusedValueWithoutDrop {
            result: u16,
            subresult: u16,
        },
        InvalidPublicFunctionReturnType {
            index: u16,
        },
        InvalidTransferObject,
        EffectsTooLarge {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            current_size: u64,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            max_size: u64,
        },
        PublishUpgradeMissingDependency,
        PublishUpgradeDependencyDowngrade,
        PackageUpgradeError {
            kind: PackageUpgradeError,
        },
        WrittenObjectsTooLarge {
            #[serde(with = "crate::_serde::ReadableDisplay")]
            object_size: u64,
            #[serde(with = "crate::_serde::ReadableDisplay")]
            max_object_size: u64,
        },
        CertificateDenied,
        IotaMoveVerificationTimeout,
        SharedObjectOperationNotAllowed,
        InputObjectDeleted,
        ExecutionCancelledDueToSharedObjectCongestion {
            congested_objects: Vec<ObjectId>,
        },
        AddressDeniedForCoin {
            address: Address,
            coin_type: String,
        },
        CoinTypeGlobalPause {
            coin_type: String,
        },
        ExecutionCancelledDueToRandomnessUnavailable,
        ExecutionCancelledDueToSharedObjectCongestionV2 {
            congested_objects: Vec<ObjectId>,
            suggested_gas_price: u64,
        },
        InvalidLinkage,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryExecutionError {
        InsufficientGas,
        InvalidGasObject,
        InvariantViolation,
        FeatureNotYetSupported,
        ObjectTooBig {
            object_size: u64,
            max_object_size: u64,
        },
        PackageTooBig {
            object_size: u64,
            max_object_size: u64,
        },
        CircularObjectOwnership {
            object: ObjectId,
        },
        InsufficientCoinBalance,
        CoinBalanceOverflow,
        PublishErrorNonZeroAddress,
        IotaMoveVerificationError,
        MovePrimitiveRuntimeError {
            location: Option<MoveLocation>,
        },
        MoveAbort {
            location: MoveLocation,
            code: u64,
        },
        VmVerificationOrDeserializationError,
        VmInvariantViolation,
        FunctionNotFound,
        ArityMismatch,
        TypeArityMismatch,
        NonEntryFunctionInvoked,
        CommandArgumentError {
            argument: u16,
            kind: CommandArgumentError,
        },
        TypeArgumentError {
            type_argument: u16,
            kind: TypeArgumentError,
        },
        UnusedValueWithoutDrop {
            result: u16,
            subresult: u16,
        },
        InvalidPublicFunctionReturnType {
            index: u16,
        },
        InvalidTransferObject,
        EffectsTooLarge {
            current_size: u64,
            max_size: u64,
        },
        PublishUpgradeMissingDependency,
        PublishUpgradeDependencyDowngrade,
        PackageUpgradeError {
            kind: PackageUpgradeError,
        },
        WrittenObjectsTooLarge {
            object_size: u64,
            max_object_size: u64,
        },
        CertificateDenied,
        IotaMoveVerificationTimeout,
        SharedObjectOperationNotAllowed,
        InputObjectDeleted,
        ExecutionCancelledDueToSharedObjectCongestion {
            congested_objects: Vec<ObjectId>,
        },
        AddressDeniedForCoin {
            address: Address,
            coin_type: String,
        },
        CoinTypeGlobalPause {
            coin_type: String,
        },
        ExecutionCancelledDueToRandomnessUnavailable,
        ExecutionCancelledDueToSharedObjectCongestionV2 {
            congested_objects: Vec<ObjectId>,
            suggested_gas_price: u64,
        },
        InvalidLinkage,
    }

    impl Serialize for ExecutionError {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    Self::InsufficientGas => ReadableExecutionError::InsufficientGas,
                    Self::InvalidGasObject => ReadableExecutionError::InvalidGasObject,
                    Self::InvariantViolation => ReadableExecutionError::InvariantViolation,
                    Self::FeatureNotYetSupported => ReadableExecutionError::FeatureNotYetSupported,
                    Self::ObjectTooBig {
                        object_size,
                        max_object_size,
                    } => ReadableExecutionError::ObjectTooBig {
                        object_size,
                        max_object_size,
                    },
                    Self::PackageTooBig {
                        object_size,
                        max_object_size,
                    } => ReadableExecutionError::PackageTooBig {
                        object_size,
                        max_object_size,
                    },
                    Self::CircularObjectOwnership { object } => {
                        ReadableExecutionError::CircularObjectOwnership { object }
                    }
                    Self::InsufficientCoinBalance => {
                        ReadableExecutionError::InsufficientCoinBalance
                    }
                    Self::CoinBalanceOverflow => ReadableExecutionError::CoinBalanceOverflow,
                    Self::PublishErrorNonZeroAddress => {
                        ReadableExecutionError::PublishErrorNonZeroAddress
                    }
                    Self::IotaMoveVerificationError => {
                        ReadableExecutionError::IotaMoveVerificationError
                    }
                    Self::MovePrimitiveRuntimeError { location } => {
                        ReadableExecutionError::MovePrimitiveRuntimeError { location }
                    }
                    Self::MoveAbort { location, code } => {
                        ReadableExecutionError::MoveAbort { location, code }
                    }
                    Self::VmVerificationOrDeserializationError => {
                        ReadableExecutionError::VmVerificationOrDeserializationError
                    }
                    Self::VmInvariantViolation => ReadableExecutionError::VmInvariantViolation,
                    Self::FunctionNotFound => ReadableExecutionError::FunctionNotFound,
                    Self::ArityMismatch => ReadableExecutionError::ArityMismatch,
                    Self::TypeArityMismatch => ReadableExecutionError::TypeArityMismatch,
                    Self::NonEntryFunctionInvoked => {
                        ReadableExecutionError::NonEntryFunctionInvoked
                    }
                    Self::CommandArgumentError { argument, kind } => {
                        ReadableExecutionError::CommandArgumentError { argument, kind }
                    }
                    Self::TypeArgumentError {
                        type_argument,
                        kind,
                    } => ReadableExecutionError::TypeArgumentError {
                        type_argument,
                        kind,
                    },
                    Self::UnusedValueWithoutDrop { result, subresult } => {
                        ReadableExecutionError::UnusedValueWithoutDrop { result, subresult }
                    }
                    Self::InvalidPublicFunctionReturnType { index } => {
                        ReadableExecutionError::InvalidPublicFunctionReturnType { index }
                    }
                    Self::InvalidTransferObject => ReadableExecutionError::InvalidTransferObject,
                    Self::EffectsTooLarge {
                        current_size,
                        max_size,
                    } => ReadableExecutionError::EffectsTooLarge {
                        current_size,
                        max_size,
                    },
                    Self::PublishUpgradeMissingDependency => {
                        ReadableExecutionError::PublishUpgradeMissingDependency
                    }
                    Self::PublishUpgradeDependencyDowngrade => {
                        ReadableExecutionError::PublishUpgradeDependencyDowngrade
                    }
                    Self::PackageUpgradeError { kind } => {
                        ReadableExecutionError::PackageUpgradeError { kind }
                    }
                    Self::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    } => ReadableExecutionError::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    },
                    Self::CertificateDenied => ReadableExecutionError::CertificateDenied,
                    Self::IotaMoveVerificationTimeout => {
                        ReadableExecutionError::IotaMoveVerificationTimeout
                    }
                    Self::SharedObjectOperationNotAllowed => {
                        ReadableExecutionError::SharedObjectOperationNotAllowed
                    }
                    Self::InputObjectDeleted => ReadableExecutionError::InputObjectDeleted,
                    Self::ExecutionCancelledDueToSharedObjectCongestion { congested_objects } => {
                        ReadableExecutionError::ExecutionCancelledDueToSharedObjectCongestion {
                            congested_objects,
                        }
                    }
                    Self::AddressDeniedForCoin { address, coin_type } => {
                        ReadableExecutionError::AddressDeniedForCoin { address, coin_type }
                    }
                    Self::CoinTypeGlobalPause { coin_type } => {
                        ReadableExecutionError::CoinTypeGlobalPause { coin_type }
                    }
                    Self::ExecutionCancelledDueToRandomnessUnavailable => {
                        ReadableExecutionError::ExecutionCancelledDueToRandomnessUnavailable
                    }
                    Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    } => ReadableExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    },
                    Self::InvalidLinkage => ReadableExecutionError::InvalidLinkage,
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    Self::InsufficientGas => BinaryExecutionError::InsufficientGas,
                    Self::InvalidGasObject => BinaryExecutionError::InvalidGasObject,
                    Self::InvariantViolation => BinaryExecutionError::InvariantViolation,
                    Self::FeatureNotYetSupported => BinaryExecutionError::FeatureNotYetSupported,
                    Self::ObjectTooBig {
                        object_size,
                        max_object_size,
                    } => BinaryExecutionError::ObjectTooBig {
                        object_size,
                        max_object_size,
                    },
                    Self::PackageTooBig {
                        object_size,
                        max_object_size,
                    } => BinaryExecutionError::PackageTooBig {
                        object_size,
                        max_object_size,
                    },
                    Self::CircularObjectOwnership { object } => {
                        BinaryExecutionError::CircularObjectOwnership { object }
                    }
                    Self::InsufficientCoinBalance => BinaryExecutionError::InsufficientCoinBalance,
                    Self::CoinBalanceOverflow => BinaryExecutionError::CoinBalanceOverflow,
                    Self::PublishErrorNonZeroAddress => {
                        BinaryExecutionError::PublishErrorNonZeroAddress
                    }
                    Self::IotaMoveVerificationError => {
                        BinaryExecutionError::IotaMoveVerificationError
                    }
                    Self::MovePrimitiveRuntimeError { location } => {
                        BinaryExecutionError::MovePrimitiveRuntimeError { location }
                    }
                    Self::MoveAbort { location, code } => {
                        BinaryExecutionError::MoveAbort { location, code }
                    }
                    Self::VmVerificationOrDeserializationError => {
                        BinaryExecutionError::VmVerificationOrDeserializationError
                    }
                    Self::VmInvariantViolation => BinaryExecutionError::VmInvariantViolation,
                    Self::FunctionNotFound => BinaryExecutionError::FunctionNotFound,
                    Self::ArityMismatch => BinaryExecutionError::ArityMismatch,
                    Self::TypeArityMismatch => BinaryExecutionError::TypeArityMismatch,
                    Self::NonEntryFunctionInvoked => BinaryExecutionError::NonEntryFunctionInvoked,
                    Self::CommandArgumentError { argument, kind } => {
                        BinaryExecutionError::CommandArgumentError { argument, kind }
                    }
                    Self::TypeArgumentError {
                        type_argument,
                        kind,
                    } => BinaryExecutionError::TypeArgumentError {
                        type_argument,
                        kind,
                    },
                    Self::UnusedValueWithoutDrop { result, subresult } => {
                        BinaryExecutionError::UnusedValueWithoutDrop { result, subresult }
                    }
                    Self::InvalidPublicFunctionReturnType { index } => {
                        BinaryExecutionError::InvalidPublicFunctionReturnType { index }
                    }
                    Self::InvalidTransferObject => BinaryExecutionError::InvalidTransferObject,
                    Self::EffectsTooLarge {
                        current_size,
                        max_size,
                    } => BinaryExecutionError::EffectsTooLarge {
                        current_size,
                        max_size,
                    },
                    Self::PublishUpgradeMissingDependency => {
                        BinaryExecutionError::PublishUpgradeMissingDependency
                    }
                    Self::PublishUpgradeDependencyDowngrade => {
                        BinaryExecutionError::PublishUpgradeDependencyDowngrade
                    }
                    Self::PackageUpgradeError { kind } => {
                        BinaryExecutionError::PackageUpgradeError { kind }
                    }
                    Self::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    } => BinaryExecutionError::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    },
                    Self::CertificateDenied => BinaryExecutionError::CertificateDenied,
                    Self::IotaMoveVerificationTimeout => {
                        BinaryExecutionError::IotaMoveVerificationTimeout
                    }
                    Self::SharedObjectOperationNotAllowed => {
                        BinaryExecutionError::SharedObjectOperationNotAllowed
                    }
                    Self::InputObjectDeleted => BinaryExecutionError::InputObjectDeleted,
                    Self::ExecutionCancelledDueToSharedObjectCongestion { congested_objects } => {
                        BinaryExecutionError::ExecutionCancelledDueToSharedObjectCongestion {
                            congested_objects,
                        }
                    }
                    Self::AddressDeniedForCoin { address, coin_type } => {
                        BinaryExecutionError::AddressDeniedForCoin { address, coin_type }
                    }
                    Self::CoinTypeGlobalPause { coin_type } => {
                        BinaryExecutionError::CoinTypeGlobalPause { coin_type }
                    }
                    Self::ExecutionCancelledDueToRandomnessUnavailable => {
                        BinaryExecutionError::ExecutionCancelledDueToRandomnessUnavailable
                    }
                    Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    } => BinaryExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    },
                    Self::InvalidLinkage => BinaryExecutionError::InvalidLinkage,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ExecutionError {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableExecutionError::deserialize(deserializer).map(|readable| match readable {
                    ReadableExecutionError::InsufficientGas => Self::InsufficientGas,
                    ReadableExecutionError::InvalidGasObject => Self::InvalidGasObject,
                    ReadableExecutionError::InvariantViolation => Self::InvariantViolation,
                    ReadableExecutionError::FeatureNotYetSupported => Self::FeatureNotYetSupported,
                    ReadableExecutionError::ObjectTooBig {
                        object_size,
                        max_object_size,
                    } => Self::ObjectTooBig {
                        object_size,
                        max_object_size,
                    },
                    ReadableExecutionError::PackageTooBig {
                        object_size,
                        max_object_size,
                    } => Self::PackageTooBig {
                        object_size,
                        max_object_size,
                    },
                    ReadableExecutionError::CircularObjectOwnership { object } => {
                        Self::CircularObjectOwnership { object }
                    }
                    ReadableExecutionError::InsufficientCoinBalance => {
                        Self::InsufficientCoinBalance
                    }
                    ReadableExecutionError::CoinBalanceOverflow => Self::CoinBalanceOverflow,
                    ReadableExecutionError::PublishErrorNonZeroAddress => {
                        Self::PublishErrorNonZeroAddress
                    }
                    ReadableExecutionError::IotaMoveVerificationError => {
                        Self::IotaMoveVerificationError
                    }
                    ReadableExecutionError::MovePrimitiveRuntimeError { location } => {
                        Self::MovePrimitiveRuntimeError { location }
                    }
                    ReadableExecutionError::MoveAbort { location, code } => {
                        Self::MoveAbort { location, code }
                    }
                    ReadableExecutionError::VmVerificationOrDeserializationError => {
                        Self::VmVerificationOrDeserializationError
                    }
                    ReadableExecutionError::VmInvariantViolation => Self::VmInvariantViolation,
                    ReadableExecutionError::FunctionNotFound => Self::FunctionNotFound,
                    ReadableExecutionError::ArityMismatch => Self::ArityMismatch,
                    ReadableExecutionError::TypeArityMismatch => Self::TypeArityMismatch,
                    ReadableExecutionError::NonEntryFunctionInvoked => {
                        Self::NonEntryFunctionInvoked
                    }
                    ReadableExecutionError::CommandArgumentError { argument, kind } => {
                        Self::CommandArgumentError { argument, kind }
                    }
                    ReadableExecutionError::TypeArgumentError {
                        type_argument,
                        kind,
                    } => Self::TypeArgumentError {
                        type_argument,
                        kind,
                    },
                    ReadableExecutionError::UnusedValueWithoutDrop { result, subresult } => {
                        Self::UnusedValueWithoutDrop { result, subresult }
                    }
                    ReadableExecutionError::InvalidPublicFunctionReturnType { index } => {
                        Self::InvalidPublicFunctionReturnType { index }
                    }
                    ReadableExecutionError::InvalidTransferObject => Self::InvalidTransferObject,
                    ReadableExecutionError::EffectsTooLarge {
                        current_size,
                        max_size,
                    } => Self::EffectsTooLarge {
                        current_size,
                        max_size,
                    },
                    ReadableExecutionError::PublishUpgradeMissingDependency => {
                        Self::PublishUpgradeMissingDependency
                    }
                    ReadableExecutionError::PublishUpgradeDependencyDowngrade => {
                        Self::PublishUpgradeDependencyDowngrade
                    }
                    ReadableExecutionError::PackageUpgradeError { kind } => {
                        Self::PackageUpgradeError { kind }
                    }
                    ReadableExecutionError::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    } => Self::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    },
                    ReadableExecutionError::CertificateDenied => Self::CertificateDenied,
                    ReadableExecutionError::IotaMoveVerificationTimeout => {
                        Self::IotaMoveVerificationTimeout
                    }
                    ReadableExecutionError::SharedObjectOperationNotAllowed => {
                        Self::SharedObjectOperationNotAllowed
                    }
                    ReadableExecutionError::InputObjectDeleted => Self::InputObjectDeleted,
                    ReadableExecutionError::ExecutionCancelledDueToSharedObjectCongestion {
                        congested_objects,
                    } => Self::ExecutionCancelledDueToSharedObjectCongestion { congested_objects },
                    ReadableExecutionError::AddressDeniedForCoin { address, coin_type } => {
                        Self::AddressDeniedForCoin { address, coin_type }
                    }
                    ReadableExecutionError::CoinTypeGlobalPause { coin_type } => {
                        Self::CoinTypeGlobalPause { coin_type }
                    }
                    ReadableExecutionError::ExecutionCancelledDueToRandomnessUnavailable => {
                        Self::ExecutionCancelledDueToRandomnessUnavailable
                    }
                    ReadableExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    } => Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    },
                    ReadableExecutionError::InvalidLinkage => Self::InvalidLinkage,
                })
            } else {
                BinaryExecutionError::deserialize(deserializer).map(|binary| match binary {
                    BinaryExecutionError::InsufficientGas => Self::InsufficientGas,
                    BinaryExecutionError::InvalidGasObject => Self::InvalidGasObject,
                    BinaryExecutionError::InvariantViolation => Self::InvariantViolation,
                    BinaryExecutionError::FeatureNotYetSupported => Self::FeatureNotYetSupported,
                    BinaryExecutionError::ObjectTooBig {
                        object_size,
                        max_object_size,
                    } => Self::ObjectTooBig {
                        object_size,
                        max_object_size,
                    },
                    BinaryExecutionError::PackageTooBig {
                        object_size,
                        max_object_size,
                    } => Self::PackageTooBig {
                        object_size,
                        max_object_size,
                    },
                    BinaryExecutionError::CircularObjectOwnership { object } => {
                        Self::CircularObjectOwnership { object }
                    }
                    BinaryExecutionError::InsufficientCoinBalance => Self::InsufficientCoinBalance,
                    BinaryExecutionError::CoinBalanceOverflow => Self::CoinBalanceOverflow,
                    BinaryExecutionError::PublishErrorNonZeroAddress => {
                        Self::PublishErrorNonZeroAddress
                    }
                    BinaryExecutionError::IotaMoveVerificationError => {
                        Self::IotaMoveVerificationError
                    }
                    BinaryExecutionError::MovePrimitiveRuntimeError { location } => {
                        Self::MovePrimitiveRuntimeError { location }
                    }
                    BinaryExecutionError::MoveAbort { location, code } => {
                        Self::MoveAbort { location, code }
                    }
                    BinaryExecutionError::VmVerificationOrDeserializationError => {
                        Self::VmVerificationOrDeserializationError
                    }
                    BinaryExecutionError::VmInvariantViolation => Self::VmInvariantViolation,
                    BinaryExecutionError::FunctionNotFound => Self::FunctionNotFound,
                    BinaryExecutionError::ArityMismatch => Self::ArityMismatch,
                    BinaryExecutionError::TypeArityMismatch => Self::TypeArityMismatch,
                    BinaryExecutionError::NonEntryFunctionInvoked => Self::NonEntryFunctionInvoked,
                    BinaryExecutionError::CommandArgumentError { argument, kind } => {
                        Self::CommandArgumentError { argument, kind }
                    }
                    BinaryExecutionError::TypeArgumentError {
                        type_argument,
                        kind,
                    } => Self::TypeArgumentError {
                        type_argument,
                        kind,
                    },
                    BinaryExecutionError::UnusedValueWithoutDrop { result, subresult } => {
                        Self::UnusedValueWithoutDrop { result, subresult }
                    }
                    BinaryExecutionError::InvalidPublicFunctionReturnType { index } => {
                        Self::InvalidPublicFunctionReturnType { index }
                    }
                    BinaryExecutionError::InvalidTransferObject => Self::InvalidTransferObject,
                    BinaryExecutionError::EffectsTooLarge {
                        current_size,
                        max_size,
                    } => Self::EffectsTooLarge {
                        current_size,
                        max_size,
                    },
                    BinaryExecutionError::PublishUpgradeMissingDependency => {
                        Self::PublishUpgradeMissingDependency
                    }
                    BinaryExecutionError::PublishUpgradeDependencyDowngrade => {
                        Self::PublishUpgradeDependencyDowngrade
                    }
                    BinaryExecutionError::PackageUpgradeError { kind } => {
                        Self::PackageUpgradeError { kind }
                    }
                    BinaryExecutionError::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    } => Self::WrittenObjectsTooLarge {
                        object_size,
                        max_object_size,
                    },
                    BinaryExecutionError::CertificateDenied => Self::CertificateDenied,
                    BinaryExecutionError::IotaMoveVerificationTimeout => {
                        Self::IotaMoveVerificationTimeout
                    }
                    BinaryExecutionError::SharedObjectOperationNotAllowed => {
                        Self::SharedObjectOperationNotAllowed
                    }
                    BinaryExecutionError::InputObjectDeleted => Self::InputObjectDeleted,
                    BinaryExecutionError::ExecutionCancelledDueToSharedObjectCongestion {
                        congested_objects,
                    } => Self::ExecutionCancelledDueToSharedObjectCongestion { congested_objects },
                    BinaryExecutionError::AddressDeniedForCoin { address, coin_type } => {
                        Self::AddressDeniedForCoin { address, coin_type }
                    }
                    BinaryExecutionError::CoinTypeGlobalPause { coin_type } => {
                        Self::CoinTypeGlobalPause { coin_type }
                    }
                    BinaryExecutionError::ExecutionCancelledDueToRandomnessUnavailable => {
                        Self::ExecutionCancelledDueToRandomnessUnavailable
                    }
                    BinaryExecutionError::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    } => Self::ExecutionCancelledDueToSharedObjectCongestionV2 {
                        congested_objects,
                        suggested_gas_price,
                    },
                    BinaryExecutionError::InvalidLinkage => Self::InvalidLinkage,
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadableCommandArgumentError {
        TypeMismatch,
        InvalidBcsBytes,
        InvalidUsageOfPureArgument,
        InvalidArgumentToPrivateEntryFunction,
        IndexOutOfBounds { index: u16 },
        SecondaryIndexOutOfBounds { result: u16, subresult: u16 },
        InvalidResultArity { result: u16 },
        InvalidGasCoinUsage,
        InvalidValueUsage,
        InvalidObjectByValue,
        InvalidObjectByMutRef,
        SharedObjectOperationNotAllowed,
        InvalidArgumentArity,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryCommandArgumentError {
        TypeMismatch,
        InvalidBcsBytes,
        InvalidUsageOfPureArgument,
        InvalidArgumentToPrivateEntryFunction,
        IndexOutOfBounds { index: u16 },
        SecondaryIndexOutOfBounds { result: u16, subresult: u16 },
        InvalidResultArity { result: u16 },
        InvalidGasCoinUsage,
        InvalidValueUsage,
        InvalidObjectByValue,
        InvalidObjectByMutRef,
        SharedObjectOperationNotAllowed,
        InvalidArgumentArity,
    }

    impl Serialize for CommandArgumentError {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    Self::TypeMismatch => ReadableCommandArgumentError::TypeMismatch,
                    Self::InvalidBcsBytes => ReadableCommandArgumentError::InvalidBcsBytes,
                    Self::InvalidUsageOfPureArgument => {
                        ReadableCommandArgumentError::InvalidUsageOfPureArgument
                    }
                    Self::InvalidArgumentToPrivateEntryFunction => {
                        ReadableCommandArgumentError::InvalidArgumentToPrivateEntryFunction
                    }
                    Self::IndexOutOfBounds { index } => {
                        ReadableCommandArgumentError::IndexOutOfBounds { index }
                    }
                    Self::SecondaryIndexOutOfBounds { result, subresult } => {
                        ReadableCommandArgumentError::SecondaryIndexOutOfBounds {
                            result,
                            subresult,
                        }
                    }
                    Self::InvalidResultArity { result } => {
                        ReadableCommandArgumentError::InvalidResultArity { result }
                    }
                    Self::InvalidGasCoinUsage => ReadableCommandArgumentError::InvalidGasCoinUsage,
                    Self::InvalidValueUsage => ReadableCommandArgumentError::InvalidValueUsage,
                    Self::InvalidObjectByValue => {
                        ReadableCommandArgumentError::InvalidObjectByValue
                    }
                    Self::InvalidObjectByMutRef => {
                        ReadableCommandArgumentError::InvalidObjectByMutRef
                    }
                    Self::SharedObjectOperationNotAllowed => {
                        ReadableCommandArgumentError::SharedObjectOperationNotAllowed
                    }
                    Self::InvalidArgumentArity => {
                        ReadableCommandArgumentError::InvalidArgumentArity
                    }
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    Self::TypeMismatch => BinaryCommandArgumentError::TypeMismatch,
                    Self::InvalidBcsBytes => BinaryCommandArgumentError::InvalidBcsBytes,
                    Self::InvalidUsageOfPureArgument => {
                        BinaryCommandArgumentError::InvalidUsageOfPureArgument
                    }
                    Self::InvalidArgumentToPrivateEntryFunction => {
                        BinaryCommandArgumentError::InvalidArgumentToPrivateEntryFunction
                    }
                    Self::IndexOutOfBounds { index } => {
                        BinaryCommandArgumentError::IndexOutOfBounds { index }
                    }
                    Self::SecondaryIndexOutOfBounds { result, subresult } => {
                        BinaryCommandArgumentError::SecondaryIndexOutOfBounds { result, subresult }
                    }
                    Self::InvalidResultArity { result } => {
                        BinaryCommandArgumentError::InvalidResultArity { result }
                    }
                    Self::InvalidGasCoinUsage => BinaryCommandArgumentError::InvalidGasCoinUsage,
                    Self::InvalidValueUsage => BinaryCommandArgumentError::InvalidValueUsage,
                    Self::InvalidObjectByValue => BinaryCommandArgumentError::InvalidObjectByValue,
                    Self::InvalidObjectByMutRef => {
                        BinaryCommandArgumentError::InvalidObjectByMutRef
                    }
                    Self::SharedObjectOperationNotAllowed => {
                        BinaryCommandArgumentError::SharedObjectOperationNotAllowed
                    }
                    Self::InvalidArgumentArity => BinaryCommandArgumentError::InvalidArgumentArity,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for CommandArgumentError {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadableCommandArgumentError::deserialize(deserializer).map(|readable| {
                    match readable {
                        ReadableCommandArgumentError::TypeMismatch => Self::TypeMismatch,
                        ReadableCommandArgumentError::InvalidBcsBytes => Self::InvalidBcsBytes,
                        ReadableCommandArgumentError::InvalidUsageOfPureArgument => {
                            Self::InvalidUsageOfPureArgument
                        }
                        ReadableCommandArgumentError::InvalidArgumentToPrivateEntryFunction => {
                            Self::InvalidArgumentToPrivateEntryFunction
                        }
                        ReadableCommandArgumentError::IndexOutOfBounds { index } => {
                            Self::IndexOutOfBounds { index }
                        }
                        ReadableCommandArgumentError::SecondaryIndexOutOfBounds {
                            result,
                            subresult,
                        } => Self::SecondaryIndexOutOfBounds { result, subresult },
                        ReadableCommandArgumentError::InvalidResultArity { result } => {
                            Self::InvalidResultArity { result }
                        }
                        ReadableCommandArgumentError::InvalidGasCoinUsage => {
                            Self::InvalidGasCoinUsage
                        }
                        ReadableCommandArgumentError::InvalidValueUsage => Self::InvalidValueUsage,
                        ReadableCommandArgumentError::InvalidObjectByValue => {
                            Self::InvalidObjectByValue
                        }
                        ReadableCommandArgumentError::InvalidObjectByMutRef => {
                            Self::InvalidObjectByMutRef
                        }
                        ReadableCommandArgumentError::SharedObjectOperationNotAllowed => {
                            Self::SharedObjectOperationNotAllowed
                        }
                        ReadableCommandArgumentError::InvalidArgumentArity => {
                            Self::InvalidArgumentArity
                        }
                    }
                })
            } else {
                BinaryCommandArgumentError::deserialize(deserializer).map(|binary| match binary {
                    BinaryCommandArgumentError::TypeMismatch => Self::TypeMismatch,
                    BinaryCommandArgumentError::InvalidBcsBytes => Self::InvalidBcsBytes,
                    BinaryCommandArgumentError::InvalidUsageOfPureArgument => {
                        Self::InvalidUsageOfPureArgument
                    }
                    BinaryCommandArgumentError::InvalidArgumentToPrivateEntryFunction => {
                        Self::InvalidArgumentToPrivateEntryFunction
                    }
                    BinaryCommandArgumentError::IndexOutOfBounds { index } => {
                        Self::IndexOutOfBounds { index }
                    }
                    BinaryCommandArgumentError::SecondaryIndexOutOfBounds { result, subresult } => {
                        Self::SecondaryIndexOutOfBounds { result, subresult }
                    }
                    BinaryCommandArgumentError::InvalidResultArity { result } => {
                        Self::InvalidResultArity { result }
                    }
                    BinaryCommandArgumentError::InvalidGasCoinUsage => Self::InvalidGasCoinUsage,
                    BinaryCommandArgumentError::InvalidValueUsage => Self::InvalidValueUsage,
                    BinaryCommandArgumentError::InvalidObjectByValue => Self::InvalidObjectByValue,
                    BinaryCommandArgumentError::InvalidObjectByMutRef => {
                        Self::InvalidObjectByMutRef
                    }
                    BinaryCommandArgumentError::SharedObjectOperationNotAllowed => {
                        Self::SharedObjectOperationNotAllowed
                    }
                    BinaryCommandArgumentError::InvalidArgumentArity => Self::InvalidArgumentArity,
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum ReadablePackageUpgradeError {
        UnableToFetchPackage {
            package_id: ObjectId,
        },
        NotAPackage {
            object_id: ObjectId,
        },
        IncompatibleUpgrade,
        DigestDoesNotMatch {
            digest: Digest,
        },
        UnknownUpgradePolicy {
            policy: u8,
        },
        PackageIdDoesNotMatch {
            package_id: ObjectId,
            ticket_id: ObjectId,
        },
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryPackageUpgradeError {
        UnableToFetchPackage {
            package_id: ObjectId,
        },
        NotAPackage {
            object_id: ObjectId,
        },
        IncompatibleUpgrade,
        DigestDoesNotMatch {
            digest: Digest,
        },
        UnknownUpgradePolicy {
            policy: u8,
        },
        PackageIdDoesNotMatch {
            package_id: ObjectId,
            ticket_id: ObjectId,
        },
    }

    impl Serialize for PackageUpgradeError {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = match self.clone() {
                    Self::UnableToFetchPackage { package_id } => {
                        ReadablePackageUpgradeError::UnableToFetchPackage { package_id }
                    }
                    Self::NotAPackage { object_id } => {
                        ReadablePackageUpgradeError::NotAPackage { object_id }
                    }
                    Self::IncompatibleUpgrade => ReadablePackageUpgradeError::IncompatibleUpgrade,
                    Self::DigestDoesNotMatch { digest } => {
                        ReadablePackageUpgradeError::DigestDoesNotMatch { digest }
                    }
                    Self::UnknownUpgradePolicy { policy } => {
                        ReadablePackageUpgradeError::UnknownUpgradePolicy { policy }
                    }
                    Self::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    } => ReadablePackageUpgradeError::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    },
                };
                readable.serialize(serializer)
            } else {
                let binary = match self.clone() {
                    Self::UnableToFetchPackage { package_id } => {
                        BinaryPackageUpgradeError::UnableToFetchPackage { package_id }
                    }
                    Self::NotAPackage { object_id } => {
                        BinaryPackageUpgradeError::NotAPackage { object_id }
                    }
                    Self::IncompatibleUpgrade => BinaryPackageUpgradeError::IncompatibleUpgrade,
                    Self::DigestDoesNotMatch { digest } => {
                        BinaryPackageUpgradeError::DigestDoesNotMatch { digest }
                    }
                    Self::UnknownUpgradePolicy { policy } => {
                        BinaryPackageUpgradeError::UnknownUpgradePolicy { policy }
                    }
                    Self::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    } => BinaryPackageUpgradeError::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    },
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for PackageUpgradeError {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                ReadablePackageUpgradeError::deserialize(deserializer).map(
                    |readable| match readable {
                        ReadablePackageUpgradeError::UnableToFetchPackage { package_id } => {
                            Self::UnableToFetchPackage { package_id }
                        }
                        ReadablePackageUpgradeError::NotAPackage { object_id } => {
                            Self::NotAPackage { object_id }
                        }
                        ReadablePackageUpgradeError::IncompatibleUpgrade => {
                            Self::IncompatibleUpgrade
                        }
                        ReadablePackageUpgradeError::DigestDoesNotMatch { digest } => {
                            Self::DigestDoesNotMatch { digest }
                        }
                        ReadablePackageUpgradeError::UnknownUpgradePolicy { policy } => {
                            Self::UnknownUpgradePolicy { policy }
                        }
                        ReadablePackageUpgradeError::PackageIdDoesNotMatch {
                            package_id,
                            ticket_id,
                        } => Self::PackageIdDoesNotMatch {
                            package_id,
                            ticket_id,
                        },
                    },
                )
            } else {
                BinaryPackageUpgradeError::deserialize(deserializer).map(|binary| match binary {
                    BinaryPackageUpgradeError::UnableToFetchPackage { package_id } => {
                        Self::UnableToFetchPackage { package_id }
                    }
                    BinaryPackageUpgradeError::NotAPackage { object_id } => {
                        Self::NotAPackage { object_id }
                    }
                    BinaryPackageUpgradeError::IncompatibleUpgrade => Self::IncompatibleUpgrade,
                    BinaryPackageUpgradeError::DigestDoesNotMatch { digest } => {
                        Self::DigestDoesNotMatch { digest }
                    }
                    BinaryPackageUpgradeError::UnknownUpgradePolicy { policy } => {
                        Self::UnknownUpgradePolicy { policy }
                    }
                    BinaryPackageUpgradeError::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    } => Self::PackageIdDoesNotMatch {
                        package_id,
                        ticket_id,
                    },
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    // --- ExecutionStatus ---

    #[test]
    fn execution_status_success() {
        let status = ExecutionStatus::Success;
        assert!(status.is_success());
        assert!(!status.is_failure());
        assert!(status.error().is_none());
        assert!(status.error_command().is_none());
    }

    #[test]
    fn execution_status_failure_with_command() {
        let status = ExecutionStatus::Failure {
            error: ExecutionError::InsufficientGas,
            command: Some(3),
        };
        assert!(!status.is_success());
        assert!(status.is_failure());
        assert_eq!(status.error(), Some(&ExecutionError::InsufficientGas));
        assert_eq!(status.error_command(), Some(3));
    }

    #[test]
    fn execution_status_failure_without_command() {
        let status = ExecutionStatus::Failure {
            error: ExecutionError::InvalidGasObject,
            command: None,
        };
        assert!(status.is_failure());
        assert!(status.error().is_some());
        assert!(status.error_command().is_none());
    }

    // --- ExecutionError is_* methods ---

    #[test]
    fn execution_error_is_methods() {
        assert!(ExecutionError::InsufficientGas.is_insufficient_gas());
        assert!(!ExecutionError::InsufficientGas.is_invalid_gas_object());

        assert!(ExecutionError::InvalidGasObject.is_invalid_gas_object());
        assert!(ExecutionError::InvariantViolation.is_invariant_violation());
        assert!(ExecutionError::FeatureNotYetSupported.is_feature_not_yet_supported());
        assert!(ExecutionError::InsufficientCoinBalance.is_insufficient_coin_balance());
        assert!(ExecutionError::CoinBalanceOverflow.is_coin_balance_overflow());
        assert!(ExecutionError::PublishErrorNonZeroAddress.is_publish_error_non_zero_address());
        assert!(ExecutionError::IotaMoveVerificationError.is_iota_move_verification_error());
        assert!(
            ExecutionError::VmVerificationOrDeserializationError
                .is_vm_verification_or_deserialization_error()
        );
        assert!(ExecutionError::VmInvariantViolation.is_vm_invariant_violation());
        assert!(ExecutionError::FunctionNotFound.is_function_not_found());
        assert!(ExecutionError::ArityMismatch.is_arity_mismatch());
        assert!(ExecutionError::TypeArityMismatch.is_type_arity_mismatch());
        assert!(ExecutionError::NonEntryFunctionInvoked.is_non_entry_function_invoked());
        assert!(ExecutionError::InvalidTransferObject.is_invalid_transfer_object());
        assert!(ExecutionError::CertificateDenied.is_certificate_denied());
        assert!(
            ExecutionError::SharedObjectOperationNotAllowed
                .is_shared_object_operation_not_allowed()
        );
        assert!(ExecutionError::InputObjectDeleted.is_input_object_deleted());
        assert!(
            ExecutionError::ExecutionCancelledDueToRandomnessUnavailable
                .is_execution_cancelled_due_to_randomness_unavailable()
        );
    }

    #[test]
    fn execution_error_with_data_variants() {
        let err = ExecutionError::ObjectTooBig {
            object_size: 100,
            max_object_size: 50,
        };
        assert!(err.is_object_too_big());
        assert!(!err.is_package_too_big());

        let err = ExecutionError::MoveAbort {
            location: MoveLocation {
                package: ObjectId::ZERO,
                module: "test".parse().unwrap(),
                function: 1,
                instruction: 2,
                function_name: None,
            },
            code: 42,
        };
        assert!(err.is_move_abort());
    }

    // --- CommandArgumentError is_* methods ---

    #[test]
    fn command_argument_error_is_methods() {
        assert!(CommandArgumentError::TypeMismatch.is_type_mismatch());
        assert!(!CommandArgumentError::TypeMismatch.is_invalid_bcs_bytes());
        assert!(CommandArgumentError::InvalidBcsBytes.is_invalid_bcs_bytes());
        assert!(
            CommandArgumentError::InvalidUsageOfPureArgument.is_invalid_usage_of_pure_argument()
        );
        assert!(CommandArgumentError::InvalidGasCoinUsage.is_invalid_gas_coin_usage());
        assert!(CommandArgumentError::InvalidValueUsage.is_invalid_value_usage());
        assert!(CommandArgumentError::InvalidObjectByValue.is_invalid_object_by_value());
        assert!(CommandArgumentError::InvalidObjectByMutRef.is_invalid_object_by_mut_ref());
        assert!(
            CommandArgumentError::SharedObjectOperationNotAllowed
                .is_shared_object_operation_not_allowed()
        );
    }

    // --- TypeArgumentError ---

    #[test]
    fn type_argument_error_is_methods() {
        assert!(TypeArgumentError::TypeNotFound.is_type_not_found());
        assert!(!TypeArgumentError::TypeNotFound.is_constraint_not_satisfied());
        assert!(TypeArgumentError::ConstraintNotSatisfied.is_constraint_not_satisfied());
    }

    // --- PackageUpgradeError ---

    #[test]
    fn package_upgrade_error_is_methods() {
        assert!(PackageUpgradeError::IncompatibleUpgrade.is_incompatible_upgrade());
        assert!(!PackageUpgradeError::IncompatibleUpgrade.is_not_a_package());
        let err = PackageUpgradeError::UnknownUpgradePolicy { policy: 99 };
        assert!(err.is_unknown_upgrade_policy());
    }
}

#[cfg(test)]
#[cfg(test)]
mod serialization_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_execution_status_success_roundtrip() {
        let status = ExecutionStatus::Success;

        // JSON (Human Readable)
        let json = serde_json::to_value(&status).unwrap();
        // Verify the custom serialization format
        assert_eq!(json, json!({ "success": true }));
        
        // Roundtrip back
        let decoded: ExecutionStatus = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, status);

        // BCS (Binary)
        let bcs = bcs::to_bytes(&status).unwrap();
        // BinaryExecutionStatus::Success is variant 0
        assert_eq!(bcs, vec![0]); 
        let decoded: ExecutionStatus = bcs::from_bytes(&bcs).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn test_execution_status_failure_roundtrip() {
        let error = ExecutionError::InsufficientGas;
        let status = ExecutionStatus::Failure {
            error: error.clone(),
            command: Some(1),
        };

        // JSON (Human Readable)
        let json = serde_json::to_value(&status).unwrap();
        // Readable uses "status": { "error": ..., "command": ... } and "success": false
        assert_eq!(json["success"], false);
        assert_eq!(json["status"]["error"]["error"], "insufficient_gas");
        assert_eq!(json["status"]["command"], 1);

        let decoded: ExecutionStatus = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, status);

        // BCS (Binary)
        let bcs = bcs::to_bytes(&status).unwrap();
        // BinaryExecutionStatus::Failure is variant 1
        // Followed by ExecutionError::InsufficientGas (variant 0)
        // Followed by Option<u64> (1 = 0x01, value 1u64 = 0x0100000000000000)
        let expected_bcs = vec![
            1, // Failure variant
            0, // InsufficientGas variant
            1, // Option::Some
            1, 0, 0, 0, 0, 0, 0, 0 // 1u64
        ];
        assert_eq!(bcs, expected_bcs);
        
        let decoded: ExecutionStatus = bcs::from_bytes(&bcs).unwrap();
        assert_eq!(decoded, status);
    }

    #[test]
    fn test_execution_status_failure_no_command() {
        let error = ExecutionError::InvalidGasObject;
        let status = ExecutionStatus::Failure {
            error: error.clone(),
            command: None,
        };

        // JSON
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["status"]["error"]["error"], "invalid_gas_object");
        assert!(json["status"].get("command").is_none());

        let decoded: ExecutionStatus = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, status);

        // Accessors
        assert_eq!(status.error(), Some(&error));
        assert_eq!(status.error_command(), None);
    }

    #[test]
    fn test_execution_error_complex_variants() {
        // Test AddressDeniedForCoin
        let addr = Address::new([7u8; 32]);
        let coin_type = "0x2::sui::SUI".to_string();
        let error = ExecutionError::AddressDeniedForCoin { 
            address: addr, 
            coin_type: coin_type.clone() 
        };

        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["error"], "address_denied_for_coin");
        assert_eq!(json["address"], addr.to_string());
        assert_eq!(json["coin_type"], coin_type);

        let decoded: ExecutionError = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, error);

        // Test ObjectTooBig with ReadableDisplay (u64 as string)
        let error = ExecutionError::ObjectTooBig {
            object_size: 100,
            max_object_size: 50,
        };
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["error"], "object_too_big");
        assert_eq!(json["object_size"], "100");
        assert_eq!(json["max_object_size"], "50");

        let decoded: ExecutionError = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, error);
    }

    #[test]
    fn test_move_location_serialization() {
        let pkg_id = ObjectId::new([2u8; 32]);
        let module = Identifier::new("coin").unwrap();
        let func_name = Identifier::new("transfer").unwrap();
        
        let location = MoveLocation {
            package: pkg_id,
            module: module.clone(),
            function: 1,
            instruction: 42,
            function_name: Some(func_name.clone()),
        };

        let json = serde_json::to_value(&location).unwrap();
        assert_eq!(json["package"], pkg_id.to_string());
        assert_eq!(json["module"], "coin");
        assert_eq!(json["function"], 1);
        assert_eq!(json["instruction"], 42);
        assert_eq!(json["functionName"], "transfer");

        let decoded: MoveLocation = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, location);
    }

    #[test]
    fn test_command_argument_error() {
        let arg_error = CommandArgumentError::IndexOutOfBounds { index: 5 };
        let iter_error = ExecutionError::CommandArgumentError { 
            argument: 2, 
            kind: arg_error.clone() 
        };

        let json = serde_json::to_value(&iter_error).unwrap();
        assert_eq!(json["error"], "command_argument_error");
        assert_eq!(json["argument"], 2);
        assert_eq!(json["kind"]["kind"], "index_out_of_bounds");
        assert_eq!(json["kind"]["index"], 5);

        let decoded: ExecutionError = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, iter_error);
    }

    #[test]
    fn test_package_upgrade_error() {
        let digest = Digest::new([9u8; 32]);
        let upgrade_error = PackageUpgradeError::DigestDoesNotMatch { digest };
        let iter_error = ExecutionError::PackageUpgradeError { 
            kind: upgrade_error.clone() 
        };

        let json = serde_json::to_value(&iter_error).unwrap();
        assert_eq!(json["error"], "package_upgrade_error");
        assert_eq!(json["kind"]["kind"], "digest_does_not_match");
        assert_eq!(json["kind"]["digest"], digest.to_string());

        let decoded: ExecutionError = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, iter_error);
    }
}
