// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

use super::{Address, Digest, Identifier, ObjectId};

/// The status of an executed Transaction
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// execution-status = success / failure
/// success = %d00
/// failure = %d01 execution-error (option u64)
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    pub fn new_failure(error: ExecutionError, command: Option<u64>) -> Self {
        Self::Failure { error, command }
    }

    pub fn unwrap(&self) {
        match self {
            Self::Success => {}
            Self::Failure { .. } => {
                panic!("Unable to unwrap() on {self:?}");
            }
        }
    }

    pub fn unwrap_err(self) -> (ExecutionError, Option<u64>) {
        match self {
            Self::Success => {
                panic!("Unable to unwrap_err() on {self:?}");
            }
            Self::Failure { error, command } => (error, command),
        }
    }

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

fn display_move_location_opt(location: &Option<MoveLocation>) -> impl core::fmt::Display + '_ {
    struct W<'a>(&'a Option<MoveLocation>);
    impl core::fmt::Display for W<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match &self.0 {
                None => write!(f, "UNKNOWN"),
                Some(l) => write!(f, "{l}"),
            }
        }
    }
    W(location)
}

fn display_congested_objects(objects: &[ObjectId]) -> impl core::fmt::Display + '_ {
    struct W<'a>(&'a [ObjectId]);
    impl core::fmt::Display for W<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let mut iter = self.0.iter();
            if let Some(first) = iter.next() {
                write!(f, "{first}")?;
                for obj in iter {
                    write!(f, ", {obj}")?;
                }
            }
            Ok(())
        }
    }
    W(objects)
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
///                 =/ execution-cancelled-due-to-shared-object-congestion-v2
///                 =/ invalid-linkage
///
/// insufficient-gas                                       = %d00
/// invalid-gas-object                                     = %d01
/// invariant-violation                                    = %d02
/// feature-not-yet-supported                              = %d03
/// object-too-big                                         = %d04 u64 u64
/// package-too-big                                        = %d05 u64 u64
/// circular-object-ownership                              = %d06 object-id
/// insufficient-coin-balance                              = %d07
/// coin-balance-overflow                                  = %d08
/// publish-error-non-zero-address                         = %d09
/// iota-move-verification-error                           = %d10
/// move-primitive-runtime-error                           = %d11 (option move-location)
/// move-abort                                             = %d12 move-location u64
/// vm-verification-or-deserialization-error               = %d13
/// vm-invariant-violation                                 = %d14
/// function-not-found                                     = %d15
/// arity-mismatch                                         = %d16
/// type-arity-mismatch                                    = %d17
/// non-entry-function-invoked                             = %d18
/// command-argument-error                                 = %d19 u16 command-argument-error
/// type-argument-error                                    = %d20 u16 type-argument-error
/// unused-value-without-drop                              = %d21 u16 u16
/// invalid-public-function-return-type                    = %d22 u16
/// invalid-transfer-object                                = %d23
/// effects-too-large                                      = %d24 u64 u64
/// publish-upgrade-missing-dependency                     = %d25
/// publish-upgrade-dependency-downgrade                   = %d26
/// package-upgrade-error                                  = %d27 package-upgrade-error
/// written-objects-too-large                              = %d28 u64 u64
/// certificate-denied                                     = %d29
/// iota-move-verification-timeout                         = %d30
/// shared-object-operation-not-allowed                    = %d31
/// input-object-deleted                                   = %d32
/// execution-cancelled-due-to-shared-object-congestion    = %d33 (vector object-id)
/// address-denied-for-coin                                = %d34 address string
/// coin-type-global-pause                                 = %d35 string
/// execution-cancelled-due-to-randomness-unavailable      = %d36
/// execution-cancelled-due-to-shared-object-congestion-v2 = %d37 (vector object-id) u64
/// invalid-linkage                                        = %d38
/// ```
// WARNING: The variant order of this enum is protocol-significant. Each variant's position
// determines its BCS discriminant (the integer sent over the wire).
// Reordering or inserting variants will break protocol compatibility.
// New variants MUST be added at the end.
// The `execution_error_bcs_discriminants` snapshot test enforces this.
#[derive(Clone, Debug, Eq, Error, PartialEq, strum::AsRefStr)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum ExecutionError {
    /// Insufficient Gas
    #[error("Insufficient Gas")]
    InsufficientGas,
    /// Invalid Gas Object.
    #[error("Invalid Gas Object. Possibly not address-owned or possibly not an IOTA coin")]
    InvalidGasObject,
    /// Invariant Violation
    #[error("INVARIANT VIOLATION")]
    InvariantViolation,
    /// Attempted to use feature that is not supported yet
    #[error("Attempted to use feature that is not supported yet")]
    FeatureNotYetSupported,
    /// Move object is larger than the maximum allowed size
    #[error(
        "Move object with size {object_size} is larger than the maximum object size {max_object_size}"
    )]
    ObjectTooBig {
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        object_size: u64,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_object_size: u64,
    },
    /// Package is larger than the maximum allowed size
    #[error(
        "Move package with size {object_size} is larger than the maximum object size {max_object_size}"
    )]
    PackageTooBig {
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        object_size: u64,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_object_size: u64,
    },
    /// Circular Object Ownership
    #[error("Circular Object Ownership, including object {object}")]
    CircularObjectOwnership { object: ObjectId },
    /// Insufficient coin balance for requested operation
    #[error("Insufficient coin balance for operation")]
    InsufficientCoinBalance,
    /// Coin balance overflowed an u64
    #[error("The coin balance overflows u64")]
    CoinBalanceOverflow,
    /// Publish Error, Non-zero Address.
    /// The modules in the package must have their self-addresses set to zero.
    #[error(
        "Publish Error, Non-zero Address. The modules in the package must have their self-addresses set to zero."
    )]
    PublishErrorNonZeroAddress,
    /// IOTA Move Bytecode Verification Error.
    #[error(
        "IOTA Move Bytecode Verification Error. Please run the IOTA Move Verifier for more information."
    )]
    IotaMoveVerificationError,
    /// Error from a non-abort instruction.
    /// Possible causes:
    ///     Arithmetic error, stack overflow, max value depth, etc."
    #[error(
        "Move Primitive Runtime Error. Location: {}. Arithmetic error, stack overflow, max value depth, etc.",
        display_move_location_opt(.location)
    )]
    MovePrimitiveRuntimeError { location: Option<MoveLocation> },
    /// Move runtime abort
    #[error("Move Runtime Abort. Location: {location}, Abort Code: {code}")]
    MoveAbort {
        location: MoveLocation,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        code: u64,
    },
    /// Bytecode verification error.
    #[error(
        "Move Bytecode Verification Error. Please run the Bytecode Verifier for more information."
    )]
    VmVerificationOrDeserializationError,
    /// MoveVm invariant violation
    #[error("MOVE VM INVARIANT VIOLATION")]
    VmInvariantViolation,
    /// Function not found
    #[error("Function Not Found")]
    FunctionNotFound,
    /// Arity mismatch for Move function.
    /// The number of arguments does not match the number of parameters
    #[error(
        "Arity mismatch for Move function. The number of arguments does not match the number of parameters"
    )]
    ArityMismatch,
    /// Type arity mismatch for Move function.
    /// Mismatch between the number of actual versus expected type arguments.
    #[error(
        "Type arity mismatch for Move function. Mismatch between the number of actual versus expected type arguments."
    )]
    TypeArityMismatch,
    /// Non Entry Function Invoked. Move Call must start with an entry function.
    #[error("Non Entry Function Invoked. Move Call must start with an entry function")]
    NonEntryFunctionInvoked,
    /// Invalid command argument
    #[error("Invalid command argument at {argument}. {kind}")]
    CommandArgumentError {
        argument: u16,
        kind: CommandArgumentError,
    },
    /// Type argument error
    #[error("Error for type argument at index {type_argument}: {kind}")]
    TypeArgumentError {
        /// Index of the problematic type argument
        type_argument: u16,
        kind: TypeArgumentError,
    },
    /// Unused result without the drop ability.
    #[error(
        "Unused result without the drop ability. Command result {result}, return value {subresult}"
    )]
    UnusedValueWithoutDrop { result: u16, subresult: u16 },
    /// Invalid public Move function signature.
    /// Unsupported return type for return value
    #[error(
        "Invalid public Move function signature. Unsupported return type for return value {index}"
    )]
    InvalidPublicFunctionReturnType { index: u16 },
    /// Invalid Transfer Object, object does not have public transfer.
    #[error("Invalid Transfer Object, object does not have public transfer")]
    InvalidTransferObject,
    /// Effects from the transaction are too large
    #[error("Effects of size {current_size} bytes too large. Limit is {max_size} bytes")]
    EffectsTooLarge {
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        current_size: u64,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_size: u64,
    },
    /// Publish or Upgrade is missing dependency
    #[error(
        "Publish/Upgrade Error, Missing dependency. A dependency of a published or upgraded package has not been assigned an on-chain address."
    )]
    PublishUpgradeMissingDependency,
    /// Publish or Upgrade dependency downgrade.
    ///
    /// Indirect (transitive) dependency of published or upgraded package has
    /// been assigned an on-chain version that is less than the version
    /// required by one of the package's transitive dependencies.
    #[error(
        "Publish/Upgrade Error, Dependency downgrade. Indirect (transitive) dependency of published or upgraded package has been assigned an on-chain version that is less than the version required by one of the package's transitive dependencies."
    )]
    PublishUpgradeDependencyDowngrade,
    /// Invalid package upgrade
    #[error("Invalid package upgrade. {kind}")]
    PackageUpgradeError { kind: PackageUpgradeError },
    /// Indicates the transaction tried to write objects too large to storage
    #[error("Written objects of {object_size} bytes too large. Limit is {max_object_size} bytes")]
    WrittenObjectsTooLarge {
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        object_size: u64,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_object_size: u64,
    },
    /// Certificate is on the deny list
    #[error("Certificate is on the deny list")]
    CertificateDenied,
    /// IOTA Move Bytecode verification timed out.
    #[error(
        "IOTA Move Bytecode Verification Timeout. Please run the IOTA Move Verifier for more information."
    )]
    IotaMoveVerificationTimeout,
    /// The requested shared object operation is not allowed
    #[error("The shared object operation is not allowed")]
    SharedObjectOperationNotAllowed,
    /// Requested shared object has been deleted
    #[error("Certificate cannot be executed due to a dependency on a deleted shared object")]
    InputObjectDeleted,
    /// Certificate is cancelled due to congestion on shared objects
    #[error("Certificate is cancelled due to congestion on shared objects: {}.", display_congested_objects(.congested_objects))]
    ExecutionCancelledDueToSharedObjectCongestion { congested_objects: Vec<ObjectId> },
    /// Address is denied for this coin type
    #[error("Address {address:?} is denied for coin {coin_type}")]
    AddressDeniedForCoin { address: Address, coin_type: String },
    /// Coin type is globally paused for use
    #[error("Coin type is globally paused for use: {coin_type}")]
    CoinTypeGlobalPause { coin_type: String },
    /// Certificate is cancelled because randomness could not be generated this
    /// epoch
    #[error("Certificate is cancelled because randomness could not be generated this epoch")]
    ExecutionCancelledDueToRandomnessUnavailable,
    /// Certificate is cancelled due to congestion on shared objects;
    /// suggested gas price can be used to give this certificate more priority.
    #[error(
        "Certificate is cancelled due to congestion on shared objects: {}. To give this certificate more priority to be executed, its gas price can be increased to at least {suggested_gas_price}.",
        display_congested_objects(.congested_objects)
    )]
    ExecutionCancelledDueToSharedObjectCongestionV2 {
        congested_objects: Vec<ObjectId>,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        suggested_gas_price: u64,
    },
    /// A valid linkage was unable to be determined for the transaction or one
    /// of its commands.
    #[error("A valid linkage was unable to be determined for the transaction")]
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
        AddressDeniedForCoin,
        CoinTypeGlobalPause,
        ExecutionCancelledDueToRandomnessUnavailable,
        ExecutionCancelledDueToSharedObjectCongestionV2,
        InvalidLinkage,
    );

    pub fn command_argument_error(kind: CommandArgumentError, argument: u16) -> Self {
        Self::CommandArgumentError { argument, kind }
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

impl core::fmt::Display for MoveLocation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            package,
            module,
            function,
            instruction,
            function_name,
        } = self;
        if let Some(fname) = function_name {
            write!(
                f,
                "{package}::{module}::{fname} (function index {function}) at offset {instruction}"
            )
        } else {
            write!(
                f,
                "{package}::{module} in function definition {function} at offset {instruction}"
            )
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
/// type-mismatch                               = %d00
/// invalid-bcs-bytes                           = %d01
/// invalid-usage-of-pure-argument              = %d02
/// invalid-argument-to-private-entry-function  = %d03
/// index-out-of-bounds                         = %d04 u16
/// secondary-index-out-of-bound                = %d05 u16 u16
/// invalid-result-arity                        = %d06 u16
/// invalid-gas-coin-usage                      = %d07
/// invalid-value-usage                         = %d08
/// invalid-object-by-value                     = %d09
/// invalid-object-by-mut-ref                   = %d10
/// shared-object-operation-not-allowed         = %d11
/// ```
#[derive(Clone, Debug, Eq, Error, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum CommandArgumentError {
    /// The type of the value does not match the expected type
    #[error("The type of the value does not match the expected type")]
    TypeMismatch,
    /// The argument cannot be deserialized into a value of the specified type
    #[error("The argument cannot be deserialized into a value of the specified type")]
    InvalidBcsBytes,
    /// The argument cannot be instantiated from raw bytes
    #[error("The argument cannot be instantiated from raw bytes")]
    InvalidUsageOfPureArgument,
    /// Invalid argument to private entry function.
    /// Private entry functions cannot take arguments from other Move functions.
    #[error(
        "Invalid argument to private entry function. \
        These functions cannot take arguments from other Move functions"
    )]
    InvalidArgumentToPrivateEntryFunction,
    /// Out of bounds access to input or results
    #[error("Out of bounds access to input or result vector {index}")]
    IndexOutOfBounds { index: u16 },
    /// Out of bounds access to subresult
    #[error(
        "Out of bounds secondary access to result vector \
        {result} at secondary index {subresult}"
    )]
    SecondaryIndexOutOfBounds { result: u16, subresult: u16 },
    /// Invalid usage of result.
    /// Expected a single result but found either no return value or multiple.
    #[error(
        "Invalid usage of result {result}, \
        expected a single result but found either no return values or multiple."
    )]
    InvalidResultArity { result: u16 },
    /// Invalid usage of Gas coin.
    /// The Gas coin can only be used by-value with a TransferObjects command.
    #[error(
        "Invalid taking of the Gas coin. \
        It can only be used by-value with TransferObjects"
    )]
    InvalidGasCoinUsage,
    /// Invalid usage of move value.
    //     Mutably borrowed values require unique usage.
    //     Immutably borrowed values cannot be taken or borrowed mutably.
    //     Taken values cannot be used again.
    #[error(
        "Invalid usage of value. \
        Mutably borrowed values require unique usage. \
        Immutably borrowed values cannot be taken or borrowed mutably. \
        Taken values cannot be used again."
    )]
    InvalidValueUsage,
    /// Immutable objects cannot be passed by-value.
    #[error("Immutable objects cannot be passed by-value")]
    InvalidObjectByValue,
    /// Immutable objects cannot be passed by mutable reference, &mut.
    #[error("Immutable objects cannot be passed by mutable reference, &mut")]
    InvalidObjectByMutRef,
    /// Shared object operations such a wrapping, freezing, or converting to
    /// owned are not allowed.
    #[error(
        "Shared object operations such a wrapping, freezing, or converting to owned are not \
        allowed."
    )]
    SharedObjectOperationNotAllowed,
    /// Invalid argument arity. Expected a single argument but found a result
    /// that expanded to multiple arguments.
    #[error(
        "Invalid argument arity. Expected a single argument but found a result that expanded to \
        multiple arguments."
    )]
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
/// unable-to-fetch-package     = %d00 object-id
/// not-a-package               = %d01 object-id
/// incompatible-upgrade        = %d02
/// digest-does-not-match       = %d03 digest
/// unknown-upgrade-policy      = %d04 u8
/// package-id-does-not-match   = %d05 object-id object-id
/// ```
#[derive(Clone, Debug, Eq, Error, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum PackageUpgradeError {
    /// Unable to fetch package
    #[error("Unable to fetch package at {package_id}")]
    UnableToFetchPackage { package_id: ObjectId },
    /// Object is not a package
    #[error("Object {object_id} is not a package")]
    NotAPackage { object_id: ObjectId },
    /// Package upgrade is incompatible with previous version
    #[error("New package is incompatible with previous version")]
    IncompatibleUpgrade,
    /// Digest in upgrade ticket and computed digest differ
    #[error("Digest in upgrade ticket and computed digest disagree")]
    DigestDoesNotMatch { digest: Digest },
    /// Upgrade policy is not valid
    #[error("Upgrade policy {policy} is not a valid upgrade policy")]
    UnknownUpgradePolicy { policy: u8 },
    /// PackageId does not match PackageId in upgrade ticket
    #[error("Package ID {package_id} does not match package ID in upgrade ticket {ticket_id}")]
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
/// type-not-found = %d00
/// constraint-not-satisfied = %d01
/// ```
#[derive(Clone, Copy, Debug, Eq, Error, Hash, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "snake_case")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum TypeArgumentError {
    /// A type was not found in the module specified
    #[error("A type was not found in the module specified")]
    TypeNotFound,
    /// A type provided did not match the specified constraint
    #[error("A type provided did not match the specified constraints")]
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

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "ExecutionStatus")]
    struct ReadableExecutionStatus {
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<FailureStatus>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct FailureStatus {
        error: ExecutionError,
        #[serde(skip_serializing_if = "Option::is_none")]
        command: Option<u16>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "ExecutionStatus")]
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
}
