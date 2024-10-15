pub mod address;
pub mod checkpoint;
pub mod crypto;
pub mod digest;
pub mod effects;
pub mod events;
pub mod execution_status;
pub mod framework;
pub mod gas;
pub mod object;
pub mod object_id;
pub mod transaction;
pub mod type_tag;
pub mod u256;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub(crate) use transaction::SignedTransactionWithIntentMessage;
pub use transaction::{
    ActiveJwk, Argument, AuthenticatorStateExpire, AuthenticatorStateUpdate,
    AuthenticatorStateUpdateV1, CancelledTransaction, ChangeEpoch, Command,
    ConsensusCommitPrologue, ConsensusCommitPrologueV1, ConsensusCommitPrologueV2,
    ConsensusCommitPrologueV3, ConsensusDeterminedVersionAssignments, EndOfEpochTransactionKind,
    GasPayment, GenesisTransaction, InputArgument, MakeMoveVector, MergeCoins, MoveCall,
    ProgrammableTransaction, Publish, RandomnessStateUpdate, SignedTransaction, SplitCoins,
    SystemPackage, Transaction, TransactionExpiration, TransactionKind, TransferObjects,
    UnresolvedGasPayment, UnresolvedInputArgument, UnresolvedInputArgumentKind,
    UnresolvedObjectReference, UnresolvedProgrammableTransaction, UnresolvedTransaction,
    UnresolvedValue, Upgrade, VersionAssignment,
};
pub use type_tag::{Identifier, StructTag, TypeParseError, TypeTag};

#[cfg(test)]
mod serialization_proptests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonalMessage<'a>(pub std::borrow::Cow<'a, [u8]>);
