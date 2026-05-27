// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Structural cross-check: each Rust mirror's `MoveShape` derive output is
//! compared against the canonical Move definition parsed from a vendored
//! `packages_compiled` blob.
//!
//! Extend by vendoring more blobs into `src/packages_compiled/`, deriving
//! `MoveShape` on more mirrors, and registering more entries in
//! [`expected_entries`].

use move_binary_format::{
    CompiledModule,
    normalized::{self, RcIdentifier, RcPool, Type},
};

use crate::{
    framework, iota_system,
    move_shape::{Field, MoveShape, Shape},
    stardust,
};

// ---------------------------------------------------------------------------
// Vendored blobs
// ---------------------------------------------------------------------------

const IOTA_FRAMEWORK: &[u8] = include_bytes!("packages_compiled/iota-framework");
const MOVE_STDLIB: &[u8] = include_bytes!("packages_compiled/move-stdlib");
const IOTA_SYSTEM: &[u8] = include_bytes!("packages_compiled/iota-system");
const STARDUST: &[u8] = include_bytes!("packages_compiled/stardust");

// ---------------------------------------------------------------------------
// Entries: Rust-mirror → Move-side coordinates
// ---------------------------------------------------------------------------

struct Entry {
    /// Which vendored package to look the Move struct up in. Needed because
    /// distinct packages can declare modules of the same short name
    /// (e.g. `0x1::bcs` vs `0x2::bcs`).
    package: Package,
    /// Short Move module name (e.g. `coin`).
    module: &'static str,
    /// Move struct name (e.g. `Coin`).
    struct_name: &'static str,
    /// Rust mirror's expected wire layout.
    rust_shape: Shape,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum Package {
    MoveStdlib,
    IotaFramework,
    IotaSystem,
    Stardust,
}

impl Package {
    fn blob(self) -> &'static [u8] {
        match self {
            Package::MoveStdlib => MOVE_STDLIB,
            Package::IotaFramework => IOTA_FRAMEWORK,
            Package::IotaSystem => IOTA_SYSTEM,
            Package::Stardust => STARDUST,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Package::MoveStdlib => "0x1",
            Package::IotaFramework => "0x2",
            Package::IotaSystem => "0x3",
            Package::Stardust => "0x107a",
        }
    }
}

/// One-line `Entry` constructor. Hides the `<Ty as MoveShape>::move_shape()`
/// boilerplate so the registry stays scannable.
macro_rules! entry {
    ($pkg:expr, $module:literal, $name:literal, $ty:ty) => {
        Entry {
            package: $pkg,
            module: $module,
            struct_name: $name,
            rust_shape: <$ty as MoveShape>::move_shape(),
        }
    };
}

fn expected_entries() -> Vec<Entry> {
    // For generic mirrors, the type argument is irrelevant — the derive
    // resolves `T` at macro-expansion time into `Shape::TypeParameter(0)`,
    // so the body of `move_shape()` never references the chosen type. `()`
    // keeps the instantiation noise-free.
    //
    // Note: some Rust mirrors have no production-bytecode counterpart and
    // therefore cannot be cross-checked here — e.g. `ecdsa_k1::KeyPair` is
    // `#[test_only]` on the Move side, so it doesn't appear in the compiled
    // package and is intentionally omitted from this registry.
    use Package::*;
    vec![
        // -- 0x2 iota-framework -----------------------------------------------
        entry!(IotaFramework, "object", "ID", framework::object::ID),
        entry!(IotaFramework, "object", "UID", framework::object::UID),
        entry!(
            IotaFramework,
            "balance",
            "Balance",
            framework::balance::Balance<()>
        ),
        entry!(
            IotaFramework,
            "balance",
            "Supply",
            framework::balance::Supply<()>
        ),
        entry!(IotaFramework, "bag", "Bag", framework::bag::Bag),
        entry!(IotaFramework, "coin", "Coin", framework::coin::Coin<()>),
        entry!(
            IotaFramework,
            "coin",
            "CoinMetadata",
            framework::coin::CoinMetadata<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "TreasuryCap",
            framework::coin::TreasuryCap<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "RegulatedCoinMetadata",
            framework::coin::RegulatedCoinMetadata<()>
        ),
        entry!(IotaFramework, "bcs", "BCS", framework::bcs::BCS),
        entry!(IotaFramework, "clock", "Clock", framework::clock::Clock),
        entry!(
            IotaFramework,
            "tx_context",
            "TxContext",
            framework::tx_context::TxContext
        ),
        entry!(IotaFramework, "intent", "Intent", framework::intent::Intent),
        entry!(IotaFramework, "url", "Url", framework::url::Url),
        entry!(
            IotaFramework,
            "versioned",
            "Versioned",
            framework::versioned::Versioned
        ),
        entry!(
            IotaFramework,
            "versioned",
            "VersionChangeCap",
            framework::versioned::VersionChangeCap
        ),
        entry!(
            IotaFramework,
            "transfer",
            "Receiving",
            framework::transfer::Receiving<()>
        ),
        entry!(
            IotaFramework,
            "borrow",
            "Referent",
            framework::borrow::Referent<()>
        ),
        entry!(IotaFramework, "borrow", "Borrow", framework::borrow::Borrow),
        entry!(IotaFramework, "iota", "IOTA", framework::iota::IOTA),
        entry!(
            IotaFramework,
            "iota",
            "IotaTreasuryCap",
            framework::iota::IotaTreasuryCap
        ),
        entry!(
            IotaFramework,
            "system_admin_cap",
            "IotaSystemAdminCap",
            framework::system_admin_cap::IotaSystemAdminCap
        ),
        entry!(
            IotaFramework,
            "account",
            "AuthenticatorFunctionRefV1Key",
            framework::account::AuthenticatorFunctionRefV1Key
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "PackageMetadataKey",
            framework::package_metadata::PackageMetadataKey
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "ConfigWriteCap",
            framework::deny_list::ConfigWriteCap
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "GlobalPauseKey",
            framework::deny_list::GlobalPauseKey
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "Scalar",
            framework::bls12381::Scalar
        ),
        entry!(IotaFramework, "bls12381", "G1", framework::bls12381::G1),
        entry!(IotaFramework, "bls12381", "G2", framework::bls12381::G2),
        entry!(IotaFramework, "bls12381", "GT", framework::bls12381::GT),
        entry!(
            IotaFramework,
            "bls12381",
            "UncompressedG1",
            framework::bls12381::UncompressedG1
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "RuleKey",
            framework::transfer_policy::RuleKey<()>
        ),
        entry!(
            IotaFramework,
            "kiosk_extension",
            "ExtensionKey",
            framework::kiosk_extension::ExtensionKey<()>
        ),
        entry!(IotaFramework, "table", "Table", framework::table::Table<(), ()>),
        entry!(
            IotaFramework,
            "table_vec",
            "TableVec",
            framework::table_vec::TableVec<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "DenyCapV1",
            framework::coin::DenyCapV1<()>
        ),
        entry!(IotaFramework, "vec_map", "Entry", framework::vec_map::Entry<(), ()>),
        entry!(IotaFramework, "vec_map", "VecMap", framework::vec_map::VecMap<(), ()>),
        entry!(
            IotaFramework,
            "vec_set",
            "VecSet",
            framework::vec_set::VecSet<()>
        ),
        entry!(
            IotaFramework,
            "priority_queue",
            "Entry",
            framework::priority_queue::Entry<()>
        ),
        entry!(
            IotaFramework,
            "priority_queue",
            "PriorityQueue",
            framework::priority_queue::PriorityQueue<()>
        ),
        entry!(
            IotaFramework,
            "zklogin_verified_id",
            "VerifiedID",
            framework::zklogin_verified_id::VerifiedID
        ),
        entry!(
            IotaFramework,
            "zklogin_verified_issuer",
            "VerifiedIssuer",
            framework::zklogin_verified_issuer::VerifiedIssuer
        ),
        entry!(
            IotaFramework,
            "timelock",
            "TimeLock",
            framework::timelock::TimeLock<()>
        ),
        entry!(IotaFramework, "dynamic_field", "Field", framework::dynamic_field::Field<(), ()>),
        entry!(
            IotaFramework,
            "dynamic_object_field",
            "Wrapper",
            framework::dynamic_object_field::Wrapper<()>
        ),
        entry!(
            IotaFramework,
            "labeler",
            "LabelerCap",
            framework::labeler::LabelerCap<()>
        ),
        entry!(IotaFramework, "linked_table", "LinkedTable", framework::linked_table::LinkedTable<(), ()>),
        entry!(IotaFramework, "linked_table", "Node", framework::linked_table::Node<(), ()>),
        entry!(IotaFramework, "object_table", "ObjectTable", framework::object_table::ObjectTable<(), ()>),
        entry!(
            IotaFramework,
            "object_bag",
            "ObjectBag",
            framework::object_bag::ObjectBag
        ),
        entry!(
            IotaFramework,
            "derived_object",
            "DerivedObjectKey",
            framework::derived_object::DerivedObjectKey<()>
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "AuthenticatorState",
            framework::authenticator_state::AuthenticatorState
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "AuthenticatorStateInner",
            framework::authenticator_state::AuthenticatorStateInner
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "JWK",
            framework::authenticator_state::JWK
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "JwkId",
            framework::authenticator_state::JwkId
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "ActiveJwk",
            framework::authenticator_state::ActiveJwk
        ),
        entry!(
            IotaFramework,
            "display",
            "Display",
            framework::display::Display<()>
        ),
        entry!(
            IotaFramework,
            "display",
            "DisplayCreated",
            framework::display::DisplayCreated<()>
        ),
        entry!(
            IotaFramework,
            "display",
            "VersionUpdated",
            framework::display::VersionUpdated<()>
        ),
        entry!(
            IotaFramework,
            "package",
            "Publisher",
            framework::package::Publisher
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeCap",
            framework::package::UpgradeCap
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeTicket",
            framework::package::UpgradeTicket
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeReceipt",
            framework::package::UpgradeReceipt
        ),
        entry!(IotaFramework, "groth16", "Curve", framework::groth16::Curve),
        entry!(
            IotaFramework,
            "groth16",
            "PreparedVerifyingKey",
            framework::groth16::PreparedVerifyingKey
        ),
        entry!(
            IotaFramework,
            "groth16",
            "PublicProofInputs",
            framework::groth16::PublicProofInputs
        ),
        entry!(
            IotaFramework,
            "groth16",
            "ProofPoints",
            framework::groth16::ProofPoints
        ),
        entry!(
            IotaFramework,
            "group_ops",
            "Element",
            framework::group_ops::Element<()>
        ),
        entry!(
            IotaFramework,
            "authenticator_function",
            "AuthenticatorFunctionRefV1",
            framework::authenticator_function::AuthenticatorFunctionRefV1<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "ImmutableAccountCreated",
            framework::account::ImmutableAccountCreated<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "MutableAccountCreated",
            framework::account::MutableAccountCreated<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "AuthenticatorFunctionRefV1Rotated",
            framework::account::AuthenticatorFunctionRefV1Rotated<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManager",
            framework::coin_manager::CoinManager<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManagerTreasuryCap",
            framework::coin_manager::CoinManagerTreasuryCap<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManagerMetadataCap",
            framework::coin_manager::CoinManagerMetadataCap<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "ImmutableCoinMetadata",
            framework::coin_manager::ImmutableCoinMetadata<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManaged",
            framework::coin_manager::CoinManaged
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "TreasuryOwnershipRenounced",
            framework::coin_manager::TreasuryOwnershipRenounced
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "MetadataOwnershipRenounced",
            framework::coin_manager::MetadataOwnershipRenounced
        ),
        entry!(IotaFramework, "token", "Token", framework::token::Token<()>),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicy",
            framework::token::TokenPolicy<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "ActionRequest",
            framework::token::ActionRequest<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "RuleKey",
            framework::token::RuleKey<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicyCreated",
            framework::token::TokenPolicyCreated<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicyCap",
            framework::token::TokenPolicyCap<()>
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "PackageMetadataV1",
            framework::package_metadata::PackageMetadataV1
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "ModuleMetadataV1",
            framework::package_metadata::ModuleMetadataV1
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "AuthenticatorMetadataV1",
            framework::package_metadata::AuthenticatorMetadataV1
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "DenyList",
            framework::deny_list::DenyList
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "ConfigKey",
            framework::deny_list::ConfigKey
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "AddressKey",
            framework::deny_list::AddressKey
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "PerTypeConfigCreated",
            framework::deny_list::PerTypeConfigCreated
        ),
        entry!(IotaFramework, "random", "Random", framework::random::Random),
        entry!(
            IotaFramework,
            "random",
            "RandomInner",
            framework::random::RandomInner
        ),
        entry!(
            IotaFramework,
            "random",
            "RandomGenerator",
            framework::random::RandomGenerator
        ),
        entry!(
            IotaFramework,
            "config",
            "Config",
            framework::config::Config<()>
        ),
        entry!(
            IotaFramework,
            "config",
            "Setting",
            framework::config::Setting<()>
        ),
        entry!(
            IotaFramework,
            "config",
            "SettingData",
            framework::config::SettingData<()>
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "ProgrammableMoveCall",
            framework::ptb_command::ProgrammableMoveCall
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "TransferObjectsData",
            framework::ptb_command::TransferObjectsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "SplitCoinsData",
            framework::ptb_command::SplitCoinsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "MergeCoinsData",
            framework::ptb_command::MergeCoinsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "PublishData",
            framework::ptb_command::PublishData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "MakeMoveVecData",
            framework::ptb_command::MakeMoveVecData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "UpgradeData",
            framework::ptb_command::UpgradeData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "Argument",
            framework::ptb_command::Argument
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "Command",
            framework::ptb_command::Command
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "ObjectRef",
            framework::ptb_call_arg::ObjectRef
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "ObjectArg",
            framework::ptb_call_arg::ObjectArg
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "CallArg",
            framework::ptb_call_arg::CallArg
        ),
        entry!(
            IotaFramework,
            "ptb",
            "ProgrammableTransaction",
            framework::ptb::ProgrammableTransaction
        ),
        entry!(
            IotaFramework,
            "auth_context",
            "AuthContext",
            framework::auth_context::AuthContext
        ),
        entry!(IotaFramework, "kiosk", "Kiosk", framework::kiosk::Kiosk),
        entry!(
            IotaFramework,
            "kiosk",
            "KioskOwnerCap",
            framework::kiosk::KioskOwnerCap
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "PurchaseCap",
            framework::kiosk::PurchaseCap<()>
        ),
        entry!(IotaFramework, "kiosk", "Borrow", framework::kiosk::Borrow),
        entry!(IotaFramework, "kiosk", "Item", framework::kiosk::Item),
        entry!(IotaFramework, "kiosk", "Listing", framework::kiosk::Listing),
        entry!(IotaFramework, "kiosk", "Lock", framework::kiosk::Lock),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemListed",
            framework::kiosk::ItemListed<()>
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemPurchased",
            framework::kiosk::ItemPurchased<()>
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemDelisted",
            framework::kiosk::ItemDelisted<()>
        ),
        entry!(
            IotaFramework,
            "kiosk_extension",
            "Extension",
            framework::kiosk_extension::Extension
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferRequest",
            framework::transfer_policy::TransferRequest<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicy",
            framework::transfer_policy::TransferPolicy<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyCap",
            framework::transfer_policy::TransferPolicyCap<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyCreated",
            framework::transfer_policy::TransferPolicyCreated<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyDestroyed",
            framework::transfer_policy::TransferPolicyDestroyed<()>
        ),
        // -- 0x1 move-stdlib --------------------------------------------------
        entry!(
            MoveStdlib,
            "fixed_point32",
            "FixedPoint32",
            crate::std::fixed_point32::FixedPoint32
        ),
        entry!(MoveStdlib, "ascii", "String", crate::std::ascii::String),
        entry!(MoveStdlib, "ascii", "Char", crate::std::ascii::Char),
        entry!(MoveStdlib, "string", "String", crate::std::string::String),
        entry!(
            MoveStdlib,
            "bit_vector",
            "BitVector",
            crate::std::bit_vector::BitVector
        ),
        entry!(
            MoveStdlib,
            "type_name",
            "TypeName",
            crate::std::type_name::TypeName
        ),
        entry!(
            MoveStdlib,
            "option",
            "Option",
            crate::std::option::Option<()>
        ),
        entry!(
            MoveStdlib,
            "uq32_32",
            "UQ32_32",
            crate::std::uq32_32::UQ32_32
        ),
        entry!(
            MoveStdlib,
            "uq64_64",
            "UQ64_64",
            crate::std::uq64_64::UQ64_64
        ),
        // -- 0x3 iota-system --------------------------------------------------
        entry!(
            IotaSystem,
            "staking_pool",
            "PoolTokenExchangeRate",
            iota_system::staking_pool::PoolTokenExchangeRate
        ),
        entry!(
            IotaSystem,
            "staking_pool",
            "StakedIota",
            iota_system::staking_pool::StakedIota
        ),
        entry!(
            IotaSystem,
            "staking_pool",
            "StakingPoolV1",
            iota_system::staking_pool::StakingPoolV1
        ),
        entry!(
            IotaSystem,
            "voting_power",
            "VotingPowerInfoV1",
            iota_system::voting_power::VotingPowerInfoV1
        ),
        entry!(
            IotaSystem,
            "validator_cap",
            "UnverifiedValidatorOperationCap",
            iota_system::validator_cap::UnverifiedValidatorOperationCap
        ),
        entry!(
            IotaSystem,
            "validator_cap",
            "ValidatorOperationCap",
            iota_system::validator_cap::ValidatorOperationCap
        ),
        entry!(
            IotaSystem,
            "validator_wrapper",
            "Validator",
            iota_system::validator_wrapper::Validator
        ),
        entry!(
            IotaSystem,
            "validator",
            "ValidatorMetadataV1",
            iota_system::validator::ValidatorMetadataV1
        ),
        entry!(
            IotaSystem,
            "validator",
            "ValidatorV1",
            iota_system::validator::ValidatorV1
        ),
        entry!(
            IotaSystem,
            "validator",
            "StakingRequestEvent",
            iota_system::validator::StakingRequestEvent
        ),
        entry!(
            IotaSystem,
            "validator",
            "UnstakingRequestEvent",
            iota_system::validator::UnstakingRequestEvent
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "ValidatorSetV1",
            iota_system::validator_set::ValidatorSetV1
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "ValidatorSetV2",
            iota_system::validator_set::ValidatorSetV2
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "ValidatorEpochInfoEventV1",
            iota_system::validator_set::ValidatorEpochInfoEventV1
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "ValidatorJoinEvent",
            iota_system::validator_set::ValidatorJoinEvent
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "ValidatorLeaveEvent",
            iota_system::validator_set::ValidatorLeaveEvent
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "CommitteeValidatorJoinEvent",
            iota_system::validator_set::CommitteeValidatorJoinEvent
        ),
        entry!(
            IotaSystem,
            "validator_set",
            "CommitteeValidatorLeaveEvent",
            iota_system::validator_set::CommitteeValidatorLeaveEvent
        ),
        entry!(
            IotaSystem,
            "iota_system_state_inner",
            "SystemParametersV1",
            iota_system::iota_system_state_inner::SystemParametersV1
        ),
        entry!(
            IotaSystem,
            "iota_system_state_inner",
            "IotaSystemStateV1",
            iota_system::iota_system_state_inner::IotaSystemStateV1
        ),
        entry!(
            IotaSystem,
            "iota_system_state_inner",
            "IotaSystemStateV2",
            iota_system::iota_system_state_inner::IotaSystemStateV2
        ),
        entry!(
            IotaSystem,
            "iota_system_state_inner",
            "SystemEpochInfoEventV1",
            iota_system::iota_system_state_inner::SystemEpochInfoEventV1
        ),
        entry!(
            IotaSystem,
            "iota_system_state_inner",
            "SystemEpochInfoEventV2",
            iota_system::iota_system_state_inner::SystemEpochInfoEventV2
        ),
        entry!(
            IotaSystem,
            "iota_system",
            "IotaSystemState",
            iota_system::iota_system::IotaSystemState
        ),
        entry!(
            IotaSystem,
            "storage_fund",
            "StorageFundV1",
            iota_system::storage_fund::StorageFundV1
        ),
        entry!(
            IotaSystem,
            "timelocked_staking",
            "TimelockedStakedIota",
            iota_system::timelocked_staking::TimelockedStakedIota
        ),
        entry!(
            IotaSystem,
            "genesis",
            "GenesisValidatorMetadata",
            iota_system::genesis::GenesisValidatorMetadata
        ),
        entry!(
            IotaSystem,
            "genesis",
            "GenesisChainParameters",
            iota_system::genesis::GenesisChainParameters
        ),
        entry!(
            IotaSystem,
            "genesis",
            "TokenAllocation",
            iota_system::genesis::TokenAllocation
        ),
        entry!(
            IotaSystem,
            "genesis",
            "TokenDistributionSchedule",
            iota_system::genesis::TokenDistributionSchedule
        ),
        // -- 0x107a stardust --------------------------------------------------
        entry!(
            Stardust,
            "irc27",
            "Irc27Metadata",
            stardust::irc27::Irc27Metadata
        ),
        entry!(Stardust, "nft", "NFT", stardust::nft::NFT),
        entry!(Stardust, "nft", "Nft", stardust::nft::Nft),
        entry!(
            Stardust,
            "nft_output",
            "NftOutput",
            stardust::nft_output::NftOutput<()>
        ),
        entry!(
            Stardust,
            "stardust_upgrade_label",
            "STARDUST_UPGRADE_LABEL",
            stardust::stardust_upgrade_label::STARDUST_UPGRADE_LABEL
        ),
        entry!(
            Stardust,
            "basic_output",
            "BasicOutput",
            stardust::basic_output::BasicOutput<()>
        ),
        entry!(Stardust, "alias", "Alias", stardust::alias::Alias),
        entry!(
            Stardust,
            "alias_output",
            "AliasOutput",
            stardust::alias_output::AliasOutput<()>
        ),
        entry!(
            Stardust,
            "timelock_unlock_condition",
            "TimelockUnlockCondition",
            stardust::timelock_unlock_condition::TimelockUnlockCondition
        ),
        entry!(
            Stardust,
            "expiration_unlock_condition",
            "ExpirationUnlockCondition",
            stardust::expiration_unlock_condition::ExpirationUnlockCondition
        ),
        entry!(
            Stardust,
            "storage_deposit_return_unlock_condition",
            "StorageDepositReturnUnlockCondition",
            stardust::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition
        ),
    ]
}

// ---------------------------------------------------------------------------
// Package loading
// ---------------------------------------------------------------------------

/// Parse a vendored `packages_compiled` blob into one normalised module per
/// inner bytecode payload, keyed by short module name.
fn load_package(
    blob: &[u8],
) -> std::collections::HashMap<String, normalized::Module<normalized::RcIdentifier>> {
    let module_blobs: Vec<Vec<u8>> =
        bcs::from_bytes(blob).expect("outer BCS Vec<Vec<u8>> of bytecode payloads");
    let mut pool = RcPool::new();
    let mut out = std::collections::HashMap::new();
    for bytes in &module_blobs {
        let cm = CompiledModule::deserialize_with_defaults(bytes).expect("decode CompiledModule");
        let m = normalized::Module::new(&mut pool, &cm, false);
        let name: String = m.id.name.as_ref().to_string();
        out.insert(name, m);
    }
    out
}

// ---------------------------------------------------------------------------
// Shape ↔ Type comparison
// ---------------------------------------------------------------------------

/// Compare a Rust-side `Shape::Struct` against a Move `normalized::Struct`.
fn check_struct(
    move_module: &str,
    move_struct: &str,
    rust: &Shape,
    move_def: &normalized::Struct<RcIdentifier>,
) -> Result<(), String> {
    let rust_fields = match rust {
        Shape::Struct { fields } => fields,
        other => {
            return Err(format!(
                "{move_module}::{move_struct}: Rust-side root is {other:?}, expected Shape::Struct"
            ));
        }
    };

    // Drop Rust-side phantom fields (e.g. `PhantomData<T>`) — Move models
    // phantom type params at the struct level, not as fields.
    let rust_fields: Vec<&Field> = rust_fields
        .iter()
        .filter(|f| !matches!(f.shape, Shape::Phantom))
        .collect();

    if rust_fields.len() != move_def.fields.len() {
        return Err(format!(
            "{move_module}::{move_struct}: field count mismatch — Rust has {} (after phantom filter), Move has {}",
            rust_fields.len(),
            move_def.fields.len()
        ));
    }

    for (rf, mf) in rust_fields.iter().zip(move_def.fields.iter()) {
        let move_name: &str = mf.name.as_ref().as_str();
        if rf.name != move_name {
            return Err(format!(
                "{move_module}::{move_struct}: field name mismatch — Rust `{}` vs Move `{}`",
                rf.name, move_name
            ));
        }
        check_type(move_module, move_struct, rf.name, &rf.shape, &mf.type_)?;
    }

    Ok(())
}

/// Compare a Rust-side `Shape::Enum` against a Move `normalized::Enum`.
/// Variants must match by name, in order, with the same per-variant fields.
fn check_enum(
    move_module: &str,
    move_enum: &str,
    rust: &Shape,
    move_def: &normalized::Enum<RcIdentifier>,
) -> Result<(), String> {
    let rust_variants = match rust {
        Shape::Enum { variants } => variants,
        other => {
            return Err(format!(
                "{move_module}::{move_enum}: Rust-side root is {other:?}, expected Shape::Enum"
            ));
        }
    };

    if rust_variants.len() != move_def.variants.len() {
        return Err(format!(
            "{move_module}::{move_enum}: variant count mismatch — Rust has {}, Move has {}",
            rust_variants.len(),
            move_def.variants.len()
        ));
    }

    for (rv, mv) in rust_variants.iter().zip(move_def.variants.iter()) {
        let move_variant_name: &str = mv.name.as_ref().as_str();
        if rv.name != move_variant_name {
            return Err(format!(
                "{move_module}::{move_enum}: variant name mismatch — Rust `{}` vs Move `{}`",
                rv.name, move_variant_name
            ));
        }

        let rust_fields: Vec<&Field> = rv
            .fields
            .iter()
            .filter(|f| !matches!(f.shape, Shape::Phantom))
            .collect();
        if rust_fields.len() != mv.fields.len() {
            return Err(format!(
                "{move_module}::{move_enum}::{}: field count mismatch — Rust has {} (after phantom filter), Move has {}",
                rv.name,
                rust_fields.len(),
                mv.fields.len()
            ));
        }
        for (rf, mf) in rust_fields.iter().zip(mv.fields.iter()) {
            let move_field_name: &str = mf.name.as_ref().as_str();
            if rf.name != move_field_name {
                return Err(format!(
                    "{move_module}::{move_enum}::{}: field name mismatch — Rust `{}` vs Move `{}`",
                    rv.name, rf.name, move_field_name
                ));
            }
            check_type(
                move_module,
                &format!("{}::{}", move_enum, rv.name),
                rf.name,
                &rf.shape,
                &mf.type_,
            )?;
        }
    }

    Ok(())
}

/// Compare a `Shape` against a Move `normalized::Type` recursively.
fn check_type(
    module: &str,
    struct_name: &str,
    field: &str,
    rust: &Shape,
    move_ty: &Type<RcIdentifier>,
) -> Result<(), String> {
    let mismatch = || {
        Err(format!(
            "{module}::{struct_name}.{field}: shape mismatch — Rust `{rust:?}` vs Move `{move_ty:?}`"
        ))
    };

    // Rust-side primitive-wrapper types (e.g. `ObjectId`, `Address`) come
    // through the derive as `Datatype { name, args: [] }` but represent a
    // Move primitive on the wire. Normalise before the structural match.
    if let Shape::Datatype { name, args } = rust
        && args.is_empty()
        && matches!(*name, "ObjectId" | "Address")
        && matches!(move_ty, Type::Address)
    {
        return Ok(());
    }

    // Rust prelude `Option<T>` is BCS-equivalent to Move's
    // `0x1::option::Option<T>`, which the Move side reports as a Datatype
    // (a struct wrapping `vector<T>`). Recurse on the inner type so callers
    // don't have to use `crate::std::option::Option` to participate.
    if let Shape::Option(rust_inner) = rust
        && let Type::Datatype(d) = move_ty
        && d.name.as_ref().as_str() == "Option"
        && d.type_arguments.len() == 1
    {
        return check_type(module, struct_name, field, rust_inner, &d.type_arguments[0]);
    }

    match (rust, move_ty) {
        (Shape::Bool, Type::Bool) => Ok(()),
        (Shape::U8, Type::U8) => Ok(()),
        (Shape::U16, Type::U16) => Ok(()),
        (Shape::U32, Type::U32) => Ok(()),
        (Shape::U64, Type::U64) => Ok(()),
        (Shape::U128, Type::U128) => Ok(()),
        (Shape::Address, Type::Address) => Ok(()),
        (Shape::Vector(a), Type::Vector(b)) => check_type(module, struct_name, field, a, b),
        (Shape::TypeParameter(n), Type::TypeParameter(m)) if *n == *m => Ok(()),
        (Shape::Datatype { name, args }, Type::Datatype(d)) => {
            let move_name: &str = d.name.as_ref().as_str();
            if *name != move_name {
                return Err(format!(
                    "{module}::{struct_name}.{field}: datatype name mismatch — Rust `{}` vs Move `{}`",
                    name, move_name
                ));
            }
            if args.len() != d.type_arguments.len() {
                return Err(format!(
                    "{module}::{struct_name}.{field}: type-arg arity mismatch — Rust {} vs Move {}",
                    args.len(),
                    d.type_arguments.len()
                ));
            }
            for (a, b) in args.iter().zip(d.type_arguments.iter()) {
                check_type(module, struct_name, field, a, b)?;
            }
            Ok(())
        }
        _ => mismatch(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn shapes_match() {
    // Load each package once, keyed by its `Package` variant — every entry
    // routes to the right blob without re-parsing.
    let entries = expected_entries();
    let mut by_package: std::collections::HashMap<
        Package,
        std::collections::HashMap<String, normalized::Module<normalized::RcIdentifier>>,
    > = std::collections::HashMap::new();
    for entry in &entries {
        by_package
            .entry(entry.package)
            .or_insert_with(|| load_package(entry.package.blob()));
    }

    let mut failures = Vec::new();
    for entry in &entries {
        let modules = by_package.get(&entry.package).expect("populated above");
        let module = match modules.get(entry.module) {
            Some(m) => m,
            None => {
                failures.push(format!(
                    "module `{}::{}` not found in {} blob",
                    entry.package.label(),
                    entry.module,
                    entry.package.label()
                ));
                continue;
            }
        };
        // A registered name may resolve to either a struct or an enum on
        // the Move side; structs and enums share a namespace within a
        // module, so they can't collide.
        let result = if let Some(move_struct) = module.structs.get(entry.struct_name) {
            check_struct(
                entry.module,
                entry.struct_name,
                &entry.rust_shape,
                move_struct,
            )
        } else if let Some(move_enum) = module.enums.get(entry.struct_name) {
            check_enum(
                entry.module,
                entry.struct_name,
                &entry.rust_shape,
                move_enum,
            )
        } else {
            Err(format!(
                "`{}::{}::{}` not found (looked in structs and enums)",
                entry.package.label(),
                entry.module,
                entry.struct_name
            ))
        };
        if let Err(e) = result {
            failures.push(e);
        }
    }
    if !failures.is_empty() {
        panic!(
            "MoveShape ↔ Move bytecode mismatch:\n  - {}",
            failures.join("\n  - ")
        );
    }
}
