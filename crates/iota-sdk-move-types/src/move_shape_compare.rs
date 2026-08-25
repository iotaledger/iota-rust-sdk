// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Structural cross-check: each Rust mirror's `MoveShape` derive output is
//! compared against the canonical Move definition parsed from a compiled
//! `packages_compiled` blob.
//!
//! The blobs are not committed — `update_compiled_packages.sh` fetches them
//! into the gitignored `src/packages_compiled/` directory at the monorepo
//! rev pinned by the `move-binary-format` dependency (`make test` does this
//! automatically when they are missing or out of date). They are read at
//! test run time, so the crate compiles without them.
//!
//! Extend by adding blobs to the `ARTIFACTS` list in that script, deriving
//! `MoveShape` on more mirrors, and registering more entries in
//! [`expected_entries`].

use move_binary_format::{
    CompiledModule,
    normalized::{self, RcIdentifier, RcPool, Type},
};

use crate::{
    iota_framework, iota_system,
    move_shape::{Field, MoveShape, Shape, Variant},
    move_stdlib, stardust,
};

// ---------------------------------------------------------------------------
// Compiled package blobs (fetched, not committed — see module docs)
// ---------------------------------------------------------------------------

/// Read a fetched artifact from `src/packages_compiled/`.
///
/// Artifacts are loaded at test run time, so the crate compiles without
/// them; a missing file fails the test with fetch instructions.
fn read_artifact(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/packages_compiled")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "could not read compiled package artifact `{}`: {e}\n\
             fetch the artifacts with `make update-compiled-packages` \
             (see crates/iota-sdk-move-types/README.md)",
            path.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Entries: Rust-mirror → Move-side coordinates
// ---------------------------------------------------------------------------

struct Entry {
    /// Which compiled package to look the Move struct up in. Needed because
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Package {
    MoveStdlib,
    IotaFramework,
    IotaSystem,
    Stardust,
}

impl Package {
    fn blob(self) -> Vec<u8> {
        read_artifact(match self {
            Package::MoveStdlib => "move-stdlib",
            Package::IotaFramework => "iota-framework",
            Package::IotaSystem => "iota-system",
            Package::Stardust => "stardust",
        })
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
        entry!(IotaFramework, "object", "ID", iota_framework::object::ID),
        entry!(IotaFramework, "object", "UID", iota_framework::object::UID),
        entry!(
            IotaFramework,
            "balance",
            "Balance",
            iota_framework::balance::Balance<()>
        ),
        entry!(
            IotaFramework,
            "balance",
            "Supply",
            iota_framework::balance::Supply<()>
        ),
        entry!(IotaFramework, "bag", "Bag", iota_framework::bag::Bag),
        entry!(
            IotaFramework,
            "coin",
            "Coin",
            iota_framework::coin::Coin<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "CoinMetadata",
            iota_framework::coin::CoinMetadata<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "TreasuryCap",
            iota_framework::coin::TreasuryCap<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "RegulatedCoinMetadata",
            iota_framework::coin::RegulatedCoinMetadata<()>
        ),
        entry!(IotaFramework, "bcs", "BCS", iota_framework::bcs::BCS),
        entry!(
            IotaFramework,
            "clock",
            "Clock",
            iota_framework::clock::Clock
        ),
        entry!(
            IotaFramework,
            "tx_context",
            "TxContext",
            iota_framework::tx_context::TxContext
        ),
        entry!(
            IotaFramework,
            "intent",
            "Intent",
            iota_framework::intent::Intent
        ),
        entry!(IotaFramework, "url", "Url", iota_framework::url::Url),
        entry!(
            IotaFramework,
            "versioned",
            "Versioned",
            iota_framework::versioned::Versioned
        ),
        entry!(
            IotaFramework,
            "versioned",
            "VersionChangeCap",
            iota_framework::versioned::VersionChangeCap
        ),
        entry!(
            IotaFramework,
            "transfer",
            "Receiving",
            iota_framework::transfer::Receiving<()>
        ),
        entry!(
            IotaFramework,
            "borrow",
            "Referent",
            iota_framework::borrow::Referent<()>
        ),
        entry!(
            IotaFramework,
            "borrow",
            "Borrow",
            iota_framework::borrow::Borrow
        ),
        entry!(IotaFramework, "iota", "IOTA", iota_framework::iota::IOTA),
        entry!(
            IotaFramework,
            "iota",
            "IotaTreasuryCap",
            iota_framework::iota::IotaTreasuryCap
        ),
        entry!(
            IotaFramework,
            "system_admin_cap",
            "IotaSystemAdminCap",
            iota_framework::system_admin_cap::IotaSystemAdminCap
        ),
        entry!(
            IotaFramework,
            "account",
            "AuthenticatorFunctionRefV1Key",
            iota_framework::account::AuthenticatorFunctionRefV1Key
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "PackageMetadataKey",
            iota_framework::package_metadata::PackageMetadataKey
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "PackageMetadataVersionFieldName",
            iota_framework::package_metadata::PackageMetadataVersionFieldName
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "ModuleMetadataV1FieldName",
            iota_framework::package_metadata::ModuleMetadataV1FieldName
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "ModulesMetadataFieldName",
            iota_framework::package_metadata::ModulesMetadataFieldName
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "ModuleName",
            iota_framework::package_metadata::ModuleName
        ),
        entry!(
            IotaFramework,
            "module_metadata",
            "ModuleMetadata",
            iota_framework::module_metadata::ModuleMetadata
        ),
        entry!(
            IotaFramework,
            "module_metadata",
            "ModuleMetadataKey",
            iota_framework::module_metadata::ModuleMetadataKey
        ),
        entry!(
            IotaFramework,
            "module_metadata",
            "ViewFunctionMetadataV1FieldName",
            iota_framework::module_metadata::ViewFunctionMetadataV1FieldName
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "ConfigWriteCap",
            iota_framework::deny_list::ConfigWriteCap
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "GlobalPauseKey",
            iota_framework::deny_list::GlobalPauseKey
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "Scalar",
            iota_framework::bls12381::Scalar
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "G1",
            iota_framework::bls12381::G1
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "G2",
            iota_framework::bls12381::G2
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "GT",
            iota_framework::bls12381::GT
        ),
        entry!(
            IotaFramework,
            "bls12381",
            "UncompressedG1",
            iota_framework::bls12381::UncompressedG1
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "RuleKey",
            iota_framework::transfer_policy::RuleKey<()>
        ),
        entry!(
            IotaFramework,
            "kiosk_extension",
            "ExtensionKey",
            iota_framework::kiosk_extension::ExtensionKey<()>
        ),
        entry!(IotaFramework, "table", "Table", iota_framework::table::Table<(), ()>),
        entry!(
            IotaFramework,
            "table_vec",
            "TableVec",
            iota_framework::table_vec::TableVec<()>
        ),
        entry!(
            IotaFramework,
            "coin",
            "DenyCapV1",
            iota_framework::coin::DenyCapV1<()>
        ),
        entry!(IotaFramework, "vec_map", "Entry", iota_framework::vec_map::Entry<(), ()>),
        entry!(IotaFramework, "vec_map", "VecMap", iota_framework::vec_map::VecMap<(), ()>),
        entry!(
            IotaFramework,
            "vec_set",
            "VecSet",
            iota_framework::vec_set::VecSet<()>
        ),
        entry!(
            IotaFramework,
            "priority_queue",
            "Entry",
            iota_framework::priority_queue::Entry<()>
        ),
        entry!(
            IotaFramework,
            "priority_queue",
            "PriorityQueue",
            iota_framework::priority_queue::PriorityQueue<()>
        ),
        entry!(
            IotaFramework,
            "zklogin_verified_id",
            "VerifiedID",
            iota_framework::zklogin_verified_id::VerifiedID
        ),
        entry!(
            IotaFramework,
            "zklogin_verified_issuer",
            "VerifiedIssuer",
            iota_framework::zklogin_verified_issuer::VerifiedIssuer
        ),
        entry!(
            IotaFramework,
            "timelock",
            "TimeLock",
            iota_framework::timelock::TimeLock<()>
        ),
        entry!(IotaFramework, "dynamic_field", "Field", iota_framework::dynamic_field::Field<(), ()>),
        entry!(
            IotaFramework,
            "dynamic_object_field",
            "Wrapper",
            iota_framework::dynamic_object_field::Wrapper<()>
        ),
        entry!(
            IotaFramework,
            "labeler",
            "LabelerCap",
            iota_framework::labeler::LabelerCap<()>
        ),
        entry!(IotaFramework, "linked_table", "LinkedTable", iota_framework::linked_table::LinkedTable<(), ()>),
        entry!(IotaFramework, "linked_table", "Node", iota_framework::linked_table::Node<(), ()>),
        entry!(IotaFramework, "object_table", "ObjectTable", iota_framework::object_table::ObjectTable<(), ()>),
        entry!(
            IotaFramework,
            "object_bag",
            "ObjectBag",
            iota_framework::object_bag::ObjectBag
        ),
        entry!(
            IotaFramework,
            "derived_object",
            "DerivedObjectKey",
            iota_framework::derived_object::DerivedObjectKey<()>
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "AuthenticatorState",
            iota_framework::authenticator_state::AuthenticatorState
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "AuthenticatorStateInner",
            iota_framework::authenticator_state::AuthenticatorStateInner
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "JWK",
            iota_framework::authenticator_state::JWK
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "JwkId",
            iota_framework::authenticator_state::JwkId
        ),
        entry!(
            IotaFramework,
            "authenticator_state",
            "ActiveJwk",
            iota_framework::authenticator_state::ActiveJwk
        ),
        entry!(
            IotaFramework,
            "display",
            "Display",
            iota_framework::display::Display<()>
        ),
        entry!(
            IotaFramework,
            "display",
            "DisplayCreated",
            iota_framework::display::DisplayCreated<()>
        ),
        entry!(
            IotaFramework,
            "display",
            "VersionUpdated",
            iota_framework::display::VersionUpdated<()>
        ),
        entry!(
            IotaFramework,
            "package",
            "Publisher",
            iota_framework::package::Publisher
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeCap",
            iota_framework::package::UpgradeCap
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeTicket",
            iota_framework::package::UpgradeTicket
        ),
        entry!(
            IotaFramework,
            "package",
            "UpgradeReceipt",
            iota_framework::package::UpgradeReceipt
        ),
        entry!(
            IotaFramework,
            "groth16",
            "Curve",
            iota_framework::groth16::Curve
        ),
        entry!(
            IotaFramework,
            "groth16",
            "PreparedVerifyingKey",
            iota_framework::groth16::PreparedVerifyingKey
        ),
        entry!(
            IotaFramework,
            "groth16",
            "PublicProofInputs",
            iota_framework::groth16::PublicProofInputs
        ),
        entry!(
            IotaFramework,
            "groth16",
            "ProofPoints",
            iota_framework::groth16::ProofPoints
        ),
        entry!(
            IotaFramework,
            "group_ops",
            "Element",
            iota_framework::group_ops::Element<()>
        ),
        entry!(
            IotaFramework,
            "authenticator_function",
            "AuthenticatorFunctionRefV1",
            iota_framework::authenticator_function::AuthenticatorFunctionRefV1<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "ImmutableAccountCreated",
            iota_framework::account::ImmutableAccountCreated<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "MutableAccountCreated",
            iota_framework::account::MutableAccountCreated<()>
        ),
        entry!(
            IotaFramework,
            "account",
            "AuthenticatorFunctionRefV1Rotated",
            iota_framework::account::AuthenticatorFunctionRefV1Rotated<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManager",
            iota_framework::coin_manager::CoinManager<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManagerTreasuryCap",
            iota_framework::coin_manager::CoinManagerTreasuryCap<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManagerMetadataCap",
            iota_framework::coin_manager::CoinManagerMetadataCap<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "ImmutableCoinMetadata",
            iota_framework::coin_manager::ImmutableCoinMetadata<()>
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "CoinManaged",
            iota_framework::coin_manager::CoinManaged
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "TreasuryOwnershipRenounced",
            iota_framework::coin_manager::TreasuryOwnershipRenounced
        ),
        entry!(
            IotaFramework,
            "coin_manager",
            "MetadataOwnershipRenounced",
            iota_framework::coin_manager::MetadataOwnershipRenounced
        ),
        entry!(
            IotaFramework,
            "token",
            "Token",
            iota_framework::token::Token<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicy",
            iota_framework::token::TokenPolicy<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "ActionRequest",
            iota_framework::token::ActionRequest<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "RuleKey",
            iota_framework::token::RuleKey<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicyCreated",
            iota_framework::token::TokenPolicyCreated<()>
        ),
        entry!(
            IotaFramework,
            "token",
            "TokenPolicyCap",
            iota_framework::token::TokenPolicyCap<()>
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "PackageMetadataV1",
            iota_framework::package_metadata::PackageMetadataV1
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "ModuleMetadataV1",
            iota_framework::package_metadata::ModuleMetadataV1
        ),
        entry!(
            IotaFramework,
            "package_metadata",
            "AuthenticatorMetadataV1",
            iota_framework::package_metadata::AuthenticatorMetadataV1
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "DenyList",
            iota_framework::deny_list::DenyList
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "ConfigKey",
            iota_framework::deny_list::ConfigKey
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "AddressKey",
            iota_framework::deny_list::AddressKey
        ),
        entry!(
            IotaFramework,
            "deny_list",
            "PerTypeConfigCreated",
            iota_framework::deny_list::PerTypeConfigCreated
        ),
        entry!(
            IotaFramework,
            "transaction_deny_rules",
            "TransactionDenyRules",
            iota_framework::transaction_deny_rules::TransactionDenyRules
        ),
        entry!(
            IotaFramework,
            "transaction_deny_rules",
            "TransactionDenyRulesInnerV1",
            iota_framework::transaction_deny_rules::TransactionDenyRulesInnerV1
        ),
        entry!(
            IotaFramework,
            "transaction_deny_rules",
            "TransactionDenyRulesUpdated",
            iota_framework::transaction_deny_rules::TransactionDenyRulesUpdated
        ),
        entry!(
            IotaFramework,
            "random",
            "Random",
            iota_framework::random::Random
        ),
        entry!(
            IotaFramework,
            "random",
            "RandomInner",
            iota_framework::random::RandomInner
        ),
        entry!(
            IotaFramework,
            "random",
            "RandomGenerator",
            iota_framework::random::RandomGenerator
        ),
        entry!(
            IotaFramework,
            "config",
            "Config",
            iota_framework::config::Config<()>
        ),
        entry!(
            IotaFramework,
            "config",
            "Setting",
            iota_framework::config::Setting<()>
        ),
        entry!(
            IotaFramework,
            "config",
            "SettingData",
            iota_framework::config::SettingData<()>
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "ProgrammableMoveCall",
            iota_framework::ptb_command::ProgrammableMoveCall
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "TransferObjectsData",
            iota_framework::ptb_command::TransferObjectsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "SplitCoinsData",
            iota_framework::ptb_command::SplitCoinsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "MergeCoinsData",
            iota_framework::ptb_command::MergeCoinsData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "PublishData",
            iota_framework::ptb_command::PublishData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "MakeMoveVecData",
            iota_framework::ptb_command::MakeMoveVecData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "UpgradeData",
            iota_framework::ptb_command::UpgradeData
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "Argument",
            iota_framework::ptb_command::Argument
        ),
        entry!(
            IotaFramework,
            "ptb_command",
            "Command",
            iota_framework::ptb_command::Command
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "ObjectRef",
            iota_framework::ptb_call_arg::ObjectRef
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "ObjectArg",
            iota_framework::ptb_call_arg::ObjectArg
        ),
        entry!(
            IotaFramework,
            "ptb_call_arg",
            "CallArg",
            iota_framework::ptb_call_arg::CallArg
        ),
        entry!(
            IotaFramework,
            "ptb",
            "ProgrammableTransaction",
            iota_framework::ptb::ProgrammableTransaction
        ),
        entry!(
            IotaFramework,
            "auth_context",
            "AuthContext",
            iota_framework::auth_context::AuthContext
        ),
        entry!(
            IotaFramework,
            "auth_context",
            "AuthenticatorFunctionInfoV1",
            iota_framework::auth_context::AuthenticatorFunctionInfoV1
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "Kiosk",
            iota_framework::kiosk::Kiosk
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "KioskOwnerCap",
            iota_framework::kiosk::KioskOwnerCap
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "PurchaseCap",
            iota_framework::kiosk::PurchaseCap<()>
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "Borrow",
            iota_framework::kiosk::Borrow
        ),
        entry!(IotaFramework, "kiosk", "Item", iota_framework::kiosk::Item),
        entry!(
            IotaFramework,
            "kiosk",
            "Listing",
            iota_framework::kiosk::Listing
        ),
        entry!(IotaFramework, "kiosk", "Lock", iota_framework::kiosk::Lock),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemListed",
            iota_framework::kiosk::ItemListed<()>
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemPurchased",
            iota_framework::kiosk::ItemPurchased<()>
        ),
        entry!(
            IotaFramework,
            "kiosk",
            "ItemDelisted",
            iota_framework::kiosk::ItemDelisted<()>
        ),
        entry!(
            IotaFramework,
            "kiosk_extension",
            "Extension",
            iota_framework::kiosk_extension::Extension
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferRequest",
            iota_framework::transfer_policy::TransferRequest<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicy",
            iota_framework::transfer_policy::TransferPolicy<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyCap",
            iota_framework::transfer_policy::TransferPolicyCap<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyCreated",
            iota_framework::transfer_policy::TransferPolicyCreated<()>
        ),
        entry!(
            IotaFramework,
            "transfer_policy",
            "TransferPolicyDestroyed",
            iota_framework::transfer_policy::TransferPolicyDestroyed<()>
        ),
        // -- 0x1 move-stdlib --------------------------------------------------
        entry!(
            MoveStdlib,
            "fixed_point32",
            "FixedPoint32",
            move_stdlib::fixed_point32::FixedPoint32
        ),
        entry!(MoveStdlib, "ascii", "String", move_stdlib::ascii::String),
        entry!(MoveStdlib, "ascii", "Char", move_stdlib::ascii::Char),
        entry!(MoveStdlib, "string", "String", move_stdlib::string::String),
        entry!(
            MoveStdlib,
            "bit_vector",
            "BitVector",
            move_stdlib::bit_vector::BitVector
        ),
        entry!(
            MoveStdlib,
            "type_name",
            "TypeName",
            move_stdlib::type_name::TypeName
        ),
        entry!(
            MoveStdlib,
            "option",
            "Option",
            move_stdlib::option::Option<()>
        ),
        entry!(
            MoveStdlib,
            "uq32_32",
            "UQ32_32",
            move_stdlib::uq32_32::UQ32_32
        ),
        entry!(
            MoveStdlib,
            "uq64_64",
            "UQ64_64",
            move_stdlib::uq64_64::UQ64_64
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

/// Parse a `packages_compiled` blob into one normalized module per inner
/// bytecode payload, keyed by short module name.
fn load_package(
    package: Package,
) -> std::collections::HashMap<String, normalized::Module<normalized::RcIdentifier>> {
    let module_blobs: Vec<Vec<u8>> =
        bcs::from_bytes(&package.blob()).expect("outer BCS Vec<Vec<u8>> of bytecode payloads");
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
    // Move primitive on the wire. Normalize before the structural match.
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
    // don't have to use `move_stdlib::option::Option` to participate.
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
        // Named types are matched by name + type-arg arity only — the derive
        // can't see Move module paths, so two same-named, same-arity types in
        // different modules (e.g. `vec_map::Entry<K, V>` vs a hypothetical
        // two-param `Entry` elsewhere) would cross-match at a reference site.
        // Each named type still gets its own registry entry checked against
        // its own module's definition, and the fixture roundtrips cover the
        // serde path, so a wrong-module reference with a *different layout*
        // is still caught there.
        (Shape::Datatype { name, args }, Type::Datatype(d)) => {
            let move_name: &str = d.name.as_ref().as_str();
            if *name != move_name {
                return Err(format!(
                    "{module}::{struct_name}.{field}: datatype name mismatch — Rust `{name}` vs Move `{move_name}`"
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
            .or_insert_with(|| load_package(entry.package));
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

/// Parse `published_api.txt` — the manifest of every public
/// `struct`/`enum` across the four system packages, fetched at the pinned
/// monorepo rev — into the set of `(address, module, name)` keys.
///
/// `move_types_drift_nightly` flags when upstream `develop` drifts from the
/// pin; [`registry_matches_published_api`] in turn keeps [`expected_entries`]
/// in sync with the manifest — so every published type has a registered
/// mirror that [`shapes_match`] then cross-checks.
///
/// The file stores one record per three lines: the type name, its kind
/// (`public struct` / `public enum`), and its `address::module` path.
fn published_api_types() -> std::collections::BTreeSet<(String, String, String)> {
    let manifest =
        String::from_utf8(read_artifact("published_api.txt")).expect("manifest is UTF-8");
    let mut types = std::collections::BTreeSet::new();
    for record in manifest.lines().collect::<Vec<_>>().chunks(3) {
        let [name, kind, path] = record else { continue };
        if !(kind.trim().ends_with("struct") || kind.trim().ends_with("enum")) {
            continue;
        }
        let (address, module) = path
            .trim()
            .split_once("::")
            .expect("published_api path is `address::module`");
        types.insert((
            address.to_owned(),
            module.to_owned(),
            name.trim().to_owned(),
        ));
    }
    types
}

/// The `(address, module, name)` keys currently registered in
/// [`expected_entries`].
fn registered_types() -> std::collections::BTreeSet<(String, String, String)> {
    expected_entries()
        .iter()
        .map(|e| {
            (
                e.package.label().to_owned(),
                e.module.to_owned(),
                e.struct_name.to_owned(),
            )
        })
        .collect()
}

/// Every published Move type must have a registered mirror, and every
/// registered entry must correspond to a real published type. Without this
/// guard a new mirror could be added but left out of [`expected_entries`] —
/// silently skipping its shape check — or an upstream type could go unmirrored
/// entirely, leaving [`shapes_match`]'s "exhaustive" claim unenforced.
#[test]
fn registry_matches_published_api() {
    let published = published_api_types();
    let registered = registered_types();

    let render = |keys: Vec<&(String, String, String)>| {
        keys.iter()
            .map(|(a, m, n)| format!("{a}::{m}::{n}"))
            .collect::<Vec<_>>()
            .join("\n  - ")
    };

    let unmirrored: Vec<_> = published.difference(&registered).collect();
    let stale: Vec<_> = registered.difference(&published).collect();

    let mut errors = Vec::new();
    if !unmirrored.is_empty() {
        errors.push(format!(
            "published Move types with no registered mirror (add an `entry!` + `MoveShape` \
             mirror, or refresh published_api.txt):\n  - {}",
            render(unmirrored)
        ));
    }
    if !stale.is_empty() {
        errors.push(format!(
            "registered entries absent from published_api.txt (stale registration or typo):\n  - {}",
            render(stale)
        ));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n\n"));
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------
//
// `shapes_match` only ever feeds the comparator *correct* shapes, so a
// comparator that regressed to always returning `Ok(())` would still pass it.
// Each test below starts from a real Move definition and the mirror's
// known-good `move_shape()`, mutates exactly one thing, and asserts the
// comparator now rejects it — one case per branch the comparator protects.

fn struct_fields(shape: Shape) -> Vec<Field> {
    match shape {
        Shape::Struct { fields } => fields,
        other => panic!("expected a struct shape, got {other:?}"),
    }
}

fn enum_variants(shape: Shape) -> Vec<Variant> {
    match shape {
        Shape::Enum { variants } => variants,
        other => panic!("expected an enum shape, got {other:?}"),
    }
}

fn field_mut<'a>(fields: &'a mut [Field], name: &str) -> &'a mut Field {
    fields
        .iter_mut()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field named `{name}`"))
}

#[track_caller]
fn reject_struct(move_def: &normalized::Struct<RcIdentifier>, shape: &Shape, needle: &str) {
    let err = check_struct("module", "Type", shape, move_def)
        .expect_err("comparator accepted a deliberately invalid shape");
    assert!(
        err.contains(needle),
        "error `{err}`\n  should contain `{needle}`"
    );
}

#[track_caller]
fn reject_enum(move_def: &normalized::Enum<RcIdentifier>, shape: &Shape, needle: &str) {
    let err = check_enum("module", "Type", shape, move_def)
        .expect_err("comparator accepted a deliberately invalid shape");
    assert!(
        err.contains(needle),
        "error `{err}`\n  should contain `{needle}`"
    );
}

fn staked_iota_shape() -> Shape {
    <iota_system::staking_pool::StakedIota as MoveShape>::move_shape()
}

// -- struct-level branches --------------------------------------------------

#[test]
fn rejects_non_struct_root() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    // A Rust enum shape where Move declares a struct.
    let shape = Shape::Enum { variants: vec![] };
    reject_struct(def, &shape, "expected Shape::Struct");
}

#[test]
fn rejects_struct_field_count_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    fields.push(Field {
        name: "extra",
        shape: Shape::U8,
    });
    reject_struct(def, &Shape::Struct { fields }, "field count mismatch");
}

#[test]
fn rejects_struct_field_name_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    field_mut(&mut fields, "principal").name = "definitely_wrong";
    reject_struct(def, &Shape::Struct { fields }, "field name mismatch");
}

#[test]
fn rejects_struct_field_primitive_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    // `stake_activation_epoch` is a `u64`; claim it is a `bool`.
    field_mut(&mut fields, "stake_activation_epoch").shape = Shape::Bool;
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

// -- type-recursion branches ------------------------------------------------

#[test]
fn rejects_datatype_name_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    // `pool_id` is an `ID`; rename the referenced datatype.
    let Shape::Datatype { name, .. } = &mut field_mut(&mut fields, "pool_id").shape else {
        panic!("pool_id should be a datatype");
    };
    *name = "Wrong";
    reject_struct(def, &Shape::Struct { fields }, "datatype name mismatch");
}

#[test]
fn rejects_datatype_arity_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    // `principal` is a `Balance<IOTA>`; drop its type argument.
    let Shape::Datatype { args, .. } = &mut field_mut(&mut fields, "principal").shape else {
        panic!("principal should be a datatype");
    };
    assert_eq!(args.len(), 1, "expected Balance<_> with one type arg");
    args.clear();
    reject_struct(def, &Shape::Struct { fields }, "type-arg arity mismatch");
}

#[test]
fn rejects_datatype_type_arg_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    // Keep `Balance<_>`'s arity but corrupt the inner type argument.
    let Shape::Datatype { args, .. } = &mut field_mut(&mut fields, "principal").shape else {
        panic!("principal should be a datatype");
    };
    args[0] = Shape::Bool;
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

#[test]
fn rejects_vector_inner_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["random"].structs.get("RandomInner").unwrap();
    let mut fields =
        struct_fields(<iota_framework::random::RandomInner as MoveShape>::move_shape());
    // `random_bytes` is a `vector<u8>`; claim a `vector<bool>`.
    let Shape::Vector(inner) = &mut field_mut(&mut fields, "random_bytes").shape else {
        panic!("random_bytes should be a vector");
    };
    **inner = Shape::Bool;
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

#[test]
fn rejects_option_inner_mismatch() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakingPoolV1").unwrap();
    let mut fields =
        struct_fields(<iota_system::staking_pool::StakingPoolV1 as MoveShape>::move_shape());
    // `activation_epoch` is an `Option<u64>`; corrupt the inner type so the
    // Option normalization can't paper over it.
    let Shape::Option(inner) = &mut field_mut(&mut fields, "activation_epoch").shape else {
        panic!("activation_epoch should be an option");
    };
    **inner = Shape::Bool;
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

#[test]
fn rejects_type_parameter_index_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["dynamic_field"].structs.get("Field").unwrap();
    let mut fields =
        struct_fields(<iota_framework::dynamic_field::Field<(), ()> as MoveShape>::move_shape());
    // `name` is type parameter #0; claim #1.
    assert_eq!(
        field_mut(&mut fields, "name").shape,
        Shape::TypeParameter(0)
    );
    field_mut(&mut fields, "name").shape = Shape::TypeParameter(1);
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

#[test]
fn rejects_objectid_normalization_off_a_non_address() {
    let pkgs = load_package(Package::IotaSystem);
    let def = pkgs["staking_pool"].structs.get("StakedIota").unwrap();
    let mut fields = struct_fields(staked_iota_shape());
    // The ObjectId/Address → Address shortcut must only fire against a Move
    // `address`; here the Move field is a `u64`, so it must be rejected.
    field_mut(&mut fields, "stake_activation_epoch").shape = Shape::Datatype {
        name: "ObjectId",
        args: vec![],
    };
    reject_struct(def, &Shape::Struct { fields }, "shape mismatch");
}

// -- enum-level branches ----------------------------------------------------

fn argument_shape() -> Shape {
    <iota_framework::ptb_command::Argument as MoveShape>::move_shape()
}

#[test]
fn rejects_non_enum_root() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["ptb_command"].enums.get("Argument").unwrap();
    // A Rust struct shape where Move declares an enum.
    let shape = Shape::Struct { fields: vec![] };
    reject_enum(def, &shape, "expected Shape::Enum");
}

#[test]
fn rejects_enum_variant_count_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["ptb_command"].enums.get("Argument").unwrap();
    let mut variants = enum_variants(argument_shape());
    variants.pop();
    reject_enum(def, &Shape::Enum { variants }, "variant count mismatch");
}

#[test]
fn rejects_enum_variant_name_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["ptb_command"].enums.get("Argument").unwrap();
    let mut variants = enum_variants(argument_shape());
    variants[0].name = "definitely_wrong";
    reject_enum(def, &Shape::Enum { variants }, "variant name mismatch");
}

#[test]
fn rejects_enum_variant_field_count_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["ptb_command"].enums.get("Argument").unwrap();
    let mut variants = enum_variants(argument_shape());
    let i = variants
        .iter()
        .position(|v| !v.fields.is_empty())
        .expect("a variant with at least one field");
    variants[i].fields.push(Field {
        name: "extra",
        shape: Shape::U8,
    });
    reject_enum(def, &Shape::Enum { variants }, "field count mismatch");
}

#[test]
fn rejects_enum_variant_field_name_mismatch() {
    let pkgs = load_package(Package::IotaFramework);
    let def = pkgs["ptb_command"].enums.get("Argument").unwrap();
    let mut variants = enum_variants(argument_shape());
    let i = variants
        .iter()
        .position(|v| !v.fields.is_empty())
        .expect("a variant with at least one field");
    variants[i].fields[0].name = "definitely_wrong";
    reject_enum(def, &Shape::Enum { variants }, "field name mismatch");
}
