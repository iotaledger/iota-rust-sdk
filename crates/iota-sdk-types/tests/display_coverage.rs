// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Guards that every public type in this crate implements `Display`.
//!
//! `every_public_type_implements_display` proves it for the listed types: a
//! type that loses its `Display` impl fails to compile here.
//!
//! `coverage_list_is_complete` keeps the list honest by scanning `src/` for
//! public types it does not mention, so a type added without a `Display` impl
//! fails instead of silently escaping the check.

fn assert_display<T: std::fmt::Display>() {}

#[test]
fn every_public_type_implements_display() {
    assert_display::<iota_sdk_types::Address>();
    assert_display::<iota_sdk_types::AddressParseError>();
    assert_display::<iota_sdk_types::Argument>();
    assert_display::<iota_sdk_types::Bls12381PublicKey>();
    assert_display::<iota_sdk_types::Bls12381Signature>();
    assert_display::<iota_sdk_types::CanceledTransaction>();
    assert_display::<iota_sdk_types::ChangeEpoch>();
    assert_display::<iota_sdk_types::ChangeEpochV2>();
    assert_display::<iota_sdk_types::ChangeEpochV3>();
    assert_display::<iota_sdk_types::ChangeEpochV4>();
    assert_display::<iota_sdk_types::ChangedObject>();
    assert_display::<iota_sdk_types::CheckpointCommitment>();
    assert_display::<iota_sdk_types::CheckpointContents>();
    assert_display::<iota_sdk_types::CheckpointContentsV1>();
    assert_display::<iota_sdk_types::CheckpointData>();
    assert_display::<iota_sdk_types::CheckpointSummary>();
    assert_display::<iota_sdk_types::CheckpointTransaction>();
    assert_display::<iota_sdk_types::CheckpointTransactionInfo>();
    assert_display::<iota_sdk_types::Coin>();
    assert_display::<iota_sdk_types::framework::CoinFromObjectError>();
    assert_display::<iota_sdk_types::Command>();
    assert_display::<iota_sdk_types::CommandArgumentError>();
    assert_display::<iota_sdk_types::ConsensusCommitPrologueV1>();
    assert_display::<iota_sdk_types::ConsensusDeterminedVersionAssignments>();
    assert_display::<iota_sdk_types::DenyRuleSet>();
    assert_display::<iota_sdk_types::Digest>();
    assert_display::<iota_sdk_types::DigestParseError>();
    assert_display::<iota_sdk_types::Ed25519PublicKey>();
    assert_display::<iota_sdk_types::Ed25519Signature>();
    assert_display::<iota_sdk_types::EndOfEpochData>();
    assert_display::<iota_sdk_types::EndOfEpochTransactionKind>();
    assert_display::<iota_sdk_types::Event>();
    assert_display::<iota_sdk_types::ExecutionError>();
    assert_display::<iota_sdk_types::ExecutionStatus>();
    assert_display::<iota_sdk_types::FromBase64Error>();
    assert_display::<iota_sdk_types::GasCostSummary>();
    assert_display::<iota_sdk_types::GasPayment>();
    assert_display::<iota_sdk_types::GenesisObject>();
    assert_display::<iota_sdk_types::GenesisTransaction>();
    assert_display::<iota_sdk_types::HashingIntentScope>();
    assert_display::<iota_sdk_types::IdOperation>();
    assert_display::<iota_sdk_types::Identifier>();
    assert_display::<iota_sdk_types::Input>();
    assert_display::<iota_sdk_types::Intent>();
    assert_display::<iota_sdk_types::IntentMessage<iota_sdk_types::Transaction>>();
    assert_display::<iota_sdk_types::PersonalMessage<'static>>();
    assert_display::<iota_sdk_types::IntentAppId>();
    assert_display::<iota_sdk_types::IntentError>();
    assert_display::<iota_sdk_types::IntentScope>();
    assert_display::<iota_sdk_types::IntentVersion>();
    assert_display::<iota_sdk_types::InvalidSignatureSchemeError>();
    assert_display::<iota_sdk_types::iota_names::config::IotaNamesConfig>();
    assert_display::<iota_sdk_types::iota_names::error::IotaNamesError>();
    assert_display::<iota_sdk_types::MakeMoveVector>();
    assert_display::<iota_sdk_types::MergeCoins>();
    assert_display::<iota_sdk_types::hash::MissingSignatureError>();
    assert_display::<iota_sdk_types::MoveAuthenticator>();
    assert_display::<iota_sdk_types::MoveAuthenticatorV1>();
    assert_display::<iota_sdk_types::MoveCall>();
    assert_display::<iota_sdk_types::MoveLocation>();
    assert_display::<iota_sdk_types::MoveObjectType>();
    assert_display::<iota_sdk_types::MovePackage>();
    assert_display::<iota_sdk_types::MovePackageData>();
    assert_display::<iota_sdk_types::MoveStruct>();
    assert_display::<iota_sdk_types::MoveStructContentsError>();
    assert_display::<iota_sdk_types::MultisigAggregatedSignature>();
    assert_display::<iota_sdk_types::MultisigCommittee>();
    assert_display::<iota_sdk_types::crypto::MultisigError>();
    assert_display::<iota_sdk_types::MultisigMember>();
    assert_display::<iota_sdk_types::MultisigMemberSignature>();
    assert_display::<iota_sdk_types::iota_names::Name>();
    assert_display::<iota_sdk_types::iota_names::NameFormat>();
    assert_display::<iota_sdk_types::iota_names::registry::NameRecord>();
    assert_display::<iota_sdk_types::iota_names::NameRegistration>();
    assert_display::<iota_sdk_types::Object>();
    assert_display::<iota_sdk_types::ObjectData>();
    assert_display::<iota_sdk_types::ObjectId>();
    assert_display::<iota_sdk_types::ObjectIn>();
    assert_display::<iota_sdk_types::ObjectOut>();
    assert_display::<iota_sdk_types::ObjectReference>();
    assert_display::<iota_sdk_types::ObjectType>();
    assert_display::<iota_sdk_types::Owner>();
    assert_display::<iota_sdk_types::InputSharedObject>();
    assert_display::<iota_sdk_types::ObjectChange>();
    assert_display::<iota_sdk_types::ObjectRemoveKind>();
    assert_display::<iota_sdk_types::ObjectVersion>();
    assert_display::<iota_sdk_types::OwnedObjectReference>();
    assert_display::<iota_sdk_types::PackageUpgradeError>();
    assert_display::<iota_sdk_types::PasskeyAuthenticator>();
    assert_display::<iota_sdk_types::PasskeyPublicKey>();
    assert_display::<iota_sdk_types::ProgrammableTransaction>();
    assert_display::<iota_sdk_types::PublicKey>();
    assert_display::<iota_sdk_types::PublicKeyError>();
    assert_display::<iota_sdk_types::Publish>();
    assert_display::<iota_sdk_types::RandomnessRound>();
    assert_display::<iota_sdk_types::RandomnessStateUpdate>();
    assert_display::<iota_sdk_types::iota_names::registry::Registry>();
    assert_display::<iota_sdk_types::iota_names::registry::RegistryEntry>();
    assert_display::<iota_sdk_types::iota_names::registry::ReverseRegistryEntry>();
    assert_display::<iota_sdk_types::Secp256k1PublicKey>();
    assert_display::<iota_sdk_types::Secp256k1Signature>();
    assert_display::<iota_sdk_types::Secp256r1PublicKey>();
    assert_display::<iota_sdk_types::Secp256r1Signature>();
    assert_display::<iota_sdk_types::SenderSignedTransaction>();
    assert_display::<iota_sdk_types::SharedObjectReference>();
    assert_display::<iota_sdk_types::crypto::SignatureFromBytesError>();
    assert_display::<iota_sdk_types::SignatureScheme>();
    assert_display::<iota_sdk_types::SignedCheckpointSummary>();
    assert_display::<iota_sdk_types::SignedTransaction>();
    assert_display::<iota_sdk_types::SimpleSignature>();
    assert_display::<iota_sdk_types::SplitCoins>();
    assert_display::<iota_sdk_types::StructTag>();
    assert_display::<iota_sdk_types::iota_names::SubnameRegistration>();
    assert_display::<iota_sdk_types::SystemPackage>();
    assert_display::<iota_sdk_types::iota_names::registry::Table>();
    assert_display::<iota_sdk_types::Transaction>();
    assert_display::<iota_sdk_types::TransactionDenyRulesUpdate>();
    assert_display::<iota_sdk_types::TransactionEffects>();
    assert_display::<iota_sdk_types::TransactionEffectsV1>();
    assert_display::<iota_sdk_types::TransactionEvents>();
    assert_display::<iota_sdk_types::TransactionExpiration>();
    assert_display::<iota_sdk_types::TransactionKind>();
    assert_display::<iota_sdk_types::TransactionV1>();
    assert_display::<iota_sdk_types::TransferObjects>();
    assert_display::<iota_sdk_types::TypeArgumentError>();
    assert_display::<iota_sdk_types::TypeOrigin>();
    assert_display::<iota_sdk_types::TypeParseError>();
    assert_display::<iota_sdk_types::TypeTag>();
    assert_display::<iota_sdk_types::UnchangedSharedKind>();
    assert_display::<iota_sdk_types::UnchangedSharedObject>();
    assert_display::<iota_sdk_types::Upgrade>();
    assert_display::<iota_sdk_types::UpgradeInfo>();
    assert_display::<iota_sdk_types::UpgradePolicy>();
    assert_display::<iota_sdk_types::UserSignature>();
    assert_display::<iota_sdk_types::ValidatorAggregatedSignature>();
    assert_display::<iota_sdk_types::ValidatorCommittee>();
    assert_display::<iota_sdk_types::ValidatorCommitteeMember>();
    assert_display::<iota_sdk_types::ValidatorSignature>();
    assert_display::<iota_sdk_types::VersionAssignment>();
    assert_display::<iota_sdk_types::Version>();
    assert_display::<iota_sdk_types::WriteKind>();
    assert_display::<iota_sdk_types::version::VersionError>();
}

/// Public types that deliberately have no `Display` impl.
const EXEMPT: &[&str] = &[
    // A hasher is a sink for bytes, not a value with a readable form.
    "Hasher",
];

#[test]
fn coverage_list_is_complete() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_sources(&src, &mut sources);
    assert!(
        !sources.is_empty(),
        "no sources found under {}",
        src.display()
    );

    let public_modules: Vec<String> = sources
        .iter()
        .flat_map(|(_, text)| declared_names(text, "pub mod "))
        .collect();
    let re_exported: String = sources
        .iter()
        .map(|(_, text)| re_exports(text))
        .collect::<Vec<_>>()
        .join("\n");
    let listed = include_str!("display_coverage.rs");

    let mut missing = Vec::new();
    for (module, text) in &sources {
        let public_module = module == "lib" || public_modules.iter().any(|m| m == module);
        for name in declared_names(text, "pub struct ")
            .into_iter()
            .chain(declared_names(text, "pub enum "))
        {
            if EXEMPT.contains(&name.as_str()) || mentions_type(listed, &name) {
                continue;
            }
            if public_module || mentions_type(&re_exported, &name) {
                missing.push(format!("{module}::{name}"));
            }
        }
    }
    missing.sort();

    assert!(
        missing.is_empty(),
        "public types missing from this test's list: {}\n\
         Add an `assert_display::<..>()` call for each, or list it in `EXEMPT`.",
        missing.join(", ")
    );
}

fn collect_sources(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            let module = if stem == "mod" {
                dir.file_name().unwrap().to_string_lossy().into_owned()
            } else {
                stem
            };
            out.push((module, std::fs::read_to_string(&path).expect("read source")));
        }
    }
}

/// The `pub use` statements of a file, each flattened onto one line.
fn re_exports(text: &str) -> String {
    let mut out = String::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if !line.trim_start().starts_with("pub use ") {
            continue;
        }
        let mut statement = line.to_owned();
        while !statement.contains(';') {
            match lines.next() {
                Some(next) => statement.push_str(next.trim()),
                None => break,
            }
        }
        out.push_str(&statement);
        out.push('\n');
    }
    out
}

/// Names of items declared at the top level of a file with the given prefix.
///
/// Indentation is the filter for nesting: anything inside a function, a private
/// inline module or a `#[cfg(test)]` block is not part of the public surface.
fn declared_names(text: &str, prefix: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(|rest| {
            rest.trim_start()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// Whether `text` names this type, as opposed to one it is a prefix of.
fn mentions_type(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + name.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}
