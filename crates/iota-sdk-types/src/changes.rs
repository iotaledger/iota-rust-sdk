// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Derivation of a transaction's balance and object changes from its effects
//! and the objects it read and wrote.
//!
//! Effects say which objects changed and how, but not what they contain, so
//! the caller supplies the objects: `input_objects` at the versions
//! [`TransactionEffectsV1::modified_at_versions`] gives, and `output_objects`
//! as the transaction wrote them. Operates purely on that in-memory data.
//!
//! An object missing from those sets is an error rather than a skipped entry:
//! a missing input coin would make a balance delta numerically wrong, and a
//! missing object would drop a change from the result, with no way for the
//! caller to tell the result was incomplete.

use std::{collections::BTreeMap, ops::Neg};

use crate::{
    Address, ExecutionStatus, Object, ObjectDigest, ObjectId, ObjectRemoveKind,
    OwnedObjectReference, Owner, StructTag, TransactionEffectsV1, TypeTag, Version, WriteKind,
    framework::Coin, object::ObjectReference,
};

/// Error deriving balance or object changes from a transaction's effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DeriveChangesError {
    /// An object the effects name was not among the supplied objects.
    MissingObject {
        object_id: ObjectId,
        version: Version,
    },
    /// An object whose type is a coin had contents that are not a valid coin.
    MalformedCoin {
        object_id: ObjectId,
        version: Version,
    },
}

impl std::fmt::Display for DeriveChangesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingObject { object_id, version } => write!(
                f,
                "object {object_id} at version {version} is unavailable (possibly pruned)"
            ),
            Self::MalformedCoin { object_id, version } => write!(
                f,
                "coin object {object_id} at version {version} has malformed contents"
            ),
        }
    }
}

impl std::error::Error for DeriveChangesError {}

/// The net change in balance of one coin type for one owner, summed over
/// every coin of that type the transaction touched.
///
/// Not a wire type: this is the output of [`derive_balance_changes`],
/// computed from the effects and the objects they name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BalanceChange {
    pub owner: Owner,
    pub coin_type: TypeTag,
    /// Negative amount means the net flow of value is away from the owner.
    pub amount: i128,
}

impl crate::TreeDisplay for BalanceChange {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Balance Change")?;
        w.leaf("Owner", &self.owner, false)?;
        w.leaf("Coin Type", &self.coin_type, false)?;
        w.leaf("Amount", &self.amount, true)
    }
}

/// What a transaction did to one object, named as a kind.
///
/// Not a wire type: this is the output of [`derive_object_changes`], computed
/// from the effects and the objects they name.
///
/// Naming the kind needs the objects as well as the effects, since
/// `object_type` and `owner` are not in the effects. Where only the effects are
/// at hand, [`ChangedObject`](crate::ChangedObject) carries each side's state,
/// and the object sets report the version each changed object ends at.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectChange {
    Published {
        package_id: ObjectId,
        version: Version,
        digest: ObjectDigest,
        modules: Vec<String>,
    },
    Mutated {
        sender: Address,
        owner: Owner,
        object_type: StructTag,
        object_id: ObjectId,
        version: Version,
        previous_version: Version,
        digest: ObjectDigest,
    },
    Deleted {
        sender: Address,
        object_type: StructTag,
        object_id: ObjectId,
        version: Version,
    },
    Wrapped {
        sender: Address,
        object_type: StructTag,
        object_id: ObjectId,
        version: Version,
    },
    Unwrapped {
        sender: Address,
        owner: Owner,
        object_type: StructTag,
        object_id: ObjectId,
        version: Version,
        digest: ObjectDigest,
    },
    Created {
        sender: Address,
        owner: Owner,
        object_type: StructTag,
        object_id: ObjectId,
        version: Version,
        digest: ObjectDigest,
    },
}

impl crate::TreeDisplay for ObjectChange {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Object Change")?;
        let kind = match self {
            Self::Published { .. } => "Published",
            Self::Mutated { .. } => "Mutated",
            Self::Deleted { .. } => "Deleted",
            Self::Wrapped { .. } => "Wrapped",
            Self::Unwrapped { .. } => "Unwrapped",
            Self::Created { .. } => "Created",
        };
        w.leaf("Kind", &kind, false)?;
        match self {
            Self::Published {
                package_id,
                version,
                digest,
                modules,
            } => {
                w.leaf("Package ID", package_id, false)?;
                w.leaf("Version", version, false)?;
                w.leaf("Digest", digest, false)?;
                w.leaves("Modules", modules, true)
            }
            Self::Deleted {
                sender,
                object_type,
                object_id,
                version,
            }
            | Self::Wrapped {
                sender,
                object_type,
                object_id,
                version,
            } => {
                w.leaf("Sender", sender, false)?;
                w.leaf("Object Type", object_type, false)?;
                w.leaf("Object ID", object_id, false)?;
                w.leaf("Version", version, true)
            }
            Self::Mutated {
                sender,
                owner,
                object_type,
                object_id,
                version,
                previous_version,
                digest,
            } => {
                w.leaf("Sender", sender, false)?;
                w.leaf("Owner", owner, false)?;
                w.leaf("Object Type", object_type, false)?;
                w.leaf("Object ID", object_id, false)?;
                w.leaf("Version", version, false)?;
                w.leaf("Previous Version", previous_version, false)?;
                w.leaf("Digest", digest, true)
            }
            Self::Unwrapped {
                sender,
                owner,
                object_type,
                object_id,
                version,
                digest,
            }
            | Self::Created {
                sender,
                owner,
                object_type,
                object_id,
                version,
                digest,
            } => {
                w.leaf("Sender", sender, false)?;
                w.leaf("Owner", owner, false)?;
                w.leaf("Object Type", object_type, false)?;
                w.leaf("Object ID", object_id, false)?;
                w.leaf("Version", version, false)?;
                w.leaf("Digest", digest, true)
            }
        }
    }
}

crate::impl_tree_display!(BalanceChange, ObjectChange);

/// Derive the balance changes of a transaction from its effects and the
/// objects it read and wrote.
///
/// For a failed transaction only the gas charge is reported, which needs no
/// objects; a transaction that names no gas object reports nothing.
/// `mocked_coin` excludes a gas coin mocked during simulation, which is in
/// neither object set.
///
/// Errors if any object the effects name is missing from the sets — a missing
/// input coin would corrupt the delta of any coin whose output is present.
pub fn derive_balance_changes<'a>(
    effects: &TransactionEffectsV1,
    input_objects: impl IntoIterator<Item = &'a Object>,
    output_objects: impl IntoIterator<Item = &'a Object>,
    mocked_coin: Option<ObjectId>,
) -> Result<Vec<BalanceChange>, DeriveChangesError> {
    // Only charge gas when the transaction fails, skipping all object parsing.
    if effects.status != ExecutionStatus::Success {
        return Ok(effects
            .gas_object()
            .map(|gas| BalanceChange {
                owner: gas.owner,
                coin_type: TypeTag::from(StructTag::new_gas()),
                amount: (effects.gas_cost_summary.net_gas_usage() as i128).neg(),
            })
            .into_iter()
            .collect());
    }

    let objects: BTreeMap<(ObjectId, Version), &Object> = input_objects
        .into_iter()
        .chain(output_objects)
        .map(|o| ((o.id(), o.version()), o))
        .collect();

    let mut balances = BTreeMap::<(Owner, TypeTag), i128>::new();

    // 1. subtract all input coins
    for modified in effects.modified_at_versions() {
        let (id, version) = (modified.object_id, modified.version);
        // The mocked gas coin is in neither object set.
        if matches!(mocked_coin, Some(coin) if id == coin) {
            continue;
        }
        if let Some((owner, coin_type, amount)) = coin_owner_type_value(&objects, id, version)? {
            *balances.entry((owner, coin_type)).or_default() -= amount as i128;
        }
    }

    // 2. add all mutated coins
    for (changed, _) in effects.all_changed_objects() {
        let object_ref = changed.reference;
        if matches!(mocked_coin, Some(coin) if object_ref.object_id == coin) {
            continue;
        }
        if let Some((owner, coin_type, amount)) =
            coin_owner_type_value(&objects, object_ref.object_id, object_ref.version)?
        {
            *balances.entry((owner, coin_type)).or_default() += amount as i128;
        }
    }

    Ok(balances
        .into_iter()
        .filter(|(_, amount)| *amount != 0)
        .map(|((owner, coin_type), amount)| BalanceChange {
            owner,
            coin_type,
            amount,
        })
        .collect())
}

/// Look up an object and return its owner, coin type and balance if it is a
/// coin. Returns `None` for non-coins; errors if the object is missing from
/// the set or its coin contents are malformed.
fn coin_owner_type_value(
    objects: &BTreeMap<(ObjectId, Version), &Object>,
    id: ObjectId,
    version: Version,
) -> Result<Option<(Owner, TypeTag, u64)>, DeriveChangesError> {
    let Some(object) = objects.get(&(id, version)) else {
        return Err(DeriveChangesError::MissingObject {
            object_id: id,
            version,
        });
    };
    let Some(move_object_type) = object.data.opt_object_type() else {
        return Ok(None);
    };
    let Some(coin_type) = move_object_type.opt_coin_type().cloned() else {
        return Ok(None);
    };
    let value = Coin::try_from_object(object)
        .map_err(|_| DeriveChangesError::MalformedCoin {
            object_id: id,
            version,
        })?
        .balance();
    Ok(Some((object.owner, coin_type, value)))
}

/// Derive the object changes of a transaction from its effects and the objects
/// it read and wrote.
///
/// `input_objects` provides the types of deleted and wrapped objects, so it
/// must hold them at the versions
/// [`TransactionEffectsV1::modified_at_versions`] gives.
///
/// Errors if an object the effects name is missing from the sets — skipping it
/// would drop a change from the result.
pub fn derive_object_changes<'a>(
    sender: Address,
    effects: &TransactionEffectsV1,
    input_objects: impl IntoIterator<Item = &'a Object>,
    output_objects: impl IntoIterator<Item = &'a Object>,
) -> Result<Vec<ObjectChange>, DeriveChangesError> {
    let mut object_changes = vec![];

    let modified_at_versions = effects
        .modified_at_versions()
        .into_iter()
        .map(|modified| (modified.object_id, modified.version))
        .collect::<BTreeMap<_, _>>();

    let outputs: BTreeMap<(ObjectId, Version), &Object> = output_objects
        .into_iter()
        .map(|o| ((o.id(), o.version()), o))
        .collect();

    // Input objects are the objects at their modified-at versions, so they are
    // unique per id and provide the pre-transaction state of removed objects.
    let inputs_by_id: BTreeMap<ObjectId, &Object> =
        input_objects.into_iter().map(|o| (o.id(), o)).collect();

    for (changed, kind) in effects.all_changed_objects() {
        let OwnedObjectReference { reference, owner } = changed;
        let ObjectReference {
            object_id,
            version,
            digest,
        } = reference;
        let Some(object) = outputs.get(&(object_id, version)) else {
            return Err(DeriveChangesError::MissingObject { object_id, version });
        };
        if let Some(move_object_type) = object.data.opt_object_type() {
            let object_type: StructTag = move_object_type.clone().into();

            match kind {
                WriteKind::Mutate => object_changes.push(ObjectChange::Mutated {
                    sender,
                    owner,
                    object_type,
                    object_id,
                    version,
                    // A mutated object was read at some version, so the
                    // effects always name one for it.
                    previous_version: *modified_at_versions
                        .get(&object_id)
                        .expect("a mutated object has a modified-at version"),
                    digest,
                }),
                WriteKind::Create => object_changes.push(ObjectChange::Created {
                    sender,
                    owner,
                    object_type,
                    object_id,
                    version,
                    digest,
                }),
                WriteKind::Unwrap => object_changes.push(ObjectChange::Unwrapped {
                    sender,
                    owner,
                    object_type,
                    object_id,
                    version,
                    digest,
                }),
            }
        } else if let Some(package) = object.data.as_opt_package()
            && kind == WriteKind::Create
        {
            object_changes.push(ObjectChange::Published {
                package_id: package.id(),
                version: package.version(),
                digest,
                modules: package
                    .serialized_module_map()
                    .keys()
                    .map(|k| k.to_string())
                    .collect(),
            })
        }
    }

    for (removed_object, kind) in effects.all_removed_objects() {
        let object_id = removed_object.object_id;
        let version = removed_object.version;
        let Some(object) = inputs_by_id.get(&object_id) else {
            // The input object lives at its modified-at version, not at the
            // removed reference's (tombstone) version.
            return Err(DeriveChangesError::MissingObject {
                object_id,
                version: modified_at_versions
                    .get(&object_id)
                    .copied()
                    .unwrap_or(version),
            });
        };
        // Packages cannot be removed; skip non-Move objects.
        if let Some(move_object_type) = object.data.opt_object_type() {
            let object_type: StructTag = move_object_type.clone().into();
            match kind {
                ObjectRemoveKind::Delete => object_changes.push(ObjectChange::Deleted {
                    sender,
                    object_type,
                    object_id,
                    version,
                }),
                ObjectRemoveKind::Wrap => object_changes.push(ObjectChange::Wrapped {
                    sender,
                    object_type,
                    object_id,
                    version,
                }),
            }
        }
    }

    Ok(object_changes)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{
        ChangedObject, ExecutionError, GasCostSummary, IdOperation, MoveObjectType, MoveStruct,
        ObjectData, ObjectIn, ObjectOut, TransactionDigest,
    };

    const LAMPORT: u64 = 4;
    const INPUT_VERSION: u64 = 3;

    fn address(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn object_id(byte: u8) -> ObjectId {
        ObjectId::new([byte; 32])
    }

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::new([byte; 32])
    }

    /// A coin of `coin_type`, whose contents lead with its id as every Move
    /// object's must.
    fn coin(
        id: ObjectId,
        version: u64,
        owner: Owner,
        balance: u64,
        coin_type: StructTag,
    ) -> Object {
        let mut contents = AsRef::<[u8; 32]>::as_ref(&id).to_vec();
        contents.extend_from_slice(&balance.to_le_bytes());
        Object {
            data: ObjectData::Struct(
                MoveStruct::new(
                    MoveObjectType::from(StructTag::new_coin(coin_type)),
                    Version::from_u64(version),
                    contents,
                )
                .unwrap(),
            ),
            owner,
            previous_transaction: TransactionDigest::default(),
            storage_rebate: 0,
        }
    }

    fn gas_coin(id: ObjectId, version: u64, owner: Owner, balance: u64) -> Object {
        coin(id, version, owner, balance, StructTag::new_gas())
    }

    fn effects(changed_objects: Vec<ChangedObject>) -> TransactionEffectsV1 {
        TransactionEffectsV1 {
            status: ExecutionStatus::Success,
            epoch: 0,
            gas_cost_summary: GasCostSummary::default(),
            transaction_digest: TransactionDigest::default(),
            gas_object_index: None,
            events_digest: None,
            dependencies: Vec::new(),
            lamport_version: Version::from_u64(LAMPORT),
            changed_objects,
            unchanged_shared_objects: Vec::new(),
            auxiliary_data_digest: None,
        }
    }

    fn mutated(id: ObjectId, owner: Owner) -> ChangedObject {
        ChangedObject {
            object_id: id,
            input_state: ObjectIn::Data {
                version: Version::from_u64(INPUT_VERSION),
                digest: digest(0),
                owner,
            },
            output_state: ObjectOut::ObjectWrite {
                digest: digest(1),
                owner,
            },
            id_operation: IdOperation::None,
        }
    }

    fn created(id: ObjectId, owner: Owner) -> ChangedObject {
        ChangedObject {
            object_id: id,
            input_state: ObjectIn::Missing,
            output_state: ObjectOut::ObjectWrite {
                digest: digest(1),
                owner,
            },
            id_operation: IdOperation::Created,
        }
    }

    fn deleted(id: ObjectId, owner: Owner) -> ChangedObject {
        ChangedObject {
            object_id: id,
            input_state: ObjectIn::Data {
                version: Version::from_u64(INPUT_VERSION),
                digest: digest(0),
                owner,
            },
            output_state: ObjectOut::Missing,
            id_operation: IdOperation::Deleted,
        }
    }

    fn wrapped(id: ObjectId, owner: Owner) -> ChangedObject {
        ChangedObject {
            object_id: id,
            input_state: ObjectIn::Data {
                version: Version::from_u64(INPUT_VERSION),
                digest: digest(0),
                owner,
            },
            output_state: ObjectOut::Missing,
            id_operation: IdOperation::None,
        }
    }

    /// Value moved out of one coin and into another shows up as a matching
    /// pair of deltas.
    #[test]
    fn a_coin_transfer_nets_out_per_owner() {
        let sender = Owner::Address(address(1));
        let recipient = Owner::Address(address(2));
        let spent = object_id(10);
        let received = object_id(11);

        let effects = effects(vec![mutated(spent, sender), created(received, recipient)]);
        let inputs = vec![gas_coin(spent, INPUT_VERSION, sender, 100)];
        let outputs = vec![
            gas_coin(spent, LAMPORT, sender, 70),
            gas_coin(received, LAMPORT, recipient, 30),
        ];

        let changes = derive_balance_changes(&effects, &inputs, &outputs, None).unwrap();
        let gas = TypeTag::from(StructTag::new_gas());
        assert_eq!(
            changes,
            vec![
                BalanceChange {
                    owner: sender,
                    coin_type: gas.clone(),
                    amount: -30,
                },
                BalanceChange {
                    owner: recipient,
                    coin_type: gas,
                    amount: 30,
                },
            ]
        );
    }

    /// Two coins of the same type reaching one owner sum into a single entry,
    /// rather than one entry per coin object.
    #[test]
    fn coins_of_one_type_sum_into_a_single_entry() {
        let sender = Owner::Address(address(1));
        let recipient = Owner::Address(address(2));
        let spent = object_id(10);
        let first = object_id(11);
        let second = object_id(12);

        let effects = effects(vec![
            mutated(spent, sender),
            created(first, recipient),
            created(second, recipient),
        ]);
        let inputs = vec![gas_coin(spent, INPUT_VERSION, sender, 100)];
        let outputs = vec![
            gas_coin(spent, LAMPORT, sender, 50),
            gas_coin(first, LAMPORT, recipient, 30),
            gas_coin(second, LAMPORT, recipient, 20),
        ];

        let changes = derive_balance_changes(&effects, &inputs, &outputs, None).unwrap();
        let gas = TypeTag::from(StructTag::new_gas());
        assert_eq!(
            changes,
            vec![
                BalanceChange {
                    owner: sender,
                    coin_type: gas.clone(),
                    amount: -50,
                },
                BalanceChange {
                    owner: recipient,
                    coin_type: gas,
                    amount: 50,
                },
            ]
        );
    }

    /// One owner holding two coin types gets one delta per type.
    #[test]
    fn balances_are_grouped_by_owner_and_coin_type() {
        let owner = Owner::Address(address(1));
        let gas_id = object_id(10);
        let other_id = object_id(11);
        let other_type = StructTag::new_staked_iota();

        let effects = effects(vec![mutated(gas_id, owner), mutated(other_id, owner)]);
        let inputs = vec![
            gas_coin(gas_id, INPUT_VERSION, owner, 100),
            coin(other_id, INPUT_VERSION, owner, 5, other_type.clone()),
        ];
        let outputs = vec![
            gas_coin(gas_id, LAMPORT, owner, 90),
            coin(other_id, LAMPORT, owner, 8, other_type.clone()),
        ];

        let changes = derive_balance_changes(&effects, &inputs, &outputs, None).unwrap();
        let amounts: Vec<_> = changes
            .iter()
            .map(|change| (change.coin_type.clone(), change.amount))
            .collect();
        assert_eq!(
            amounts,
            vec![
                (TypeTag::from(StructTag::new_gas()), -10),
                (TypeTag::from(other_type), 3),
            ]
        );
    }

    /// A coin whose balance is unchanged is not reported at all.
    #[test]
    fn a_zero_delta_is_dropped() {
        let owner = Owner::Address(address(1));
        let id = object_id(10);

        let effects = effects(vec![mutated(id, owner)]);
        let inputs = vec![gas_coin(id, INPUT_VERSION, owner, 100)];
        let outputs = vec![gas_coin(id, LAMPORT, owner, 100)];

        assert!(
            derive_balance_changes(&effects, &inputs, &outputs, None)
                .unwrap()
                .is_empty()
        );
    }

    /// A coin the effects name but the caller did not supply is an error, not
    /// a silently wrong delta.
    #[test]
    fn a_missing_input_coin_is_an_error() {
        let owner = Owner::Address(address(1));
        let id = object_id(10);

        let effects = effects(vec![mutated(id, owner)]);
        let outputs = vec![gas_coin(id, LAMPORT, owner, 100)];

        assert_eq!(
            derive_balance_changes(&effects, &[], &outputs, None),
            Err(DeriveChangesError::MissingObject {
                object_id: id,
                version: Version::from_u64(INPUT_VERSION),
            })
        );
    }

    /// A gas coin mocked during simulation is in neither object set, so naming
    /// it keeps the run from erroring on it.
    #[test]
    fn a_mocked_gas_coin_is_excluded() {
        let owner = Owner::Address(address(1));
        let mock = object_id(10);

        let effects = effects(vec![mutated(mock, owner)]);

        assert!(
            derive_balance_changes(&effects, &[], &[], Some(mock))
                .unwrap()
                .is_empty()
        );
        assert!(derive_balance_changes(&effects, &[], &[], None).is_err());
    }

    /// A failed transaction changed nothing but still paid gas, so the charge
    /// is reported without consulting any object.
    #[test]
    fn a_failed_transaction_reports_only_the_gas_charge() {
        let owner = Owner::Address(address(1));
        let gas_id = object_id(10);

        let mut effects = effects(vec![mutated(gas_id, owner)]);
        effects.status = ExecutionStatus::Failure {
            error: ExecutionError::InsufficientGas,
            command: None,
        };
        effects.gas_object_index = Some(0);
        effects.gas_cost_summary = GasCostSummary {
            computation_cost: 1000,
            storage_cost: 100,
            storage_rebate: 50,
            ..GasCostSummary::default()
        };

        let changes = derive_balance_changes(&effects, &[], &[], None).unwrap();
        assert_eq!(
            changes,
            vec![BalanceChange {
                owner,
                coin_type: TypeTag::from(StructTag::new_gas()),
                amount: -1050,
            }]
        );
    }

    /// A transaction that names no gas object has no owner to charge, so a
    /// failure reports nothing rather than an invented one.
    #[test]
    fn a_failed_transaction_without_a_gas_object_reports_nothing() {
        let mut effects = effects(Vec::new());
        effects.status = ExecutionStatus::Failure {
            error: ExecutionError::InsufficientGas,
            command: None,
        };
        effects.gas_cost_summary = GasCostSummary {
            computation_cost: 1000,
            ..GasCostSummary::default()
        };

        assert!(
            derive_balance_changes(&effects, &[], &[], None)
                .unwrap()
                .is_empty()
        );
    }

    /// A changed object that is not a coin contributes no balance change.
    #[test]
    fn a_non_coin_object_is_ignored() {
        let owner = Owner::Address(address(1));
        let clock_id = object_id(10);
        let coin_id = object_id(11);

        let non_coin = |id: ObjectId, version: u64| {
            let mut contents = AsRef::<[u8; 32]>::as_ref(&id).to_vec();
            contents.extend_from_slice(&[0u8; 8]);
            Object {
                data: ObjectData::Struct(
                    MoveStruct::new(
                        MoveObjectType::from(StructTag::new_clock()),
                        Version::from_u64(version),
                        contents,
                    )
                    .unwrap(),
                ),
                owner,
                previous_transaction: TransactionDigest::default(),
                storage_rebate: 0,
            }
        };

        let effects = effects(vec![mutated(clock_id, owner), mutated(coin_id, owner)]);
        let inputs = vec![
            non_coin(clock_id, INPUT_VERSION),
            gas_coin(coin_id, INPUT_VERSION, owner, 100),
        ];
        let outputs = vec![
            non_coin(clock_id, LAMPORT),
            gas_coin(coin_id, LAMPORT, owner, 90),
        ];

        let changes = derive_balance_changes(&effects, &inputs, &outputs, None).unwrap();
        assert_eq!(
            changes.len(),
            1,
            "only the coin contributes a balance change"
        );
        assert_eq!(changes[0].amount, -10);
    }

    /// Every write and removal kind reaches the matching variant. The result
    /// is grouped by kind rather than following the order of the effects,
    /// since it walks the object sets in turn.
    #[test]
    fn object_changes_report_each_kind() {
        let sender = address(1);
        let owner = Owner::Address(sender);
        let created_id = object_id(10);
        let mutated_id = object_id(11);
        let deleted_id = object_id(12);
        let wrapped_id = object_id(13);

        let effects = effects(vec![
            created(created_id, owner),
            mutated(mutated_id, owner),
            deleted(deleted_id, owner),
            wrapped(wrapped_id, owner),
        ]);
        let inputs = vec![
            gas_coin(mutated_id, INPUT_VERSION, owner, 1),
            gas_coin(deleted_id, INPUT_VERSION, owner, 1),
            gas_coin(wrapped_id, INPUT_VERSION, owner, 1),
        ];
        let outputs = vec![
            gas_coin(created_id, LAMPORT, owner, 1),
            gas_coin(mutated_id, LAMPORT, owner, 1),
        ];

        let changes = derive_object_changes(sender, &effects, &inputs, &outputs).unwrap();
        let kinds: Vec<_> = changes
            .iter()
            .map(|change| match change {
                ObjectChange::Created { object_id, .. } => ("created", *object_id),
                ObjectChange::Mutated { object_id, .. } => ("mutated", *object_id),
                ObjectChange::Deleted { object_id, .. } => ("deleted", *object_id),
                ObjectChange::Wrapped { object_id, .. } => ("wrapped", *object_id),
                ObjectChange::Unwrapped { object_id, .. } => ("unwrapped", *object_id),
                ObjectChange::Published { package_id, .. } => ("published", *package_id),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("mutated", mutated_id),
                ("created", created_id),
                ("deleted", deleted_id),
                ("wrapped", wrapped_id),
            ]
        );

        // A mutated object reports where it came from.
        let ObjectChange::Mutated {
            previous_version, ..
        } = changes
            .iter()
            .find(|change| matches!(change, ObjectChange::Mutated { .. }))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(*previous_version, Version::from_u64(INPUT_VERSION));
    }

    /// An unwrapped object is a write with no input state whose id already
    /// existed, so it is neither created nor mutated.
    #[test]
    fn an_unwrapped_object_is_reported_as_unwrapped() {
        let sender = address(1);
        let owner = Owner::Address(sender);
        let id = object_id(10);

        let effects = effects(vec![ChangedObject {
            object_id: id,
            input_state: ObjectIn::Missing,
            output_state: ObjectOut::ObjectWrite {
                digest: digest(1),
                owner,
            },
            id_operation: IdOperation::None,
        }]);
        let outputs = vec![gas_coin(id, LAMPORT, owner, 1)];

        let changes = derive_object_changes(sender, &effects, &[], &outputs).unwrap();
        assert!(matches!(
            changes.as_slice(),
            [ObjectChange::Unwrapped { object_id, .. }] if *object_id == id
        ));
    }

    /// A newly published package is reported with its module names. So is a
    /// user package upgrade, which lands at a fresh id. A system package
    /// upgrade keeps its id and so is a mutate, which packages do not report.
    #[test]
    fn a_published_package_is_reported_with_its_modules() {
        use std::collections::BTreeMap;

        use crate::{Identifier, MovePackage};

        let sender = address(1);
        let package_id = object_id(10);
        let upgraded_id = object_id(11);

        let package = |id: ObjectId, version: u64| Object {
            data: ObjectData::Package(MovePackage {
                id,
                version: Version::from_u64(version),
                modules: BTreeMap::from([(Identifier::from_static("counter"), vec![0u8])]),
                type_origin_table: Vec::new(),
                linkage_table: BTreeMap::new(),
            }),
            owner: Owner::Immutable,
            previous_transaction: TransactionDigest::default(),
            storage_rebate: 0,
        };
        // A publish or a user upgrade: the id is new, so the write creates it.
        let published = |id| ChangedObject {
            object_id: id,
            input_state: ObjectIn::Missing,
            output_state: ObjectOut::PackageWrite {
                version: Version::from_u64(1),
                digest: digest(1),
            },
            id_operation: IdOperation::Created,
        };
        // A system upgrade: the id already exists, at the previous version.
        let system_upgrade = ChangedObject {
            object_id: ObjectId::FRAMEWORK,
            input_state: ObjectIn::Data {
                version: Version::from_u64(1),
                digest: digest(0),
                owner: Owner::Immutable,
            },
            output_state: ObjectOut::PackageWrite {
                version: Version::from_u64(2),
                digest: digest(1),
            },
            id_operation: IdOperation::None,
        };

        let effects = effects(vec![
            published(package_id),
            published(upgraded_id),
            system_upgrade,
        ]);
        let outputs = vec![
            package(package_id, 1),
            package(upgraded_id, 1),
            package(ObjectId::FRAMEWORK, 2),
        ];
        let inputs = vec![package(ObjectId::FRAMEWORK, 1)];

        let changes = derive_object_changes(sender, &effects, &inputs, &outputs).unwrap();
        let published_ids: Vec<_> = changes
            .iter()
            .map(|change| match change {
                ObjectChange::Published {
                    package_id,
                    modules,
                    ..
                } => {
                    assert_eq!(modules, &["counter".to_string()]);
                    *package_id
                }
                other => panic!("expected a published package, got {other:?}"),
            })
            .collect();
        assert_eq!(
            published_ids,
            vec![package_id, upgraded_id],
            "the system upgrade is a mutate, so it is not reported"
        );
    }

    /// An object the effects wrote but the caller did not supply is an error,
    /// since skipping it would drop a change from the result.
    #[test]
    fn a_missing_output_object_is_an_error() {
        let sender = address(1);
        let owner = Owner::Address(sender);
        let id = object_id(10);

        let effects = effects(vec![created(id, owner)]);

        assert_eq!(
            derive_object_changes(sender, &effects, &[], &[]),
            Err(DeriveChangesError::MissingObject {
                object_id: id,
                version: Version::from_u64(LAMPORT),
            })
        );
    }

    /// A removed object is looked up at its modified-at version, so the error
    /// names that rather than the tombstone version.
    #[test]
    fn a_missing_removed_object_is_named_at_its_input_version() {
        let sender = address(1);
        let owner = Owner::Address(sender);
        let id = object_id(10);

        let effects = effects(vec![deleted(id, owner)]);

        assert_eq!(
            derive_object_changes(sender, &effects, &[], &[]),
            Err(DeriveChangesError::MissingObject {
                object_id: id,
                version: Version::from_u64(INPUT_VERSION),
            })
        );
    }
}
