// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Signing with the IOTA app.

use std::collections::HashSet;

use iota_crypto::DerivationPath;
use iota_types::{
    BcsError, Ed25519Signature, Input, Intent, IntentMessage, Object, PersonalMessage, Transaction,
    TransactionKind,
};
use serde::Serialize;

use super::{
    Reader,
    app::{self, Instruction},
    block_protocol, encode_path,
};
use crate::{LedgerError, Transport};

/// Sign a transaction, passing its input objects for clear signing when
/// there are any.
pub(crate) async fn transaction(
    transport: &dyn Transport,
    path: &DerivationPath,
    transaction: &Transaction,
    objects: &[Object],
) -> Result<Ed25519Signature, LedgerError> {
    let objects = if objects.is_empty() {
        None
    } else {
        check_objects(transaction, objects)?;
        let count = u32::try_from(objects.len()).map_err(|_| LedgerError::PayloadTooLong)?;
        let mut packed = count.to_le_bytes().to_vec();
        for object in objects {
            write_u32_prefixed(&mut packed, &bcs_to_bytes(object)?)?;
        }
        Some(packed)
    };
    intent_message(
        transport,
        path,
        &bcs_to_bytes(&transaction.intent_message())?,
        objects.as_deref(),
    )
    .await
}

/// Check that `objects` hold every owned or immutable input and gas coin of
/// `transaction` at the version it references, as the device looks them up by
/// digest.
fn check_objects(transaction: &Transaction, objects: &[Object]) -> Result<(), LedgerError> {
    let transaction = match transaction {
        Transaction::V1(transaction) => transaction,
        _ => unimplemented!("a new Transaction enum variant was added and needs to be handled"),
    };
    let inputs = match &transaction.kind {
        TransactionKind::Programmable(programmable) => programmable.inputs.as_slice(),
        _ => &[],
    };
    let digests = objects.iter().map(Object::digest).collect::<HashSet<_>>();
    let missing = inputs
        .iter()
        .filter_map(|input| match input {
            Input::ImmutableOrOwned(reference) => Some(reference),
            _ => None,
        })
        .chain(&transaction.gas_payment.objects)
        .find(|reference| !digests.contains(reference.digest()));
    match missing {
        Some(reference) => Err(LedgerError::MissingObject(*reference.object_id())),
        None => Ok(()),
    }
}

/// Sign a personal message.
pub(crate) async fn personal_message(
    transport: &dyn Transport,
    path: &DerivationPath,
    message: &PersonalMessage<'_>,
) -> Result<Ed25519Signature, LedgerError> {
    let message = IntentMessage::new(Intent::personal_message(), &message.0);
    intent_message(transport, path, &bcs_to_bytes(&message)?, None).await
}

/// Sign a BCS-serialized intent message; the device hashes it itself.
async fn intent_message(
    transport: &dyn Transport,
    path: &DerivationPath,
    intent_message: &[u8],
    packed_objects: Option<&[u8]>,
) -> Result<Ed25519Signature, LedgerError> {
    let mut message = Vec::with_capacity(4 + intent_message.len());
    write_u32_prefixed(&mut message, intent_message)?;
    let path = encode_path(path)?;

    let mut parameters: Vec<&[u8]> = vec![&message, &path];
    parameters.extend(packed_objects);
    let response = block_protocol::send(transport, Instruction::Sign, &parameters)
        .await
        .map_err(app::map_app_error)?;

    Ok(Ed25519Signature::new(Reader::new(&response).array()?))
}

fn bcs_to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, LedgerError> {
    bcs::to_bytes(value).map_err(|e| LedgerError::Serialization(BcsError::new(e)))
}

/// Append `bytes` prefixed with their length as a little-endian `u32`.
fn write_u32_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LedgerError> {
    let len = u32::try_from(bytes.len()).map_err(|_| LedgerError::PayloadTooLong)?;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use iota_types::{
        Address, GasPayment, MoveStruct, ObjectData, ObjectId, Owner, ProgrammableTransaction,
        StructTag, TransactionDigest, TransactionExpiration, TransactionV1, Version,
    };

    use super::*;

    /// An IOTA coin with every byte of its id set to `id`.
    fn coin(id: u8, version: u64) -> Object {
        let mut contents = [id; ObjectId::LENGTH].to_vec();
        contents.extend_from_slice(&1_000u64.to_le_bytes());
        let coin = MoveStruct::new(
            StructTag::new_gas_coin().into(),
            Version::from_u64(version),
            contents,
        )
        .unwrap();
        Object::new(
            ObjectData::Struct(coin),
            Owner::Address(Address::ZERO),
            TransactionDigest::default(),
            0,
        )
    }

    /// A transaction that takes `input` and pays for gas with `gas`.
    fn transaction(input: &Object, gas: &Object) -> Transaction {
        Transaction::V1(TransactionV1 {
            kind: TransactionKind::Programmable(ProgrammableTransaction {
                inputs: vec![
                    Input::ImmutableOrOwned(input.object_ref()),
                    Input::Pure(vec![]),
                ],
                commands: vec![],
            }),
            sender: Address::ZERO,
            gas_payment: GasPayment {
                objects: vec![gas.object_ref()],
                owner: Address::ZERO,
                price: 1_000,
                budget: 1_000_000,
            },
            expiration: TransactionExpiration::None,
        })
    }

    #[test]
    fn accepts_every_referenced_object_among_others() {
        let (input, gas) = (coin(1, 1), coin(2, 1));
        check_objects(&transaction(&input, &gas), &[coin(3, 1), gas, input]).unwrap();
    }

    #[test]
    fn rejects_a_missing_gas_coin() {
        let (input, gas) = (coin(1, 1), coin(2, 1));
        assert!(matches!(
            check_objects(&transaction(&input, &gas), &[input]),
            Err(LedgerError::MissingObject(id)) if id == gas.id()
        ));
    }

    #[test]
    fn rejects_an_input_at_another_version() {
        let (input, gas) = (coin(1, 1), coin(2, 1));
        assert!(matches!(
            check_objects(&transaction(&input, &gas), &[coin(1, 2), gas]),
            Err(LedgerError::MissingObject(id)) if id == input.id()
        ));
    }
}
