// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Signing with the IOTA app.

use iota_crypto::DerivationPath;
use iota_types::{
    BcsError, Ed25519Signature, Intent, IntentMessage, Object, PersonalMessage, Transaction,
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
