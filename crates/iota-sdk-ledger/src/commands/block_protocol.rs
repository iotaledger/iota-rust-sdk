// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The block protocol, which carries command parameters and results of any
//! length in chunks small enough for single APDUs.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use super::{app::Instruction, exec};
use crate::{LedgerError, Transport};

/// Parameter bytes per chunk; each chunk also carries the 32-byte hash of the
/// next one.
const CHUNK_SIZE: usize = 180;
/// Upper bound on the chunks the device may store on the host during one
/// command.
const MAX_STORED_CHUNKS: usize = 1024;
/// Upper bound on the length of a block protocol result.
const MAX_RESULT_LEN: usize = 64 * 1024;

type ChunkHash = [u8; 32];

#[derive(Clone, Copy, Debug)]
enum LedgerToHost {
    ResultAccumulating,
    ResultFinal,
    GetChunk,
    PutChunk,
}

impl TryFrom<u8> for LedgerToHost {
    type Error = LedgerError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ResultAccumulating),
            1 => Ok(Self::ResultFinal),
            2 => Ok(Self::GetChunk),
            3 => Ok(Self::PutChunk),
            _ => Err(LedgerError::invalid_response(format!(
                "unknown block protocol instruction {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum HostToLedger {
    Start = 0,
    GetChunkResponseSuccess = 1,
    GetChunkResponseFailure = 2,
    PutChunkResponse = 3,
    ResultAccumulatingResponse = 4,
}

/// Send `parameters` to `instruction` through the block protocol and return the
/// result.
///
/// Each parameter is split into chunks that are hash-linked back to front, so
/// the device receives only the hash of each parameter's first chunk and
/// requests the chunks it needs by hash.
pub(super) async fn send(
    transport: &dyn Transport,
    instruction: Instruction,
    parameters: &[&[u8]],
) -> Result<Vec<u8>, LedgerError> {
    let mut chunks = HashMap::new();
    let mut payload = vec![HostToLedger::Start as u8];

    for parameter in parameters {
        let mut last_hash: ChunkHash = [0; 32];
        for chunk in parameter.chunks(CHUNK_SIZE).rev() {
            let linked_chunk = [&last_hash, chunk].concat();
            last_hash = Sha256::digest(&linked_chunk).into();
            chunks.insert(last_hash, linked_chunk);
        }
        payload.extend_from_slice(&last_hash);
    }
    let max_chunks = chunks.len() + MAX_STORED_CHUNKS;

    let mut result = Vec::new();
    loop {
        let response = exec(transport, instruction.command(payload)).await?;
        let (&request, data) = response
            .split_first()
            .ok_or_else(|| LedgerError::invalid_response("empty block protocol response"))?;
        let request = LedgerToHost::try_from(request)?;

        if matches!(
            request,
            LedgerToHost::ResultAccumulating | LedgerToHost::ResultFinal
        ) {
            if result.len() + data.len() > MAX_RESULT_LEN {
                return Err(LedgerError::invalid_response("result is too long"));
            }
            result.extend_from_slice(data);
        }

        payload = match request {
            LedgerToHost::ResultAccumulating => {
                vec![HostToLedger::ResultAccumulatingResponse as u8]
            }
            LedgerToHost::ResultFinal => break,
            LedgerToHost::GetChunk => {
                let hash = data
                    .get(..32)
                    .ok_or_else(|| LedgerError::invalid_response("chunk request without hash"))?;
                match chunks.get(hash) {
                    Some(chunk) => {
                        [&[HostToLedger::GetChunkResponseSuccess as u8], &chunk[..]].concat()
                    }
                    None => vec![HostToLedger::GetChunkResponseFailure as u8],
                }
            }
            LedgerToHost::PutChunk => {
                if chunks.len() >= max_chunks {
                    return Err(LedgerError::invalid_response(
                        "device stored too many chunks",
                    ));
                }
                chunks.insert(Sha256::digest(data).into(), data.to_vec());
                vec![HostToLedger::PutChunkResponse as u8]
            }
        };
    }

    Ok(result)
}
