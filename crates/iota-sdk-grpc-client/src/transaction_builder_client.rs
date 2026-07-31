// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`TransactionBuilderClient`] for the GRPC [`Client`].

use std::time::Duration;

use iota_grpc_types::{
    read_mask_fields::{
        EpochField, EpochReadMask, ObjectReadMask, OwnedObjectReadMask, SimulateReadMask,
        TransactionField, TransactionReadMask,
    },
    v1::transaction_execution_service::SimulatedTransaction,
};
use iota_transaction_builder::{ObjectsPage, ProtocolConfig, TransactionBuilderClient, WaitForTx};
use iota_types::{
    Address, Object, ObjectId, SignedTransaction, StructTag, Transaction, TransactionDigest,
    TransactionEffects, UserSignature, Version,
};

use crate::{
    Client,
    api::{Error, MetadataEnvelope, check_result_count, saturating_usize_to_u32},
};

/// How long [`TransactionBuilderClient::wait_for_tx`] polls before giving up.
const WAIT_FOR_TX_TIMEOUT: Duration = Duration::from_secs(60);
/// Interval between polls in [`TransactionBuilderClient::wait_for_tx`].
const WAIT_FOR_TX_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Extract the result for the single item of a one-item batch request.
///
/// A `NOT_FOUND` for the item maps to `None`, since these callers treat a
/// missing object or transaction as an absence rather than a failure. A failure
/// of the call itself still propagates — including a `NOT_FOUND`, which says
/// the endpoint is wrong rather than that the item is absent.
///
/// Anything other than exactly one result is a protocol error, not an absent
/// item: the batched reads answer every request, so an empty batch says the
/// server broke that promise rather than that the item is missing.
fn single_item<T>(
    response: Result<MetadataEnvelope<Vec<Result<T, Error>>>, Error>,
) -> Result<Option<T>, Error> {
    let mut items = response?.into_inner();
    check_result_count(&items, 1)?;

    match items.pop().expect("count checked above") {
        Ok(item) => Ok(Some(item)),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e),
    }
}

impl TransactionBuilderClient for Client {
    type Error = crate::api::Error;
    type DryRunResult = SimulatedTransaction;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        // Default read mask (`reference` + `bcs`) provides everything needed to
        // reconstruct the SDK object.
        let response = self
            .get_objects_with_versions([(object_id, version.into())], ObjectReadMask::default())
            .await;

        match single_item(response)? {
            Some(obj) => Ok(Some(obj.object()?)),
            None => Ok(None),
        }
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        let page = self
            .list_owned_objects(
                owner,
                struct_tag,
                limit.map(saturating_usize_to_u32),
                cursor.map(prost::bytes::Bytes::from),
                OwnedObjectReadMask::default(),
            )
            .await?
            .into_inner();
        let data = page
            .items
            .iter()
            .map(|obj| obj.object().map_err(Error::from))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = page.next_page_token.map(|token| token.to_vec());
        Ok(ObjectsPage { data, next_cursor })
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        let epoch = self
            .get_epoch(
                None,
                EpochReadMask::from(EpochField::PROTOCOL_CONFIG_ATTRIBUTES),
            )
            .await?
            .into_inner();
        let attributes = epoch
            .protocol_config
            .and_then(|config| config.attributes)
            .map(|attrs| attrs.attributes)
            .unwrap_or_default();
        Ok(ProtocolConfig { attributes })
    }

    async fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<SignedTransaction>, Self::Error> {
        let response = self
            .get_transactions(
                [digest],
                TransactionReadMask::from([
                    TransactionField::TRANSACTION,
                    TransactionField::SIGNATURES,
                ]),
            )
            .await;

        match single_item(response)? {
            Some(tx) => {
                let transaction = tx.transaction()?.transaction()?;
                let signatures = Vec::<UserSignature>::try_from(tx.signatures()?)?;
                Ok(Some(SignedTransaction {
                    transaction,
                    signatures,
                }))
            }
            None => Ok(None),
        }
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        let response = self
            .get_transactions(
                [digest],
                TransactionReadMask::from(TransactionField::EFFECTS_BCS),
            )
            .await;

        match single_item(response)? {
            Some(tx) => Ok(Some(tx.effects()?.effects()?)),
            None => Ok(None),
        }
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        let epoch = self
            .get_epoch(
                epoch.into(),
                EpochReadMask::from(EpochField::REFERENCE_GAS_PRICE),
            )
            .await?
            .into_inner();
        Ok(epoch.reference_gas_price)
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        // Simulate with relaxed checks and read the gas used from the resulting
        // effects.
        let simulated = self
            .simulate_transaction(tx.clone(), true, SimulateReadMask::default())
            .await?;
        let effects = simulated
            .into_inner()
            .executed_transaction()?
            .effects()?
            .effects()?;
        Ok(match effects {
            TransactionEffects::V1(v1) => Some(v1.gas_cost_summary.gas_used()),
            _ => unimplemented!(
                "a new TransactionEffects enum variant was added and needs to be handled"
            ),
        })
    }

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        Ok(self
            .simulate_transaction(tx.clone(), skip_checks, SimulateReadMask::default())
            .await?
            .into_inner())
    }

    async fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        let wait_for = wait_for.into();
        let signed_transaction = SignedTransaction {
            transaction: tx.clone(),
            signatures: signatures.to_vec(),
        };
        // The default execute read mask includes `effects`.
        let result = self
            .execute_transaction(signed_transaction, None, TransactionReadMask::default())
            .await?
            .into_inner();
        let effects = result.effects()?.effects()?;

        if let Some(wait_for) = wait_for {
            self.wait_for_tx(tx.digest(), wait_for).await?;
        }

        Ok(effects)
    }

    async fn wait_for_tx(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> Result<(), Self::Error> {
        // Request only the field that proves the desired condition: any
        // transaction field confirms it is indexed on the node, while
        // `checkpoint` is only populated once it has been finalized.
        let mask = match wait_for {
            WaitForTx::IndexedOnNode => {
                TransactionReadMask::from(TransactionField::TRANSACTION_DIGEST)
            }
            WaitForTx::Finalized => TransactionReadMask::from(TransactionField::CHECKPOINT),
            _ => {
                unimplemented!("a new WaitForTx enum variant was added and needs to be handled")
            }
        };

        let poll = async {
            let mut interval = tokio::time::interval(WAIT_FOR_TX_POLL_INTERVAL);
            loop {
                interval.tick().await;
                let response = self.get_transactions([digest], mask.clone()).await;

                // An absent transaction is not indexed yet — keep polling.
                if let Some(tx) = single_item(response)? {
                    let ready = match wait_for {
                        WaitForTx::IndexedOnNode => true,
                        WaitForTx::Finalized => tx.checkpoint_sequence_number().is_ok(),
                        _ => unreachable!("checked above"),
                    };
                    if ready {
                        return Ok(());
                    }
                }
            }
        };

        tokio::time::timeout(WAIT_FOR_TX_TIMEOUT, poll)
            .await
            .map_err(|_| {
                Error::from(tonic::Status::deadline_exceeded(format!(
                    "timed out waiting for transaction {digest} after {}s",
                    WAIT_FOR_TX_TIMEOUT.as_secs()
                )))
            })?
    }
}

#[cfg(test)]
mod tests {
    use tonic::metadata::MetadataMap;

    use super::{Error, MetadataEnvelope, single_item};
    use crate::api::{ProtocolError, RpcStatus};

    fn not_found_status() -> RpcStatus {
        RpcStatus {
            code: tonic::Code::NotFound.into(),
            message: String::new(),
            details: Vec::new(),
        }
    }

    #[test]
    fn a_not_found_for_the_call_itself_is_not_an_absent_item() {
        let response: Result<MetadataEnvelope<Vec<Result<u32, Error>>>, Error> =
            Err(Error::from(tonic::Status::not_found("no such route")));

        assert!(
            single_item(response).is_err(),
            "a call-level not-found means the endpoint is wrong, not that the item is absent"
        );
    }

    #[test]
    fn a_not_found_for_the_item_is_an_absent_item() {
        let items: Vec<Result<u32, Error>> = vec![Err(Error::Server(not_found_status()))];
        let response = Ok(MetadataEnvelope::new(items, MetadataMap::new()));

        assert!(
            single_item(response)
                .expect("an absent item is not an error")
                .is_none()
        );
    }

    #[test]
    fn an_empty_batch_is_not_an_absent_item() {
        let items: Vec<Result<u32, Error>> = Vec::new();
        let response = Ok(MetadataEnvelope::new(items, MetadataMap::new()));

        assert!(
            matches!(
                single_item(response),
                Err(Error::Protocol(ProtocolError::UnexpectedResultCount {
                    expected: 1,
                    actual: 0
                }))
            ),
            "a batch with no results means the server did not answer the request"
        );
    }

    #[test]
    fn a_batch_with_more_results_than_requested_is_an_error() {
        let items: Vec<Result<u32, Error>> = vec![Ok(1), Ok(2)];
        let response = Ok(MetadataEnvelope::new(items, MetadataMap::new()));

        assert!(
            matches!(
                single_item(response),
                Err(Error::Protocol(ProtocolError::UnexpectedResultCount {
                    expected: 1,
                    actual: 2
                }))
            ),
            "results can no longer be paired with the request, so the first one is not usable"
        );
    }
}
