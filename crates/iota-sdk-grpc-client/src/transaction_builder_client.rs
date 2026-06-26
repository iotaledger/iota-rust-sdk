// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`TransactionBuilderClient`] for the GRPC [`Client`].

use std::time::Duration;

use iota_grpc_types::{
    read_mask_fields::{EpochField, TransactionField},
    v1::transaction_execution_service::SimulatedTransaction,
};
use iota_transaction_builder::{ObjectsPage, ProtocolConfig, TransactionBuilderClient, WaitForTx};
use iota_types::{
    Address, Object, ObjectId, SignedTransaction, StructTag, Transaction, TransactionDigest,
    TransactionEffects, UserSignature, Version,
};

use crate::{
    Client,
    api::{Error, saturating_usize_to_u32},
};

/// How long [`TransactionBuilderClient::wait_for_tx`] polls before giving up.
const WAIT_FOR_TX_TIMEOUT: Duration = Duration::from_secs(60);
/// Interval between polls in [`TransactionBuilderClient::wait_for_tx`].
const WAIT_FOR_TX_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Returns `true` if the error represents a "not found" response from the
/// server. Used to map a missing object/transaction to `Ok(None)` (and to keep
/// polling while waiting for a transaction to be indexed).
fn is_not_found(err: &Error) -> bool {
    match err {
        Error::Server(status) => status.code == tonic::Code::NotFound as i32,
        Error::Grpc(status) => status.code() == tonic::Code::NotFound,
        _ => false,
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
        match self
            .get_objects_with_versions([(object_id, version.into())])
            .await
        {
            Ok(envelope) => match envelope.into_inner().first() {
                Some(obj) => Ok(Some(obj.object()?)),
                None => Ok(None),
            },
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(e),
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
            .get_epoch_masked(None, EpochField::PROTOCOL_CONFIG_ATTRIBUTES)
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
        match self
            .get_transactions_masked(
                [digest],
                [TransactionField::TRANSACTION, TransactionField::SIGNATURES],
            )
            .await
        {
            Ok(envelope) => match envelope.into_inner().into_iter().next() {
                Some(tx) => {
                    let transaction = tx.transaction()?.transaction()?;
                    let signatures = Vec::<UserSignature>::try_from(tx.signatures()?)?;
                    Ok(Some(SignedTransaction {
                        transaction,
                        signatures,
                    }))
                }
                None => Ok(None),
            },
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        match self
            .get_transactions_masked([digest], TransactionField::EFFECTS_BCS)
            .await
        {
            Ok(envelope) => match envelope.into_inner().into_iter().next() {
                Some(tx) => Ok(Some(tx.effects()?.effects()?)),
                None => Ok(None),
            },
            Err(e) if is_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        let epoch = self
            .get_epoch_masked(epoch.into(), EpochField::REFERENCE_GAS_PRICE)
            .await?
            .into_inner();
        Ok(epoch.reference_gas_price)
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        // Simulate with relaxed checks and read the gas used from the resulting
        // effects.
        let simulated = self.simulate_transaction(tx.clone(), true).await?;
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
            .simulate_transaction(tx.clone(), skip_checks)
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
            .execute_transaction(signed_transaction, None)
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
            WaitForTx::IndexedOnNode => TransactionField::TRANSACTION_DIGEST,
            WaitForTx::Finalized => TransactionField::CHECKPOINT,
            _ => {
                unimplemented!("a new WaitForTx enum variant was added and needs to be handled")
            }
        };

        let poll = async {
            let mut interval = tokio::time::interval(WAIT_FOR_TX_POLL_INTERVAL);
            loop {
                interval.tick().await;
                match self.get_transactions_masked([digest], mask.clone()).await {
                    Ok(envelope) => {
                        if let Some(tx) = envelope.into_inner().first() {
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
                    // Not indexed yet — keep polling.
                    Err(e) if is_not_found(&e) => {}
                    Err(e) => return Err(e),
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
