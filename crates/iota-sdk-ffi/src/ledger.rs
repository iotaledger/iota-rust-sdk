// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_sdk::types::crypto::SignatureScheme;

// use crate::graphql::GraphQLClient;
use crate::types::{
    address::Address,
    crypto::Ed25519PublicKey,
    signature::{SimpleSignature, UserSignature},
    transaction::Transaction,
};

#[derive(uniffi::Object)]
pub struct LedgerSigner(pub iota_ledger_signer::LedgerSigner);

#[derive(Debug, derive_more::Display, uniffi::Object)]
pub struct LedgerSignerError(iota_ledger_signer::LedgerSignerError);

#[uniffi::export]
impl LedgerSigner {
    #[uniffi::constructor]
    pub fn new_with_default(
        path: String,
        // TODO
        // client: Arc<GraphQLClient>,
    ) -> Result<Self, LedgerSignerError> {
        // TODO unwrap
        let collect = bip32::DerivationPath::from_str(&path).unwrap();
        // .into_iter()
        // .map(|c| c.0)
        // .collect::<Vec<_>>();
        let path = collect;

        Ok(Self(
            iota_ledger_signer::LedgerSigner::new_with_default(
                path, // TODO unwrap
                None,
            )
            .map_err(LedgerSignerError)?,
        ))
    }

    // pub fn new(ledger: Ledger, path: bip32::DerivationPath, client:
    // Option<IotaClient>) -> Self {     LedgerSigner {
    //         ledger,
    //         path,
    //         client,
    //     }
    // }

    // pub fn get_signature_scheme(&self) -> SignatureScheme {
    //     self.0.get_signature_scheme()
    // }

    pub fn get_address(&self) -> Result<Address, LedgerSignerError> {
        Ok(self
            .0
            .get_address()
            .map(Address::from)
            .map_err(LedgerSignerError)?)
    }

    pub fn get_public_key(&self) -> Result<Ed25519PublicKey, LedgerSignerError> {
        Ok(self
            .0
            .get_public_key()
            .map(Ed25519PublicKey::from)
            .map_err(LedgerSignerError)?)
    }

    pub async fn sign_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<UserSignature, LedgerSignerError> {
        let signature = self
            .0
            .sign_transaction_unchecked(&transaction.0)
            .await
            .map_err(LedgerSignerError)?;

        Ok(UserSignature::new_simple(&SimpleSignature::new_ed25519(
            &(signature.signature.into()),
            &(signature.public_key.into()),
        )))
    }

    //     pub async fn sign_transaction(
    //         &self,
    //         transaction: &Transaction,
    //         address: &Address,
    //     ) -> Result<SignedTransaction, LedgerSignerError> {
    //         let objects = if let Some(client) = &self.client {
    //             match utils::load_objects_with_client(client, transaction).await
    // {                 Ok(objects) => objects,
    //                 Err(e) => {
    //                     warn!("Failed to load objects: {e}. Falling back to
    // blind-signing.");                     vec![]
    //                 }
    //             }
    //         } else {
    //             vec![]
    //         };

    //         self.ledger
    //             .sign_intent(
    //                 &self.path,
    //                 address,
    //                 Intent::iota_transaction(),
    //                 transaction,
    //                 objects,
    //             )
    //             .map_err(LedgerSignerError::from)
    //     }

    //     pub fn sign_message(
    //         &self,
    //         message: Vec<u8>,
    //         address: &Address,
    //     ) -> Result<SignedTransaction, LedgerSignerError> {
    //         self.ledger
    //             .sign_intent(
    //                 &self.path,
    //                 address,
    //                 Intent::personal_message(),
    //                 &message,
    //                 vec![],
    //             )
    //             .map_err(LedgerSignerError::from)
    //     }
}
