// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

// use iota_sdk::{
//     IotaClient,
//     rpc_types::{IotaObjectData, IotaObjectDataOptions, IotaObjectResponse},
//     types::{
//         base_types::{ObjectID, ObjectType},
//         object::{MoveObject, Object},
//         transaction::{InputObjectKind, TransactionData, TransactionDataAPI},
//     },
// };
use iota_graphql_client::{
    Client as IotaClient, pagination::PaginationFilter, query_types::ObjectFilter,
};
use iota_types::{Input, Object, ObjectId, Transaction, TransactionKind};

use crate::LedgerSignerError;

pub(crate) async fn load_objects_with_client(
    client: &IotaClient,
    transaction: &Transaction,
) -> Result<Vec<Object>, LedgerSignerError> {
    let object_ids = object_ids_from_transaction(transaction)?;

    if object_ids.is_empty() {
        return Ok(vec![]);
    }

    let responses = client
        .objects(
            ObjectFilter {
                object_ids: Some(object_ids),
                ..Default::default()
            },
            PaginationFilter::default(),
        )
        .await?;

    // TODO properly iterate pages?

    Ok(responses.data)
}

fn object_ids_from_transaction(
    transaction: &Transaction,
) -> Result<Vec<ObjectId>, LedgerSignerError> {
    // TODO v1 ? Need a Tx API ?
    let object_ids = transaction
        .as_v1()
        .gas_payment
        .objects
        .iter()
        .map(|payment| payment.object_id);

    let ptb = if let TransactionKind::ProgrammableTransaction(ptb) = &transaction.as_v1().kind {
        ptb
    } else {
        panic!("Expected ProgrammableTransaction")
    };

    let input_objects = ptb.inputs.iter().filter_map(|input| match input {
        Input::ImmutableOrOwned(object_ref) => Some(object_ref.object_id),
        _ => None,
    });

    let mut unique_ids = HashSet::new();
    unique_ids.extend(object_ids);
    unique_ids.extend(input_objects);

    Ok(unique_ids.into_iter().collect())
}
