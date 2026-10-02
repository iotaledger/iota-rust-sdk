// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The client against a transport that replays recorded server responses.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{StreamExt, TryStreamExt};
use iota_sdk_graphql_client_next::{
    Error, GraphQLClient, RetryPolicy, TransportError, TransportErrorKind, TypeFilter,
    iota_client_api::LedgerClient,
    iota_types::{
        Address, GasPayment, ObjectId, ProgrammableTransaction, StructTag, Transaction,
        TransactionDigest, TransactionExpiration, TransactionKind, TransactionV1,
    },
    transport::{BoxFuture, HttpRequest, HttpResponse, Transport},
};
use serde_json::Value;

const MAINNET: &str = "1.32.1-de85b83edc93";
const TESTNET: &str = "1.33.1-rc-d864b0092161";

/// Replays queued responses and records the requests it receives.
#[derive(Clone, Debug, Default)]
struct Replay {
    state: Arc<Mutex<ReplayState>>,
}

#[derive(Debug, Default)]
struct ReplayState {
    replies: VecDeque<Option<HttpResponse>>,
    requests: Vec<HttpRequest>,
}

impl Replay {
    /// Answer the next request with `body`, from a server running `version`.
    fn reply(&self, version: &str, body: &str) -> &Self {
        self.reply_with_status(200, version, body)
    }

    fn reply_with_status(&self, status: u16, version: &str, body: &str) -> &Self {
        let headers = vec![("x-iota-rpc-version".to_owned(), version.to_owned())];
        self.state
            .lock()
            .unwrap()
            .replies
            .push_back(Some(HttpResponse::new(
                status,
                headers,
                body.as_bytes().to_vec(),
            )));
        self
    }

    /// Never answer the next request.
    fn hang(&self) {
        self.state.lock().unwrap().replies.push_back(None);
    }

    fn requests(&self) -> Vec<HttpRequest> {
        self.state.lock().unwrap().requests.clone()
    }

    fn bodies(&self) -> Vec<Value> {
        self.requests()
            .iter()
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }

    fn client(&self) -> GraphQLClient {
        GraphQLClient::builder("http://localhost:9125/graphql")
            .transport(self.clone())
            .retry(
                RetryPolicy::new(3)
                    .with_backoff(Duration::from_millis(1), Duration::from_millis(1)),
            )
            .build()
            .unwrap()
    }
}

impl Transport for Replay {
    fn post(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        let reply = {
            let mut state = self.state.lock().unwrap();
            state.requests.push(request);
            state
                .replies
                .pop_front()
                .expect("no reply left for the request")
        };
        Box::pin(async move {
            match reply {
                Some(response) => Ok(response),
                None => std::future::pending().await,
            }
        })
    }
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The selection of the first field named `field` in `query`, up to its
/// closing brace.
fn selection<'a>(query: &'a str, field: &str) -> &'a str {
    let start = query.find(&format!("{field} {{")).unwrap();
    let end = start + query[start..].find('}').unwrap();
    &query[start..end]
}

fn transaction_without_gas_objects() -> Transaction {
    Transaction::V1(TransactionV1 {
        kind: TransactionKind::Programmable(ProgrammableTransaction {
            inputs: Vec::new(),
            commands: Vec::new(),
        }),
        sender: Address::ZERO,
        gas_payment: GasPayment {
            objects: Vec::new(),
            owner: Address::ZERO,
            price: 1000,
            budget: 50_000_000,
        },
        expiration: TransactionExpiration::None,
    })
}

#[tokio::test]
async fn learns_the_server_version_from_responses() {
    let replay = Replay::default();
    replay.reply(MAINNET, r#"{"data":{"chainIdentifier":"6364aad5"}}"#);
    let client = replay.client();
    assert_eq!(client.server_version(), None);

    assert_eq!(client.chain_id().await.unwrap(), "6364aad5");

    let version = client.server_version().unwrap();
    assert_eq!(version.as_str(), MAINNET);
    assert!(!version.is_at_least(1, 33, 0));
}

#[tokio::test]
async fn json_objects_select_only_the_contents_json() {
    let replay = Replay::default();
    replay.reply(MAINNET, &fixture("object_json.json"));

    let contents = replay
        .client()
        .object(ObjectId::SYSTEM_STATE)
        .json()
        .await
        .unwrap()
        .unwrap();

    assert!(contents.is_object());
    let request = &replay.bodies()[0];
    assert_eq!(
        request["variables"]["objectId"],
        ObjectId::SYSTEM_STATE.to_string()
    );
    let query = request["query"].as_str().unwrap();
    assert!(query.contains("json"));
    assert!(!query.contains("bcs"));
}

#[tokio::test]
async fn events_carry_their_transaction_and_skip_package_bytes() {
    let replay = Replay::default();
    replay.reply(TESTNET, &fixture("events.json"));

    let page = replay
        .client()
        .events()
        .event_type(TypeFilter::Package(Address::FRAMEWORK))
        .last(2)
        .await
        .unwrap();

    assert_eq!(page.len(), 2);
    for event in page.items() {
        assert!(event.transaction_digest.is_some());
        assert_eq!(event.event_type.address(), Address::FRAMEWORK);
        assert!(!event.contents.is_empty());
    }
    let request = &replay.bodies()[0];
    assert_eq!(
        request["variables"]["filter"]["eventType"],
        Address::FRAMEWORK.to_string()
    );
    assert_eq!(request["variables"]["last"], 2);
    let query = request["query"].as_str().unwrap();
    assert!(!selection(query, "package").contains("bcs"));
}

#[tokio::test]
async fn coins_are_filtered_by_their_coin_type() {
    let replay = Replay::default();
    replay.reply(MAINNET, &fixture("coins.json"));
    let owner = Address::ZERO;

    let coins = replay
        .client()
        .coins(owner)
        .coin_type(StructTag::new_gas())
        .await
        .unwrap();

    assert!(!coins.is_empty());
    let filter = &replay.bodies()[0]["variables"]["filter"];
    assert_eq!(filter["owner"], owner.to_string());
    assert_eq!(filter["type"], StructTag::new_gas_coin().to_string());
}

#[tokio::test]
async fn balance_sums_the_coin_type() {
    let replay = Replay::default();
    replay.reply(MAINNET, &fixture("balance.json"));

    let balance = replay.client().balance(Address::ZERO).await.unwrap();

    assert_eq!(balance.coin_type, StructTag::new_gas());
    assert_eq!(balance.total_balance, 10_191_558_270_400);
    assert_eq!(balance.coin_object_count, 1);
    assert_eq!(
        replay.bodies()[0]["variables"]["coinType"],
        StructTag::new_gas().to_string()
    );
}

#[tokio::test]
async fn transaction_effects_alone() {
    let replay = Replay::default();
    replay.reply(MAINNET, &fixture("transaction_effects.json"));
    let digest = TransactionDigest::ZERO;

    let effects = replay.client().transaction(digest).effects().await.unwrap();

    assert!(effects.is_some());
    assert_eq!(
        replay.bodies()[0]["variables"]["digest"],
        digest.to_string()
    );
}

#[tokio::test]
async fn items_follow_the_end_cursor_with_the_same_page_size() {
    let replay = Replay::default();
    replay
        .reply(MAINNET, &fixture("effects_page_1.json"))
        .reply(MAINNET, &fixture("effects_page_2.json"));

    let effects = replay
        .client()
        .transactions()
        .effects()
        .first(2)
        .items()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

    assert_eq!(effects.len(), 4);
    let first_page: Value = serde_json::from_str(&fixture("effects_page_1.json")).unwrap();
    let requests = replay.bodies();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["variables"]["first"], 2);
    assert!(requests[0]["variables"]["after"].is_null());
    assert_eq!(requests[1]["variables"]["first"], 2);
    assert_eq!(
        requests[1]["variables"]["after"],
        first_page["data"]["transactionBlocks"]["pageInfo"]["endCursor"]
    );
}

#[tokio::test]
async fn backward_items_come_from_the_end_of_the_list() {
    let pages_replay = Replay::default();
    pages_replay
        .reply(MAINNET, &fixture("effects_page_2.json"))
        .reply(MAINNET, &fixture("effects_page_1.json"));
    let pages = pages_replay
        .client()
        .transactions()
        .effects()
        .last(2)
        .pages()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let expected = pages
        .into_iter()
        .flat_map(|page| page.into_items().into_iter().rev())
        .collect::<Vec<_>>();

    let replay = Replay::default();
    replay
        .reply(MAINNET, &fixture("effects_page_2.json"))
        .reply(MAINNET, &fixture("effects_page_1.json"));
    let items = replay
        .client()
        .transactions()
        .effects()
        .last(2)
        .items()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

    assert_eq!(items, expected);
    let second_page: Value = serde_json::from_str(&fixture("effects_page_2.json")).unwrap();
    let requests = replay.bodies();
    assert_eq!(requests[1]["variables"]["last"], 2);
    assert_eq!(
        requests[1]["variables"]["before"],
        second_page["data"]["transactionBlocks"]["pageInfo"]["startCursor"]
    );
}

#[tokio::test]
async fn a_failed_page_ends_the_stream_after_the_error() {
    let replay = Replay::default();
    replay
        .reply(MAINNET, &fixture("effects_page_1.json"))
        .reply_with_status(400, MAINNET, "bad request");

    let pages = replay
        .client()
        .transactions()
        .effects()
        .first(2)
        .pages()
        .collect::<Vec<_>>()
        .await;

    assert_eq!(pages.len(), 2);
    let resume = pages[0].as_ref().unwrap().end_cursor().cloned().unwrap();
    assert!(pages[1].is_err());

    replay.reply(MAINNET, &fixture("effects_page_2.json"));
    let resumed = replay
        .client()
        .transactions()
        .effects()
        .first(2)
        .after(resume.clone())
        .await
        .unwrap();
    assert_eq!(resumed.len(), 2);
    assert_eq!(replay.bodies()[2]["variables"]["after"], resume.as_str());
}

#[tokio::test]
async fn retries_transient_failures() {
    let replay = Replay::default();
    replay
        .reply_with_status(503, MAINNET, "<html>Service Unavailable</html>")
        .reply(MAINNET, r#"{"data":{"chainIdentifier":"6364aad5"}}"#);

    assert_eq!(replay.client().chain_id().await.unwrap(), "6364aad5");
    assert_eq!(replay.requests().len(), 2);
}

#[tokio::test]
async fn a_single_attempt_policy_does_not_retry() {
    let replay = Replay::default();
    replay.reply_with_status(503, MAINNET, "<html>Service Unavailable</html>");
    let client = GraphQLClient::builder("http://localhost:9125/graphql")
        .transport(replay.clone())
        .retry(RetryPolicy::none())
        .build()
        .unwrap();

    let Err(Error::Transport(error)) = client.chain_id().await else {
        panic!("expected a transport error");
    };
    assert_eq!(error.status_code(), Some(503));
    assert_eq!(replay.requests().len(), 1);
}

#[tokio::test]
async fn server_errors_keep_their_code_and_are_not_retried() {
    let replay = Replay::default();
    replay.reply(
        TESTNET,
        r#"{"data":null,"errors":[{"message":"Connection's page size of 1000 exceeds max of 50","path":["events"],"extensions":{"code":"BAD_USER_INPUT"}}]}"#,
    );

    let Err(Error::Server(errors)) = replay.client().events().first(1000).await else {
        panic!("expected a server error");
    };
    assert!(errors.has_code("BAD_USER_INPUT"));
    assert_eq!(replay.requests().len(), 1);
}

#[tokio::test]
async fn dry_runs_select_fields_by_server_version() {
    let transaction = transaction_without_gas_objects();

    let replay = Replay::default();
    replay
        .reply(MAINNET, r#"{"data":{"chainIdentifier":"6364aad5"}}"#)
        .reply(MAINNET, &fixture("dry_run_1_32.json"));
    let result = replay.client().dry_run(&transaction).await.unwrap();
    let requests = replay.bodies();
    assert_eq!(requests[0]["operationName"], "ChainIdentifierQuery");
    let query = requests[1]["query"].as_str().unwrap();
    assert!(!query.contains("suggestedGasPrice"));
    assert!(!query.contains("bcsUnsigned"));
    assert_eq!(requests[1]["variables"]["txMeta"]["gasPrice"], 1000);
    assert!(result.effects.is_some());
    assert_eq!(result.transaction, None);
    assert_eq!(result.suggested_gas_price, None);

    let replay = Replay::default();
    replay
        .reply(TESTNET, r#"{"data":{"chainIdentifier":"2304aa97"}}"#)
        .reply(TESTNET, &fixture("dry_run_1_33.json"));
    let result = replay.client().dry_run(&transaction).await.unwrap();
    let query = replay.bodies()[1]["query"].as_str().unwrap().to_owned();
    assert!(query.contains("suggestedGasPrice"));
    assert!(query.contains("bcsUnsigned"));
    assert!(result.transaction.is_some());
    assert_eq!(result.suggested_gas_price, Some(1000));
}

#[tokio::test]
async fn requests_carry_the_configured_headers() {
    let replay = Replay::default();
    replay.reply(MAINNET, r#"{"data":{"chainIdentifier":"6364aad5"}}"#);
    let client = GraphQLClient::builder("http://localhost:9125/graphql")
        .transport(replay.clone())
        .header("x-api-key", "secret")
        .build()
        .unwrap();

    client.chain_id().await.unwrap();

    let request = &replay.requests()[0];
    let header = |name: &str| {
        request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    assert_eq!(header("x-api-key").as_deref(), Some("secret"));
    assert_eq!(
        header("user-agent").as_deref(),
        Some(iota_sdk_graphql_client_next::USER_AGENT)
    );
    assert_eq!(header("content-type").as_deref(), Some("application/json"));
}

#[tokio::test]
async fn each_attempt_has_a_deadline() {
    let replay = Replay::default();
    replay.hang();
    let client = GraphQLClient::builder("http://localhost:9125/graphql")
        .transport(replay.clone())
        .timeout(Duration::from_millis(20))
        .retry(RetryPolicy::none())
        .build()
        .unwrap();

    let Err(Error::Transport(error)) = client.chain_id().await else {
        panic!("expected a transport error");
    };
    assert_eq!(error.kind(), TransportErrorKind::Timeout);
}

#[tokio::test]
async fn waiting_polls_until_the_transaction_is_finalized() {
    let replay = Replay::default();
    replay
        .reply(MAINNET, r#"{"data":{"transactionBlock":null}}"#)
        .reply(MAINNET, &fixture("finalized.json"));

    replay
        .client()
        .wait_for_transaction(TransactionDigest::ZERO)
        .await
        .unwrap();

    assert_eq!(replay.requests().len(), 2);
}

#[tokio::test]
async fn waiting_gives_up_at_its_deadline() {
    let replay = Replay::default();
    for _ in 0..10 {
        replay.reply(MAINNET, r#"{"data":{"transactionBlock":null}}"#);
    }

    let result = replay
        .client()
        .wait_for_transaction(TransactionDigest::ZERO)
        .timeout(Duration::from_millis(150))
        .await;

    assert!(matches!(result, Err(Error::TimedOut(_))));
}

#[tokio::test]
async fn the_ledger_client_cursor_round_trips() {
    let replay = Replay::default();
    replay
        .reply(MAINNET, &fixture("coins.json"))
        .reply(MAINNET, &fixture("coins.json"));
    let client = replay.client();

    let page = LedgerClient::objects(&client, None, Address::ZERO, None, Some(3))
        .await
        .unwrap();
    let response: Value = serde_json::from_str(&fixture("coins.json")).unwrap();
    let page_info = &response["data"]["objects"]["pageInfo"];
    assert_eq!(
        page.next_cursor.is_some(),
        page_info["hasNextPage"].as_bool().unwrap()
    );

    let cursor = page_info["endCursor"].as_str().unwrap();
    LedgerClient::objects(
        &client,
        None,
        Address::ZERO,
        Some(cursor.as_bytes().to_vec()),
        Some(3),
    )
    .await
    .unwrap();
    let requests = replay.bodies();
    assert_eq!(requests[0]["variables"]["first"], 3);
    assert_eq!(requests[1]["variables"]["after"], cursor);
}

#[cfg(feature = "move-types")]
#[tokio::test]
async fn decoded_objects_are_filtered_by_their_rust_type() {
    use iota_move_types::{
        MoveObject,
        iota_framework::{coin::Coin, iota::IOTA},
    };

    let replay = Replay::default();
    replay.reply(MAINNET, &fixture("iota_coins.json"));

    let page = replay
        .client()
        .objects()
        .owner(Address::ZERO)
        .decode::<Coin<IOTA>>()
        .await
        .unwrap();

    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].value.balance.value, 10_191_558_270_400);
    assert_eq!(
        replay.bodies()[0]["variables"]["filter"]["type"],
        Coin::<IOTA>::struct_tag().to_string()
    );
}
