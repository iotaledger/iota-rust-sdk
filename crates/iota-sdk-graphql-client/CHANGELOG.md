## [1.0.0-rc.1] - 2026-10-09

### 🚀 Features

- Re-add wasm support for GraphQL subscription streams (#1438)
- *(graphql)* Add `affectedAddress` transaction filter (#1451)
- *(graphql)* Add `AddressTransactionBlockRelationship` (#1452)
- [**breaking**] Hold at most one complex transaction filter (#1461)
- Add typed move_objects queries for GraphQL and gRPC (#1439)
- *(graphql-client)* Re-export reqwest (#1579)
- Re-export iota_types from every crate that names it publicly (#1581)
- *(graphql-client)* Re-export cynic as a public dependency (#1578)
- *(graphql)* [**breaking**] Expose the dry-run transaction and suggested gas price (#1543)
- [**breaking**] Add GraphQLClientBuilder and remove set_rpc_server (#1643)
- Decode the GraphQL server's error codes (#1646)
- *(graphql-client)* [**breaking**] Append Move view call arguments and take the function by package, module and name (#1353)

### 🐛 Bug Fixes

- *(graphql)* Don't drop GraphQL errors (#1546)
- *(graphql-client)* [**breaking**] Return a GraphQLResult from the network constructors (#1638)

### 🚜 Refactor

- Unify sequence-number spelling to sequence_number (#1405)
- *(txn-builder)* [**breaking**] Reduce the public surface of iota-sdk-transaction-builder (#1475)
- Replace the GraphQL client error Kind with a thiserror enum (#1376)
- [**breaking**] Rename `Client` to `GrpcClient` and `GraphQLClient` (#1503)
- Give the GraphQL client a specific error name (#1482)
- *(graphql-client)* [**breaking**] Drop the chrono dependency and its From impl (#1584)
- *(graphql-client)* [**breaking**] Drop the From impls for WebSocket transport errors (#1583)
- *(graphql-client)* [**breaking**] Rename the query fragment types from *Query to *QueryFragment (#1565)
- [**breaking**] Remove dead and inconsistent public API before 1.0 (#1574)
- *(graphql-client)* [**breaking**] Return a query object from chain_id through define_query! (#1566)
- *(graphql-client)* [**breaking**] Return query objects from the paginated methods (#1569)
- *(graphql-client)* [**breaking**] Return query objects from the methods with optional inputs (#1575)
- *(graphql)* [**breaking**] Make query types private and export unnameable trait bounds (#1573)
- [**breaking**] Replace bcs::Error in public signatures with iota_types::BcsError (#1591)
- *(graphql-client)* [**breaking**] Select only the fields each query decodes (#1634)
- [**breaking**] Take base64ct::Error out of the public API (#1589)
- *(graphql-client)* [**breaking**] Stream from the list queries and turn the subscriptions into builders (#1576)
- [**breaking**] Take plain values in the query-object setters (#1657)
- *(graphql)* [**breaking**] Subscription filters to enum-based API (#1644)
- *(graphql-client)* [**breaking**] Return query objects from the methods with nothing to configure (#1577)
- *(graphql-client)* [**breaking**] Make the streams module crate-private (#1659)
- *(graphql-client)* [**breaking**] Take SDK types instead of strings (#1654)
- *(graphql-client)* [**breaking**] Take plain values in the filter builders (#1656)

### ⚙️ Miscellaneous Tasks

- Use a real #[view] function in the move_view_call docs (#1433)
- [**breaking**] Update dependencies (#1346)
- Add docs.rs metadata to the crates missing it (#1595)
- *(graphql-client)* Compile the unit tests only on native targets (#1605)
- Use the README as the crate docs where it can carry them (#1602)

## [1.0.0-beta.1] - 2026-08-31

### 🚀 Features

- Make public enums non_exhaustive (#487)
- *(transaction-builder)* Add `DryRunResult` associated type to `ClientMethods` (#508)
- *(iota-sdk-graphql-client)* Add move_view_call (#516)
- *(graphql)* Add `request_and_wait_for_finalized` for better waiting on faucet funds (#552)
- *(scripts)* Add cargo sort script (#1061)
- Use Version struct over type def (#1084)
- *(types)* Enhance Identifier, TypeTag and StructTag (#1092)
- *(iota-sdk-types)* EndOfEpochTransactionKind changes (#980) (#1106)
- *(gRPC)* Add grpc client, types and proto-build (#1062)
- Update `TransactionEffects` (#580)
- Implement ClientMethods for the gRPC client (#1190)
- *(bindings)* Add wasm (#1020)
- Add distinct digest newtype wrappers (#1232)
- Expose Error::kind() with HTTP status and decode-target context (#1170)
- *(grpc)* Improve client API with typed per-endpoint read masks (#1253)
- Add ServiceConfig::supports_feature (#1333)
- [**breaking**] Use GraphQL subscriptions for events_stream and transactions_stream (#1194)
- [**breaking**] Make GraphQL filter types non_exhaustive (#1343)
- *(bindings)* Expose GraphQL subscriptions over the FFI (#1303)
- Add transaction_builder constructors to the clients (#1359)
- *(transaction-builder)* Split transaction builder client trait (#1280)

### 🐛 Bug Fixes

- *(tx-builder)* Fix WaitForTx::Indexed usage and docs (#548)
- *(faucet)* Fix request_and_wait() (#546)
- *(transaction-builder)* Send TransactionMetadata in dry-run to avoid gas_budget=0 (#1042)
- Surface HTTP status and body when GraphQL response decode fails (#1185)
- Surface GraphQL errors instead of panicking on partial responses (#1229)
- Unbreak feature-powerset check, tests, and tx examples (#1238)
- Forward pagination arguments in the checkpoints GraphQL query (#1245)
- Remove FaucetClient::new_testnet() as the testnet faucet is web-only (#1244)
- Remove redundant borrows flagged by clippy 1.97 (#1267)
- Remove FaucetClient::new_devnet() as the devnet faucet is web-only (#1276)
- *(graphql)* Reconstruct CheckpointSummary from bcs (#1235)
- *(iota-sdk-graphql-client)* Send a zero gas budget for a dry run (#1354)

### 🚜 Refactor

- *(graphql-client)* Split lib.rs into modular API files (#535)
- Reverse dependency between graphql-client and transaction-builder (#530)
- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- [**breaking**] Make the SenderSignedTransaction inner field private (#1351)
- Name type_ fields after the type they hold (#1369)
- Use one GraphQL casing in exported names (#1377)
- Spell out transaction in client API names (#1388)

### ⚙️ Miscellaneous Tasks

- Fix broken links (#443)
- Bump to edition 2024 (#481)
- *(iota-sdk-types)* Make `StructTag` fields private (#486)
- Rename `Address::STD_LIB` to `Address::STD` (#488)
- Remove eyre from crates APIs (#484)
- Some nits (#483)
- Typos (#562)
- *(examples+tests)* Switch to testnet (#997)
- Add clippy:redundant_clone to workspace lints (#1035)
- Remove ZkLogin and JWK (#1071)
- Standardize derive macro ordering across codebase (#1158)
- Rename `ClientMethods` to `TransactionBuilderClient` (#1198)
- Fix flaky coins_stream test (#1252)
- Make transaction data/effects tests localnet-stable (#1281)
- Rename content_digest -> contents_digest (#1284)
- *(ci)* Bump the localnet test binary to v1.29.0 (#1335)

## [0.0.1-alpha.1] - 2025-11-07

Initial Release
