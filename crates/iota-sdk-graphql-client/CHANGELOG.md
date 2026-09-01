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
