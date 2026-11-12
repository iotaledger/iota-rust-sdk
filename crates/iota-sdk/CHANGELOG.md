## [3.0.0-rc.1] - 2026-10-09

### 🚀 Features

- *(grpc)* View_function_call (#1291)
- Add the gRPC client to the FFI bindings (#1477)
- [**breaking**] Hold at most one complex transaction filter (#1461)
- Add gRPC transaction execution and simulation to the FFI bindings (#1498)
- Add gRPC checkpoint reads, streams and filters to the FFI bindings (#1511)
- Add gRPC view function calls to the FFI bindings (#1517)
- Add typed move_objects queries for GraphQL and gRPC (#1439)
- *(graphql-client)* [**breaking**] Append Move view call arguments and take the function by package, module and name (#1353)

### 🐛 Bug Fixes

- *(graphql)* Don't drop GraphQL errors (#1546)
- *(iota-sdk)* [**breaking**] Route rand, ed25519 and move-types serde through the umbrella features (#1596)
- *(graphql-client)* [**breaking**] Return a GraphQLResult from the network constructors (#1638)

### 🚜 Refactor

- Align gRPC client method naming with the GraphQL client (#1408)
- *(types)* [**breaking**] Reduce the public surface of iota-sdk-types (#1473)
- [**breaking**] Rename `Client` to `GrpcClient` and `GraphQLClient` (#1503)
- Give the GraphQL client a specific error name (#1482)
- *(txn-builder)* [**breaking**] Make gas sponsorship a capability the caller passes in (#1504)
- *(grpc-client)* [**breaking**] Move the list queries' optional inputs to setters (#1554)
- *(grpc-client)* [**breaking**] Move the read masks and `skip_checks` to setters (#1555)
- *(grpc-client)* [**breaking**] Move the optional inputs of checkpoints, execution, epoch and health to setters (#1556)
- *(grpc-client)* [**breaking**] Move the checkpoint streams' inputs to setters (#1557)
- [**breaking**] Remove dead and inconsistent public API before 1.0 (#1574)
- *(graphql-client)* [**breaking**] Return query objects from the paginated methods (#1569)
- *(graphql-client)* [**breaking**] Return query objects from the methods with optional inputs (#1575)
- *(graphql)* [**breaking**] Make query types private and export unnameable trait bounds (#1573)
- *(graphql-client)* [**breaking**] Stream from the list queries and turn the subscriptions into builders (#1576)
- *(graphql)* [**breaking**] Subscription filters to enum-based API (#1644)
- *(graphql-client)* [**breaking**] Take SDK types instead of strings (#1654)
- *(graphql-client)* [**breaking**] Take plain values in the filter builders (#1656)

### ⚙️ Miscellaneous Tasks

- Run the flaky examples against localnet (#1471)
- Rename gRPC examples to use a grpc_ prefix (#1487)
- *(docs)* Point localnet instructions at iota-localnet (#1509)
- *(iota-sdk)* [**breaking**] Rename `txn-builder` feature to `transaction-builder` (#1515)
- [**breaking**] Update dependencies (#1346)
- Add docs.rs metadata to the crates missing it (#1595)
- *(iota-sdk)* Add a README and use it as the crate docs (#1603)

## [3.0.0-beta.1] - 2026-08-31

### 🚀 Features

- *(iota-sdk-crypto)* Add generate_mnemonic() (#424)
- *(ci)* Run rust examples (#447)
- *(transaction-builder)* Add support for extensible async signer (#445)
- Make sure `iota-sdk` is wasm compatible (#476)
- Make public enums non_exhaustive (#487)
- Add examples using the releases (#409)
- *(ffi)* Add `to_json` and `from_json` to most types (#520)
- *(iota-sdk-graphql-client)* Add move_view_call (#516)
- Add AA bindings examples (#541)
- *(graphql)* Add `request_and_wait_for_finalized` for better waiting on faucet funds (#552)
- *(examples)* Remove obsolete sleep (#1024)
- *(examples)* Add multisig example to Rust and all bindings (#988)
- *(types)* Add versioning to MoveAuthenticator (#1002)
- Add polling indexer example using graphql client (#978)
- *(iota-rust-sdk)* [**breaking**] Add more feature gates (#1050)
- *(scripts)* Add cargo sort script (#1061)
- Use Version struct over type def (#1084)
- *(types)* Enhance Identifier, TypeTag and StructTag (#1092)
- Add move package example (#1046)
- MoveStruct improvements (#1119)
- `TransactionKind` improvements (#1130)
- *(iota-sdk-types)* [**breaking**] Make MoveStruct contents checked (#1133)
- *(gRPC)* Add grpc client, types and proto-build (#1062)
- Update `TransactionEffects` (#580)
- [**breaking**] `MultisigAggregatedSignature` changes (#1137)
- *(iota-sdk-types)* Update `Object` (#1186)
- Add address_transactions example (#1172)
- Add `iota-sdk-move-types` crate (#1124)
- Add distinct digest newtype wrappers (#1232)
- *(grpc)* Improve client API with typed per-endpoint read masks (#1253)
- Add on-chain deny-rule transaction kinds and DenyRuleSet
- Add random() to the private key types (#1310)
- [**breaking**] Use GraphQL subscriptions for events_stream and transactions_stream (#1194)
- *(iota-sdk-transaction-builder)* Add authorize_upgrade and commit_upgrade helpers (#1339)
- [**breaking**] Make GraphQL filter types non_exhaustive (#1343)
- Add transaction_builder constructors to the clients (#1359)

### 🐛 Bug Fixes

- *(examples)* Update package id for events (#1008)
- Correct wasm getrandom configuration for downstream consumers (#1193)
- Unbreak feature-powerset check, tests, and tx examples (#1238)
- *(examples)* Avoid type-only object queries that time out (#1296)

### 🚜 Refactor

- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- Name type_ fields after the type they hold (#1369)
- Spell out transaction in client API names (#1388)
- Unify option-accessor spelling to opt_x (#1391)

### ⚙️ Miscellaneous Tasks

- *(examples)* Import through `iota-sdk` (#478)
- Bump to edition 2024 (#481)
- *(iota-sdk-types)* Make `StructTag` fields private (#486)
- Rename `Address::STD_LIB` to `Address::STD` (#488)
- *(transaction-builder)* Rename `name` to `assign` (#482)
- Some nits (#483)
- *(examples)* Replace more instances of `request_and_wait` (#554)
- *(examples+tests)* Switch to testnet (#997)
- Add clippy:redundant_clone to workspace lints (#1035)
- Re-enable AA examples (#1038)
- Remove ZkLogin and JWK (#1071)
- Remove `schemars` (#1073)
- Standardize derive macro ordering across codebase (#1158)
- Rename enum opt/mut getters (#1138)
- Make transaction data/effects tests localnet-stable (#1281)
- Rename content_digest -> contents_digest (#1284)
- Re-enable the Move view call examples (#1348)
- Add reference docs generation for all binding languages (#1249)
- Add cargo-semver-checks job (#1349)
- Add missing crate metadata and README files (#1386)

## [3.0.0-alpha.1] - 2025-11-07

Initial Release
