## [1.0.0-beta.1] - 2026-08-31

### 🚀 Features

- *(transaction-builder)* Add support for extensible async signer (#445)
- Make sure `iota-sdk` is wasm compatible (#476)
- *(ci)* Add license check workflow (#480)
- Make public enums non_exhaustive (#487)
- Add Move Authenticator support (#442)
- *(transaction-builder)* Add `DryRunResult` associated type to `ClientMethods` (#508)
- *(iota-sdk-graphql-client)* Add move_view_call (#516)
- *(transaction-builder)* Add `set_sender` method (#549)
- *(types)* Add versioning to MoveAuthenticator (#1002)
- *(scripts)* Add cargo sort script (#1061)
- Use Version struct over type def (#1084)
- *(types)* Enhance Identifier, TypeTag and StructTag (#1092)
- ObjectReference changes for monorepo (#522) (#1097)
- *(iota-sdk-types)* [**breaking**] Add Input consts and methods (#1105)
- `TransactionKind` improvements (#1130)
- *(transaction-builder)* Impl TryFrom<Transaction> for TransactionBuilder (#1129)
- *(transaction-builder)* Re-export dry run types (#1144)
- Update `TransactionEffects` (#580)
- *(iota-sdk-types)* Update `Object` (#1186)
- Implement ClientMethods for the gRPC client (#1190)
- Changes to `MoveAuthenticator` (#1231)
- Add distinct digest newtype wrappers (#1232)
- *(txn-builder)* Add `finish_kind` and `gas_refs` (#1289)
- *(txn-builder)* Resolve input objects in one request (#1290)
- *(grpc)* Improve client API with typed per-endpoint read masks (#1253)
- Add a multi-recipient pay helper to the transaction builder (#1278)
- *(iota-sdk-transaction-builder)* Add authorize_upgrade and commit_upgrade helpers (#1339)
- *(transaction-builder)* Split transaction builder client trait (#1280)

### 🐛 Bug Fixes

- *(iota-sdk-transaction-builder)* Always wait for gas station tx to be indexed (#536)
- *(tx-builder)* Fix WaitForTx::Indexed usage and docs (#548)
- *(transaction-builder)* Send TransactionMetadata in dry-run to avoid gas_budget=0 (#1042)
- *(txn-builder)* Paginate auto gas-coin selection (#1162)
- Correct wasm getrandom configuration for downstream consumers (#1193)

### 🚜 Refactor

- Reverse dependency between graphql-client and transaction-builder (#530)
- [**breaking**] Rename TransactionBuilder::arg to result (#1338)
- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- Name type_ fields after the type they hold (#1369)
- Rename TransactionBuilder::set_sender to sender and make it chainable (#1382)
- Spell out transaction in client API names (#1388)

### ⚙️ Miscellaneous Tasks

- Bump to edition 2024 (#481)
- *(iota-sdk-types)* Make `StructTag` fields private (#486)
- Rename `Address::STD_LIB` to `Address::STD` (#488)
- *(transaction-builder)* Rename `name` to `assign` (#482)
- *(examples+tests)* Switch to testnet (#997)
- Add clippy:redundant_clone to workspace lints (#1035)
- Standardize derive macro ordering across codebase (#1158)
- Rename `ClientMethods` to `TransactionBuilderClient` (#1198)
- Add missing crate metadata and README files (#1386)

## [0.0.1-alpha.1] - 2025-11-07

Initial Release
