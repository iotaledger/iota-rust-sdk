## [1.0.0-beta.1] - 2026-09-01

### 🚀 Features

- *(types)* Add ChangeEpochV4 (#474)
- *(transaction-builder)* Add support for extensible async signer (#445)
- Add Move Authenticator support (#442)
- *(transaction-builder)* Add `DryRunResult` associated type to `ClientMethods` (#508)
- *(ffi)* Export more derivable traits (#421)
- Add examples using the releases (#409)
- *(binding)* Expose more intent types (#518)
- *(ffi)* Add `to_json` and `from_json` to most types (#520)
- *(iota-sdk-graphql-client)* Add move_view_call (#516)
- *(iota-types)* Better Address parsing (#538)
- Add AA bindings examples (#541)
- *(transaction-builder)* Add `set_sender` method (#549)
- *(graphql)* Add `request_and_wait_for_finalized` for better waiting on faucet funds (#552)
- *(examples)* Remove obsolete sleep (#1024)
- *(examples)* Add multisig example to Rust and all bindings (#988)
- Bump `uniffi-bindgen-go` to 0.29 (#991)
- *(types)* Add versioning to MoveAuthenticator (#1002)
- *(iota-sdk-types)* Add passkey to multisig (#1075)
- BCS ABNF compile-time generation (#1040)
- Use Version struct over type def (#1084)
- *(types)* Enhance Address with system package constants and methods (#1085)
- *(types)* Enhance ObjectId with system constants and methods (#540) (#1086)
- *(types)* Enhance Digest with additional methods and constants (#1088)
- *(iota-sdk-types)* Derive AddAssign and SubAssign for GasCostSummary (#1089)
- *(types)* Enhance Identifier, TypeTag and StructTag (#1092)
- *(iota-sdk-types)* Derive Hash on Event and add SystemEpochInfoEvent helpers (#1096)
- `Owner` improvements (#1100)
- MovePackage changes (#973) (#1104)
- Add move package example (#1046)
- `TransactionKind` improvements (#1130)
- *(transaction-builder)* Impl TryFrom<Transaction> for TransactionBuilder (#1129)
- *(bindings)* Remove built artifacts (#1135)
- [**breaking**] `MultisigAggregatedSignature` changes (#1137)
- [**breaking**] Separate Event and GraphQlEvent types (#1184)
- *(iota-sdk-types)* Update `Object` (#1186)
- Add address_transactions example (#1172)
- Add `iota-sdk-move-types` crate (#1124)
- Add distinct digest newtype wrappers (#1232)
- *(bindings)* Update to uniffi 31 (#1029)
- *(iota-sdk-transaction-builder)* Add authorize_upgrade and commit_upgrade helpers (#1339)
- *(bindings)* Expose GraphQL subscriptions over the FFI (#1303)
- Add transaction_builder constructors to the clients (#1359)
- *(iota-sdk-types)* Derive the object sets from TransactionEffectsV1 (#1331)
- *(bindings)* Expose the tree-style Display as to_display_string() (#1372)

### 🐛 Bug Fixes

- *(tx-builder)* Fix WaitForTx::Indexed usage and docs (#548)
- *(examples)* Update package id for events (#1008)
- *(ffi)* Use strings for Epoch datetimes in FFI (#1081)
- *(examples)* Segfault in the go `coin_balances` example for addresses without a balance (#1080)
- *(examples)* Avoid type-only object queries that time out (#1296)

### 🚜 Refactor

- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- Name type_ fields after the type they hold (#1369)
- *(iota-sdk-ffi)* Align MultisigAggregator with the validator aggregator (#1380)
- Move BCS/JSON conversions onto their types (#1378)
- *(iota-sdk-ffi)* [**breaking**] Derive the remote uniffi types as local mirrors (#1392)
- Spell out transaction in client API names (#1388)
- Unify option-accessor spelling to opt_x (#1391)

### ⚙️ Miscellaneous Tasks

- *(types)* Add some missing functionality needed by core (#463)
- *(types)* Add string methods to ObjectId (#467)
- Rename `Address::STD_LIB` to `Address::STD` (#488)
- *(transaction-builder)* Rename `name` to `assign` (#482)
- *(examples)* Replace more instances of `request_and_wait` (#554)
- Typos (#562)
- *(examples+tests)* Switch to testnet (#997)
- Re-enable AA examples (#1038)
- Remove ZkLogin and JWK (#1071)
- Remove `ExecutionTimeEstimate` related types (#1078)
- Make transaction data/effects tests localnet-stable (#1281)
- Re-enable the Move view call examples (#1348)

## [0.0.1-alpha.1] - 2025-12-03

Initial Release
