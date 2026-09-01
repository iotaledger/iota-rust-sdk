## [1.0.0-beta.1] - 2026-09-01

### 🚀 Features

- *(examples)* Remove obsolete sleep (#1024)
- *(examples)* Add multisig example to Rust and all bindings (#988)
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

- *(ffi)* Use strings for Epoch datetimes in FFI (#1081)
- *(examples)* Segfault in the go `coin_balances` example for addresses without a balance (#1080)
- *(bindings,ci)* Remove unsafeFlags from swift publish (#1136)
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

- *(swift)* Rename examples to PascalCase (#1036)
- Re-enable AA examples (#1038)
- Remove ZkLogin and JWK (#1071)
- Remove `ExecutionTimeEstimate` related types (#1078)
- Make transaction data/effects tests localnet-stable (#1281)
- Re-enable the Move view call examples (#1348)

## [0.0.1-alpha.1] - 2026-03-09

Initial Release
