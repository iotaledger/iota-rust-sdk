## [3.0.0-beta.1] - 2026-09-02

### 🚀 Features

- Add `iota-sdk-move-types` crate (#1124)
- *(wasm)* Add release example (#1225)
- Add distinct digest newtype wrappers (#1232)
- *(bindings)* Update to uniffi 31 (#1029)
- *(iota-sdk-transaction-builder)* Add authorize_upgrade and commit_upgrade helpers (#1339)
- Add transaction_builder constructors to the clients (#1359)
- *(iota-sdk-types)* Derive the object sets from TransactionEffectsV1 (#1331)
- *(bindings)* Expose the tree-style Display as to_display_string() (#1372)

### 🐛 Bug Fixes

- Apply PaginationFilter direction default in wasm bindings (#1230)
- *(examples)* Avoid type-only object queries that time out (#1296)

### 🚜 Refactor

- [**breaking**] Use US English spellings in comments and public APIs (#1322)
- [**breaking**] Rename generate to random_with and pair every random_with with random (#1344)
- Name type_ fields after the type they hold (#1369)
- *(iota-sdk-ffi)* Align MultisigAggregator with the validator aggregator (#1380)
- Move BCS/JSON conversions onto their types (#1378)
- *(iota-sdk-ffi)* [**breaking**] Derive the remote uniffi types as local mirrors (#1392)
- Spell out transaction in client API names (#1388)
- Unify option-accessor spelling to opt_x (#1391)

### ⚙️ Miscellaneous Tasks

- Make transaction data/effects tests localnet-stable (#1281)
- Re-enable the Move view call examples (#1348)

## [3.0.0-alpha.1] - 2026-06-16

Initial Release
